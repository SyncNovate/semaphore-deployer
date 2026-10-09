package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// HTTPClient is the mTLS HTTP client the executor uses for every
// outbound call to the `semaphore-deployer` fork. The client
// pins against the server's CA bundle (no system CAs) and presents
// the executor's Ed25519 client cert + key for mutual TLS.
//
// Why a dedicated client (not http.DefaultClient): http.DefaultClient
// has a default Transport with no timeouts, no mTLS, no connection
// pooling tuned for long-lived executors. A misconfigured
// server or DNS could hang a request indefinitely; the dedicated
// client enforces a hard 30s timeout per the design doc §10.9.4
// (operations either complete or surface a loud error, never
// silently fail).
type HTTPClient struct {
	client    *http.Client
	serverURL string
}

// NewHTTPClient builds an mTLS HTTP client. The four cert paths
// (client cert, client key, server CA, plus the URL) come from
// Config; the client fails fast if any of them is missing or
// unparseable.
//
// The server CA bundle is the ONLY CA the client trusts for the
// outbound connection. We do NOT consult the system root CAs
// (InsecureSkipVerify-style) so a compromised system CA cannot
// MITM the executor.
func NewHTTPClient(cfg Config, timeout time.Duration) (*HTTPClient, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("executor/client: ServerURL is required")
	}
	if cfg.ClientCertPath == "" {
		return nil, errors.New("executor/client: ClientCertPath is required")
	}
	if cfg.ClientKeyPath == "" {
		return nil, errors.New("executor/client: ClientKeyPath is required")
	}
	if cfg.ServerCAFile == "" {
		return nil, errors.New("executor/client: ServerCAFile is required")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// Load the server CA bundle. We do NOT fall back to system
	// roots — the customer explicitly pins against this file.
	caPEM, err := os.ReadFile(cfg.ServerCAFile)
	if err != nil {
		return nil, fmt.Errorf("executor/client: read server CA: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("executor/client: server CA file %s is not a valid PEM bundle",
			cfg.ServerCAFile)
	}

	// Load the client cert + key from PEM files. tls.X509KeyPair
	// expects a single cert + key; if the PEM file contains a
	// chain (cert + intermediate), we use the first cert for the
	// leaf. Chain validation is the server's job.
	certPEM, err := os.ReadFile(cfg.ClientCertPath)
	if err != nil {
		return nil, fmt.Errorf("executor/client: read client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("executor/client: read client key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("executor/client: parse client cert+key: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// ServerName is set per-request via the URL; we don't
		// pin it here because the URL drives the dial.
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		// Disable HTTP/2 for the mTLS connection: the design
		// doc says mTLS works better over HTTP/1.1 (the fork's
		// server is HTTP/1.1). Re-enable if a future sub-chunk
		// adds HTTP/2 support.
		ForceAttemptHTTP2: false,
		// Custom dialer with a connect timeout so a DNS hang
		// does not block past the response-header timeout.
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return &HTTPClient{
		client:    client,
		serverURL: cfg.ServerURL,
	}, nil
}

// Do sends an authenticated request. The bearer token is
// attached as `Authorization: Bearer <token>`. The request
// respects the caller's context for cancellation. The caller
// owns the response body and must close it.
func (c *HTTPClient) Do(ctx context.Context, method, path, bearerToken string, body []byte) (*http.Response, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("executor/client: nil client")
	}
	if path == "" {
		return nil, errors.New("executor/client: path is required")
	}
	url := c.serverURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("executor/client: build request: %w", err)
	}
	if body != nil {
		req.Body = readCloserFromBytes(body)
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	return c.client.Do(req)
}

// readCloserFromBytes wraps a byte slice in an io.ReadCloser so
// http.NewRequestWithContext can consume it as a request body.
func readCloserFromBytes(b []byte) *byteReadCloser {
	return &byteReadCloser{b: b}
}

type byteReadCloser struct {
	b   []byte
	pos int
}

func (r *byteReadCloser) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		// CRITICAL: must return the sentinel io.EOF, not a
		// custom "EOF" error. The Go http transport's request
		// body reader checks for io.EOF specifically to know
		// when to flush + send. A non-io.EOF error at
		// end-of-body makes the transport either hang or
		// close the connection mid-handshake (the EOF we saw
		// on the registration tests).
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
func (r *byteReadCloser) Close() error { return nil }

// pemToTLSCert is a test helper that builds a tls.Certificate
// from PEM-encoded cert + key bytes (no file). Production code
// reads the cert + key from disk via NewHTTPClient; tests use
// this to avoid temp-file plumbing.
func pemToTLSCert(certPEM, keyPEM []byte) (tls.Certificate, error) {
	// Validate the PEM blocks before handing them to
	// tls.X509KeyPair (which would otherwise return a generic
	// "no PEM blocks" error). Pre-validation gives better test
	// failure messages.
	if block, _ := pem.Decode(certPEM); block == nil {
		return tls.Certificate{}, errors.New("pemToTLSCert: cert is not PEM")
	}
	if block, _ := pem.Decode(keyPEM); block == nil {
		return tls.Certificate{}, errors.New("pemToTLSCert: key is not PEM")
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// NewHTTPClientForTest builds an HTTPClient with the option to
// skip CA verification. TEST SCAFFOLDING ONLY — production
// code MUST use NewHTTPClient (which pins against the explicit
// CA bundle). The InsecureSkipVerify flag exists because the
// skeleton's test cert chain (httptest self-signed) doesn't
// give us a portable way to extract the server's CA back to
// PEM; the cross-cutting test surface in R-I.4.e builds a
// proper cert chain.
func NewHTTPClientForTest(cfg Config, timeout time.Duration, insecureSkipVerify bool) (*HTTPClient, error) {
	c, err := NewHTTPClient(cfg, timeout)
	if err != nil {
		return nil, err
	}
	if insecureSkipVerify {
		// Rewrite the transport's TLS config to skip CA
		// verification. We do NOT touch the client cert
		// (mTLS is still presented); only the server-CA
		// check is bypassed.
		transport := c.client.Transport.(*http.Transport)
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	return c, nil
}

// newHTTPClientWithTLSConfig is a test-only constructor that
// builds an HTTPClient from an in-memory *tls.Config (no disk
// I/O, no PEM parsing). Used by the transport-level tests
// in client_test.go and registration_test.go.
//
// The function is unexported because production code MUST use
// NewHTTPClient (which pins against the explicit CA bundle
// loaded from disk). This constructor exists so the test
// surface can exercise the mTLS handshake shape without
// standing up a full cert chain.
func newHTTPClientWithTLSConfig(serverURL string, tlsConfig *tls.Config, timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &HTTPClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		serverURL: serverURL,
	}
}

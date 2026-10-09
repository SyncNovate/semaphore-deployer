package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewHTTPClientRequiresAllCertPaths pins the constructor
// invariants: every path field on Config is required at startup.
// A real prod deployment never wants to fall back to "no cert"
// or "no CA" — those are silent-degradation footguns.
func TestNewHTTPClientRequiresAllCertPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no server URL", func(c *Config) { c.ServerURL = "" }},
		{"no client cert path", func(c *Config) { c.ClientCertPath = "" }},
		{"no client key path", func(c *Config) { c.ClientKeyPath = "" }},
		{"no server CA file", func(c *Config) { c.ServerCAFile = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validHTTPClientConfig()
			tc.mutate(&cfg)
			if _, err := NewHTTPClient(cfg, 5*time.Second); err == nil {
				t.Errorf("NewHTTPClient should reject %q", tc.name)
			}
		})
	}
}

// TestNewHTTPClientDoAttachesBearerHeader verifies the auth
// header plumbing. Uses a real httptest server so the Do
// call actually completes; the in-memory client + the
// recording server's TLS config is bridged via
// InsecureSkipVerify (test scaffolding only — see the
// helper's comment for why).
func TestNewHTTPClientDoAttachesBearerHeader(t *testing.T) {
	var receivedAuth string
	recordingServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer recordingServer.Close()

	client := newInMemoryTestClientPointingAt(t, recordingServer.URL)
	resp, err := client.Do(
		context.Background(),
		http.MethodGet,
		"/api/v1/executor/heartbeat",
		"my-bearer-token",
		nil,
	)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	if receivedAuth != "Bearer my-bearer-token" {
		t.Errorf("Authorization = %q, want 'Bearer my-bearer-token'", receivedAuth)
	}
}

// TestNewHTTPClientDoHandlesServerError verifies that a 5xx
// from the server surfaces as an error from Do (the caller
// decides whether to retry — heartbeat + claim retry, result
// does not).
func TestNewHTTPClientDoHandlesServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := newInMemoryTestClientPointingAt(t, server.URL)
	resp, err := client.Do(
		context.Background(),
		http.MethodGet,
		"/api/v1/executor/heartbeat",
		"tok",
		nil,
	)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// ---- Test scaffolding ---------------------------------------------------

// validHTTPClientConfig returns a Config that would pass
// NewHTTPClient's path-validation step. The cert paths point
// to /dev/null so the file-read step will fail — useful for
// the "rejects path X" tests that don't reach the file-read
// step.
func validHTTPClientConfig() Config {
	return Config{
		ServerURL:                 "https://example.com",
		ClientCertPath:            "/some/cert",
		ClientKeyPath:             "/some/key",
		ServerCAFile:              "/some/ca",
		HeartbeatIntervalSeconds:  10,
		ClaimPollIntervalSeconds:  5,
		OfflineTimeoutMinutes:     5,
	}
}

// generateEd25519TestCert returns (certBytes, key) for a
// self-signed Ed25519 cert. Used only in the in-memory
// transport test scaffolding. The cert is suitable for the
// client's mTLS presentation (signed leaf, no chain). It is
// NOT suitable for server-side verification — the test
// scaffolding uses InsecureSkipVerify for that leg.
func generateEd25519TestCert(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der, priv
}

// parseLeaf parses a DER cert into a *x509.Certificate for
// the tls.Certificate.Leaf field.
func parseLeaf(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}

// newInMemoryTestClientPointingAt builds an in-memory TLS
// client with the given server URL. The InsecureSkipVerify is
// a test-scaffolding concession: httptest's self-signed
// cert is not portable back to a PEM file the client can pin
// against. Real production mTLS (with a real CA chain) is
// exercised in R-I.4.e's cross-cutting tests.
func newInMemoryTestClientPointingAt(t *testing.T, serverURL string) *HTTPClient {
	t.Helper()
	cert, key := generateEd25519TestCert(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert},
			PrivateKey:  key,
			Leaf:        parseLeaf(t, cert),
		}},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}
	return newHTTPClientWithTLSConfig(serverURL, tlsConfig, 5*time.Second)
}

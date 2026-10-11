package executor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// PlatformClient is the executor's plain-HTTPS client for the
// SentraOps platform BE (the SOC console's backend). It is a
// separate client from HTTPClient (which is mTLS-pinned to the
// Semaphore server) because:
//
//   - The platform BE does not terminate mTLS at its edge (the
//     nginx in front of it does the TLS, but does not pin a
//     client cert).
//   - The platform BE uses a shared-secret API key (the
//     `X-Sentraops-Api-Key` header) to authenticate the
//     executor's command-inbox calls (R-I.12.b design). The
//     mTLS client cert was used for the fork's Semaphore
//     registration, not for the platform BE inbox.
//
// The shared secret is rotated by the platform operator; the
// executor writes the current secret to /etc/sentraops-executor/
// api_key at install time (mode 0600) and re-reads it on every
// call. The OS file mode is the only protection — the platform
// API key is intentionally not derived from the mTLS cert, so
// a leaked file is a fully-scoped shared secret, not a session
// for a different system.
//
// Why not use the existing HTTPClient: HTTPClient is hard-wired
// to present the mTLS cert + key. The platform BE would not
// validate those (its mTLS path is dormant), but every byte
// would still be sent over the wire. Mixing the two clients
// makes the wire surface obvious in a packet capture and the
// auth model obvious in code review.
type PlatformClient struct {
	client    *http.Client
	serverURL string
	apiKey    string
}

// NewPlatformClient builds a plain-HTTPS client. The API key
// is read from disk at construction (so a secret rotation
// requires a service restart, which is the same lifecycle as
// the mTLS cert rotation). The client fails fast on a missing
// or unreadable key file.
func NewPlatformClient(cfg Config, apiKeyPath string, timeout time.Duration) (*PlatformClient, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("executor/platform_client: ServerURL is required")
	}
	if apiKeyPath == "" {
		return nil, errors.New("executor/platform_client: apiKeyPath is required")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// Read + mode-check the API key file. The install script
	// writes it 0600 root:root; we double-check here to fail
	// loud if a customer sysadmin accidentally relaxed the
	// perms.
	info, err := os.Stat(apiKeyPath)
	if err != nil {
		return nil, fmt.Errorf("executor/platform_client: stat api key: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("executor/platform_client: api key file %s has insecure mode %#o (must be 0o600 or stricter)",
			apiKeyPath, mode)
	}
	raw, err := os.ReadFile(apiKeyPath)
	if err != nil {
		return nil, fmt.Errorf("executor/platform_client: read api key: %w", err)
	}
	apiKey := string(raw)
	// Strip the trailing newline the install script writes
	// after the secret (echo > file appends \n).
	if n := len(apiKey); n > 0 && apiKey[n-1] == '\n' {
		apiKey = apiKey[:n-1]
	}
	if apiKey == "" {
		return nil, errors.New("executor/platform_client: api key file is empty")
	}

	// Plain TLS, no client cert. The platform BE is expected
	// to be behind nginx with a public cert (or a Letsencrypt
	// cert in production). We do NOT InsecureSkipVerify; the
	// customer's system CAs are trusted for the platform
	// host only.
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// No client certificate presented.
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}

	return &PlatformClient{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		serverURL: cfg.ServerURL,
		apiKey:    apiKey,
	}, nil
}

// Do sends an authenticated request to the platform BE.
// The shared secret is sent as `X-Sentraops-Api-Key` per the
// BE's require_api_key dep (R-I.12.a). The caller owns the
// response body and must close it.
func (c *PlatformClient) Do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("executor/platform_client: nil client")
	}
	if path == "" {
		return nil, errors.New("executor/platform_client: path is required")
	}
	url := c.serverURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("executor/platform_client: build request: %w", err)
	}
	if body != nil {
		req.Body = readCloserFromBytes(body)
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Sentraops-Api-Key", c.apiKey)
	req.Header.Set("User-Agent", "sentraops-executor/"+executorVersion)
	return c.client.Do(req)
}

// executorVersion is the build-stamped version. Injected at
// link time from cmd/executor/main.go (the cmd package owns
// the version var so a binary rebuild surfaces the new
// version in the User-Agent without an executor package
// edit). Default is "dev" for test builds.
var executorVersion = "dev"

// SetExecutorVersion is the test hook. Production code
// should NOT call this — the cmd package sets the var
// directly so a real binary always reports its real version.
func SetExecutorVersion(v string) {
	if v != "" {
		executorVersion = v
	}
}

// StatusCode is a tiny helper that returns the response
// status code or 0 if the response is nil. Centralised so
// every caller reads the same way.
func StatusCode(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// String returns the string form of a status code (used for
// log fields). Centralised so the format is consistent.
func StatusString(code int) string {
	if code == 0 {
		return "nil-response"
	}
	return strconv.Itoa(code)
}

// drainAndClose discards the body and closes the connection.
// Call this when you don't care about the body but want the
// connection to be reusable. This is a copy of the helper
// from executor/client.go in case the platform client ends
// up in a different package; keep them in sync.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

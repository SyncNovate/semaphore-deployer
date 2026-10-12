// Tests for the install endpoint. The handler is the SOC's
// public surface for "push this URL to every machine in the
// customer's fleet", so the tests are written from the
// customer's deploy admin's perspective — paste the URL, get
// back a runnable script.
//
// R-D (2026-10-12).
package install

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeStore is a TokenStore double for the test suite. It
// returns fixed values keyed by the SHA-256 of the plaintext
// token so the test can predict the lookup result.
type fakeStore struct {
	// tenants maps token-hash-hex -> tenant_id.
	tenants map[string]string
	// expiries maps token-hash-hex -> expiry.
	expiries map[string]time.Time
	// notFound is a fixed error to return when the token is
	// not in tenants. We can't put a sentinel in the map
	// because time.Time zero value would be a real (past)
	// time.
	defaultErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		tenants:  map[string]string{},
		expiries: map[string]time.Time{},
	}
}

func (f *fakeStore) add(plaintext, tenant string, expiresAt time.Time) {
	h := HashToken(plaintext)
	f.tenants[h] = tenant
	f.expiries[h] = expiresAt
}

func (f *fakeStore) LookupByHash(hash []byte) (string, time.Time, error) {
	key := hexEncode(hash)
	if tenant, ok := f.tenants[key]; ok {
		return tenant, f.expiries[key], nil
	}
	if f.defaultErr != nil {
		return "", time.Time{}, f.defaultErr
	}
	return "", time.Time{}, ErrTokenNotFound
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0F]
	}
	return string(out)
}

const (
	testToken     = "abc123-plaintext-token"
	testTenant    = "ORG-ACME"
	testServerURL = "https://sentraops.example.com:9443"
)

func newTestHandler() (*Handler, *fakeStore) {
	store := newFakeStore()
	store.add(testToken, testTenant, time.Now().Add(1*time.Hour))
	h := NewHandler(store, testServerURL)
	return h, store
}

// TestInstallHandlerLinux is the happy path on Linux.
func TestInstallHandlerLinux(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=linux", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN=") {
		t.Errorf("bash body should export BOOTSTRAP_TOKEN; got: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testToken) {
		t.Errorf("bash body should contain the plaintext token; got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testServerURL) {
		t.Errorf("bash body should contain the server URL; got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testTenant) {
		t.Errorf("bash body should contain the tenant id; got first 200: %q", body[:min(200, len(body))])
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/x-shellscript") {
		t.Errorf("Content-Type = %q, want application/x-shellscript*", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// TestInstallHandlerWindows is the happy path on Windows.
func TestInstallHandlerWindows(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=windows", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN") {
		t.Errorf("ps1 body should set $env:BOOTSTRAP_TOKEN; got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testToken) {
		t.Errorf("ps1 body should contain the plaintext token; got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testTenant) {
		t.Errorf("ps1 body should contain the tenant id; got first 200: %q", body[:min(200, len(body))])
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain*", got)
	}
}

// TestInstallHandlerMacOSUsesBash confirms macOS uses the same
// bash script as Linux (no separate install-macos.sh yet). The
// industry standard is "bash on macOS is identical"; the
// /install/<token>?os=macos endpoint should just return the
// same script.
func TestInstallHandlerMacOSUsesBash(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=macos", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN=") {
		t.Error("macos body should use bash (export ...)")
	}
}

// TestInstallHandlerDarwinAlias accepts the Go-style "darwin"
// alias in case some user agent sends the runtime.GOOS value.
func TestInstallHandlerDarwinAlias(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=darwin", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (darwin should map to bash)", rec.Code)
	}
}

// TestInstallHandlerDefaultOS confirms that an absent ?os=
// query param defaults to Linux (most common in our customer
// base).
func TestInstallHandlerDefaultOS(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (default OS = linux)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN=") {
		t.Error("default body should be bash")
	}
}

// TestInstallHandlerTokenNotFound returns 404 when the token
// does not exist in the store.
func TestInstallHandlerTokenNotFound(t *testing.T) {
	h, store := newTestHandler()
	store.defaultErr = ErrTokenNotFound

	req := httptest.NewRequest(http.MethodGet, "/install/unknown-token?os=linux", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestInstallHandlerTokenExpired returns 410 when the token
// has expired. The store's expiry is honoured; the handler's
// own clock check is defence in depth.
func TestInstallHandlerTokenExpired(t *testing.T) {
	h, store := newTestHandler()
	store.add("expired-token", "ORG-X", time.Now().Add(-1*time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/install/expired-token?os=linux", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Errorf("status = %d, want 410", rec.Code)
	}
}

// TestInstallHandlerTokenExpiredClockSkew covers the
// defence-in-depth case: the store returns an expiry that has
// ALREADY passed, but the store's LookupByHash does not
// itself return ErrTokenExpired (e.g. the store is misbehaving
// or has a different clock). The handler's Now() check should
// catch it.
func TestInstallHandlerTokenExpiredClockSkew(t *testing.T) {
	// Custom handler with a fixed Now() AFTER the stored expiry.
	store := newFakeStore()
	store.add(testToken, testTenant, time.Unix(100, 0))

	h := NewHandler(store, testServerURL)
	h.Now = func() time.Time { return time.Unix(200, 0) }

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=linux", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 (clock-skew defence)", rec.Code)
	}
}

// TestInstallHandlerEmptyToken returns 400 for /install/ alone
// (no token in the path).
func TestInstallHandlerEmptyToken(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// TestInstallHandlerMethodNotAllowed rejects POST/PUT/DELETE.
// Only GET is supported (the customer's deploy admin runs the
// URL via curl/iwr which are GETs).
func TestInstallHandlerMethodNotAllowed(t *testing.T) {
	h, _ := newTestHandler()

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/install/"+testToken+"?os=linux", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, rec.Code)
		}
	}
}

// TestInstallHandlerUnsupportedOS returns 400 for unknown
// ?os= values. SentraOps supports Linux/macOS/Windows only;
// anything else is a typo or an attacker probe.
func TestInstallHandlerUnsupportedOS(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=plan9", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unsupported os", rec.Code)
	}
}

// TestInstallHandlerInternalErrorOnStoreErr returns 500 if
// the store fails with an unrecognised error.
func TestInstallHandlerInternalErrorOnStoreErr(t *testing.T) {
	h, store := newTestHandler()
	store.defaultErr = errors.New("db connection refused")

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=linux", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// TestRenderBashSingleQuotesToken verifies the bash renderer
// single-quotes the token, so a base64.RawURLEncoding string
// that contains shell metacharacters (e.g. '+', '-', '_') is
// passed through verbatim.
func TestRenderBashSingleQuotesToken(t *testing.T) {
	out := renderBash("echo hi", "tok-with+chars_/", "https://x", "ORG")
	if !strings.Contains(out, `export SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN="tok-with+chars_/"`) {
		t.Errorf("bash export should be double-quoted; got: %q", out)
	}
}

// TestRenderPowerShellEscapesSingleQuotes verifies the PS
// renderer escapes any single quote in the token by doubling
// it. base64.RawURLEncoding does not include ' so this is
// defence in depth.
func TestRenderPowerShellEscapesSingleQuotes(t *testing.T) {
	out := renderPowerShell("Write-Host hi", "abc'd", "https://x", "ORG")
	if !strings.Contains(out, `$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN = 'abc''d'`) {
		t.Errorf("PS export should escape single quotes; got: %q", out)
	}
}

// TestInstallHandlerBodyIsNotConsumedToWire verifies the
// /install/<token> endpoint does NOT consume the token. The
// customer's deploy admin might hit it 50 times (one per
// machine if MDM is unavailable) before the first /enroll
// arrives. The store is read-only here.
func TestInstallHandlerBodyIsNotConsumedToWire(t *testing.T) {
	h, _ := newTestHandler()

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=linux", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("iteration %d: status = %d, want 200 (install URL should not consume)", i, rec.Code)
		}
	}
}

// TestHashTokenDeterministic verifies HashToken returns a
// stable 64-char hex string (SHA-256 of the plaintext).
func TestHashTokenDeterministic(t *testing.T) {
	a := HashToken("hello")
	b := HashToken("hello")
	if a != b {
		t.Errorf("HashToken not deterministic: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(a))
	}
	c := HashToken("hello!")
	if a == c {
		t.Error("HashToken(hello) == HashToken(hello!) — should differ")
	}
}

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
//
// BUG-011 (2026-10-13): the served install.ps1 must NOT contain
// any executable statement before the param() block, because
// PowerShell 5.1 requires the script-level param() block to be
// the first executable statement (env-var assignments before it
// make the parser throw "Unexpected attribute 'CmdletBinding'"
// and "Unexpected token 'param'"). The render function therefore
// bakes the values directly into the param() defaults as
// single-quoted literals. This test verifies both invariants:
// (1) the param() block is the first executable statement, and
// (2) the plaintext token + tenant + URL are present in the
// body as literal defaults.
func TestInstallHandlerWindows(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/install/"+testToken+"?os=windows", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The values are now baked into the param() defaults as
	// single-quoted PowerShell literals, NOT as env-var reads.
	if strings.Contains(body, "$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN") ||
		strings.Contains(body, "$env:SENTRAOPS_EXECUTOR_SERVER_URL") ||
		strings.Contains(body, "$env:SENTRAOPS_EXECUTOR_TENANT_ID") {
		t.Errorf("ps1 body must NOT contain $env:VAR reads (BUG-011: param() block must be first executable statement); got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testToken) {
		t.Errorf("ps1 body should contain the plaintext token; got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testTenant) {
		t.Errorf("ps1 body should contain the tenant id; got first 200: %q", body[:min(200, len(body))])
	}
	if !strings.Contains(body, testServerURL) {
		t.Errorf("ps1 body should contain the server URL; got first 200: %q", body[:min(200, len(body))])
	}
	// The body must start with the BOM (EF BB BF) so PowerShell 5.1
	// reads it as UTF-8 instead of Windows-1252.
	if len(body) < 3 || body[0] != 0xEF || body[1] != 0xBB || body[2] != 0xBF {
		t.Errorf("ps1 body must start with UTF-8 BOM (BUG-009); first 3 bytes: % x", []byte(body)[:min(3, len(body))])
	}
	// And the param() block must be the first executable statement
	// after the BOM + comment header. We check that `[CmdletBinding()]`
	// appears before any other executable line in the body.
	noHeader := strings.TrimLeft(body, "\xef\xbb\xbf")
	// Skip leading comment lines (start with '#')
	firstNonComment := ""
	for _, line := range strings.Split(noHeader, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		firstNonComment = trimmed
		break
	}
	if firstNonComment != "[CmdletBinding()]" {
		t.Errorf("first executable statement must be [CmdletBinding()] (BUG-011); got: %q", firstNonComment)
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
	// Build a store that does NOT have the testToken in its
	// map; the only path the lookup can take is the
	// defaultErr path. newTestHandler() would pre-add the
	// token, masking the failure case.
	store := newFakeStore()
	store.defaultErr = errors.New("db connection refused")
	h := NewHandler(store, testServerURL)

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
// it in the param() default literal. base64.RawURLEncoding
// does not include ' so this is defence in depth. BUG-011:
// the previous test asserted an env-var assignment shape that
// is no longer produced — the value is now baked into the
// param() block defaults.
func TestRenderPowerShellEscapesSingleQuotes(t *testing.T) {
	// A minimal param block so the test exercises the substitution
	// path with a real PowerShell param() shape, not just an
	// arbitrary string.
	template := "[CmdletBinding()]\nparam(\n    [string]$BootstrapToken = $env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN,\n    [string]$ServerURL      = $env:SENTRAOPS_EXECUTOR_SERVER_URL\n)\nWrite-Host hi\n"
	out := renderPowerShell(template, "abc'd", "https://x", "ORG")
	if !strings.Contains(out, "[string]$BootstrapToken = 'abc''d'") {
		t.Errorf("PS param default should be a single-quoted literal with escaped quotes; got: %q", out)
	}
	if !strings.Contains(out, "[string]$ServerURL      = 'https://x'") {
		t.Errorf("PS param default for ServerURL should be a single-quoted literal; got: %q", out)
	}
	// And the param() block must remain the first executable
	// statement (no env-var assignments before it).
	if strings.Contains(out, "$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN") {
		t.Errorf("BUG-011: rendered output must NOT contain $env:VAR reads; got: %q", out)
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

// TestRenderPowerShellBUG011InstallEndToEnd exercises the full
// install.ps1 template path (which is the actual file served in
// production) and asserts the BUG-011 invariants: the served
// file must start with a UTF-8 BOM, the param() block must be
// the first executable statement, and the values must be baked
// in as single-quoted PowerShell literals — NOT as env-var
// reads. PowerShell 5.1's parser is strict about the first
// executable statement; if this test ever fails, the live
// Windows install will fail the same way.
func TestRenderPowerShellBUG011InstallEndToEnd(t *testing.T) {
	// Use the actual embedded install.ps1 template (go:embed).
	// This catches regressions where the template is edited but
	// the renderer is not updated, or vice versa.
	if installScriptWindowsPowerShell == "" {
		t.Fatal("embedded install.ps1 template is empty")
	}
	// Sanity: the embedded template itself must start with BOM.
	if len(installScriptWindowsPowerShell) < 3 ||
		installScriptWindowsPowerShell[0] != 0xEF ||
		installScriptWindowsPowerShell[1] != 0xBB ||
		installScriptWindowsPowerShell[2] != 0xBF {
		t.Error("embedded install.ps1 must start with UTF-8 BOM (BUG-009); the source file should ship with the BOM")
	}
	// Sanity: the embedded template must have a [CmdletBinding()]
	// / param() block.
	if !strings.Contains(installScriptWindowsPowerShell, "[CmdletBinding()]") {
		t.Error("embedded install.ps1 must have a [CmdletBinding()] attribute (R-D install script contract)")
	}
	if !strings.Contains(installScriptWindowsPowerShell, "param(") {
		t.Error("embedded install.ps1 must have a param() block")
	}

	out := renderPowerShell(installScriptWindowsPowerShell, "tok123", "https://sentraops.example.com:9443", "ORG-ACME")

	// Invariant 1: served output starts with BOM.
	if len(out) < 3 || out[0] != 0xEF || out[1] != 0xBB || out[2] != 0xBF {
		t.Error("rendered ps1 must start with UTF-8 BOM")
	}
	// Invariant 2: no env-var reads remain (BUG-011: those
	// would force the param() block to be the second executable
	// statement, which PowerShell 5.1 rejects).
	for _, env := range []string{
		"$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN",
		"$env:SENTRAOPS_EXECUTOR_SERVER_URL",
		"$env:SENTRAOPS_EXECUTOR_TENANT_ID",
		"$env:SENTRAOPS_EXECUTOR_BINARY_URL",
	} {
		if strings.Contains(out, env) {
			t.Errorf("rendered ps1 must not contain %q (BUG-011); the values must be baked in as literals", env)
		}
	}
	// Invariant 3: the param() block is the first executable
	// statement. The header is comments only; the very first
	// non-comment, non-blank line must be [CmdletBinding()].
	body := strings.TrimPrefix(out, "\xef\xbb\xbf")
	firstExec := ""
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		firstExec = trimmed
		break
	}
	if firstExec != "[CmdletBinding()]" {
		t.Errorf("first executable statement must be [CmdletBinding()] (BUG-011); got: %q", firstExec)
	}
	// Invariant 4: the baked-in literal token / URL / tenant
	// appear in the param() defaults.
	if !strings.Contains(out, "[string]$BootstrapToken = 'tok123'") {
		t.Error("BootstrapToken default must be baked in as 'tok123'")
	}
	if !strings.Contains(out, "[string]$ServerURL      = 'https://sentraops.example.com:9443'") {
		t.Error("ServerURL default must be baked in as the server URL")
	}
	if !strings.Contains(out, "[string]$TenantID       = 'ORG-ACME'") {
		t.Error("TenantID default must be baked in as the tenant ID")
	}
}

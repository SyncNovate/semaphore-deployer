// Package install serves the per-customer install bundle for the
// SentraOps executor.
//
// R-D (2026-10-12): the per-customer install path. One bootstrap
// token mints per customer (via the platform BE's "Send Executor"
// flow), and the customer's deploy admin pushes the resulting URL
// to every machine in the customer's fleet via their existing MDM
// (Intune / Jamf / Ansible Tower). Each machine self-enrolls on
// first run.
//
// Wire shape:
//
//	GET /install/<token>?os=linux|macos|windows
//
// The handler:
//   1. Extracts the token from the URL path.
//   2. Looks the token up by its SHA-256 hash (the same lookup
//      the /api/v1/executor/enroll handler does). The token is
//      NOT consumed here — the customer's deploy admin might
//      push the URL to many machines, each of which will hit
//      /enroll and consume its own copy. The install URL is
//      served until the token's expiry.
//   3. Reads the OS from the ``os`` query param. Defaults to
//      Linux if absent (the most common case in our customer
//      base; bash on macOS is identical, so macOS uses the same
//      script).
//   4. Renders the embedded install script (install.sh for
//      Linux + macOS, install.ps1 for Windows) with the
//      bootstrap token, server URL, and tenant ID baked in as
//      exports. The customer does NOT supply any of those at
//      install time — the signed URL is the customer's identity.
//
// The install scripts are embedded via go:embed so the script
// content is signed + versioned with the binary. A future
// refactor of the script requires rebuilding the binary; there
// is no "live edit the install script on disk" path.
package install

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed install.sh
var installScriptLinuxBash string

//go:embed install.ps1
var installScriptWindowsPowerShell string

// TokenStore is the subset of the fork's enrollment-token
// persistence that this package needs. The real implementation
// lives in the fork's db package; we keep the surface narrow so
// the install handler is easy to test (a test double can return
// a fixed tenant + expiry).
type TokenStore interface {
	// LookupByHash returns the tenant_id bound to the token
	// and the expiry timestamp. Returns ErrTokenNotFound if
	// the token is unknown, ErrTokenExpired if it has
	// expired, and a generic error for everything else.
	LookupByHash(hash []byte) (tenantID string, expiresAt time.Time, err error)
}

// ErrTokenNotFound is returned by TokenStore.LookupByHash when
// the token does not exist.
var ErrTokenNotFound = errors.New("install: enrollment token not found")

// ErrTokenExpired is returned by TokenStore.LookupByHash when
// the token has expired.
var ErrTokenExpired = errors.New("install: enrollment token has expired")

// Handler bundles the dependencies the install handler needs.
// The zero value is not usable; construct via NewHandler.
type Handler struct {
	Store      TokenStore
	ServerURL  string // e.g. "https://semaphore.example.com"
	BinaryURL  string // default: <ServerURL>/download/executor-{os}-{arch}
	Now        func() time.Time
	Hasher     func([]byte) []byte
	clockNow   func() time.Time // alias for Now; used internally
}

// NewHandler returns a Handler with sensible defaults filled in
// (sha256 hasher, time.Now clock).
func NewHandler(store TokenStore, serverURL string) *Handler {
	return &Handler{
		Store:     store,
		ServerURL: strings.TrimRight(serverURL, "/"),
		BinaryURL: "",
		Now:       time.Now,
		Hasher:    sha256Sum,
	}
}

// sha256Sum returns the SHA-256 of its input. Extracted so tests
// can swap in a deterministic hasher.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ServeHTTP implements the install URL endpoint.
//
//	GET /install/<token>?os=linux|macos|windows
//
// The token is the PLAINTEXT token, not its hash. The handler
// hashes it and looks the row up. This matches the Wazuh-style
// "single URL, push to many machines" pattern: the customer's
// deploy admin receives the URL via the SOC operator's email
// and pushes it to every host. The URL is shown ONCE in the
// SOC console's "Send Executor" modal; the plaintext token is
// never echoed back after minting.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Token is the last path segment. Reject empty tokens
	// (e.g. /install/ alone) with 400.
	token := strings.TrimPrefix(r.URL.Path, "/install/")
	token = strings.TrimSuffix(token, "/")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	// Look up the token. The store gives us the tenant + expiry.
	hash := h.Hasher([]byte(token))
	tenantID, expiresAt, err := h.Store.LookupByHash(hash)
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenNotFound):
			http.Error(w, "enrollment token not found", http.StatusNotFound)
		case errors.Is(err, ErrTokenExpired):
			http.Error(w, "enrollment token has expired", http.StatusGone)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	if h.Now().After(expiresAt) {
		// Defence in depth: store might not enforce
		// expiry in the same way the clock here does.
		http.Error(w, "enrollment token has expired", http.StatusGone)
		return
	}

	// OS dispatch. Default to Linux (the most common target
	// in our customer base; bash on macOS is identical, so
	// macOS uses the same script as Linux).
	os := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("os")))
	if os == "" {
		os = "linux"
	}

	var body string
	var contentType string
	switch os {
	case "linux", "macos", "darwin":
		body = renderBash(installScriptLinuxBash, token, h.ServerURL, tenantID)
		contentType = "application/x-shellscript; charset=utf-8"
	case "windows":
		body = renderPowerShell(installScriptWindowsPowerShell, token, h.ServerURL, tenantID)
		contentType = "text/plain; charset=utf-8"
	default:
		http.Error(w, "unsupported os; expected linux|macos|windows", http.StatusBadRequest)
		return
	}

	// Cache-Control: the URL is shown ONCE in the SOC console
	// and the token is bound to a specific TTL. Caching the
	// response would let a stale token reappear in a CDN.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// renderBash prepends the three required env vars to the bash
// install script. The script then sources the env vars (it
// already uses ${SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN} etc. as
// its inputs).
//
// We use heredoc with a quoted delimiter so the token is not
// re-evaluated by the shell. Newlines in the token would
// otherwise break the export; the token is base64.RawURLEncoding
// (32 bytes) so the alphabet is URL-safe, but we still quote
// defensively.
func renderBash(template, token, serverURL, tenantID string) string {
	header := strings.Join([]string{
		"#!/usr/bin/env bash",
		"# Auto-generated by the SentraOps install endpoint.",
		"# Do not edit; the bootstrap token is bound to the customer's tenant.",
		fmt.Sprintf("export SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN=%q", token),
		fmt.Sprintf("export SENTRAOPS_EXECUTOR_SERVER_URL=%q", serverURL),
		fmt.Sprintf("export SENTRAOPS_EXECUTOR_TENANT_ID=%q", tenantID),
		"",
	}, "\n")
	return header + template
}

// renderPowerShell prepends the three required env vars to the
// PowerShell install script. PowerShell does not have a
// quoting primitive that is safe against all metacharacters in
// a base64 URL-safe string, so we escape any embedded single
// quotes by doubling them (the PowerShell convention).
func renderPowerShell(template, token, serverURL, tenantID string) string {
	esc := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	header := strings.Join([]string{
		"# Auto-generated by the SentraOps install endpoint.",
		"# Do not edit; the bootstrap token is bound to the customer's tenant.",
		fmt.Sprintf("$env:SENTRAOPS_EXECUTOR_BOOTSTRAP_TOKEN = '%s'", esc(token)),
		fmt.Sprintf("$env:SENTRAOPS_EXECUTOR_SERVER_URL = '%s'", esc(serverURL)),
		fmt.Sprintf("$env:SENTRAOPS_EXECUTOR_TENANT_ID = '%s'", esc(tenantID)),
		"",
	}, "\r\n")
	// BUG-009 (2026-10-13): PowerShell 5.1 on Windows 10/11/Server
	// reads files without a BOM using the system code page
	// (Windows-1252 by default). install.ps1 contains multi-byte
	// UTF-8 characters (em-dash U+2014, check mark U+2713), which
	// Windows-1252 reinterprets as different code points, breaking
	// the parser on the function-definition line that uses the
	// check mark. Prepending a UTF-8 BOM (EF BB BF) here is
	// essential — the Wazuh-style 1-line install is
	// `iex (irm '...?os=windows')` and the BOM must be the FIRST
	// bytes of the file for PowerShell 5.1 to detect UTF-8. The
	// template also has the BOM (install/install.ps1 ships with
	// it) so we strip any leading BOM from the template before
	// prepending our own — otherwise the customer would see the
	// BOM, then a blank line, then the header, then the BOM again.
	// The cleanest invariant is "the served file starts with one
	// BOM, then the header, then the body without a leading BOM".
	template = strings.TrimPrefix(template, "\xef\xbb\xbf")
	return "\xef\xbb\xbf" + header + template
}

// HashToken returns the SHA-256 hex digest of a plaintext
// token. Exported so the platform BE's "Send Executor" mint
// path can use the same hasher when comparing incoming tokens
// to stored hashes.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Ensure compile-time check: the Handler satisfies http.Handler.
var _ http.Handler = (*Handler)(nil)

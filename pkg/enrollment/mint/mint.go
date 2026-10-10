// Package mint owns the shared enrollment-token mint path used by:
//
//   - the ``semaphore mint-token`` CLI (cli/cmd/mint_token.go), which
//     operators drive from a terminal to generate an install link,
//   - the ``POST /api/v1/executor/enroll-token`` HTTP endpoint
//     (api/executor/enroll_token.go), which the SentraOps SOC
//     console's Deployments tab drives via its Send Executor modal.
//
// Both callers produce the same token row, the same wire-format
// install link, and the same audit chain. Centralising the
// "generate + hash + insert + build install URL" sequence here
// guarantees the two surfaces can't drift (different ttl math,
// different URL shape, different row contents) and keeps the
// security-sensitive bits in one audited location.
//
// The function is intentionally synchronous and stateless: the
// caller supplies a connected ``db.Store`` + the parsed inputs.
// The CLI's ``resolveStoreForMintToken`` and the HTTP handler's
// ``helpers.Store(r)`` both satisfy the contract.
package mint

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/db"
)

// Request is the input to ``Token``. The caller is responsible for
// validating ``InstallBaseURL`` already; ``Token`` re-validates as a
// belt-and-braces defence-in-depth because the install link IS the
// trust handoff to the customer's deploy admin.
type Request struct {
	TenantID       string
	DeploymentZone []string // optional; the executor may claim without zone until assigned
	ExecutorName   string   // optional; defaults to executor_id at enroll time
	Hostname       string   // optional; the customer's first-boot agent fills it in
	TTL            time.Duration
	InstallBaseURL string // required; e.g. "https://sentraops.example.com"
	Now            time.Time
}

// Result is the canonical mint output. The CLI prints it (JSON or
// human-readable), the HTTP handler returns it as JSON. Both share
// the field names so the SOC console's Send Executor modal can
// parse the install URL out without a fork-specific parser.
type Result struct {
	Token        string    `json:"token"`
	TokenHash    string    `json:"token_hash"`
	TenantID     string    `json:"tenant_id"`
	ZoneIDs      []string  `json:"zone_ids"`
	ExecutorName string    `json:"executor_name"`
	Hostname     string    `json:"hostname"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	InstallLink  string    `json:"install_link"`
}

// MaxTTL is the upper bound the CLI enforces and the HTTP handler
// re-validates. Anything > 60 min is a security boundary violation;
// the token is a single-use bootstrap credential, not a session
// cookie. A larger TTL weakens the 5-min stolen-token response window.
const MaxTTL = 60 * time.Minute

// DefaultTTL mirrors ``db.EnrollmentTokenTTL`` so callers that
// don't pass a TTL explicitly get the same shape the
// EnrollHandler /mint path used to produce on its own.
const DefaultTTL = 5 * time.Minute

// Token mints a single-use enrollment token row, hashes it for
// safe server-side storage, composes the install link, and returns
// the plaintext + the row's identity fields.
//
// Inputs that fail validation return a descriptive error WITHOUT
// having touched the store — the row is INSERTed only after every
// check passes, so a partial failure cannot produce a token the
// operator can't recover.
func Token(store db.Store, req Request) (*Result, error) {
	// 1. Tenant id is mandatory.
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, fmt.Errorf("--tenant-id is required")
	}
	// 2. Install base URL is mandatory + must parse.
	base := strings.TrimRight(strings.TrimSpace(req.InstallBaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("install base URL is required (set SENTRAOPS_PUBLIC_URL or pass --install-base-url)")
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("--install-base-url %q is not a valid URL: %w", base, err)
	}
	// 3. TTL bounded.
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if ttl > MaxTTL {
		return nil, fmt.Errorf("ttl may not exceed %s (the token is a security boundary, not a session cookie)", MaxTTL)
	}
	// 4. Time anchor — caller supplies Now so tests can pin it.
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	expiresAt := now.Add(ttl)
	// 5. Generate 32 bytes of cryptographically random entropy.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(plaintext))
	hashHex := hex.EncodeToString(sum[:])
	// 6. Encode zones as JSON (matches Executor.DeploymentZoneIDsJSON).
	zoneJSON, err := json.Marshal(req.DeploymentZone)
	if err != nil {
		return nil, fmt.Errorf("marshal zone ids: %w", err)
	}
	// 7. Persist.
	tok := db.EnrollmentToken{
		TokenHash:             hashHex,
		TenantID:              strings.TrimSpace(req.TenantID),
		DeploymentZoneIDsJSON: string(zoneJSON),
		ExecutorName:          strings.TrimSpace(req.ExecutorName),
		Hostname:              strings.TrimSpace(req.Hostname),
		ExpiresAt:             expiresAt,
		CreatedAt:             now,
	}
	if _, err := store.CreateEnrollmentToken(tok); err != nil {
		return nil, fmt.Errorf("create enrollment token: %w", err)
	}
	// 8. Compose the install link. The path "/install/<token>" is the
	//    documented Wazuh-style pattern; the bash wrapper on the
	//    customer side reads the token from the URL.
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse base url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/install/" + plaintext
	installLink := u.String()

	return &Result{
		Token:        plaintext,
		TokenHash:    hashHex,
		TenantID:     tok.TenantID,
		ZoneIDs:      req.DeploymentZone,
		ExecutorName: tok.ExecutorName,
		Hostname:     tok.Hostname,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		InstallLink:  installLink,
	}, nil
}
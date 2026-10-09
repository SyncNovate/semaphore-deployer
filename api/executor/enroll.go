package executor

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/enrollment/certgen"
	"github.com/semaphoreui/semaphore/pkg/jwt"
	"github.com/semaphoreui/semaphore/pkg/tz"

	log "github.com/sirupsen/logrus"
)

// HeaderEnrollmentToken is the single-use token the executor sends to
// /enroll. Format: opaque base64url string (>= 32 bytes of entropy).
// Carries NO tenant binding — the binding lives on the
// enrollment_tokens row, looked up by SHA-256 hash of the token.
const HeaderEnrollmentToken = "X-Enrollment-Token"

// EnrollResponse is the body returned by POST /api/v1/executor/enroll
// on success. The executor writes CertPEM + KeyPEM to its standard
// paths, then uses ExecutorToken on every subsequent /heartbeat,
// /claim, /result call (mirrors the bearer-token flow from /register
// in R-I.1.d).
type EnrollResponse struct {
	ExecutorID         string    `json:"executor_id"`
	ExecutorToken      string    `json:"executor_token"`        // bearer token for X-Executor-Token
	TokenExpiresAt     time.Time `json:"token_expires_at"`
	CertPEM            string    `json:"cert_pem"`              // leaf mTLS cert (PEM)
	KeyPEM             string    `json:"key_pem"`               // leaf private key (PEM, PKCS#8)
	CABundlePEM        string    `json:"ca_bundle_pem"`         // CA cert for server verification
	SentraOpsURL       string    `json:"sentraops_url"`         // server URL the executor should use
	TenantID           string    `json:"tenant_id"`             // bound tenant (echoed for the executor's logs)
	ExpiresAt          time.Time `json:"cert_expires_at"`       // leaf cert expiry (informational)
}

// EnrollHandler is the executor's first-boot endpoint. It accepts a
// short-lived enrollment token (X-Enrollment-Token), atomically marks
// it consumed, mints a fresh executor row, and returns the long-lived
// mTLS cert + bearer token + tenant binding the executor needs to
// transition into normal mode (R-I.10.re1).
//
// The handler sits OUTSIDE the tenant-binding middleware AND outside
// the executor-auth middleware because the token IS the proof of
// tenant binding at this point. There is no prior identity.
//
// Failure-mode posture (matches /register's existence-probe
// prevention, R-I.1.d):
//   - missing token                       → 401 enrollment_token_required
//   - unknown / malformed / unparseable   → 401 enrollment_token_invalid
//                                           (same response, no probe)
//   - valid token, already consumed       → 409 enrollment_token_already_consumed
//   - valid token, past ExpiresAt         → 410 enrollment_token_expired
//   - server-side mint failure            → 500 internal_error
//   - success                             → 200 + EnrollResponse
//
// The handler is mounted OUTSIDE the auth middleware in router.go so
// the customer's executor can reach it on first boot before it has
// any cert.
func EnrollHandler(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.Header.Get(HeaderEnrollmentToken))
	if raw == "" {
		helpers.WriteErrorStatus(w, "enrollment_token_required", http.StatusUnauthorized)
		return
	}

	hashHex := hashTokenHex(raw)

	store := helpers.Store(r)

	// Atomically consume the token. This is the single-use gate.
	// A concurrent retry surfaces ErrAlreadyExists → 409.
	executorID, err := db.NewExecutorID()
	if err != nil {
		log.WithError(err).Error("enroll_executor_id_generate_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	consumed, err := store.ConsumeEnrollmentToken(hashHex, executorID, tz.Now())
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// Same posture as RegisterHandler: don't leak
			// whether the token exists.
			helpers.WriteErrorStatus(w, "enrollment_token_invalid", http.StatusUnauthorized)
			return
		}
		if errors.Is(err, db.ErrAlreadyExists) {
			helpers.WriteErrorStatus(w, "enrollment_token_already_consumed", http.StatusConflict)
			return
		}
		log.WithError(err).Error("enroll_consume_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	// Even though ConsumeEnrollmentToken only succeeds on
	// non-consumed rows, double-check expiry post-acquire so a
	// race between TTL check and consume surfaces as 410, not 200.
	if consumed.IsExpired() {
		helpers.WriteErrorStatus(w, "enrollment_token_expired", http.StatusGone)
		return
	}

	// Mint the executor's bearer token (for X-Executor-Token).
	// Same shape as RegisterHandler — 32 bytes, base64-url-no-pad,
	// SHA-256 hashed on the server side.
	plainExecToken, execTokenHash, err := mintExecutorBearerToken()
	if err != nil {
		log.WithError(err).Error("enroll_executor_token_mint_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	// Mint the executor's mTLS leaf cert using the platform CA.
	ca, err := loadPlatformCA()
	if err != nil {
		log.WithError(err).Error("enroll_ca_load_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}
	hostname := strings.TrimSpace(consumed.Hostname)
	leaf, err := certgen.IssueExecutorCert(&ca, executorID, hostname)
	if err != nil {
		log.WithError(err).Error("enroll_leaf_cert_issue_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	// Provision the executor row with the bound tenant + zone from
	// the token, the freshly-minted bearer token, and an "online"
	// status so the first heartbeat doesn't have to also act as
	// registration. Platforms/ExecutorVersion/AnsibleVersion are
	// empty strings here; the executor fills them in on the first
	// heartbeat.
	tokenExpiresAt := tz.Now().Add(TokenTTL)
	execName := strings.TrimSpace(consumed.ExecutorName)
	if execName == "" {
		execName = executorID
	}
	zoneID := firstZoneOrEmpty(consumed.DeploymentZoneIDs())
	_, err = store.CreateExecutor(db.Executor{
		ExecutorID:         executorID,
		Name:               execName,
		TenantID:           consumed.TenantID,
		DeploymentZoneID:   zoneID,
		PlatformsSupportedJSON: "",
		ExecutorVersion:    "",
		AnsibleVersion:     "",
		Hostname:           hostname,
		Status:             db.ExecutorStatusOnline,
		RegistrationAt:     tz.Now(),
		AuthTokenHash:      &execTokenHash,
		AuthTokenExpiresAt: &tokenExpiresAt,
	})
	if err != nil {
		if errors.Is(err, db.ErrAlreadyExists) {
			// Vanishingly unlikely (executor_id is a fresh
			// ULID) but handled for completeness.
			helpers.WriteErrorStatus(w, "executor_already_registered", http.StatusConflict)
			return
		}
		log.WithError(err).Error("enroll_create_executor_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	// Audit event: executor.enrolled (separate from executor.register
	// because the bootstrap path is operationally distinct — no
	// platform-BE service JWT, just the customer's first-boot
	// exchange).
	DefaultPropagator().Propagate(AuditEvent{
		Event:            "executor.enrolled",
		ExecutorID:       executorID,
		TenantID:         consumed.TenantID,
		DeploymentZoneID: zoneID,
		Payload: map[string]any{
			"hostname":        hostname,
			"executor_name":   execName,
			"token_ttl_min":   int(db.EnrollmentTokenTTL.Minutes()),
			"observed_at":     tz.Now(),
		},
	})

	helpers.WriteJSON(w, http.StatusOK, EnrollResponse{
		ExecutorID:     executorID,
		ExecutorToken:  plainExecToken,
		TokenExpiresAt: tokenExpiresAt,
		CertPEM:        string(leaf.CertPEM),
		KeyPEM:         string(leaf.KeyPEM),
		CABundlePEM:    string(leaf.CABundlePEM),
		SentraOpsURL:   deriveSentraOpsURL(r),
		TenantID:       consumed.TenantID,
		ExpiresAt:      tz.Now().Add(365 * 24 * time.Hour), // matches IssueExecutorCert
	})
}

// mintExecutorBearerToken returns (plaintext, sha256-hex-digest).
// Mirrors mintToken() in controller.go; kept here so the enroll path
// is self-contained — we may want a different TTL in future and this
// keeps the change scoped to this file.
func mintExecutorBearerToken() (string, string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(b[:])
	return plain, hashTokenHex(plain), nil
}

// loadPlatformCA loads the platform's CA from the platform's KMS /
// file (env var SENTRAOPS_PLATFORM_CA_CERT_PEM + KEY_PEM for now;
// the production wiring is R-I.10.re1 follow-up). For test
// scaffolding, callers can override via WithCAPEM at startup; the
// default behaviour (no CA configured) returns an error so a
// production server with a misconfigured KMS fails loud.
func loadPlatformCA() (certgen.CAMaterial, error) {
	certPEM, keyPEM := lookupPlatformCAPEM()
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return certgen.CAMaterial{}, errors.New("platform CA not configured (set SENTRAOPS_PLATFORM_CA_CERT_PEM + SENTRAOPS_PLATFORM_CA_KEY_PEM)")
	}
	if _, _, _, err := certgen.ParseCA(certPEM, keyPEM); err != nil {
		return certgen.CAMaterial{}, err
	}
	return certgen.CAMaterial{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// firstZoneOrEmpty returns the first zone from a JSON-decoded list,
// or "" if the list is empty. The executor row's deployment_zone_id
// column is a single VARCHAR (matches the R-I.1.d schema); if a token
// binds multiple zones, /enroll picks the first and the operator can
// re-assign via /api/v1/executors/{id} (post-R-I.11).
func firstZoneOrEmpty(zones []string) string {
	if len(zones) == 0 {
		return ""
	}
	return zones[0]
}

// deriveSentraOpsURL returns the public URL the executor should call
// for subsequent /heartbeat etc. Defaults to the request's Host so the
// executor can be installed behind the same hostname the customer's
// install.sh used. Override via SENTRAOPS_PUBLIC_URL.
func deriveSentraOpsURL(r *http.Request) string {
	if v := lookupPublicURLOverride(); v != "" {
		return v
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// lookupPlatformCAPEM + lookupPublicURLOverride are tiny indirection
// helpers so tests can override via package-level variables without
// having to thread env reads everywhere.
var (
	platformCAPEMOverride       func() ([]byte, []byte) = defaultPlatformCAPEM
	platformPublicURLOverride  func() string            = defaultPlatformPublicURL
)

func lookupPlatformCAPEM() ([]byte, []byte)       { return platformCAPEMOverride() }
func lookupPublicURLOverride() string              { return platformPublicURLOverride() }

func defaultPlatformCAPEM() ([]byte, []byte) {
	// Production wiring (R-I.10.re1 follow-up): read from the
	// platform's KMS. For this slice, env-var fallback so the
	// handler compiles + can be smoke-tested.
	return nil, nil
}

func defaultPlatformPublicURL() string { return "" }

// SetPlatformCAPEMForTest lets tests inject a CA pair. Not part of the
// production API.
func SetPlatformCAPEMForTest(certPEM, keyPEM []byte) {
	platformCAPEMOverride = func() ([]byte, []byte) { return certPEM, keyPEM }
}

// SetPublicURLForTest lets tests inject the public URL override. Not
// part of the production API.
func SetPublicURLForTest(url string) {
	platformPublicURLOverride = func() string { return url }
}

// _ keeps the jwt import alive — the enroll handler does not mint
// JWTs directly (it relies on the executor's existing JWT path), but
// keeping the import lets us add a service JWT to the response later
// without touching imports.
var _ = jwt.Verify
// Package executor hosts the customer-side deployment executor's HTTP
// API + the auth middleware that gates it. The executor is a service
// that lives on the customer's network, claims deployment jobs from
// this fork, runs Ansible locally, and reports results back.
//
// SentraOps fork (R-I.1.d). See
// docs/architecture/2026-10-07-semaphore-fork-design.md §4.3 + §5.1.
package executor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/tz"

	log "github.com/sirupsen/logrus"
)

// Context keys.
const (
	// ContextKeyExecutor is the executor stored in the request context
	// after the auth middleware resolves it. Handlers read it via
	// helpers.GetFromContext(r, ContextKeyExecutor).(*db.Executor).
	ContextKeyExecutor = "executor"

	// HeaderExecutorToken is the bearer-token header the executor
	// sends on every authenticated call. The plaintext is never
	// stored on the server — we store the SHA-256 hex digest of it.
	// Registered / refresh responses carry the plaintext exactly
	// once.
	HeaderExecutorToken = "X-Executor-Token"
)

// TokenTTL is the lifetime of an executor bearer token (24h per
// design doc §5.1). Re-registration mints a fresh token; heartbeats
// do NOT rotate.
const TokenTTL = 24 * time.Hour

// ExecutorAuthMiddleware is the request-time auth gate for every
// /api/v1/executor/* endpoint EXCEPT /register (which is pre-registration
// and authenticates the executor via the platform-BE mTLS handshake +
// service JWT). It:
//   1. Reads X-Executor-Token (mandatory).
//   2. SHA-256-hashes the token and looks up the matching executor row.
//   3. Stores the executor in the request context (ContextKeyExecutor).
//   4. Rejects the request with 401 if the token is unknown / malformed
//      / expired.
//
// We collapse all failure modes to the same generic 401 + error so a
// probe cannot distinguish "unknown token" from "expired token".
// (Existence-probe prevention — same posture as the runner middleware.)
func ExecutorAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(r.Header.Get(HeaderExecutorToken))
		if token == "" {
			helpers.WriteErrorStatus(w, "executor_token_required", http.StatusUnauthorized)
			return
		}

		store := helpers.Store(r)
		exec, err := store.GetExecutorByTokenHash(hashTokenHex(token))
		if err != nil {
			// 401 + same error text for all unknown-token
			// paths. Existence-probe prevention.
			helpers.WriteErrorStatus(w, "executor_token_invalid", http.StatusUnauthorized)
			return
		}

		if exec.RevokedAt != nil {
			// Distinct from "unknown token" because the
			// operator MUST be told "you are revoked" so the
			// executor's self-diagnostic + the platform's
			// anomaly detection can react. Per design doc §5.1
			// (revoked executor's claim → 403
			// `executor_revoked`).
			helpers.WriteErrorStatus(w, "executor_revoked", http.StatusForbidden)
			return
		}

		if exec.AuthTokenExpiresAt != nil && !exec.AuthTokenExpiresAt.After(tz.Now()) {
			helpers.WriteErrorStatus(w, "executor_token_expired", http.StatusUnauthorized)
			return
		}

		r = helpers.SetContextValue(r, ContextKeyExecutor, exec)
		next.ServeHTTP(w, r)
	})
}

// executorFromContext pulls the executor placed by the auth middleware
// off the request. Returns (nil, false) if the executor is not present
// (handler was reached without going through the middleware — usually
// a routing bug).
func executorFromContext(r *http.Request) (*db.Executor, bool) {
	v, ok := helpers.GetOkFromContext(r, ContextKeyExecutor)
	if !ok {
		return nil, false
	}
	e, ok := v.(*db.Executor)
	return e, ok
}

// mintToken generates a fresh 32-byte random bearer token and returns
// the plaintext (caller returns to the executor exactly once) plus
// the SHA-256 hex digest (caller stores on the row). Format:
//
//	plaintext: "<24-base32-chars><padding>"  (~ 44 chars)
//	hash:      sha256 hex digest (64 chars)
//
// Plaintext generation uses crypto/rand; the format is base64
// (URL-safe, no padding) so the operator's executor config can carry
// it without escaping.
func mintToken() (plaintext string, hashHex string, err error) {
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return "", "", err
	}
	plaintext = base64URLNoPad(b[:])
	hashHex = hashTokenHex(plaintext)
	return plaintext, hashHex, nil
}

// hashTokenHex returns the lowercase hex SHA-256 digest of the token.
// Used both at registration (server stores hashHex) and at every
// authenticated call (server hashes the caller-supplied plaintext
// and looks up by hashHex).
func hashTokenHex(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// base64URLNoPad is a tiny helper to keep the file's import set
// minimal — net/http + crypto/sha256 + encoding/hex is the rest.
func base64URLNoPad(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := make([]byte, 0, ((len(b)+2)/3)*4)
	var buf uint32
	var nbits uint32
	for _, c := range b {
		buf = (buf << 8) | uint32(c)
		nbits += 8
		for nbits >= 6 {
			shift := nbits - 6
			out = append(out, alphabet[(buf>>shift)&0x3F])
			nbits = shift
			buf &= (uint32(1) << shift) - 1
		}
	}
	if nbits > 0 {
		out = append(out, alphabet[(buf<<(6-nbits))&0x3F])
	}
	return string(out)
}

// LogExecutorEvent is a convenience log helper that the endpoint
// handlers use to emit a structured log row consistent with the audit
// payload the webhook will also push.
func LogExecutorEvent(level log.Level, msg string, fields log.Fields) {
	log.WithFields(fields).Log(level, msg)
}

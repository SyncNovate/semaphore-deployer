package executor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/pkg/enrollment/certgen"
	"github.com/semaphoreui/semaphore/pkg/tz"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTestPlatformCA generates a fresh Ed25519 CA, installs the PEM
// pair into the enroll handler's package-level overrides, and restores
// the previous values on cleanup.
func withTestPlatformCA(t *testing.T) certgen.CAMaterial {
	t.Helper()
	ca, err := certgen.NewCA("SentraOps Test CA")
	require.NoError(t, err)
	prevCert := platformCAPEMOverride
	prevURL := platformPublicURLOverride
	t.Cleanup(func() {
		platformCAPEMOverride = prevCert
		platformPublicURLOverride = prevURL
	})
	SetPlatformCAPEMForTest(ca.CertPEM, ca.KeyPEM)
	SetPublicURLForTest("https://sentraops.example.com")
	return ca
}

// mintEnrollmentToken creates a token row via the store, returning the
// plaintext token (the caller passes it to the executor's
// X-Enrollment-Token header) and the SHA-256 hash (for direct lookups
// in tests). The token is bound to the supplied tenant + zones +
// hostname + name, and expires at now + ttl.
func mintEnrollmentToken(t *testing.T, store db.Store, tenantID string, zoneIDs []string, hostname string, name string, ttl time.Duration) (string, string) {
	t.Helper()
	plain := randomBase64Token(t)
	hashHex := hashTokenHex(plain)
	tok := db.EnrollmentToken{
		TokenHash:     hashHex,
		TenantID:      tenantID,
		ExecutorName:  name,
		Hostname:      hostname,
		ExpiresAt:     tz.Now().Add(ttl),
		CreatedAt:     tz.Now(),
	}
	require.NoError(t, tok.SetDeploymentZoneIDs(zoneIDs))
	_, err := store.CreateEnrollmentToken(tok)
	require.NoError(t, err)
	return plain, hashHex
}

// randomBase64Token returns a 32-byte cryptographically random token
// base64-url-encoded (matches what the platform BE will mint in
// production — R-I.10.re1 follow-up).
func randomBase64Token(t *testing.T) string {
	t.Helper()
	var b [32]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// TestEnrollHandler_RequiresToken verifies /enroll refuses with 401
// when X-Enrollment-Token is missing or empty. Same posture as
// RegisterHandler's X-Register-Token check (R-I.1.d): the rejection
// happens before any DB lookup so a malformed token cannot be used to
// probe whether a valid one exists.
func TestEnrollHandler_RequiresToken(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformCA(t)

	cases := []struct {
		name      string
		headerVal string
	}{
		{"empty header", ""},
		{"whitespace only", "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
			req = helpers.SetContextValue(req, "store", store)
			if tc.headerVal != "" {
				req.Header.Set(HeaderEnrollmentToken, tc.headerVal)
			}
			w := httptest.NewRecorder()
			EnrollHandler(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// TestEnrollHandler_RejectsUnknownToken verifies an unknown token
// returns 401 (NOT 404) so a probe cannot distinguish "valid token"
// from "unknown token" (existence-probe prevention — same posture as
// the executor auth middleware).
func TestEnrollHandler_RejectsUnknownToken(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformCA(t)

	// A token that is well-formed but not in the store.
	bogus := randomBase64Token(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderEnrollmentToken, bogus)

	w := httptest.NewRecorder()
	EnrollHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestEnrollHandler_RejectsExpiredToken verifies a token past its
// ExpiresAt returns 410 enrollment_token_expired. The token must
// remain in the store (not consumed) so the customer's install.sh
// can retry after the SOC admin re-mints.
func TestEnrollHandler_RejectsExpiredToken(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformCA(t)

	plain, hashHex := mintEnrollmentToken(t, store, "ORG-1", []string{"ZONE-A"}, "host-1", "exec-1", -time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderEnrollmentToken, plain)

	w := httptest.NewRecorder()
	EnrollHandler(w, req)

	assert.Equal(t, http.StatusGone, w.Code)

	// Token is still in the store (not consumed) so a retry
	// after re-mint works.
	got, err := store.GetEnrollmentTokenByHash(hashHex)
	require.NoError(t, err)
	assert.Nil(t, got.ConsumedAt, "expired token is NOT consumed (so retry possible after re-mint)")
}

// TestEnrollHandler_RejectsAlreadyConsumed verifies the single-use
// invariant: a second consume attempt on the same token returns 409.
// The first consume must succeed and the second must fail.
func TestEnrollHandler_RejectsAlreadyConsumed(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformCA(t)

	plain, _ := mintEnrollmentToken(t, store, "ORG-1", []string{"ZONE-A"}, "host-1", "exec-1", 5*time.Minute)

	// First call succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	req1 = helpers.SetContextValue(req1, "store", store)
	req1.Header.Set(HeaderEnrollmentToken, plain)
	w1 := httptest.NewRecorder()
	EnrollHandler(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code, "first enroll must succeed")

	// Second call on the same token fails with 409.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	req2 = helpers.SetContextValue(req2, "store", store)
	req2.Header.Set(HeaderEnrollmentToken, plain)
	w2 := httptest.NewRecorder()
	EnrollHandler(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

// TestEnrollHandler_HappyPath verifies the full success path: a valid
// token → 200 + EnrollResponse with a usable mTLS cert, bearer token,
// tenant binding, and SentraOps URL. The executor row is persisted
// with the bound tenant + zone + auth token hash so subsequent calls
// to /heartbeat /claim /result work.
func TestEnrollHandler_HappyPath(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformCA(t)
	rec := installMockedPropagator(t)

	plain, _ := mintEnrollmentToken(t, store, "ORG-1", []string{"ZONE-A"}, "host-happy", "exec-happy", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderEnrollmentToken, plain)

	w := httptest.NewRecorder()
	EnrollHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var res EnrollResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))

	// Surface-level assertions.
	assert.NotEmpty(t, res.ExecutorID, "executor id assigned")
	assert.NotEmpty(t, res.ExecutorToken, "bearer token returned exactly once")
	assert.True(t, res.TokenExpiresAt.After(time.Now().UTC()), "bearer token expires in the future")
	assert.Equal(t, "ORG-1", res.TenantID, "tenant binding flows from the token, NOT the request body")
	assert.Equal(t, "https://sentraops.example.com", res.SentraOpsURL, "public URL override surfaces in the response")

	// Cert is a real, parseable PEM cert signed by the platform CA.
	leafBlock, _ := pem.Decode([]byte(res.CertPEM))
	require.NotNil(t, leafBlock, "cert pem must decode")
	require.Equal(t, "CERTIFICATE", leafBlock.Type)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, res.ExecutorID, leaf.Subject.CommonName, "leaf CN is the executor id")
	assert.False(t, leaf.IsCA, "leaf is not a CA")
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth, "leaf has clientAuth EKU")
	// Leaf must verify against the platform CA.
	roots := x509.NewCertPool()
	caBlock, _ := pem.Decode([]byte(res.CABundlePEM))
	require.NotNil(t, caBlock, "ca bundle pem must decode")
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)
	roots.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	assert.NoError(t, err, "leaf cert verifies against the bundled CA")

	// Key is a parseable PKCS#8 Ed25519 private key.
	keyBlock, _ := pem.Decode([]byte(res.KeyPEM))
	require.NotNil(t, keyBlock, "key pem must decode")
	require.Equal(t, "PRIVATE KEY", keyBlock.Type)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	_, ok := parsedKey.(ed25519.PrivateKey)
	assert.True(t, ok, "leaf key is Ed25519")

	// Executor row is persisted with the bound tenant + zone + the
	// freshly-minted bearer token hash.
	exec, err := store.GetExecutorByTokenHash(hashTokenHex(res.ExecutorToken))
	require.NoError(t, err)
	assert.Equal(t, res.ExecutorID, exec.ExecutorID)
	assert.Equal(t, "ORG-1", exec.TenantID)
	assert.Equal(t, "ZONE-A", exec.DeploymentZoneID)
	assert.Equal(t, "exec-happy", exec.Name)
	assert.Equal(t, "host-happy", exec.Hostname)
	assert.Equal(t, db.ExecutorStatusOnline, exec.Status)

	// Audit event fires with the correct tenant + executor.
	events := rec.byName("executor.enrolled")
	require.Len(t, events, 1, "exactly one enroll audit event")
	assert.Equal(t, res.ExecutorID, events[0].ExecutorID)
	assert.Equal(t, "ORG-1", events[0].TenantID)
	assert.Equal(t, "ZONE-A", events[0].DeploymentZoneID)
}

// TestEnrollHandler_FailsLoudWithoutCA verifies the handler refuses to
// mint a cert when the platform CA is not configured. Without this
// guard, a misconfigured production server would silently mint a
// self-signed leaf that the executor cannot use to verify the server.
func TestEnrollHandler_FailsLoudWithoutCA(t *testing.T) {
	store := sql.CreateTestStore()
	// Override to nothing (default behaviour) — no CA configured.
	SetPlatformCAPEMForTest(nil, nil)
	t.Cleanup(func() {
		// Restore sane default for any later sub-tests in this
		// test run.
		prevCert := platformCAPEMOverride
		prevURL := platformPublicURLOverride
		platformCAPEMOverride = prevCert
		platformPublicURLOverride = prevURL
	})

	plain, _ := mintEnrollmentToken(t, store, "ORG-1", []string{"ZONE-A"}, "host-1", "exec-1", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderEnrollmentToken, plain)

	w := httptest.NewRecorder()
	EnrollHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCertGen_RoundTrip is a package-internal smoke test for the
// certgen helper itself: a CA mints a leaf, the leaf verifies against
// the CA, and the key is the matching Ed25519 keypair.
func TestCertGen_RoundTrip(t *testing.T) {
	ca, err := certgen.NewCA("RT CA")
	require.NoError(t, err)
	leaf, err := certgen.IssueExecutorCert(&ca, "EXEC-1", "host-1.example.com")
	require.NoError(t, err)

	roots := x509.NewCertPool()
	caBlock, _ := pem.Decode(ca.CertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	require.NoError(t, err)
	roots.AddCert(caCert)

	leafBlock, _ := pem.Decode(leaf.CertPEM)
	parsed, err := x509.ParseCertificate(leafBlock.Bytes)
	require.NoError(t, err)

	_, err = parsed.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSName:   "host-1.example.com",
	})
	assert.NoError(t, err, "leaf verifies against CA + hostname SAN")
}

// TestCertGen_RejectsNonCA guards against silent misconfiguration:
// parsing a non-CA cert into the CA loader must fail loud.
func TestCertGen_RejectsNonCA(t *testing.T) {
	leafCA, err := certgen.NewCA("Inner CA")
	require.NoError(t, err)
	leaf, err := certgen.IssueExecutorCert(&leafCA, "EXEC-X", "host-x")
	require.NoError(t, err)

	// Try to parse the LEAF as a CA — must fail.
	_, _, _, err = certgen.ParseCA(leaf.CertPEM, leafCA.KeyPEM)
	assert.Error(t, err, "parsing a non-CA cert as a CA must fail")
}
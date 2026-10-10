package executor

// R-I.10 — /api/v1/executor/enroll-token test suite.
//
// Pins the contract the R-I.9 SOC console's Send Executor modal
// depends on:
//   - happy path (mint succeeds + token row persists)
//   - missing X-Register-Token / X-Service-Auth refuse with 401
//   - service JWT tenant != body tenant refuses with 403
//   - TTL bounded ≤ 60 min
//   - default TTL is 5 min
//   - missing tenant_id / install_base_url refuse with 400
//   - end-to-end: the minted token round-trips through /enroll

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apimiddleware "github.com/semaphoreui/semaphore/api/middleware"
	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/pkg/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnrollTokenHandler_HappyPath drives the platform-BE-facing
// mint endpoint end-to-end: a service JWT + X-Register-Token +
// body produce a token row + a stable JSON response.
func TestEnrollTokenHandler_HappyPath(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-R-I-9",
		ActorID:  "op-r-i-9",
	})
	body := map[string]any{
		"tenant_id":           "ORG-R-I-9",
		"deployment_zone_ids": []string{"ZONE-A", "ZONE-B"},
		"executor_name":       "exec-1",
		"hostname":            "host-1.example.com",
		"ttl_minutes":         5,
		"install_base_url":    "https://sentraops.example.com",
	}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token":              "test-token-r-i-9",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var res EnrollTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.NotEmpty(t, res.Token, "plaintext token must be returned once")
	assert.Equal(t, "ORG-R-I-9", res.TenantID)
	assert.Equal(t, []string{"ZONE-A", "ZONE-B"}, res.ZoneIDs)
	assert.Equal(t, "exec-1", res.ExecutorName)
	assert.Equal(t, "host-1.example.com", res.Hostname)
	assert.True(t, strings.HasPrefix(res.InstallLink, "https://sentraops.example.com/install/"),
		"install link must be rooted at install_base_url + /install/<token>")
	assert.True(t, res.ExpiresAt.After(res.CreatedAt))

	// Token row persisted, lookup-by-hash succeeds.
	loaded, err := store.GetEnrollmentTokenByHash(res.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, "ORG-R-I-9", loaded.TenantID)
}

// TestEnrollTokenHandler_RequiresXRegisterToken refuses missing
// X-Register-Token. Same posture as RegisterHandler.
func TestEnrollTokenHandler_RequiresXRegisterToken(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-X",
	})
	body := map[string]any{"tenant_id": "ORG-X", "install_base_url": "https://x"}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "register_token_required")
}

// TestEnrollTokenHandler_RequiresServiceAuth refuses missing
// X-Service-Auth.
func TestEnrollTokenHandler_RequiresServiceAuth(t *testing.T) {
	store := sql.CreateTestStore()
	body := map[string]any{"tenant_id": "ORG-X", "install_base_url": "https://x"}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token": "test-token",
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "service_auth_required")
}

// TestEnrollTokenHandler_TenantMismatch refuses when the service
// JWT's tenant_id does not match the body's tenant_id. The actor
// (BE operator) can only mint for tenants they're bound to.
func TestEnrollTokenHandler_TenantMismatch(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-A",
	})
	body := map[string]any{"tenant_id": "ORG-B", "install_base_url": "https://x"}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token":              "test-token",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "tenant_mismatch")
}

// TestEnrollTokenHandler_TTLBoundBy60Min refuses ttl_minutes > 60
// (the same guard the CLI enforces via the shared helper).
func TestEnrollTokenHandler_TTLBoundBy60Min(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-X",
	})
	body := map[string]any{
		"tenant_id":        "ORG-X",
		"ttl_minutes":      61,
		"install_base_url": "https://x",
	}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token":              "test-token",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid_request")
}

// TestEnrollTokenHandler_DefaultTTLIs5Min — when ttl_minutes is 0
// the shared helper applies the default 5 min.
func TestEnrollTokenHandler_DefaultTTLIs5Min(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-DEF",
	})
	body := map[string]any{
		"tenant_id":        "ORG-DEF",
		"install_base_url": "https://x",
	}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token":              "test-token",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var res EnrollTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	delta := res.ExpiresAt.Sub(res.CreatedAt)
	assert.True(t, delta > 4*time.Minute && delta < 6*time.Minute,
		"default TTL is 5 min, got %s", delta)
}

// TestEnrollTokenHandler_MissingTenantID refuses an empty body
// tenant_id. Same posture as the CLI's --tenant-id required guard.
func TestEnrollTokenHandler_MissingTenantID(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-X",
	})
	body := map[string]any{"install_base_url": "https://x"}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token":              "test-token",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "tenant_id_required")
}

// TestEnrollTokenHandler_MissingInstallBaseURL refuses an empty
// install_base_url. The install link IS the trust handoff to the
// customer's deploy admin; we refuse to mint without one.
func TestEnrollTokenHandler_MissingInstallBaseURL(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-X",
	})
	body := map[string]any{"tenant_id": "ORG-X"}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", body, map[string]string{
		"X-Register-Token":              "test-token",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	EnrollTokenHandler(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "install_base_url_required")
}

// TestEnrollTokenHandler_IntegratesWithEnroll closes the round-trip —
// the token returned by /enroll-token is consumed by the existing
// /enroll handler (the customer's first-boot path). This pins the
// invariant that the HTTP mint + the /enroll consume compose.
func TestEnrollTokenHandler_IntegratesWithEnroll(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-RT",
		ActorID:  "op-rt",
	})

	mintBody := map[string]any{
		"tenant_id":        "ORG-RT",
		"install_base_url": "https://x",
		"hostname":         "host-rt",
	}
	mintReq := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/enroll-token", mintBody, map[string]string{
		"X-Register-Token":              "test-token",
		apimiddleware.HeaderServiceAuth: svc,
	})
	wMint := httptest.NewRecorder()
	EnrollTokenHandler(wMint, mintReq)
	require.Equal(t, http.StatusOK, wMint.Code)
	var mintRes EnrollTokenResponse
	require.NoError(t, json.Unmarshal(wMint.Body.Bytes(), &mintRes))

	// /enroll consumes the minted token. The hostname comes from
	// the enrollment token row (set at mint time), not the body.
	withTestPlatformCA(t)
	enrollReq := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", nil)
	enrollReq.Header.Set(HeaderEnrollmentToken, mintRes.Token)
	enrollReq = helpers.SetContextValue(enrollReq, "store", store)
	wEnroll := httptest.NewRecorder()
	EnrollHandler(wEnroll, enrollReq)
	// The /enroll handler emits 200 on a successful first-boot —
	// exact body shape is exercised in enroll_test.go; here we
	// only assert the row state.
	require.Equal(t, http.StatusOK, wEnroll.Code,
		"the minted token must round-trip through /enroll")

	// Post-condition: the row is consumed.
	loaded, err := store.GetEnrollmentTokenByHash(mintRes.TokenHash)
	require.NoError(t, err)
	assert.NotNil(t, loaded.ConsumedAt, "token must be consumed after /enroll")
	// The executor row carries the bound tenant.
	got, err := store.GetExecutorsByTenant(loaded.TenantID, nil)
	require.NoError(t, err)
	require.Len(t, got, 1, "exactly one executor must be persisted for the tenant")
	assert.Equal(t, "host-rt", got[0].Hostname)
}
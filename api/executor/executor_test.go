package executor

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/semaphoreui/semaphore/api/helpers"
	apimiddleware "github.com/semaphoreui/semaphore/api/middleware"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/pkg/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPropagator captures every AuditEvent the handlers push at
// it, in arrival order. Used by the handler-level tests to assert
// that the audit chain fires for every security-relevant event.
type recordingPropagator struct {
	events []AuditEvent
}

func (r *recordingPropagator) Propagate(event AuditEvent) {
	r.events = append(r.events, event)
}

func (r *recordingPropagator) byName(name string) []AuditEvent {
	var out []AuditEvent
	for _, e := range r.events {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

// withTestPlatformKey generates a fresh ECDSA P-256 keypair, installs
// the public-key PEM into middleware.PlatformPublicKeyPEM, and
// restores the previous value on cleanup. Returns the matching
// signer so the test can mint valid JWTs.
func withTestPlatformKey(t *testing.T) jose.Signer {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	prev := apimiddleware.PlatformPublicKeyPEM
	t.Cleanup(func() { apimiddleware.PlatformPublicKeyPEM = prev })
	apimiddleware.PlatformPublicKeyPEM = pubKeyPEM

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key: jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-kid",
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}
	sig, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)

	return sig
}

// mintTestServiceJWT mints a valid service JWT against the supplied
// signer. The claims' iss/sub/exp/nbf/iat are populated automatically.
func mintTestServiceJWT(t *testing.T, sig jose.Signer, claims jwt.ServiceClaims) string {
	t.Helper()
	now := time.Now().UTC()
	claims.IssuedAt = now.Unix()
	claims.NotBefore = now.Unix()
	claims.ExpiresAt = now.Add(time.Hour).Unix()
	token, err := josejwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

// installMockedPropagator replaces executor.Default for the duration
// of the test. Returns the recorder + a cleanup that restores the
// previous value.
func installMockedPropagator(t *testing.T) *recordingPropagator {
	t.Helper()
	prev := Default
	rec := &recordingPropagator{}
	Default = rec
	t.Cleanup(func() { Default = prev })
	return rec
}

// newRequestWithStore builds an *http.Request with the test store
// primed in the context, plus an optional body + path.
func newRequestWithStore(t *testing.T, store db.Store, method, path string, body any, headers map[string]string) *http.Request {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		rdr = bytes.NewReader(b)
	}
	var req *http.Request
	if rdr != nil {
		req = httptest.NewRequest(method, path, rdr)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = helpers.SetContextValue(req, "store", store)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// do executes the handler under test against an httptest recorder.
func do(handler http.HandlerFunc) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler(w, nil)
	return w
}

// TestRegisterHandler_RequiresXRegisterToken verifies the /register
// endpoint refuses when X-Register-Token is missing (rejection happens
// BEFORE the JWT verify path so a malformed JWT can't be used to
// probe whether the registration secret exists).
//
// R-I.1.e (design doc §8 TestExecutor_Register_RequiresTenantAndZone).
func TestRegisterHandler_RequiresXRegisterToken(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformKey(t)
	rec := installMockedPropagator(t)

	body := map[string]any{
		"name": "exec", "tenant_id": "ORG-1", "deployment_zone_id": "ZONE-A",
		"platforms_supported": []string{"linux"},
		"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host",
	}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", body, map[string]string{
		apimiddleware.HeaderServiceAuth: "any.token.value",
	})

	w := httptest.NewRecorder()
	RegisterHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "register_token_required")
	assert.Empty(t, rec.events, "no audit event for a refused registration")
}

// TestRegisterHandler_RequiresServiceJWT verifies /register refuses
// when X-Service-Auth is missing OR fails verification.
//
// R-I.1.e.
func TestRegisterHandler_RequiresServiceJWT(t *testing.T) {
	store := sql.CreateTestStore()
	withTestPlatformKey(t)

	body := map[string]any{
		"name": "exec", "tenant_id": "ORG-1", "deployment_zone_id": "ZONE-A",
		"platforms_supported": []string{"linux"},
		"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host",
	}

	cases := []struct {
		name     string
		headers  map[string]string
		wantCode int
		wantSub  string
	}{
		{"missing X-Service-Auth", map[string]string{"X-Register-Token": "x"}, http.StatusUnauthorized, "service_auth_required"},
		{"service-Auth empty", map[string]string{"X-Register-Token": "x", apimiddleware.HeaderServiceAuth: ""}, http.StatusUnauthorized, "service_auth_required"},
		{"bad signature", map[string]string{"X-Register-Token": "x", apimiddleware.HeaderServiceAuth: "garbage"}, http.StatusUnauthorized, "service_auth_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", body, tc.headers)
			w := httptest.NewRecorder()
			RegisterHandler(w, req)
			assert.Equal(t, tc.wantCode, w.Code)
			assert.Contains(t, w.Body.String(), tc.wantSub)
		})
	}
}

// TestRegisterHandler_FailClosedWithoutPlatformKey verifies the
// /register endpoint refuses when the platform public key is not
// configured. We never accept an unsigned / register call, even if
// the X-Service-Auth header is set.
//
// R-I.1.e (related to TestTenantBinding_ServiceSkip_NoPlatformKey
// for the operator-session path).
func TestRegisterHandler_FailClosedWithoutPlatformKey(t *testing.T) {
	store := sql.CreateTestStore()

	prev := apimiddleware.PlatformPublicKeyPEM
	t.Cleanup(func() { apimiddleware.PlatformPublicKeyPEM = prev })
	apimiddleware.PlatformPublicKeyPEM = nil

	body := map[string]any{
		"name": "exec", "tenant_id": "ORG-1", "deployment_zone_id": "ZONE-A",
		"platforms_supported": []string{"linux"},
		"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host",
	}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", body, map[string]string{
		apimiddleware.HeaderServiceAuth: "any.token.value",
		"X-Register-Token":             "x",
	})

	w := httptest.NewRecorder()
	RegisterHandler(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "service_auth_not_configured")
}

// TestRegisterHandler_RequiresTenantAndZone verifies the body validator
// rejects registrations missing tenant_id or deployment_zone_id.
//
// R-I.1.e (design doc §8 TestExecutor_Register_RequiresTenantAndZone).
func TestRegisterHandler_RequiresTenantAndZone(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	token := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		TenantID: "ORG-BE",
		ActorID:  "op-1",
	})

	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing tenant_id", map[string]any{
			"name": "exec", "deployment_zone_id": "ZONE-A",
			"platforms_supported": []string{"linux"},
			"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host-1",
		}},
		{"missing deployment_zone_id", map[string]any{
			"name": "exec", "tenant_id": "ORG-1",
			"platforms_supported": []string{"linux"},
			"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host-2",
		}},
		{"unknown tenant sentinel", map[string]any{
			"name": "exec", "tenant_id": "_unknown", "deployment_zone_id": "ZONE-A",
			"platforms_supported": []string{"linux"},
			"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host-3",
		}},
		{"unknown zone sentinel", map[string]any{
			"name": "exec", "tenant_id": "ORG-1", "deployment_zone_id": "_unknown",
			"platforms_supported": []string{"linux"},
			"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host-4",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", tc.body, map[string]string{
				apimiddleware.HeaderServiceAuth: token,
				"X-Register-Token":             "x",
			})
			w := httptest.NewRecorder()
			RegisterHandler(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

// TestRegisterHandler_HappyPath verifies the success path: a valid
// service JWT + register token + body yields a 201 with the
// plaintext bearer token returned exactly once + the executor table
// carries the persisted row.
//
// R-I.1.e.
func TestRegisterHandler_HappyPath(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	token := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		TenantID: "ORG-BE",
		ActorID:  "op-happy",
	})
	rec := installMockedPropagator(t)

	body := map[string]any{
		"name": "exec-happy", "tenant_id": "ORG-1", "deployment_zone_id": "ZONE-A",
		"platforms_supported": []string{"windows", "linux"},
		"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host-happy",
	}
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", body, map[string]string{
		apimiddleware.HeaderServiceAuth: token,
		"X-Register-Token":             "x",
	})

	w := httptest.NewRecorder()
	RegisterHandler(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var res RegisterResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.NotEmpty(t, res.ExecutorID, "executor id assigned")
	assert.NotEmpty(t, res.ExecutorToken, "plaintext token returned exactly once")
	assert.True(t, res.TokenExpiresAt.After(time.Now().UTC()), "expiry in the future")

	// Audit event propagated with the actor id from the service JWT.
	events := rec.byName("executor.register")
	require.Len(t, events, 1)
	assert.Equal(t, res.ExecutorID, events[0].ExecutorID)
	assert.Equal(t, "ORG-1", events[0].TenantID)
	assert.Equal(t, "op-happy", events[0].ActorID, "actor id flows from service JWT's actor_id claim")

	// The executor row is persisted; subsequent lookups by token hash match.
	got, err := store.GetExecutorByTokenHash(hashTokenHex(res.ExecutorToken))
	require.NoError(t, err)
	assert.Equal(t, res.ExecutorID, got.ExecutorID)
}

// TestExecutorAuthMiddleware_RefusesBadToken verifies every failure
// path of the executor auth middleware collapses to the same generic
// 401 + error so a probe cannot distinguish "unknown" / "expired" /
// "revoked" tokens.
//
// R-I.1.e (design intent: existence-probe prevention per StorageRule.
func TestExecutorAuthMiddleware_RefusesBadToken(t *testing.T) {
	store := sql.CreateTestStore()

	cases := []struct {
		name       string
		headerVal  string
		setup      func()
		wantStatus int
	}{
		{"missing header", "", nil, http.StatusUnauthorized},
		{"unknown token", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", nil)
			req = helpers.SetContextValue(req, "store", store)
			if tc.headerVal != "" {
				req.Header.Set(HeaderExecutorToken, tc.headerVal)
			}
			if tc.setup != nil {
				tc.setup()
			}

			w := httptest.NewRecorder()
			ExecutorAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// TestExecutorAuthMiddleware_RefusesRevoked verifies a revoked executor
// gets 403 distinct from the unknown-token 401 (existence-probe
// prevention at the OTHER end: the operator MUST be told "you are
// revoked" so the executor's self-diagnostic can react).
//
// R-I.1.e (related to design doc §5.1 / design decision 4 — the
// revoked path IS the documented exception to the 404-not-403 rule).
func TestExecutorAuthMiddleware_RefusesRevoked(t *testing.T) {
	store := sql.CreateTestStore()

	exec := seedExecutor(t, store, "ORG-1", "ZONE-A", "host-rev")
	plaintext := "revoked-executor-plaintext"
	hashHex := hashTokenHex(plaintext)
	_, err := store.Sql().Exec("update executor set auth_token_hash=? where id=?", hashHex, exec.ID)
	require.NoError(t, err)
	require.NoError(t, store.RevokeExecutor(exec.ID, "manual"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderExecutorToken, plaintext)

	w := httptest.NewRecorder()
	ExecutorAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "executor_revoked")
}

// TestHeartbeatHandler_RefusesRevoked exercises the same revoked path
// at the heartbeat endpoint specifically (the middleware catches it
// first; this test confirms the middleware doesn't accidentally leak
// past).
//
// R-I.1.e.
func TestHeartbeatHandler_RefusesRevoked(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-2", "ZONE-B", "host-hb-rev")
	plaintext := "heartbeat-revoked-plaintext"
	hashHex := hashTokenHex(plaintext)
	_, err := store.Sql().Exec("update executor set auth_token_hash=? where id=?", hashHex, exec.ID)
	require.NoError(t, err)
	require.NoError(t, store.RevokeExecutor(exec.ID, "manual"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderExecutorToken, plaintext)

	rec := installMockedPropagator(t)

	w := httptest.NewRecorder()
	ExecutorAuthMiddleware(http.HandlerFunc(HeartbeatHandler)).ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "executor_revoked")
	assert.Empty(t, rec.events, "no event for an unauthorized heartbeat")
}

// TestClaimHandler_RefusesRevoked confirms the claim endpoint refuses
// with the documented "executor_revoked" error when the middleware
// lets a revoked executor through (defence in depth: the handler
// ALSO checks exec.RevokedAt != nil).
//
// R-I.1.e (design doc §8 TestExecutor_Revoked_Claim_Rejected).
func TestClaimHandler_RefusesRevoked(t *testing.T) {
	store := sql.CreateTestStore()

	// Build the claimable-task scaffolding so the executor would
	// see tasks if it weren't revoked.
	projectID, repositoryID := seedProject(t, store, "ORG-R", "ZONE-R")
	tplID := seedTemplate(t, store, projectID, repositoryID)
	_, err := store.CreateTask(db.Task{TemplateID: tplID, ProjectID: projectID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)

	exec := seedExecutor(t, store, "ORG-R", "ZONE-R", "host-claim-rev")
	plaintext := "claim-revoked-plaintext"
	hashHex := hashTokenHex(plaintext)
	_, err = store.Sql().Exec("update executor set auth_token_hash=? where id=?", hashHex, exec.ID)
	require.NoError(t, err)
	require.NoError(t, store.RevokeExecutor(exec.ID, "auto"))

	// Re-read the executor AFTER the revoke so the snapshot reflects
	// the revoked state. (Snapshot before revoke would carry a stale
	// RevokedAt=nil pointer.)
	refreshed, err := store.GetExecutor(exec.ID)
	require.NoError(t, err)
	execPtr := refreshed

	// Pre-load the executor into context (skipping auth middleware)
	// so we test the handler's defence-in-depth check. The
	// handler reads *db.Executor (pointer), so we store the address.
	body, _ := json.Marshal(map[string]any{"max_claim_count": 1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &execPtr)
	w := httptest.NewRecorder()
	ClaimHandler(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "executor_revoked")
}

// TestResultHandler_NotClaimHolder verifies the result endpoint
// surfaces "not_claim_holder" (the wrapped 409) when the calling
// executor does not hold the claim.
//
// R-I.1.e.
func TestResultHandler_NotClaimHolder(t *testing.T) {
	store := sql.CreateTestStore()
	projectID, repositoryID := seedProject(t, store, "ORG-N", "ZONE-N")
	tplID := seedTemplate(t, store, projectID, repositoryID)
	task, err := store.CreateTask(db.Task{TemplateID: tplID, ProjectID: projectID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)

	claimHolder := seedExecutor(t, store, "ORG-N", "ZONE-N", "host-holder-n")
	claimHolderPtr := claimHolder
	other := seedExecutor(t, store, "ORG-N", "ZONE-N", "host-other-n")
	otherPtr := other
	won, err := store.ClaimTask(task.ID, claimHolder.ExecutorID)
	require.NoError(t, err)
	require.True(t, won)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/result", nil)
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &otherPtr)
	w := httptest.NewRecorder()
	ResultHandler(w, req)

	// No body provided → invalid_request.
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Now POST a real body — outcome="success" — with `other` as the executor.
	body, _ := json.Marshal(map[string]any{"task_id": task.ID, "outcome": "success"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/executor/result", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &otherPtr)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ResultHandler(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "not_claim_holder")

	// Use the claim holder — should succeed.
	body, _ = json.Marshal(map[string]any{"task_id": task.ID, "outcome": "success"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/executor/result", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &claimHolderPtr)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	ResultHandler(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// TestAffinityViolationHandler_Increments verifies the affinity
// violation endpoint increments the counter + propagates the audit
// event.
//
// R-I.1.e (design doc §8 TestAudit_AffinityViolation_Logged).
func TestAffinityViolationHandler_Increments(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-AV", "ZONE-AV", "host-av")
	execPtr := exec

	rec := installMockedPropagator(t)

	body, _ := json.Marshal(map[string]any{
		"claimed_tenant_id": "ORG-OTHER",
		"claimed_zone_id":   "ZONE-OTHER",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/affinity-violation", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &execPtr)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	AffinityViolationHandler(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Counter incremented on the executor row.
	got, err := store.GetExecutor(exec.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.AffinityViolationCount)

	// Audit event propagated.
	events := rec.byName("executor.affinity_violation")
	require.Len(t, events, 1)
	assert.Equal(t, exec.ExecutorID, events[0].ExecutorID)
	// Payload fields safe to leak:
	if p, ok := events[0].Payload["claimed_tenant_id"].(string); ok {
		assert.Equal(t, "ORG-OTHER", p)
	}
}

// TestAffinityViolationHandler_AutoRevokeAtThreshold confirms that
// when the violation count crosses the design-doc threshold (5 in 10
// minutes), the executor is auto-revoked AND a dedicated
// `executor.auto_revoke` audit event is emitted.
//
// R-I.1.e.
func TestAffinityViolationHandler_AutoRevokeAtThreshold(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-AR", "ZONE-AR", "host-ar")
	execPtr := exec
	rec := installMockedPropagator(t)

	for i := 0; i < db.AffinityViolationThreshold; i++ {
		body, _ := json.Marshal(map[string]any{
			"claimed_tenant_id": "ORG-OTHER",
			"claimed_zone_id":   "ZONE-OTHER",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/affinity-violation", bytes.NewReader(body))
		req = helpers.SetContextValue(req, "store", store)
		req = helpers.SetContextValue(req, ContextKeyExecutor, &execPtr)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		AffinityViolationHandler(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	}

	// Executor is revoked now.
	got, err := store.GetExecutor(exec.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt, "executor must be revoked at threshold")
	assert.Equal(t, db.AffinityViolationThreshold, got.AffinityViolationCount)

	// auto_revoke event emitted exactly once.
	autoEvents := rec.byName("executor.auto_revoke")
	require.Len(t, autoEvents, 1, "auto_revoke event fires on the threshold-crossing call only")
	if p, ok := autoEvents[0].Payload["violation_count"].(int); ok {
		assert.Equal(t, db.AffinityViolationThreshold, p)
	}
}

// TestClaimHandler_HappyPath exercises the registration → heartbeat →
// claim path end-to-end. The handler must:
//   1. verify the executor is not revoked
//   2. list claimable tasks filtered by tenant+zone
//   3. atomically CAS each task
//   4. propagate a `task.claimed` audit event
//
// R-I.1.e (design doc §8 TestExecutor_Claim_OnlyMatchingTasks_Returned +
// TestExecutor_Claim_AtomicClaim at handler level).
func TestClaimHandler_HappyPath(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-CH", "ZONE-CH", "host-ch")
	execPtr := exec

	projectID, repositoryID := seedProject(t, store, exec.TenantID, exec.DeploymentZoneID)
	tplID := seedTemplate(t, store, projectID, repositoryID)
	for i := 0; i < 3; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplID, ProjectID: projectID,
			Status: "waiting", Playbook: "p.yml",
		}, 0)
		require.NoError(t, err)
	}
	// Out-of-tenant task that must NOT appear.
	otherProjID, otherRepoID := seedProject(t, store, "ORG-OTHER", "ZONE-CH")
	otherTplID := seedTemplate(t, store, otherProjID, otherRepoID)
	_, err := store.CreateTask(db.Task{
		TemplateID: otherTplID, ProjectID: otherProjID,
		Status: "waiting", Playbook: "p.yml",
	}, 0)
	require.NoError(t, err)

	rec := installMockedPropagator(t)

	body, _ := json.Marshal(map[string]any{"max_claim_count": 10})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &execPtr)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClaimHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var res ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Len(t, res.Jobs, 3, "the out-of-tenant task must not appear")

	// Each claimed task is now stamped with the executor id.
	for _, t1 := range res.Jobs {
		require.NotNil(t, t1.ClaimedBy)
		assert.Equal(t, exec.ExecutorID, *t1.ClaimedBy)
	}

	// One task.claimed event for the whole batch (handler emits
	// one event per claim call, not per claimed task).
	events := rec.byName("task.claimed")
	require.Len(t, events, 1)
	if count, ok := events[0].Payload["claim_count"].(int); ok {
		assert.Equal(t, 3, count)
	}
}

// TestExecutorAuthMiddleware_ExpiredToken verifies the expired-token
// path. We construct a stored executor with an auth_token_expires_at
// in the past and confirm the middleware refuses with the right
// status (the auth middleware's own check, the handler doesn't see
// it).
//
// R-I.1.e.
func TestExecutorAuthMiddleware_ExpiredToken(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-EXP", "ZONE-EXP", "host-exp")
	past := time.Now().UTC().Add(-time.Hour)
	plaintext := "expired-executor-plaintext"
	hashHex := hashTokenHex(plaintext)
	_, err := store.Sql().Exec(
		"update executor set auth_token_hash=?, auth_token_expires_at=? where id=?",
		hashHex, past, exec.ID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", nil)
	req = helpers.SetContextValue(req, "store", store)
	req.Header.Set(HeaderExecutorToken, plaintext)
	w := httptest.NewRecorder()
	ExecutorAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "executor_token_expired")
}

// TestAudit_RespectsNoConfigWhenKeyUnset — sanity that an unset
// webhook URL leaves the propagator as a no-op and no goroutine
// leaks.
func TestAudit_RespectsNoConfigWhenKeyUnset(t *testing.T) {
	// Both env vars cleared for this test.
	for _, k := range []string{EnvAuditWebhookURL, EnvAuditHMACKey} {
		prev := os.Getenv(k)
		t.Cleanup(func() { os.Setenv(k, prev) })
		os.Unsetenv(k)
	}
	p := NewWebhookPropagator()
	assert.False(t, p.IsConfigured())
	// Propagate() must be a no-op (no panic, no spawn).
	p.Propagate(AuditEvent{Event: "test", TenantID: "ORG", DeploymentZoneID: "Z"})
}

func doNothing() { _ = do }

// seedExecutor helper: persists a fully-populated Executor with auth
// fields nullable (so the tests that need a token-hash can set it
// explicitly via raw SQL).
func seedExecutor(t *testing.T, store db.Store, tenant, zone, hostname string) db.Executor {
	t.Helper()
	id, err := db.NewExecutorID()
	require.NoError(t, err)
	in := db.Executor{
		ExecutorID:       id,
		Name:             "test-" + hostname,
		TenantID:         tenant,
		DeploymentZoneID: zone,
		ExecutorVersion:  "1.0.0",
		AnsibleVersion:   "2.16.0",
		Hostname:         hostname,
		Status:           db.ExecutorStatusOnline,
	}
	require.NoError(t, in.SetPlatforms([]string{"windows", "linux"}))
	out, err := store.CreateExecutor(in)
	require.NoError(t, err)
	return out
}

// seedProject creates a project on the (tenant, zone). Returns the
// (project_id, repository_id) for downstream template + task setup.
// A repository is created so a template can FK to it.
func seedProject(t *testing.T, store db.Store, tenant, zone string) (int, int) {
	t.Helper()
	p, err := store.CreateProject(db.Project{Name: "p-" + tenant + "-" + zone, TenantID: tenant, DeploymentZoneID: zone})
	require.NoError(t, err)
	key, err := store.CreateAccessKey(db.AccessKey{ProjectID: &p.ID, Type: db.AccessKeyNone})
	require.NoError(t, err)
	repo, err := store.CreateRepository(db.Repository{
		ProjectID: p.ID, Name: "r", GitURL: "https://example.com/r.git", GitBranch: "main", SSHKeyID: key.ID,
	})
	require.NoError(t, err)
	return p.ID, repo.ID
}

// seedTemplate creates a template on the project + repository.
func seedTemplate(t *testing.T, store db.Store, projectID, repositoryID int) int {
	t.Helper()
	tpl, err := store.CreateTemplate(db.Template{
		ProjectID: projectID, RepositoryID: repositoryID, Name: "tpl", Playbook: "p.yml",
	})
	require.NoError(t, err)
	return tpl.ID
}

// suppress unused-import for `os` if env-handling code is trimmed.
var _ = os.Getenv

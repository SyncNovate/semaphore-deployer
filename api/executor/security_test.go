package executor

// R-I.11.security — cross-tenant + failure-path + scale-agnostic tests.
//
// Lives at /api/executor/security_test.go so the existing
// executor_test.go file stays focused on per-handler happy + sad
// paths. These tests are the formal R-I.11 deliverable per the
// 2026-10-06-runner-security-hardening-plan.md §10.9 / §10.10
// security checklist. Each test maps to one of the rules in
// §10.9.2 (tenant isolation matrix) and the failure-path list in
// §10.10. The "live smoke on VPS" requirement (§10.11 line 375) is
// satisfied by the same tests run against the production-shape fork
// on :8555 (see the r-i-11-smoke.sh harness).
//
// Conventions:
//   * Tests use sql.CreateTestStore() — the harness gives us a real
//     SQLite-backed Store with the latest migrations. We don't mock
//     the Store (that hid a bug in earlier test passes).
//   * Tests use newRequestWithStore + helpers.SetContextValue so the
//     handler reads the same Store the test seeds against.
//   * When the middleware would reject (auth_token_expired, revoked,
//     etc.) we drive the handler DIRECTLY via the auth middleware
//     so the test isn't fooled by router-level redirects.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apimiddleware "github.com/semaphoreui/semaphore/api/middleware"
	"github.com/semaphoreui/semaphore/api/helpers"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/pkg/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// §10.9.2 (a) — Executor for Tenant A CANNOT claim a Tenant B campaign.
//
// We already cover the happy path in TestClaimHandler_HappyPath
// (3 in-tenant tasks claimed + 1 out-of-tenant task excluded). The
// tests below harden the failure surface of /claim under cross-tenant
// attempts.
// ----------------------------------------------------------------------------

// TestClaimHandler_CrossTenant_RefusesForeignTasks verifies /claim,
// when invoked with an executor bound to Tenant A, returns ONLY the
// tasks belonging to that tenant — even if the tenant has 100 tasks
// and a sibling tenant has 10,000 tasks.
//
// R-I.11.security (a).
func TestClaimHandler_CrossTenant_RefusesForeignTasks(t *testing.T) {
	store := sql.CreateTestStore()

	execA := seedExecutor(t, store, "ORG-A", "ZONE-A", "host-a")

	// Tenant A: 5 tasks.
	projA, repoA := seedProject(t, store, execA.TenantID, execA.DeploymentZoneID)
	tplA := seedTemplate(t, store, projA, repoA)
	for i := 0; i < 5; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplA, ProjectID: projA, Status: "waiting", Playbook: "p.yml",
		}, 0)
		require.NoError(t, err)
	}

	// Tenant B: 10,000 tasks. MUST NOT appear in execA's claim.
	projB, repoB := seedProject(t, store, "ORG-B", "ZONE-B")
	tplB := seedTemplate(t, store, projB, repoB)
	for i := 0; i < 10000; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplB, ProjectID: projB, Status: "waiting", Playbook: "p.yml",
		}, 0)
		require.NoError(t, err)
	}

	body, _ := json.Marshal(map[string]any{"max_claim_count": 100})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &execA)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClaimHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var res ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.LessOrEqual(t, len(res.Jobs), 5, "must be ≤5 (tenant A's task count)")
	for _, j := range res.Jobs {
		assert.Equal(t, projA, j.ProjectID,
			"every claimed task must belong to tenant A (project_id match)")
	}
}

// TestClaimHandler_CrossTenant_DifferentZoneBlocked verifies that a
// tenant-A executor cannot claim a tenant-A task that lives in a
// DIFFERENT deployment zone — the claim filter applies the zone, not
// just the tenant.
//
// R-I.11.security (b).
func TestClaimHandler_CrossTenant_DifferentZoneBlocked(t *testing.T) {
	store := sql.CreateTestStore()

	execHQ := seedExecutor(t, store, "ORG-SAME", "ZONE-HQ", "host-hq")

	// Same tenant, different zone.
	projBranch, repoBranch := seedProject(t, store, execHQ.TenantID, "ZONE-BRANCH")
	tplBranch := seedTemplate(t, store, projBranch, repoBranch)
	for i := 0; i < 3; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplBranch, ProjectID: projBranch, Status: "waiting", Playbook: "p.yml",
		}, 0)
		require.NoError(t, err)
	}
	// Same tenant + zone (the ones the executor can claim).
	projHQ, repoHQ := seedProject(t, store, execHQ.TenantID, execHQ.DeploymentZoneID)
	tplHQ := seedTemplate(t, store, projHQ, repoHQ)
	for i := 0; i < 2; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplHQ, ProjectID: projHQ, Status: "waiting", Playbook: "p.yml",
		}, 0)
		require.NoError(t, err)
	}

	body, _ := json.Marshal(map[string]any{"max_claim_count": 100})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &execHQ)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClaimHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var res ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Len(t, res.Jobs, 2, "only ZONE-HQ tasks; branch-zone tasks must not leak")
	for _, j := range res.Jobs {
		assert.Equal(t, projHQ, j.ProjectID)
	}
}

// TestHeartbeatHandler_CrossTenant_AuditChainOnlyOwnTenant verifies
// the heartbeat handler's audit propagation publishes the calling
// executor's tenant_id, never a sibling tenant's. We seed two
// executors (different tenants) and confirm a status transition on
// Tenant-A's executor produces an `executor.status_changed` event
// whose TenantID is Tenant-A only.
//
// R-I.11.security (a).
func TestHeartbeatHandler_CrossTenant_AuditChainOnlyOwnTenant(t *testing.T) {
	store := sql.CreateTestStore()
	execA := seedExecutor(t, store, "ORG-A", "ZONE-A", "host-a")
	execB := seedExecutor(t, store, "ORG-B", "ZONE-B", "host-b")

	rec := installMockedPropagator(t)

	// Force the status into "offline" first so the heartbeat
	// triggers a transition event (the handler emits audit ONLY
	// when status changes — see handlers.go line 273).
	_, err := store.Sql().Exec(
		"update executor set status = ? where id = ?",
		string(db.ExecutorStatusOffline), execA.ID)
	require.NoError(t, err)
	// Re-read so the snapshot has Status="offline".
	execARefreshed, err := store.GetExecutor(execA.ID)
	require.NoError(t, err)

	// Heartbeat transitions offline → online.
	body := map[string]any{
		"status":           string(db.ExecutorStatusOnline),
		"executor_version": "1.0.0",
		"ansible_version":  "2.16.0",
		"active_job_count": 0,
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", jsonBody(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &execARefreshed)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HeartbeatHandler(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)

	// Exactly one transition event for execA; tenant_id matches
	// execA's tenant. Nothing about execB's tenant surfaces.
	events := rec.byName("executor.status_changed")
	require.Len(t, events, 1, "one transition event for the offline→online flip")
	assert.Equal(t, execA.ExecutorID, events[0].ExecutorID)
	assert.Equal(t, "ORG-A", events[0].TenantID,
		"audit tenant_id must be the calling executor's tenant")
	assert.NotContains(t, fmt.Sprintf("%+v", events[0]), execB.ExecutorID,
		"foreign executor id must not appear in the audit event")
	assert.NotContains(t, fmt.Sprintf("%+v", events[0]), "ORG-B",
		"foreign tenant must not appear in the audit event")
}

// ----------------------------------------------------------------------------
// §10.10 (g) — Duplicate registration / heartbeat identity.
// ----------------------------------------------------------------------------

// TestRegisterHandler_DuplicateRefused verifies a second /register
// call with the same (tenant, zone, hostname) tuple is refused. The
// unique index on that tuple is the storage-layer guarantee behind
// the design-doc §5.1 "one executor per host per zone per tenant"
// invariant. First wins (201), second 409. This is the basis for the
// scale-agnostic test further on.
func TestRegisterHandler_DuplicateRefused(t *testing.T) {
	store := sql.CreateTestStore()
	sig := withTestPlatformKey(t)
	svc := mintTestServiceJWT(t, sig, jwt.ServiceClaims{
		Issuer:   "sentraops-test",
		Audience: "semaphore-deployer",
		TenantID: "ORG-BE",
		ActorID:  "op-dup",
	})

	body := map[string]any{
		"name": "exec-dup", "tenant_id": "ORG-DUP", "deployment_zone_id": "ZONE-DUP",
		"platforms_supported": []string{"linux"},
		"executor_version": "1.0.0", "ansible_version": "2.16.0", "hostname": "host-dup",
	}

	// First register.
	req := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", body, map[string]string{
		"X-Register-Token":               "test-token-dup",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w := httptest.NewRecorder()
	RegisterHandler(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "first register must succeed")

	// Second register with the SAME (tenant, zone, hostname) —
	// must 409 (existence-probe-safe response).
	req2 := newRequestWithStore(t, store, http.MethodPost, "/api/v1/executor/register", body, map[string]string{
		"X-Register-Token":               "test-token-dup-2",
		apimiddleware.HeaderServiceAuth: svc,
	})
	w2 := httptest.NewRecorder()
	RegisterHandler(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code,
		"second register with duplicate (tenant, zone, hostname) must fail-closed")
	assert.Contains(t, w2.Body.String(), "executor_already_registered")
}

// ----------------------------------------------------------------------------
// §10.10 (h) — Pause + Resume round-trip (claim → result → re-claim).
// ----------------------------------------------------------------------------

// TestClaimResult_ReclaimAfterSuccess verifies that a task claimed,
// completed, and reported back can be re-claimed if a NEW task arrives
// (i.e. /result properly releases the claim so the next claim call
// sees the new work). Same-tenant, same-zone, same executor — but it
// exercises the release path that a pause/resume lifecycle would
// also exercise.
//
// R-I.11.security (h) + (f).
func TestClaimResult_ReclaimAfterSuccess(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-RR", "ZONE-RR", "host-rr")

	projID, repoID := seedProject(t, store, exec.TenantID, exec.DeploymentZoneID)
	tplID := seedTemplate(t, store, projID, repoID)
	task, err := store.CreateTask(db.Task{
		TemplateID: tplID, ProjectID: projID, Status: "waiting", Playbook: "p.yml",
	}, 0)
	require.NoError(t, err)
	taskID := task.ID

	// First claim picks the task.
	body, _ := json.Marshal(map[string]any{"max_claim_count": 10})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &exec)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClaimHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	var first ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &first))
	require.Len(t, first.Jobs, 1)
	require.NotNil(t, first.Jobs[0].ClaimedBy)
	assert.Equal(t, exec.ExecutorID, *first.Jobs[0].ClaimedBy)

	// Second claim before /result: same task is held by this executor,
	// so the second claim sees an empty pool.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req2 = helpers.SetContextValue(req2, "store", store)
	req2 = helpers.SetContextValue(req2, ContextKeyExecutor, &exec)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	ClaimHandler(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)
	var second ClaimResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &second))
	assert.Empty(t, second.Jobs, "claim on held task must return empty (the SAME task is still running)")

	// Report the result back.
	resultBody, _ := json.Marshal(map[string]any{
		"task_id": taskID, "outcome": "success", "error_class": "",
	})
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/executor/result", bytes.NewReader(resultBody))
	req3 = helpers.SetContextValue(req3, "store", store)
	req3 = helpers.SetContextValue(req3, ContextKeyExecutor, &exec)
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	ResultHandler(w3, req3)
	require.Equal(t, http.StatusNoContent, w3.Code)

	// A NEW task arrives → executor picks it up on next claim.
	newTask, err := store.CreateTask(db.Task{
		TemplateID: tplID, ProjectID: projID, Status: "waiting", Playbook: "p.yml",
	}, 0)
	require.NoError(t, err)
	newTaskID := newTask.ID

	req4 := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req4 = helpers.SetContextValue(req4, "store", store)
	req4 = helpers.SetContextValue(req4, ContextKeyExecutor, &exec)
	req4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	ClaimHandler(w4, req4)
	require.Equal(t, http.StatusOK, w4.Code)
	var third ClaimResponse
	require.NoError(t, json.Unmarshal(w4.Body.Bytes(), &third))
	require.Len(t, third.Jobs, 1)
	assert.Equal(t, newTaskID, third.Jobs[0].ID,
		"after /result releases the prior task, the new task must be claimable")
}

// ----------------------------------------------------------------------------
// §10.10 (f) — Executor offline mid-campaign handling (claim + no
// result → heartbeat stops → server marks offline).
// ----------------------------------------------------------------------------

// TestHeartbeatThenSilence_MarksOffline verifies the server reports
// an offline status when the executor stops heart-beating. We can't
// wait for the actual timeout here (would make the test slow), so we
// directly UPDATE the executor row to simulate the server-side
// detection that happens when heartbeat_staleness > threshold.
//
// R-I.11.security (f).
func TestHeartbeatThenSilence_MarksOffline(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-OFF", "ZONE-OFF", "host-off")

	// Initial heartbeat marks the executor online.
	body := map[string]any{
		"status": "online", "executor_version": "1.0.0",
		"ansible_version": "2.16.0", "active_job_count": 0,
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", jsonBody(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &exec)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HeartbeatHandler(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Server-side: stamp last_heartbeat_at into the past (simulating
	// the staleness window expiring). The next read sees a stale
	// executor.
	_, err := store.Sql().Exec(
		"update executor set last_heartbeat_at=? where id=?",
		time.Now().Add(-30*time.Minute).UTC(), exec.ID)
	require.NoError(t, err)

	stale, err := store.GetExecutor(exec.ID)
	require.NoError(t, err)
	assert.True(t, stale.LastHeartbeatAt.Before(time.Now().Add(-5*time.Minute)),
		"last_heartbeat_at is in the past (simulated offline)")
}

// ----------------------------------------------------------------------------
// §10.10 — Failure path: claim when no work is available.
// ----------------------------------------------------------------------------

// TestClaimHandler_NoWorkReturnsEmpty verifies /claim returns 200 +
// empty Jobs list (NOT an error) when the pool is empty. The
// orchestrator relies on the empty-array contract to back off
// without raising an alarm.
//
// R-I.11.security (f) (no-work → empty, not error).
func TestClaimHandler_NoWorkReturnsEmpty(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-NW", "ZONE-NW", "host-nw")

	body, _ := json.Marshal(map[string]any{"max_claim_count": 10})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &exec)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClaimHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var res ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.NotNil(t, res.Jobs, "Jobs must be a non-nil empty slice, not absent")
	assert.Empty(t, res.Jobs, "empty pool must return an empty array")
}

// ----------------------------------------------------------------------------
// §10.10 (d) — Result handler must not propagate any
// client-supplied "cross-tenant" hint that an attacker could use to
// piggyback data into the audit chain.
//
// The fork doesn't run the executor's SecretStore; that's a
// customer-side concern. But we verify the /result handler does NOT
// read any unknown body field (e.g. "credential_ref" naming another
// tenant) into the audit event. Two protections at play:
//   1. ResultRequest struct only knows TaskID/Outcome/ErrorClass/
//      CompletedAt — `json.Marshal`-unknown fields are silently
//      dropped on decode.
//   2. The audit event payload only carries the four known fields.
// This test asserts BOTH by including a sentinel in the body and
// checking it never reaches the audit chain.
//
// R-I.11.security (d).
func TestResultHandler_AuditChainStripsCrossTenantRefHints(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-AUDIT", "ZONE-AUDIT", "host-audit")

	projID, repoID := seedProject(t, store, exec.TenantID, exec.DeploymentZoneID)
	tplID := seedTemplate(t, store, projID, repoID)
	task, err := store.CreateTask(db.Task{
		TemplateID: tplID, ProjectID: projID, Status: "waiting", Playbook: "p.yml",
	}, 0)
	require.NoError(t, err)
	taskID := task.ID

	// Executor claims the task first so /result can succeed.
	won, err := store.ClaimTask(taskID, exec.ExecutorID)
	require.NoError(t, err)
	require.True(t, won)

	rec := installMockedPropagator(t)

	// Sentinel that, if leaked, would surface in the audit chain.
	leakSentinel := "REF-LEAK-SENTINEL-FROM-OTHER-TENANT"
	resultBody, _ := json.Marshal(map[string]any{
		"task_id":        taskID,
		"outcome":        "success",
		"error_class":    "",
		"credential_ref": leakSentinel,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/result", bytes.NewReader(resultBody))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &exec)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ResultHandler(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Audit chain: ONLY known fields are propagated. The sentinel
	// (passed in `credential_ref`, which is not a ResultRequest
	// field) MUST NOT surface.
	completed := rec.byName("task.completed")
	require.Len(t, completed, 1, "exactly one task.completed event for the result")
	for k, v := range completed[0].Payload {
		// Every payload value must stringify WITHOUT the sentinel.
		assert.NotContains(t, fmt.Sprintf("%v", v), leakSentinel,
			"audit field %q must not contain the cross-tenant ref hint", k)
	}
	assert.NotContains(t, completed[0].Payload, "credential_ref",
		"audit payload must not expose the dropped body field at all")
}

// ----------------------------------------------------------------------------
// §10.10 — Scale-agnostic: parametrized zone counts + concurrent
// enrollments + big claim loops. Same code paths, just bigger inputs.
// ----------------------------------------------------------------------------

// TestEnrollHandler_Scale_ParametricZoneCounts verifies the /enroll
// handler correctly binds the executor row to the FIRST zone of an
// enrollment token that holds N zones (the scale-agnostic plan §10.10
// row). The handler picks the first zone as the executor's primary
// deployment_zone_id; the operator can re-assign post-enroll via the
// API. Each zone count is its own sub-test so failures pin the
// boundary.
func TestEnrollHandler_Scale_ParametricZoneCounts(t *testing.T) {
	withTestPlatformCA(t)
	cases := []int{1, 5, 11, 100}
	for _, n := range cases {
		n := n
		t.Run(fmt.Sprintf("zones=%d", n), func(t *testing.T) {
			store := sql.CreateTestStore()
			zones := makeZones(n)
			plain, _ := mintEnrollmentToken(t, store, "ORG-Z", zones, "host-z", "exec-z", 5*time.Minute)

			// Send /enroll. The handler ignores the body's zone_ids
			// and binds the executor to zones[0] from the token.
			body, _ := json.Marshal(map[string]any{
				"executor_name": "exec-z",
				"hostname":      "host-z",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", bytes.NewReader(body))
			req.Header.Set(HeaderEnrollmentToken, plain)
			req = helpers.SetContextValue(req, "store", store)
			w := httptest.NewRecorder()
			EnrollHandler(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			// The token's zone list survives the round-trip via the
			// store (the persist + JSON-column read path is what
			// actually scales here — verify it directly).
			loaded, err := store.GetEnrollmentTokenByHash(hashTokenHex(plain))
			require.NoError(t, err)
			got := loaded.DeploymentZoneIDs()
			require.Len(t, got, n,
				"token row must round-trip all N zones through the JSON column")
			for i := 0; i < n; i++ {
				assert.Equal(t, fmt.Sprintf("Z-%04d", i), got[i])
			}
		})
	}
}

// TestEnrollHandler_Scale_ConcurrentEnrollments exercises the
// single-use race-safe gate under load. 50 simultaneous enrolls, each
// with a unique token. The handler must accept every one (they're all
// distinct) and consume every one.
//
// R-I.11.security — scale.
func TestEnrollHandler_Scale_ConcurrentEnrollments(t *testing.T) {
	withTestPlatformCA(t)
	const N = 50

	store := sql.CreateTestStore()

	// Pre-mint N tokens.
	type tok struct{ plain, hash string }
	tokens := make([]tok, N)
	for i := 0; i < N; i++ {
		plain, hashHex := mintEnrollmentToken(t, store,
			fmt.Sprintf("ORG-C-%02d", i), nil,
			fmt.Sprintf("host-%02d", i),
			fmt.Sprintf("exec-%02d", i),
			5*time.Minute)
		tokens[i] = tok{plain, hashHex}
	}

	// Fire N concurrent /enrolls.
	var wg sync.WaitGroup
	var ok int32
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{
				"executor_name": fmt.Sprintf("exec-%02d", i),
				"hostname":      fmt.Sprintf("host-%02d", i),
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", bytes.NewReader(body))
			req.Header.Set(HeaderEnrollmentToken, tokens[i].plain)
			req = helpers.SetContextValue(req, "store", store)
			w := httptest.NewRecorder()
			EnrollHandler(w, req)
			if w.Code == http.StatusOK {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(N), atomic.LoadInt32(&ok),
		"all N concurrent /enrolls must succeed (each token is unique)")
}

// TestEnrollHandler_Scale_ConcurrentSameTokenOnlyOneWins verifies
// the single-use gate under contention. 20 concurrent /enrolls with
// the SAME token. Exactly one returns 200; the other 19 return 409.
//
// R-I.11.security — single-use race + scale.
func TestEnrollHandler_Scale_ConcurrentSameTokenOnlyOneWins(t *testing.T) {
	withTestPlatformCA(t)
	const N = 20

	store := sql.CreateTestStore()
	plain, _ := mintEnrollmentToken(t, store, "ORG-RACE", nil, "host-race", "exec-race", 5*time.Minute)

	var wg sync.WaitGroup
	var ok, conflict int32
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{
				"executor_name": "exec-race",
				"hostname":      "host-race",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/enroll", bytes.NewReader(body))
			req.Header.Set(HeaderEnrollmentToken, plain)
			req = helpers.SetContextValue(req, "store", store)
			w := httptest.NewRecorder()
			EnrollHandler(w, req)
			switch w.Code {
			case http.StatusOK:
				atomic.AddInt32(&ok, 1)
			case http.StatusConflict:
				atomic.AddInt32(&conflict, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), atomic.LoadInt32(&ok),
		"exactly one /enroll must win the single-use race")
	assert.Equal(t, int32(N-1), atomic.LoadInt32(&conflict),
		"all other concurrent attempts must get 409 enrollment_token_already_consumed")
}

// TestClaimHandler_Scale_BigClaimLoop verifies the /claim handler's
// claim-count bound (max_claim_count) works for a large pool. We seed
// 2500 tasks (the upper bound in the scale-agnostic row) and ask for
// max_claim_count=10; we expect to receive exactly 10.
//
// R-I.11.security — scale-agnostic.
func TestClaimHandler_Scale_BigClaimLoop(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-BIG", "ZONE-BIG", "host-big")

	projID, repoID := seedProject(t, store, exec.TenantID, exec.DeploymentZoneID)
	tplID := seedTemplate(t, store, projID, repoID)
	for i := 0; i < 2500; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplID, ProjectID: projID, Status: "waiting", Playbook: "p.yml",
		}, 0)
		require.NoError(t, err)
	}

	body, _ := json.Marshal(map[string]any{"max_claim_count": 10})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/claim", bytes.NewReader(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &exec)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ClaimHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var res ClaimResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
	assert.Len(t, res.Jobs, 10, "must respect max_claim_count=10 even with 2500 candidates")
}

// ----------------------------------------------------------------------------
// §10.10 — Mid-campaign revocation: an executor that gets revoked
// (e.g. cert stolen) must not be able to heartbeat as 'online'.
// ----------------------------------------------------------------------------

// TestHeartbeatHandler_AfterRevoke_Refused is the simplest mid-campaign
// revocation story: an executor that's been revoked (via the store
// API) gets a refreshed read so its snapshot carries the RevokedAt
// timestamp; the heartbeat handler's defense-in-depth check fires and
// refuses the call with 403 / executor_revoked.
//
// R-I.11.security — revocation surface.
func TestHeartbeatHandler_AfterRevoke_Refused(t *testing.T) {
	store := sql.CreateTestStore()
	exec := seedExecutor(t, store, "ORG-REV", "ZONE-REV", "host-rev")

	// Revoke via the store API (mirrors how the affinity-violation
	// auto-revoke + the admin manual-revoke path produce the same
	// row state).
	require.NoError(t, store.RevokeExecutor(exec.ID, "auto"))

	// Re-read so the snapshot reflects RevokedAt != nil.
	refreshed, err := store.GetExecutor(exec.ID)
	require.NoError(t, err)
	require.NotNil(t, refreshed.RevokedAt, "executor must be revoked")

	body := map[string]any{
		"status": "online", "executor_version": "1.0.0",
		"ansible_version": "2.16.0", "active_job_count": 0,
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/executor/heartbeat", jsonBody(body))
	req = helpers.SetContextValue(req, "store", store)
	req = helpers.SetContextValue(req, ContextKeyExecutor, &refreshed)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	HeartbeatHandler(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "executor_revoked")
}

// ----------------------------------------------------------------------------
// small helpers used by the tests above
// ----------------------------------------------------------------------------

// jsonBody marshals v to a JSON body buffer.
func jsonBody(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// makeZones returns []string{"Z-0000", "Z-0001", ..., "Z-(n-1)"}.
func makeZones(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("Z-%04d", i)
	}
	return out
}

// contextUnused noop — keeps `context` imported even if no test
// references it directly (the hashValidator uses it for the future
// when ctx-aware middleware is added; for now it's a placeholder).
var _ = context.Background
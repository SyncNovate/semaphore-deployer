package sql

import (
	"errors"
	"sort"
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecutor_Claim_AtomicClaim verifies the compare-and-set claim
// behaviour (design doc §5.1; R-I.1.d). Two CAS updates for the same
// task id from different executor ids: exactly one wins, the other
// sees ErrAlreadyClaimed. Existing tasks not in the eligible status
// (running / success / failed) are NOT in the claimable list.
//
// SentraOps fork (R-I.1.e; design doc §8 TestExecutor_Claim_AtomicClaim).
func TestExecutor_Claim_AtomicClaim(t *testing.T) {
	store := CreateTestStore()
	projectID, repositoryID := newTemplateTestProject(t, store)

	tpl, err := store.CreateTemplate(db.Template{
		ProjectID:    projectID,
		RepositoryID: repositoryID,
		Name:         "tpl-claim",
		Playbook:     "site.yml",
	})
	require.NoError(t, err)

	task, err := store.CreateTask(db.Task{
		TemplateID: tpl.ID,
		ProjectID:  projectID,
		Status:     "waiting",
		Playbook:   "site.yml",
	}, 0)
	require.NoError(t, err)

	// Bind two executors to the same tenant+zone (allowed by the
	// unique index since their hostnames differ).
	execA := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-a")
	execB := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-b")

	// CAS — A wins.
	wonA, err := store.ClaimTask(task.ID, execA.ExecutorID)
	require.NoError(t, err)
	assert.True(t, wonA, "first claim must succeed")

	// CAS — B sees ErrAlreadyClaimed.
	wonB, err := store.ClaimTask(task.ID, execB.ExecutorID)
	if assert.Error(t, err) {
		assert.True(t, errors.Is(err, db.ErrAlreadyClaimed),
			"second concurrent claim must surface ErrAlreadyClaimed, got %v", err)
	}
	assert.False(t, wonB, "second claim must lose the race")

	// Confirm the row carries A's id + a stamped timestamp.
	var claimedBy string
	row := store.Sql().QueryRow("select claimed_by from task where id=?", task.ID)
	require.NoError(t, row.Scan(&claimedBy))
	assert.Equal(t, execA.ExecutorID, claimedBy)
}

// TestExecutor_Claim_NonExistentTask_NotFound verifies the CAS
// distinguish ErrAlreadyClaimed (task exists + claimed) from
// ErrNotFound (no such task). The driver behavior must not collapse
// the two — existence-probe prevention for the executor path.
// R-I.1.e.
func TestExecutor_Claim_NonExistentTask_NotFound(t *testing.T) {
	store := CreateTestStore()
	exec := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-a")

	won, err := store.ClaimTask(999_999, exec.ExecutorID)
	assert.False(t, won)
	require.Error(t, err)
	assert.True(t, errors.Is(err, db.ErrNotFound),
		"non-existent task must surface ErrNotFound (not ErrAlreadyClaimed), got %v", err)
}

// TestExecutor_GetClaimableTasks_OnlyMatchingTasks verifies the task
// list filters by both tenant AND zone. Tasks on a different tenant
// or a different zone must NOT appear in the result.
//
// R-I.1.e (design doc §8 TestExecutor_Claim_OnlyMatchingTasks_Returned).
func TestExecutor_GetClaimableTasks_OnlyMatchingTasks(t *testing.T) {
	store := CreateTestStore()

	// Two projects on the SAME tenant but DIFFERENT zones.
	pA, err := store.CreateProject(db.Project{
		Name: "project-a", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)
	pB, err := store.CreateProject(db.Project{
		Name: "project-b", TenantID: "ORG-1", DeploymentZoneID: "ZONE-B",
	})
	require.NoError(t, err)
	pC, err := store.CreateProject(db.Project{
		Name: "project-c", TenantID: "ORG-2", DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	// Create one task per project (foreign-key scaffolding: each needs
	// a repository + template).
	require.NoError(t, err)
	keyA, err := store.CreateAccessKey(db.AccessKey{ProjectID: &pA.ID, Type: db.AccessKeyNone})
	require.NoError(t, err)
	keyB, err := store.CreateAccessKey(db.AccessKey{ProjectID: &pB.ID, Type: db.AccessKeyNone})
	require.NoError(t, err)
	keyC, err := store.CreateAccessKey(db.AccessKey{ProjectID: &pC.ID, Type: db.AccessKeyNone})
	require.NoError(t, err)

	repoA, err := store.CreateRepository(db.Repository{ProjectID: pA.ID, Name: "r", GitURL: "https://example.com/r.git", GitBranch: "main", SSHKeyID: keyA.ID})
	require.NoError(t, err)
	repoB, err := store.CreateRepository(db.Repository{ProjectID: pB.ID, Name: "r", GitURL: "https://example.com/r.git", GitBranch: "main", SSHKeyID: keyB.ID})
	require.NoError(t, err)
	repoC, err := store.CreateRepository(db.Repository{ProjectID: pC.ID, Name: "r", GitURL: "https://example.com/r.git", GitBranch: "main", SSHKeyID: keyC.ID})
	require.NoError(t, err)

	tplA, err := store.CreateTemplate(db.Template{ProjectID: pA.ID, RepositoryID: repoA.ID, Name: "t", Playbook: "p.yml"})
	require.NoError(t, err)
	tplB, err := store.CreateTemplate(db.Template{ProjectID: pB.ID, RepositoryID: repoB.ID, Name: "t", Playbook: "p.yml"})
	require.NoError(t, err)
	tplC, err := store.CreateTemplate(db.Template{ProjectID: pC.ID, RepositoryID: repoC.ID, Name: "t", Playbook: "p.yml"})
	require.NoError(t, err)

	taskA, err := store.CreateTask(db.Task{TemplateID: tplA.ID, ProjectID: pA.ID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)
	taskB, err := store.CreateTask(db.Task{TemplateID: tplB.ID, ProjectID: pB.ID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)
	taskC, err := store.CreateTask(db.Task{TemplateID: tplC.ID, ProjectID: pC.ID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)

	// Query the eligible set for (ORG-1, ZONE-A). Only taskA must appear.
	got, err := store.GetClaimableTasksForTenantAndZone("ORG-1", "ZONE-A", 10, []string{"linux"})
	require.NoError(t, err)
	require.Len(t, got, 1, "exactly one claimable task expected")
	assert.Equal(t, taskA.ID, got[0].ID)

	// Sanity: ORG-2/ZONE-A sees taskC; ORG-1/ZONE-B sees taskB.
	gotC, err := store.GetClaimableTasksForTenantAndZone("ORG-2", "ZONE-A", 10, []string{"linux"})
	require.NoError(t, err)
	require.Len(t, gotC, 1)
	assert.Equal(t, taskC.ID, gotC[0].ID)

	gotB, err := store.GetClaimableTasksForTenantAndZone("ORG-1", "ZONE-B", 10, []string{"linux"})
	require.NoError(t, err)
	require.Len(t, gotB, 1)
	assert.Equal(t, taskB.ID, gotB[0].ID)
}

// TestExecutor_GetClaimableTasks_ExcludesClaimed verifies the partial
// index on (claimed_by IS NULL) is honoured: a task that's already
// claimed does not appear in subsequent listings for the same
// (tenant, zone). R-I.1.e.
func TestExecutor_GetClaimableTasks_ExcludesClaimed(t *testing.T) {
	store := CreateTestStore()
	p, err := store.CreateProject(db.Project{
		Name: "proj-claimed", TenantID: "ORG-X", DeploymentZoneID: "ZONE-X",
	})
	require.NoError(t, err)
	keyRow, err := store.CreateAccessKey(db.AccessKey{ProjectID: &p.ID, Type: db.AccessKeyNone})
	require.NoError(t, err)
	repoRow, err := store.CreateRepository(db.Repository{
		ProjectID: p.ID, Name: "r", GitURL: "https://example.com/r.git", GitBranch: "main", SSHKeyID: keyRow.ID,
	})
	require.NoError(t, err)
	tplRow, err := store.CreateTemplate(db.Template{ProjectID: p.ID, RepositoryID: repoRow.ID, Name: "t", Playbook: "p.yml"})
	require.NoError(t, err)
	task, err := store.CreateTask(db.Task{TemplateID: tplRow.ID, ProjectID: p.ID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)

	exec := mustCreateExecutor(t, store, "ORG-X", "ZONE-X", "host-x")

	got, err := store.GetClaimableTasksForTenantAndZone("ORG-X", "ZONE-X", 10, []string{"linux"})
	require.NoError(t, err)
	require.Len(t, got, 1, "before claim: list contains the task")

	won, err := store.ClaimTask(task.ID, exec.ExecutorID)
	require.NoError(t, err)
	require.True(t, won)

	got, err = store.GetClaimableTasksForTenantAndZone("ORG-X", "ZONE-X", 10, []string{"linux"})
	require.NoError(t, err)
	assert.Empty(t, got, "after claim: list must be empty (claimed row excluded)")
}

// TestExecutor_HeartbeatExecutor_UpdatesLastSeen verifies the bulk
// UPDATE path used by /api/v1/executor/heartbeat. Stamps status,
// last_heartbeat_at, executor_version, ansible_version in one
// statement.
//
// R-I.1.e (design doc §8 TestExecutor_Heartbeat_UpdatesLastSeen).
func TestExecutor_HeartbeatExecutor_UpdatesLastSeen(t *testing.T) {
	store := CreateTestStore()

	execIn, err := newTestExecutor("ORG-1", "ZONE-A", "host-hb")
	require.NoError(t, err)
	created, err := store.CreateExecutor(execIn)
	require.NoError(t, err)
	require.Nil(t, created.LastHeartbeatAt, "fresh registration has no heartbeat yet")

	updated, err := store.HeartbeatExecutor(
		created.ExecutorID,
		db.ExecutorStatusOnline,
		"1.2.3",
		"2.16.0",
		3,
	)
	require.NoError(t, err)
	require.NotNil(t, updated.LastHeartbeatAt)
	assert.Equal(t, "online", updated.Status)
	assert.Equal(t, "1.2.3", updated.ExecutorVersion)

	// Idempotent second call.
	again, err := store.HeartbeatExecutor(
		created.ExecutorID,
		db.ExecutorStatusDegraded,
		"1.2.4",
		"2.16.0",
		0,
	)
	require.NoError(t, err)
	assert.Equal(t, "degraded", again.Status)
	assert.Equal(t, "1.2.4", again.ExecutorVersion)
	require.NotNil(t, again.LastHeartbeatAt)
}

// TestExecutor_HeartbeatExecutor_Revoked_ReturnsErrExecutorRevoked
// confirms the heartbeat path refuses to update a revoked executor
// (the caller must surface 403 + suggest self-decommission).
//
// R-I.1.e (related to TestExecutor_Revoked_Claim_Rejected in handler-
// level tests).
func TestExecutor_HeartbeatExecutor_Revoked_ReturnsErrExecutorRevoked(t *testing.T) {
	store := CreateTestStore()
	created := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-rev")
	require.NoError(t, store.RevokeExecutor(created.ID, "manual"))

	_, err := store.HeartbeatExecutor(created.ExecutorID, db.ExecutorStatusOnline, "1.0.0", "2.16.0", 0)
	require.Error(t, err)
	assert.True(t, errors.Is(err, db.ErrExecutorRevoked))
}

// TestExecutor_GetExecutorByTokenHash_NotStored returns ErrNotFound
// for an empty hash AND for a token that doesn't match any row.
// Existence-probe prevention.
//
// R-I.1.e.
func TestExecutor_GetExecutorByTokenHash_NotStored(t *testing.T) {
	store := CreateTestStore()

	_, err := store.GetExecutorByTokenHash("")
	require.Error(t, err)
	assert.True(t, errors.Is(err, db.ErrNotFound),
		"empty hash must surface ErrNotFound (not leak row existence)")

	_, err = store.GetExecutorByTokenHash("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
	require.Error(t, err)
	assert.True(t, errors.Is(err, db.ErrNotFound))
}

// TestExecutor_GetExecutorByTokenHash_Match exercises the
// authentication path's happy case: insert a hash, look it up.
//
// R-I.1.e.
func TestExecutor_GetExecutorByTokenHash_Match(t *testing.T) {
	store := CreateTestStore()
	exec := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-hash")

	const hashHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	_, err := store.Sql().Exec(
		"update executor set auth_token_hash=? where id=?", hashHex, exec.ID)
	require.NoError(t, err)

	got, err := store.GetExecutorByTokenHash(hashHex)
	require.NoError(t, err)
	assert.Equal(t, exec.ExecutorID, got.ExecutorID)
}

// TestExecutor_RecordExecutorTaskResult_NotClaimHolder returns
// ErrInvalidOperation when a different executor tries to record a
// result for a task it does not claim. Poisoned-executor defence.
//
// R-I.1.e.
func TestExecutor_RecordExecutorTaskResult_NotClaimHolder(t *testing.T) {
	store := CreateTestStore()
	projectID, repositoryID := newTemplateTestProject(t, store)
	tpl, err := store.CreateTemplate(db.Template{ProjectID: projectID, RepositoryID: repositoryID, Name: "t", Playbook: "p.yml"})
	require.NoError(t, err)
	task, err := store.CreateTask(db.Task{TemplateID: tpl.ID, ProjectID: projectID, Status: "waiting", Playbook: "p.yml"}, 0)
	require.NoError(t, err)

	claimHolder := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-holder")
	other := mustCreateExecutor(t, store, "ORG-1", "ZONE-A", "host-other")

	won, err := store.ClaimTask(task.ID, claimHolder.ExecutorID)
	require.NoError(t, err)
	require.True(t, won)

	// The other executor tries to overwrite the result: rejected.
	err = store.RecordExecutorTaskResult(task.ID, other.ExecutorID, "success", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, db.ErrInvalidOperation),
		"non-claim-holder result must surface ErrInvalidOperation, got %v", err)

	// The claim holder is the only writer that succeeds.
	err = store.RecordExecutorTaskResult(task.ID, claimHolder.ExecutorID, "success", "")
	require.NoError(t, err)

	// Confirm the row carries the recorded outcome + error class.
	var storedOutcome, storedErrClass *string
	row := store.Sql().QueryRow("select result_outcome, result_error_class from task where id=?", task.ID)
	require.NoError(t, row.Scan(&storedOutcome, &storedErrClass))
	require.NotNil(t, storedOutcome)
	assert.Equal(t, "success", *storedOutcome)
}

// TestExecutor_GetClaimableTasks_HonoursMaxCount caps the listing at
// maxCount. R-I.1.e (sanity for the SQL LIMIT).
func TestExecutor_GetClaimableTasks_HonoursMaxCount(t *testing.T) {
	store := CreateTestStore()
	p, err := store.CreateProject(db.Project{Name: "proj-cap", TenantID: "ORG-C", DeploymentZoneID: "ZONE-C"})
	require.NoError(t, err)
	keyRow, err := store.CreateAccessKey(db.AccessKey{ProjectID: &p.ID, Type: db.AccessKeyNone})
	require.NoError(t, err)
	repoRow, err := store.CreateRepository(db.Repository{ProjectID: p.ID, Name: "r", GitURL: "https://example.com/r.git", GitBranch: "main", SSHKeyID: keyRow.ID})
	require.NoError(t, err)
	tplRow, err := store.CreateTemplate(db.Template{ProjectID: p.ID, RepositoryID: repoRow.ID, Name: "t", Playbook: "p.yml"})
	require.NoError(t, err)

	const created = 5
	for i := 0; i < created; i++ {
		_, err := store.CreateTask(db.Task{
			TemplateID: tplRow.ID,
			ProjectID:  p.ID,
			Status:     "waiting",
			Playbook:   "p.yml",
		}, 0)
		require.NoError(t, err)
	}

	got, err := store.GetClaimableTasksForTenantAndZone("ORG-C", "ZONE-C", 3, []string{"linux"})
	require.NoError(t, err)
	assert.Len(t, got, 3, "maxCount must cap the listing at 3 rows")

	// Without a cap (zero / negative) the storage clamps to a sane
	// default rather than returning everything.
	got, err = store.GetClaimableTasksForTenantAndZone("ORG-C", "ZONE-C", 0, []string{"linux"})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(got), 100, "default cap must keep the list bounded")

	// Stable order: tasks come back ASC by id.
	got2, err := store.GetClaimableTasksForTenantAndZone("ORG-C", "ZONE-C", 100, []string{"linux"})
	require.NoError(t, err)
	if len(got2) > 1 {
		ids := make([]int, len(got2))
		for i, t := range got2 {
			ids[i] = t.ID
		}
		assert.True(t, sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] < ids[j] }),
			"claimable task list must be ASC by id (FIFO fairness)")
	}
}

// mustCreateExecutor is a small helper that builds + persists an
// executor. Centralised here so the claim-test table reads cleanly.
func mustCreateExecutor(t *testing.T, store db.Store, tenantID, zoneID, hostname string) db.Executor {
	t.Helper()
	in, err := newTestExecutor(tenantID, zoneID, hostname)
	require.NoError(t, err)
	out, err := store.CreateExecutor(in)
	require.NoError(t, err)
	return out
}

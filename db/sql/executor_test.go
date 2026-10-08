package sql

import (
	"testing"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestExecutor builds a fully-populated Executor for the given tenant /
// zone / hostname. The caller can override fields after.
func newTestExecutor(tenantID, zoneID, hostname string) (db.Executor, error) {
	id, err := db.NewExecutorID()
	if err != nil {
		return db.Executor{}, err
	}
	e := db.Executor{
		ExecutorID:       id,
		Name:             "test-" + hostname,
		TenantID:         tenantID,
		DeploymentZoneID: zoneID,
		ExecutorVersion:  "1.0.0",
		AnsibleVersion:   "2.16.0",
		Hostname:         hostname,
		Status:           db.ExecutorStatusOnline,
	}
	if err := e.SetPlatforms([]string{"windows", "linux"}); err != nil {
		return db.Executor{}, err
	}
	return e, nil
}

func TestExecutor_CreateGet_RoundTrip(t *testing.T) {
	store := CreateTestStore()

	in, err := newTestExecutor("ORG-1", "ZONE-A", "host-a")
	require.NoError(t, err)

	out, err := store.CreateExecutor(in)
	require.NoError(t, err)
	assert.NotZero(t, out.ID)
	assert.Equal(t, in.ExecutorID, out.ExecutorID)
	assert.Equal(t, in.PlatformsSupportedJSON, out.PlatformsSupportedJSON)
	assert.Equal(t, []string{"windows", "linux"}, out.Platforms())

	// Get by surrogate id.
	got, err := store.GetExecutor(out.ID)
	require.NoError(t, err)
	assert.Equal(t, in.ExecutorID, got.ExecutorID)
	assert.Equal(t, "ORG-1", got.TenantID)
	assert.Equal(t, "ZONE-A", got.DeploymentZoneID)
	assert.Equal(t, db.ExecutorStatusOnline, got.Status)
	assert.False(t, got.IsRevoked())

	// Get by public id.
	got2, err := store.GetExecutorByExecutorID(in.ExecutorID)
	require.NoError(t, err)
	assert.Equal(t, out.ID, got2.ID)
}

func TestExecutor_Create_DuplicateHostname_Rejected(t *testing.T) {
	store := CreateTestStore()

	first, err := newTestExecutor("ORG-1", "ZONE-A", "host-a")
	require.NoError(t, err)
	_, err = store.CreateExecutor(first)
	require.NoError(t, err)

	// Same tenant + zone + hostname but a different executor_id. The
	// unique index on (tenant_id, deployment_zone_id, hostname) must
	// reject this.
	second, err := newTestExecutor("ORG-1", "ZONE-A", "host-a")
	require.NoError(t, err)
	_, err = store.CreateExecutor(second)
	assert.ErrorIs(t, err, db.ErrAlreadyExists)
}

func TestExecutor_Create_DuplicateExecutorID_Rejected(t *testing.T) {
	store := CreateTestStore()

	first, err := newTestExecutor("ORG-1", "ZONE-A", "host-a")
	require.NoError(t, err)
	_, err = store.CreateExecutor(first)
	require.NoError(t, err)

	// Same executor_id but a different (tenant, zone, hostname). The
	// unique index on executor_id must reject this.
	second, err := newTestExecutor("ORG-2", "ZONE-B", "host-b")
	require.NoError(t, err)
	second.ExecutorID = first.ExecutorID
	_, err = store.CreateExecutor(second)
	assert.ErrorIs(t, err, db.ErrAlreadyExists)
}

func TestExecutor_Create_SameHostnameDifferentTenant_Allowed(t *testing.T) {
	// The unique index is on (tenant, zone, hostname), not just hostname.
	// Two different tenants can register the same hostname.
	store := CreateTestStore()

	a, err := newTestExecutor("ORG-1", "ZONE-A", "shared-host")
	require.NoError(t, err)
	_, err = store.CreateExecutor(a)
	require.NoError(t, err)

	b, err := newTestExecutor("ORG-2", "ZONE-A", "shared-host")
	require.NoError(t, err)
	_, err = store.CreateExecutor(b)
	require.NoError(t, err)

	gotA, err := store.GetExecutorsByTenant("ORG-1", nil)
	require.NoError(t, err)
	require.Len(t, gotA, 1)
	assert.Equal(t, a.ExecutorID, gotA[0].ExecutorID)

	gotB, err := store.GetExecutorsByTenant("ORG-2", nil)
	require.NoError(t, err)
	require.Len(t, gotB, 1)
	assert.Equal(t, b.ExecutorID, gotB[0].ExecutorID)
}

func TestExecutor_GetByExecutorID_NotFound(t *testing.T) {
	store := CreateTestStore()

	_, err := store.GetExecutorByExecutorID("EXEC-01HZX2N3K9ABCDEF0456")
	assert.ErrorIs(t, err, db.ErrNotFound)
}

func TestExecutor_GetByTenant_All(t *testing.T) {
	store := CreateTestStore()

	a, err := newTestExecutor("ORG-1", "ZONE-A", "host-a")
	require.NoError(t, err)
	_, err = store.CreateExecutor(a)
	require.NoError(t, err)

	b, err := newTestExecutor("ORG-1", "ZONE-B", "host-b")
	require.NoError(t, err)
	_, err = store.CreateExecutor(b)
	require.NoError(t, err)

	other, err := newTestExecutor("ORG-2", "ZONE-A", "host-x")
	require.NoError(t, err)
	_, err = store.CreateExecutor(other)
	require.NoError(t, err)

	got, err := store.GetExecutorsByTenant("ORG-1", nil)
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestExecutor_GetByTenant_ZoneFilter(t *testing.T) {
	store := CreateTestStore()

	a, err := newTestExecutor("ORG-1", "ZONE-A", "host-a")
	require.NoError(t, err)
	_, err = store.CreateExecutor(a)
	require.NoError(t, err)

	b, err := newTestExecutor("ORG-1", "ZONE-B", "host-b")
	require.NoError(t, err)
	_, err = store.CreateExecutor(b)
	require.NoError(t, err)

	zoneB := "ZONE-B"
	got, err := store.GetExecutorsByTenant("ORG-1", &zoneB)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, b.ExecutorID, got[0].ExecutorID)
}

func TestExecutor_GetClaimable_FilterByStatus(t *testing.T) {
	store := CreateTestStore()

	online, err := newTestExecutor("ORG-1", "ZONE-A", "host-online")
	require.NoError(t, err)
	_, err = store.CreateExecutor(online)
	require.NoError(t, err)

	offline, err := newTestExecutor("ORG-1", "ZONE-A", "host-offline")
	require.NoError(t, err)
	offline.Status = db.ExecutorStatusOffline
	_, err = store.CreateExecutor(offline)
	require.NoError(t, err)

	got, err := store.GetClaimableExecutors("ORG-1", "ZONE-A", []string{"linux"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, online.ExecutorID, got[0].ExecutorID)
}

func TestExecutor_GetClaimable_FilterByPlatforms(t *testing.T) {
	store := CreateTestStore()

	win, err := newTestExecutor("ORG-1", "ZONE-A", "host-win")
	require.NoError(t, err)
	require.NoError(t, win.SetPlatforms([]string{"windows"}))
	_, err = store.CreateExecutor(win)
	require.NoError(t, err)

	lin, err := newTestExecutor("ORG-1", "ZONE-A", "host-lin")
	require.NoError(t, err)
	require.NoError(t, lin.SetPlatforms([]string{"linux"}))
	_, err = store.CreateExecutor(lin)
	require.NoError(t, err)

	// A linux request should match only the linux executor.
	got, err := store.GetClaimableExecutors("ORG-1", "ZONE-A", []string{"linux"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, lin.ExecutorID, got[0].ExecutorID)

	// A windows request should match only the windows executor.
	got, err = store.GetClaimableExecutors("ORG-1", "ZONE-A", []string{"windows"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, win.ExecutorID, got[0].ExecutorID)

	// A "linux or windows" request should match both.
	got, err = store.GetClaimableExecutors("ORG-1", "ZONE-A", []string{"linux", "windows"})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// A darwin request should match neither.
	got, err = store.GetClaimableExecutors("ORG-1", "ZONE-A", []string{"darwin"})
	require.NoError(t, err)
	assert.Len(t, got, 0)
}

func TestExecutor_GetClaimable_ExcludesRevoked(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-revoked")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)
	require.NoError(t, store.RevokeExecutor(out.ID, "test"))

	got, err := store.GetClaimableExecutors("ORG-1", "ZONE-A", []string{"linux"})
	require.NoError(t, err)
	assert.Len(t, got, 0)
}

func TestExecutor_Update(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-update")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	out.Name = "renamed"
	require.NoError(t, out.SetPlatforms([]string{"darwin"}))
	out.ExecutorVersion = "1.2.3"
	out.Status = db.ExecutorStatusDegraded
	now := time.Now().UTC()
	out.LastHeartbeatAt = &now

	require.NoError(t, store.UpdateExecutor(out))

	got, err := store.GetExecutor(out.ID)
	require.NoError(t, err)
	assert.Equal(t, "renamed", got.Name)
	assert.Equal(t, "1.2.3", got.ExecutorVersion)
	assert.Equal(t, db.ExecutorStatusDegraded, got.Status)
	assert.Equal(t, []string{"darwin"}, got.Platforms())
	require.NotNil(t, got.LastHeartbeatAt)
	assert.WithinDuration(t, now, *got.LastHeartbeatAt, time.Second)
}

func TestExecutor_Delete(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-delete")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	require.NoError(t, store.DeleteExecutor(out.ID))

	_, err = store.GetExecutor(out.ID)
	assert.ErrorIs(t, err, db.ErrNotFound)
}

func TestExecutor_Revoke(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-revoke")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	require.NoError(t, store.RevokeExecutor(out.ID, "operator action"))

	got, err := store.GetExecutor(out.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)
	assert.Equal(t, "operator action", got.RevokeReason)
	assert.Equal(t, db.ExecutorStatusOffline, got.Status)
	assert.True(t, got.IsRevoked())
}

func TestExecutor_IncrementAffinityViolation_NotFound(t *testing.T) {
	store := CreateTestStore()

	_, err := store.IncrementAffinityViolation(99999)
	assert.ErrorIs(t, err, db.ErrNotFound)
}

func TestExecutor_IncrementAffinityViolation_FirstTime(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-aff")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	count, err := store.IncrementAffinityViolation(out.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	got, err := store.GetExecutor(out.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.AffinityViolationCount)
	assert.False(t, got.IsRevoked())
	assert.NotNil(t, got.AffinityViolationWindowStart)
}

func TestExecutor_IncrementAffinityViolation_AutoRevoke(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-auto-revoke")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	// Bump to (Threshold - 1). The next increment should trigger revoke.
	for i := 0; i < db.AffinityViolationThreshold-1; i++ {
		_, err = store.IncrementAffinityViolation(out.ID)
		require.NoError(t, err)
	}

	got, err := store.GetExecutor(out.ID)
	require.NoError(t, err)
	assert.False(t, got.IsRevoked(), "executor should not be revoked before threshold")

	// The threshold-crossing increment fires the auto-revoke.
	count, err := store.IncrementAffinityViolation(out.ID)
	require.NoError(t, err)
	assert.Equal(t, db.AffinityViolationThreshold, count)

	got, err = store.GetExecutor(out.ID)
	require.NoError(t, err)
	assert.True(t, got.IsRevoked(), "executor must be revoked at threshold")
	assert.Contains(t, got.RevokeReason, "auto-revoked")
	assert.Equal(t, db.ExecutorStatusOffline, got.Status)
}

func TestExecutor_IncrementAffinityViolation_OnRevoked_Noop(t *testing.T) {
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-revoked-aff")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	// Pre-revoke via operator action.
	require.NoError(t, store.RevokeExecutor(out.ID, "manual"))

	// An increment on an already-revoked executor should NOT change
	// the count (the rule already fired / the operator already acted).
	count, err := store.IncrementAffinityViolation(out.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "revoked executor's counter must not change on a no-op increment")
}

func TestExecutor_IncrementAffinityViolation_WindowReset(t *testing.T) {
	// We can't time-travel SQLite's wall clock from the test, so we
	// exercise the window-reset path by directly setting the executor's
	// window start to a moment well outside the 10-minute window, then
	// incrementing and asserting the counter resets to 1.
	store := CreateTestStore()

	e, err := newTestExecutor("ORG-1", "ZONE-A", "host-window")
	require.NoError(t, err)
	out, err := store.CreateExecutor(e)
	require.NoError(t, err)

	// Bump once to create a non-null window.
	_, err = store.IncrementAffinityViolation(out.ID)
	require.NoError(t, err)

	// Read the current window, then push the row 1 hour into the past
	// via raw SQL (UpdateExecutor does not write the affinity columns —
	// those are owned by IncrementAffinityViolation).
	got, err := store.GetExecutor(out.ID)
	require.NoError(t, err)
	oldWindow := got.AffinityViolationWindowStart
	require.NotNil(t, oldWindow)
	expired := oldWindow.Add(-1 * time.Hour)
	_, err = store.Sql().Exec(
		"update executor set affinity_violation_count=?, affinity_violation_window_start=? where id=?",
		4, expired, out.ID)
	require.NoError(t, err)

	// Increment. Window must reset, counter starts at 1.
	count, err := store.IncrementAffinityViolation(out.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "window reset must zero the counter")

	got, err = store.GetExecutor(out.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.AffinityViolationCount)
	require.NotNil(t, got.AffinityViolationWindowStart)
	assert.True(t, got.AffinityViolationWindowStart.After(*oldWindow),
		"window start should be moved to now")
}

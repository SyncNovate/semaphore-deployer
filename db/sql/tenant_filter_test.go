package sql

import (
	"testing"

	"github.com/semaphoreui/semaphore/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetProjectForTenant_TenantMatch verifies the happy path: a
// project in the requested tenant is returned. SentraOps fork
// (R-I.1.c) — design doc §4.2 storage-layer filter.
func TestGetProjectForTenant_TenantMatch(t *testing.T) {
	store := CreateTestStore()
	proj, err := store.CreateProject(db.Project{
		Name:             "p",
		TenantID:         "ORG-1",
		DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	got, err := store.GetProjectForTenant(proj.ID, "ORG-1")
	require.NoError(t, err)
	assert.Equal(t, proj.ID, got.ID)
	assert.Equal(t, "ORG-1", got.TenantID)
}

// TestGetProjectForTenant_TenantMismatch_404 verifies the cross-tenant
// read path: a foreign-tenant project must return ErrNotFound, NOT a
// 403 (per design doc decision 4: 404 not 403 to avoid existence
// leak). This is the security boundary.
func TestGetProjectForTenant_TenantMismatch_404(t *testing.T) {
	store := CreateTestStore()
	proj, err := store.CreateProject(db.Project{
		Name:             "p",
		TenantID:         "ORG-1",
		DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	_, err = store.GetProjectForTenant(proj.ID, "ORG-2")
	assert.ErrorIs(t, err, db.ErrNotFound)
}

// TestGetProjectForTenant_NotFound verifies the non-existent path
// also returns ErrNotFound (so a probe cannot distinguish "exists
// but in another tenant" from "does not exist").
func TestGetProjectForTenant_NotFound(t *testing.T) {
	store := CreateTestStore()

	_, err := store.GetProjectForTenant(99999, "ORG-1")
	assert.ErrorIs(t, err, db.ErrNotFound)
}

// TestGetProjectsForTenant verifies the list filter: projects in the
// tenant are returned; projects in other tenants are not.
func TestGetProjectsForTenant(t *testing.T) {
	store := CreateTestStore()

	a, err := store.CreateProject(db.Project{Name: "a", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A"})
	require.NoError(t, err)
	b, err := store.CreateProject(db.Project{Name: "b", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A"})
	require.NoError(t, err)
	_, err = store.CreateProject(db.Project{Name: "c", TenantID: "ORG-2", DeploymentZoneID: "ZONE-A"})
	require.NoError(t, err)

	got, err := store.GetProjectsForTenant("ORG-1")
	require.NoError(t, err)
	require.Len(t, got, 2)
	// Returned in name order (a, b).
	assert.Equal(t, a.ID, got[0].ID)
	assert.Equal(t, b.ID, got[1].ID)

	got, err = store.GetProjectsForTenant("ORG-2")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "ORG-2", got[0].TenantID)
}

// TestUpdateProjectForTenant verifies the cross-tenant write path
// returns ErrNotFound and does NOT mutate the row.
func TestUpdateProjectForTenant(t *testing.T) {
	store := CreateTestStore()
	proj, err := store.CreateProject(db.Project{
		Name:             "p",
		TenantID:         "ORG-1",
		DeploymentZoneID: "ZONE-A",
		MaxParallelTasks: 1,
	})
	require.NoError(t, err)

	// Same-tenant update succeeds.
	proj.MaxParallelTasks = 5
	require.NoError(t, store.UpdateProjectForTenant(proj, "ORG-1"))

	got, err := store.GetProject(proj.ID)
	require.NoError(t, err)
	assert.Equal(t, 5, got.MaxParallelTasks)

	// Cross-tenant update is rejected with ErrNotFound; row is unchanged.
	proj.MaxParallelTasks = 99
	err = store.UpdateProjectForTenant(proj, "ORG-2")
	assert.ErrorIs(t, err, db.ErrNotFound)

	got, err = store.GetProject(proj.ID)
	require.NoError(t, err)
	assert.Equal(t, 5, got.MaxParallelTasks, "cross-tenant update must not mutate the row")
}

// TestDeleteProjectForTenant verifies cross-tenant delete is rejected
// with ErrNotFound and the project is not removed.
func TestDeleteProjectForTenant(t *testing.T) {
	store := CreateTestStore()
	proj, err := store.CreateProject(db.Project{
		Name:             "p",
		TenantID:         "ORG-1",
		DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	// Cross-tenant delete is rejected.
	err = store.DeleteProjectForTenant(proj.ID, "ORG-2")
	assert.ErrorIs(t, err, db.ErrNotFound)

	// Project still exists.
	_, err = store.GetProject(proj.ID)
	require.NoError(t, err)

	// Same-tenant delete succeeds.
	require.NoError(t, store.DeleteProjectForTenant(proj.ID, "ORG-1"))
	_, err = store.GetProject(proj.ID)
	assert.ErrorIs(t, err, db.ErrNotFound)
}

// TestGetInventoryForTenant verifies the inventory tenant filter.
func TestGetInventoryForTenant(t *testing.T) {
	store := CreateTestStore()

	proj, err := store.CreateProject(db.Project{
		Name: "p", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	inv1, err := store.CreateInventory(db.Inventory{
		ProjectID: proj.ID, Name: "inv1", Type: db.InventoryStatic,
		TenantID: "ORG-1",
	})
	require.NoError(t, err)

	// Cross-tenant read.
	_, err = store.GetInventoryForTenant(proj.ID, inv1.ID, "ORG-2")
	assert.ErrorIs(t, err, db.ErrNotFound)

	// Same-tenant read.
	got, err := store.GetInventoryForTenant(proj.ID, inv1.ID, "ORG-1")
	require.NoError(t, err)
	assert.Equal(t, inv1.ID, got.ID)
}

// TestGetInventoriesForTenant_ProjectCrossTenant_404 verifies the
// defense-in-depth chain: a cross-tenant read of a project also
// returns ErrNotFound for its inventory list.
func TestGetInventoriesForTenant_ProjectCrossTenant_404(t *testing.T) {
	store := CreateTestStore()

	proj, err := store.CreateProject(db.Project{
		Name: "p", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)
	_, err = store.CreateInventory(db.Inventory{
		ProjectID: proj.ID, Name: "inv1", Type: db.InventoryStatic, TenantID: "ORG-1",
	})
	require.NoError(t, err)

	_, err = store.GetInventoriesForTenant(proj.ID, db.RetrieveQueryParams{}, nil, "ORG-2")
	assert.ErrorIs(t, err, db.ErrNotFound,
		"cross-tenant project read must reject the inventory list call too")
}

// TestGetInventoriesForTenant_FilterRowLevel verifies the per-row
// tenant filter: an inventory whose row tenant_id differs from the
// project tenant_id cannot be returned. This is a corruption guard —
// in normal operation a project's inventory always inherits the
// project's tenant_id, but defense in depth catches a future bug.
func TestGetInventoriesForTenant_FilterRowLevel(t *testing.T) {
	store := CreateTestStore()

	proj, err := store.CreateProject(db.Project{
		Name: "p", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	// Insert an inventory directly with a foreign tenant_id to
	// simulate a future bug. Use raw SQL because the public
	// CreateInventory writes whatever tenant_id we pass. The
	// `inventory` JSON body column is NOT NULL (default SQLite
	// inventory schema), so seed it with "{}"; the row-level
	// tenant filter test only cares about the tenant_id column.
	_, err = store.Sql().Exec(
		"insert into project__inventory (project_id, name, type, inventory, tenant_id) values (?, ?, ?, ?, ?)",
		proj.ID, "rogue", string(db.InventoryStatic), "{}", "ORG-2")
	require.NoError(t, err)

	// The list for ORG-1 must not return the rogue row, even
	// though the project's tenant is ORG-1.
	got, err := store.GetInventoriesForTenant(proj.ID, db.RetrieveQueryParams{}, nil, "ORG-1")
	require.NoError(t, err)
	assert.Len(t, got, 0, "row-level tenant filter must exclude the rogue row")
}

// TestGetAccessKeyForTenant verifies the access key tenant filter.
func TestGetAccessKeyForTenant(t *testing.T) {
	store := CreateTestStore()

	proj, err := store.CreateProject(db.Project{
		Name: "p", TenantID: "ORG-1", DeploymentZoneID: "ZONE-A",
	})
	require.NoError(t, err)

	key, err := store.CreateAccessKey(db.AccessKey{
		ProjectID: &proj.ID, Type: db.AccessKeyNone, Name: "k1", TenantID: "ORG-1",
	})
	require.NoError(t, err)

	_, err = store.GetAccessKeyForTenant(proj.ID, key.ID, "ORG-2")
	assert.ErrorIs(t, err, db.ErrNotFound)

	got, err := store.GetAccessKeyForTenant(proj.ID, key.ID, "ORG-1")
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
}

// TestUpdateAccessKeyForTenant_ProjectIDRequired verifies the
// unbound-key path is rejected: an access key without a ProjectID
// is not project-scoped so the tenant filter cannot apply, and the
// method fails loud instead of falling through to the unscoped path.
func TestUpdateAccessKeyForTenant_ProjectIDRequired(t *testing.T) {
	store := CreateTestStore()

	key := db.AccessKey{
		Type: db.AccessKeyString, Name: "k-unbound", TenantID: "ORG-1",
		// ProjectID intentionally nil.
	}
	err := store.UpdateAccessKeyForTenant(key, "ORG-1")
	assert.ErrorIs(t, err, db.ErrInvalidOperation)
}

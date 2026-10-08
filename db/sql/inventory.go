package sql

import (
	"github.com/Masterminds/squirrel"
	"github.com/semaphoreui/semaphore/db"
)

func (d *SqlDb) GetInventory(projectID int, inventoryID int) (inventory db.Inventory, err error) {
	err = d.getObject(projectID, db.InventoryProps, inventoryID, &inventory)

	return
}

func (d *SqlDb) GetInventories(projectID int, params db.RetrieveQueryParams, types []db.InventoryType) ([]db.Inventory, error) {
	var inventories []db.Inventory
	err := d.getObjects(projectID, db.InventoryProps, params, func(builder squirrel.SelectBuilder) squirrel.SelectBuilder {
		if len(types) == 0 {
			return builder
		}

		return builder.Where(squirrel.Eq{"type": types})
	}, &inventories)
	return inventories, err
}

func (d *SqlDb) GetInventoryRefs(projectID int, inventoryID int) (db.ObjectReferrers, error) {
	return d.getObjectRefs(projectID, db.InventoryProps, inventoryID)
}

func (d *SqlDb) DeleteInventory(projectID int, inventoryID int) error {
	return d.deleteObject(projectID, db.InventoryProps, inventoryID)
}

// GetInventoryForTenant returns the inventory only if its tenant_id
// matches the supplied tenantID. Cross-tenant reads return ErrNotFound
// (not 403) so the operator cannot probe for foreign-tenant resource
// existence — per design doc §4.2 + decision 4.
//
// SentraOps fork (R-I.1.c).
func (d *SqlDb) GetInventoryForTenant(projectID int, inventoryID int, tenantID string) (db.Inventory, error) {
	inv, err := d.GetInventory(projectID, inventoryID)
	if err != nil {
		return db.Inventory{}, err
	}
	if inv.TenantID != tenantID {
		return db.Inventory{}, db.ErrNotFound
	}
	return inv, nil
}

// GetInventoriesForTenant returns the inventories for the project that
// are also in the supplied tenant. Defense in depth: the project's own
// tenant_id is verified first, then a per-row tenant_id filter is
// applied so a cross-tenant row cannot sneak in via a join.
func (d *SqlDb) GetInventoriesForTenant(projectID int, params db.RetrieveQueryParams, types []db.InventoryType, tenantID string) ([]db.Inventory, error) {
	// Verify the project is in the tenant first (404 not 403 on
	// cross-tenant project access).
	if _, err := d.GetProjectForTenant(projectID, tenantID); err != nil {
		return nil, err
	}

	q, err := d.makeObjectsQuery(projectID, db.InventoryProps, params)
	if err != nil {
		return nil, err
	}
	q = q.Where("pe.tenant_id=?", tenantID)

	if len(types) > 0 {
		q = q.Where(squirrel.Eq{"type": types})
	}

	query, args, err := q.ToSql()
	if err != nil {
		return nil, err
	}

	var inventories []db.Inventory
	_, err = d.selectAll(&inventories, query, args...)
	return inventories, err
}

// UpdateInventoryForTenant updates the inventory only if its tenant_id
// matches tenantID. Returns ErrNotFound on cross-tenant write.
func (d *SqlDb) UpdateInventoryForTenant(inventory db.Inventory, tenantID string) error {
	if _, err := d.GetInventoryForTenant(inventory.ProjectID, inventory.ID, tenantID); err != nil {
		return err
	}
	return d.UpdateInventory(inventory)
}

// DeleteInventoryForTenant deletes the inventory only if its tenant_id
// matches tenantID. Returns ErrNotFound on cross-tenant delete.
func (d *SqlDb) DeleteInventoryForTenant(projectID int, inventoryID int, tenantID string) error {
	if _, err := d.GetInventoryForTenant(projectID, inventoryID, tenantID); err != nil {
		return err
	}
	return d.DeleteInventory(projectID, inventoryID)
}

func (d *SqlDb) UpdateInventory(inventory db.Inventory) error {

	_, err := d.exec(
		"update project__inventory set "+
			"name=?, "+
			"type=?, "+
			"runner_tag=?, "+
			"ssh_key_id=?, "+
			"inventory=?, "+
			"become_key_id=?, "+
			"template_id=?, "+
			"repository_id=?, "+
			"tenant_id=? "+
			"where id=?",
		inventory.Name,
		inventory.Type,
		inventory.RunnerTag,
		inventory.SSHKeyID,
		inventory.Inventory,
		inventory.BecomeKeyID,
		inventory.TemplateID,
		inventory.RepositoryID,
		inventory.TenantID,
		inventory.ID)

	return err
}

func (d *SqlDb) CreateInventory(inventory db.Inventory) (newInventory db.Inventory, err error) {
	insertID, err := d.insert(
		"id",
		"insert into project__inventory ("+
			"project_id, name, type, "+
			"ssh_key_id, inventory, become_key_id, "+
			"template_id, repository_id, runner_tag, "+
			"tenant_id) values "+
			"(?, ?, ?, "+
			"?, ?, ?, "+
			"?, ?, ?, "+
			"?)",
		inventory.ProjectID,
		inventory.Name,
		inventory.Type,
		inventory.SSHKeyID,
		inventory.Inventory,
		inventory.BecomeKeyID,
		inventory.TemplateID,
		inventory.RepositoryID,
		inventory.RunnerTag,
		inventory.TenantID,
	)

	if err != nil {
		return
	}

	newInventory = inventory
	newInventory.ID = insertID
	return
}

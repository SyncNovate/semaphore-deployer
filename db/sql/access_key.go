package sql

import (
	"database/sql"

	"github.com/Masterminds/squirrel"
	"github.com/semaphoreui/semaphore/db"
)

func (d *SqlDb) GetAccessKey(projectID int, accessKeyID int) (key db.AccessKey, err error) {
	err = d.getObject(projectID, db.AccessKeyProps, accessKeyID, &key)
	return
}

func (d *SqlDb) GetAccessKeyRefs(projectID int, keyID int) (db.ObjectReferrers, error) {
	return d.getObjectRefs(projectID, db.AccessKeyProps, keyID)
}

func (d *SqlDb) GetAccessKeys(projectID int, options db.GetAccessKeyOptions, params db.RetrieveQueryParams) (keys []db.AccessKey, err error) {
	keys = make([]db.AccessKey, 0)

	q, err := d.makeObjectsQuery(projectID, db.AccessKeyProps, params)

	if err != nil {
		return
	}

	if !options.IgnoreOwner {
		q = q.Where("pe.owner=?", options.Owner)

		switch options.Owner {
		case db.AccessKeyVariable, db.AccessKeyEnvironment:
			q = q.Where(squirrel.Eq{"pe.environment_id": *options.EnvironmentID})
		case db.AccessKeySecretStorage:
			q = q.Where(squirrel.Eq{"pe.storage_id": options.StorageID})
		}
	} else if options.EnvironmentID != nil {
		q = q.Where(squirrel.Eq{"pe.environment_id": *options.EnvironmentID})
	}

	if options.SourceStorageID != nil {
		q = q.Where(squirrel.Eq{"pe.source_storage_id": *options.SourceStorageID})
	}

	query, args, err := q.ToSql()

	if err != nil {
		return
	}

	_, err = d.selectAll(&keys, query, args...)

	for i := range keys {
		keys[i].Empty = keys[i].IsEmpty()
	}

	return
}

func (d *SqlDb) UpdateAccessKey(key db.AccessKey) error {
	err := key.Validate(key.OverrideSecret)

	if err != nil {
		return err
	}

	var res sql.Result

	var args []any
	query := "update access_key set name=?, tenant_id=?"
	args = append(args, key.Name, key.TenantID)

	if !key.IgnorePlain {
		query += ", plain=?"
		args = append(args, key.Plain)
	}

	if key.OverrideSecret {

		query += ", type=?, secret=?, source_storage_id=?, source_storage_key=?, source_storage_type=?"
		args = append(args, key.Type)
		args = append(args, key.Secret)
		args = append(args, key.SourceStorageID)
		args = append(args, key.SourceStorageKey)
		args = append(args, key.SourceStorageType)
	}

	query += " where id=?"
	args = append(args, key.ID)

	query += " and project_id=?"
	args = append(args, key.ProjectID)

	res, err = d.exec(query, args...)

	return validateMutationResult(res, err)
}

func (d *SqlDb) CreateAccessKey(key db.AccessKey) (newKey db.AccessKey, err error) {

	var insertID int

	if key.IgnorePlain {
		insertID, err = d.insert(
			"id",
			"insert into access_key ("+
				"name, "+
				"type, "+
				"project_id, "+
				"secret, "+
				"environment_id, "+
				"owner, "+
				"storage_id, "+
				"source_storage_id, "+
				"source_storage_key, "+
				"source_storage_type, "+
				"synchronized, "+
				"tenant_id) "+
				"values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			key.Name,
			key.Type,
			key.ProjectID,
			key.Secret,
			key.EnvironmentID,
			key.Owner,
			key.StorageID,
			key.SourceStorageID,
			key.SourceStorageKey,
			key.SourceStorageType,
			key.Synchronized,
			key.TenantID,
		)
	} else {
		insertID, err = d.insert(
			"id",
			"insert into access_key ("+
				"name, "+
				"type, "+
				"project_id, "+
				"secret, "+
				"plain, "+
				"environment_id, "+
				"owner, "+
				"storage_id, "+
				"source_storage_id, "+
				"source_storage_key, "+
				"source_storage_type, "+
				"synchronized, "+
				"tenant_id) "+
				"values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			key.Name,
			key.Type,
			key.ProjectID,
			key.Secret,
			key.Plain,
			key.EnvironmentID,
			key.Owner,
			key.StorageID,
			key.SourceStorageID,
			key.SourceStorageKey,
			key.SourceStorageType,
			key.Synchronized,
			key.TenantID,
		)

	}

	if err != nil {
		return
	}

	newKey = key
	newKey.ID = insertID
	return
}

func (d *SqlDb) DeleteAccessKey(projectID int, accessKeyID int) error {
	return d.deleteObject(projectID, db.AccessKeyProps, accessKeyID)
}

// GetAccessKeyForTenant returns the access key only if its tenant_id
// matches the supplied tenantID. Cross-tenant reads return ErrNotFound
// (not 403) so the operator cannot probe for foreign-tenant resource
// existence — per design doc §4.2 + decision 4.
//
// SentraOps fork (R-I.1.c).
func (d *SqlDb) GetAccessKeyForTenant(projectID int, accessKeyID int, tenantID string) (db.AccessKey, error) {
	key, err := d.GetAccessKey(projectID, accessKeyID)
	if err != nil {
		return db.AccessKey{}, err
	}
	if key.TenantID != tenantID {
		return db.AccessKey{}, db.ErrNotFound
	}
	return key, nil
}

// GetAccessKeysForTenant returns the access keys for the project that
// are also in the supplied tenant. Defense in depth: the project's own
// tenant_id is verified first, then a per-row tenant_id filter is
// applied.
func (d *SqlDb) GetAccessKeysForTenant(projectID int, options db.GetAccessKeyOptions, params db.RetrieveQueryParams, tenantID string) ([]db.AccessKey, error) {
	if _, err := d.GetProjectForTenant(projectID, tenantID); err != nil {
		return nil, err
	}

	keys := make([]db.AccessKey, 0)
	q, err := d.makeObjectsQuery(projectID, db.AccessKeyProps, params)
	if err != nil {
		return nil, err
	}
	q = q.Where("pe.tenant_id=?", tenantID)

	if !options.IgnoreOwner {
		q = q.Where("pe.owner=?", options.Owner)
		switch options.Owner {
		case db.AccessKeyVariable, db.AccessKeyEnvironment:
			if options.EnvironmentID == nil {
				return nil, db.ErrInvalidOperation
			}
			q = q.Where(squirrel.Eq{"pe.environment_id": *options.EnvironmentID})
		case db.AccessKeySecretStorage:
			q = q.Where(squirrel.Eq{"pe.storage_id": options.StorageID})
		}
	} else if options.EnvironmentID != nil {
		q = q.Where(squirrel.Eq{"pe.environment_id": *options.EnvironmentID})
	}

	if options.SourceStorageID != nil {
		q = q.Where(squirrel.Eq{"pe.source_storage_id": *options.SourceStorageID})
	}

	query, args, err := q.ToSql()
	if err != nil {
		return nil, err
	}

	_, err = d.selectAll(&keys, query, args...)
	if err != nil {
		return nil, err
	}

	for i := range keys {
		keys[i].Empty = keys[i].IsEmpty()
	}
	return keys, nil
}

// UpdateAccessKeyForTenant updates the access key only if its tenant_id
// matches tenantID. Returns ErrNotFound on cross-tenant write.
func (d *SqlDb) UpdateAccessKeyForTenant(key db.AccessKey, tenantID string) error {
	// ProjectID is *int; an unbound key (e.g. an environment or
	// secret-storage owned key) is not project-scoped so the tenant
	// filter cannot apply. Reject those here so a malformed call
	// fails loud instead of falling through to the unscoped path.
	if key.ProjectID == nil {
		return db.ErrInvalidOperation
	}
	if _, err := d.GetAccessKeyForTenant(*key.ProjectID, key.ID, tenantID); err != nil {
		return err
	}
	return d.UpdateAccessKey(key)
}

// DeleteAccessKeyForTenant deletes the access key only if its tenant_id
// matches tenantID. Returns ErrNotFound on cross-tenant delete.
func (d *SqlDb) DeleteAccessKeyForTenant(projectID int, accessKeyID int, tenantID string) error {
	if _, err := d.GetAccessKeyForTenant(projectID, accessKeyID, tenantID); err != nil {
		return err
	}
	return d.DeleteAccessKey(projectID, accessKeyID)
}

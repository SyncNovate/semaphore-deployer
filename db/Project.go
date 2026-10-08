package db

import (
	"time"
)

// Project is the top level structure in Semaphore
type Project struct {
	ID                     int       `db:"id" json:"id" backup:"-"`
	Name                   string    `db:"name" json:"name" binding:"required"`
	Created                time.Time `db:"created" json:"created" backup:"-"`
	Alert                  bool      `db:"alert" json:"alert,omitempty"`
	AlertChat              *string   `db:"alert_chat" json:"alert_chat,omitempty"`
	MaxParallelTasks       int       `db:"max_parallel_tasks" json:"max_parallel_tasks,omitempty"`
	Type                   string    `db:"type" json:"type"`
	DefaultSecretStorageID *int      `db:"default_secret_storage_id" json:"default_secret_storage_id,omitempty" backup:"-"`

	// SentraOps fork (R-I.1.b): every project is bound to exactly one tenant
	// and one deployment zone. The API rejects creates without both. The
	// backfill default is `_unknown` (design doc §3.4) so the migration
	// applies cleanly to existing dev instances; R-I.2 sweeps those rows.
	TenantID          string `db:"tenant_id" json:"tenant_id" binding:"required"`
	DeploymentZoneID  string `db:"deployment_zone_id" json:"deployment_zone_id" binding:"required"`
}

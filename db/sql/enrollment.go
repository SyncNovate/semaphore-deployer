package sql

import (
	"database/sql"
	"errors"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/tz"
)

// isUniqueConstraintError (declared in executor.go) is reused here.

// CreateEnrollmentToken persists a fresh token row. The caller is the
// platform BE (out of scope for the /enroll handler itself).
func (d *SqlDb) CreateEnrollmentToken(t db.EnrollmentToken) (db.EnrollmentToken, error) {
	if t.CreatedAt.IsZero() {
		t.CreatedAt = tz.Now()
	}
	_, err := d.insert(
		"", // enrollment_tokens has no surrogate id column; token_hash is the PK
		"insert into enrollment_tokens ("+
			"token_hash, "+
			"tenant_id, "+
			"deployment_zone_ids, "+
			"executor_name, "+
			"hostname, "+
			"expires_at, "+
			"consumed_at, "+
			"consumed_by_executor_id, "+
			"created_at) "+
			"values (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		t.TokenHash,
		t.TenantID,
		t.DeploymentZoneIDsJSON,
		t.ExecutorName,
		t.Hostname,
		t.ExpiresAt,
		t.ConsumedAt,
		t.ConsumedByExecutorID,
		t.CreatedAt,
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return db.EnrollmentToken{}, db.ErrAlreadyExists
		}
		return db.EnrollmentToken{}, err
	}
	return t, nil
}

// GetEnrollmentTokenByHash returns the token row whose token_hash
// matches the supplied SHA-256 hex digest.
func (d *SqlDb) GetEnrollmentTokenByHash(hashHex string) (db.EnrollmentToken, error) {
	if hashHex == "" {
		return db.EnrollmentToken{}, db.ErrNotFound
	}
	var t db.EnrollmentToken
	var consumedAt sql.NullTime
	var consumedBy sql.NullString
	err := d.Sql().QueryRow(
		d.PrepareQuery(
			"select "+
				"token_hash, "+
				"tenant_id, "+
				"deployment_zone_ids, "+
				"executor_name, "+
				"hostname, "+
				"expires_at, "+
				"consumed_at, "+
				"consumed_by_executor_id, "+
				"created_at "+
				"from enrollment_tokens where token_hash = ?",
		),
		hashHex,
	).Scan(
		&t.TokenHash,
		&t.TenantID,
		&t.DeploymentZoneIDsJSON,
		&t.ExecutorName,
		&t.Hostname,
		&t.ExpiresAt,
		&consumedAt,
		&consumedBy,
		&t.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.EnrollmentToken{}, db.ErrNotFound
		}
		return db.EnrollmentToken{}, err
	}
	if consumedAt.Valid {
		t.ConsumedAt = &consumedAt.Time
	}
	if consumedBy.Valid {
		v := consumedBy.String
		t.ConsumedByExecutorID = &v
	}
	return t, nil
}

// ConsumeEnrollmentToken atomically marks the token consumed and
// stamps ConsumedByExecutorID. Returns ErrAlreadyExists if the row
// was already consumed (single-use, race-safe). The WHERE clause
// includes expires_at > ? so an expired token is NOT consumed —
// the caller's IsExpired() check on the returned row then surfaces
// 410 enrollment_token_expired WITHOUT marking the row as consumed
// (the customer's install.sh can retry after the SOC admin re-mints).
func (d *SqlDb) ConsumeEnrollmentToken(hashHex string, executorID string, consumedAt time.Time) (db.EnrollmentToken, error) {
	if hashHex == "" {
		return db.EnrollmentToken{}, db.ErrNotFound
	}
	res, err := d.exec(
		"update enrollment_tokens set consumed_at = ?, consumed_by_executor_id = ? "+
			"where token_hash = ? and consumed_at is null and expires_at > ?",
		consumedAt,
		executorID,
		hashHex,
		consumedAt,
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return db.EnrollmentToken{}, db.ErrAlreadyExists
		}
		return db.EnrollmentToken{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return db.EnrollmentToken{}, err
	}
	if rows == 0 {
		// Either the token doesn't exist, was already consumed,
		// or is past ExpiresAt. Disambiguate via a follow-up SELECT
		// so the handler can return the right status code WITHOUT
		// having touched the DB.
		t, getErr := d.GetEnrollmentTokenByHash(hashHex)
		if getErr != nil {
			return db.EnrollmentToken{}, getErr
		}
		if t.IsConsumed() {
			return db.EnrollmentToken{}, db.ErrAlreadyExists
		}
		if t.IsExpired() {
			// Caller checks IsExpired() and returns 410.
			return t, nil
		}
		// The row exists + not consumed + not expired + update
		// affected 0 rows. Should not happen, but if it does,
		// surface as ErrNotFound rather than silently succeeding.
		return db.EnrollmentToken{}, db.ErrNotFound
	}
	return d.GetEnrollmentTokenByHash(hashHex)
}

// Compile-time interface check (matches the pattern in executor.go).
var _ db.EnrollmentTokenRepository = (*SqlDb)(nil)
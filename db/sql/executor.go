package sql

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/tz"
)

// executorColumns lists the columns the SELECT queries pull back, in a
// stable order matching the executorInsertColumns / executorUpdateColumns
// slices below. Centralised so the insert + update + select paths cannot
// drift apart.
var executorColumns = []string{
	"id",
	"executor_id",
	"name",
	"tenant_id",
	"deployment_zone_id",
	"platforms_supported",
	"executor_version",
	"ansible_version",
	"hostname",
	"status",
	"last_heartbeat_at",
	"registration_at",
	"revoked_at",
	"revoke_reason",
	"affinity_violation_count",
	"affinity_violation_window_start",
	"auth_token_hash",
	"auth_token_expires_at",
}

// isUniqueConstraintError reports whether the given error is a unique-key
// violation from one of the three supported dialects. The check is
// intentionally loose (substring on the error message) because each
// driver formats the violation differently and the gorp layer does not
// normalise it.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") || // SQLite, Postgres
		strings.Contains(msg, "duplicate entry") || // MySQL
		strings.Contains(msg, "duplicate key") // Postgres
}

func (d *SqlDb) CreateExecutor(exec db.Executor) (newExec db.Executor, err error) {
	if exec.RegistrationAt.IsZero() {
		exec.RegistrationAt = tz.Now()
	}

	insertId, err := d.insert(
		"id",
		"insert into executor ("+
			"executor_id, "+
			"name, "+
			"tenant_id, "+
			"deployment_zone_id, "+
			"platforms_supported, "+
			"executor_version, "+
			"ansible_version, "+
			"hostname, "+
			"status, "+
			"last_heartbeat_at, "+
			"registration_at, "+
			"revoked_at, "+
			"revoke_reason, "+
			"affinity_violation_count, "+
			"affinity_violation_window_start, "+
			"auth_token_hash, "+
			"auth_token_expires_at) "+
			"values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		exec.ExecutorID,
		exec.Name,
		exec.TenantID,
		exec.DeploymentZoneID,
		exec.PlatformsSupportedJSON,
		exec.ExecutorVersion,
		exec.AnsibleVersion,
		exec.Hostname,
		exec.Status,
		exec.LastHeartbeatAt,
		exec.RegistrationAt,
		exec.RevokedAt,
		exec.RevokeReason,
		exec.AffinityViolationCount,
		exec.AffinityViolationWindowStart,
		exec.AuthTokenHash,
		exec.AuthTokenExpiresAt,
	)

	if err != nil {
		if isUniqueConstraintError(err) {
			err = db.ErrAlreadyExists
		}
		return
	}

	newExec = exec
	newExec.ID = insertId
	return
}

func (d *SqlDb) GetExecutor(executorID int) (exec db.Executor, err error) {
	query, args, err := squirrel.Select(executorColumns...).
		From("executor").
		Where("id=?", executorID).
		ToSql()
	if err != nil {
		return
	}
	err = d.selectOne(&exec, query, args...)
	return
}

func (d *SqlDb) GetExecutorByExecutorID(executorID string) (exec db.Executor, err error) {
	query, args, err := squirrel.Select(executorColumns...).
		From("executor").
		Where("executor_id=?", executorID).
		ToSql()
	if err != nil {
		return
	}
	err = d.selectOne(&exec, query, args...)
	return
}

func (d *SqlDb) GetExecutorsByTenant(tenantID string, zoneID *string) (executors []db.Executor, err error) {
	q := squirrel.Select(executorColumns...).
		From("executor").
		Where("tenant_id=?", tenantID)

	if zoneID != nil {
		q = q.Where("deployment_zone_id=?", *zoneID)
	}

	q = q.OrderBy("registration_at DESC")

	query, args, err := q.ToSql()
	if err != nil {
		return
	}

	_, err = d.selectAll(&executors, query, args...)
	return
}

func (d *SqlDb) GetClaimableExecutors(tenantID string, zoneID string, platforms []string) (executors []db.Executor, err error) {
	// Pull every online executor for the tenant + zone, then filter by
	// platform support in Go. The per-tenant executor count is bounded
	// (O(10-1000) in practice); if it ever grows, denormalise into a
	// separate executor__platform table. R-I.1.b scope: portable SQL.
	q := squirrel.Select(executorColumns...).
		From("executor").
		Where("tenant_id=?", tenantID).
		Where("deployment_zone_id=?", zoneID).
		Where("status=?", db.ExecutorStatusOnline).
		Where("revoked_at IS NULL")

	query, args, err := q.ToSql()
	if err != nil {
		return
	}

	var rows []db.Executor
	if _, err = d.selectAll(&rows, query, args...); err != nil {
		return
	}

	executors = make([]db.Executor, 0, len(rows))
	for _, e := range rows {
		if executorSupportsAny(e, platforms) {
			executors = append(executors, e)
		}
	}
	return
}

// executorSupportsAny reports whether the executor supports at least one
// of the requested platforms. An empty platforms list is treated as "any
// platform" (returns true), which is the safe default for callers that
// pass a wildcard.
func executorSupportsAny(e db.Executor, platforms []string) bool {
	if len(platforms) == 0 {
		return true
	}
	supported := e.Platforms()
	if len(supported) == 0 {
		// Conservative: an executor that declared no platforms at
		// registration does NOT claim work. Forces operators to set
		// platforms explicitly.
		return false
	}
	for _, want := range platforms {
		for _, have := range supported {
			if equalFoldASCII(want, have) {
				return true
			}
		}
	}
	return false
}

// equalFoldASCII is a case-insensitive ASCII-only string compare. We
// avoid strings.EqualFold to keep this file's import set minimal.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func (d *SqlDb) UpdateExecutor(exec db.Executor) error {
	_, err := d.exec(
		"update executor set "+
			"name=?, "+
			"platforms_supported=?, "+
			"executor_version=?, "+
			"ansible_version=?, "+
			"status=?, "+
			"last_heartbeat_at=?, "+
			"revoke_reason=? "+
			"where id=?",
		exec.Name,
		exec.PlatformsSupportedJSON,
		exec.ExecutorVersion,
		exec.AnsibleVersion,
		exec.Status,
		exec.LastHeartbeatAt,
		exec.RevokeReason,
		exec.ID,
	)
	return err
}

func (d *SqlDb) DeleteExecutor(executorID int) error {
	_, err := d.exec("delete from executor where id=?", executorID)
	return err
}

func (d *SqlDb) RevokeExecutor(executorID int, reason string) error {
	now := tz.Now()
	_, err := d.exec(
		"update executor set revoked_at=?, revoke_reason=?, status=? where id=? and revoked_at is null",
		now, reason, db.ExecutorStatusOffline, executorID,
	)
	return err
}

func (d *SqlDb) IncrementAffinityViolation(executorID int) (newCount int, err error) {
	// The auto-revoke rule (design doc §6 / decision 5): 5 violations in
	// 10 minutes → revoke. The window starts on the first violation and
	// expires after 10 minutes of inactivity.
	//
	// Implementation: read the current window, decide whether to reset,
	// then increment in a single transaction so concurrent claims don't
	// lose updates. We rely on SQLite's single-connection pool + the
	// Postgres/MySQL transaction isolation level being read-committed
	// (the default) for correctness.
	tx, err := d.Sql().Begin()
	if err != nil {
		return 0, err
	}

	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// 1. Read the current counter + window_start.
	row := tx.QueryRow(d.PrepareQuery(
		"select affinity_violation_count, affinity_violation_window_start, revoked_at "+
			"from executor where id=?"), executorID)

	var currentCount int
	var currentWindow *time.Time
	var revokedAt *time.Time
	if scanErr := row.Scan(&currentCount, &currentWindow, &revokedAt); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			err = db.ErrNotFound
			return
		}
		err = scanErr
		return
	}

	// A revoked executor does not need an increment — the rule already
	// fired. Just return the current count.
	if revokedAt != nil {
		newCount = currentCount
		err = tx.Commit()
		return
	}

	// 2. Decide whether the window has expired.
	now := tz.Now()
	windowExpired := currentWindow == nil || now.Sub(*currentWindow) > db.DefaultAfffinityViolationWindow

	if windowExpired {
		currentCount = 0
	}

	// 3. Increment + write the new window.
	newCount = currentCount + 1

	if windowExpired {
		if _, execErr := tx.Exec(d.PrepareQuery(
			"update executor set "+
				"affinity_violation_count=?, "+
				"affinity_violation_window_start=?, "+
				"revoked_at=?, "+
				"revoke_reason=?, "+
				"status=? "+
				"where id=?"),
			newCount, now, nil, "", db.ExecutorStatusOnline, executorID,
		); execErr != nil {
			err = execErr
			return
		}
	} else {
		if _, execErr := tx.Exec(d.PrepareQuery(
			"update executor set "+
				"affinity_violation_count=?, "+
				"affinity_violation_window_start=? "+
				"where id=?"),
			newCount, currentWindow, executorID,
		); execErr != nil {
			err = execErr
			return
		}
	}

	// 4. Auto-revoke if the threshold is reached.
	if newCount >= db.AffinityViolationThreshold {
		if _, execErr := tx.Exec(d.PrepareQuery(
			"update executor set revoked_at=?, revoke_reason=?, status=? where id=?"),
			now,
			"auto-revoked: affinity violation threshold reached",
			db.ExecutorStatusOffline,
			executorID,
		); execErr != nil {
			err = execErr
			return
		}
	}

	err = tx.Commit()
	return
}

// GetExecutorByTokenHash implements ExecutorManager. Looks up the
// executor whose stored auth_token_hash matches the supplied SHA-256
// hex digest. Returns ErrNotFound for empty hashes + for no-match
// cases; the caller (the ExecutorAuthMiddleware) collapses both to
// 401 to avoid an existence-probe side channel.
//
// R-I.1.d.
func (d *SqlDb) GetExecutorByTokenHash(tokenHashHex string) (exec db.Executor, err error) {
	if tokenHashHex == "" {
		err = db.ErrNotFound
		return
	}

	query, args, err := squirrel.Select(executorColumns...).
		From("executor").
		Where("auth_token_hash=?", tokenHashHex).
		ToSql()
	if err != nil {
		return
	}

	err = d.selectOne(&exec, query, args...)
	return
}

// HeartbeatExecutor implements ExecutorManager. Atomic UPDATE that
// stamps the executor's status + last_heartbeat_at + version
// fields. Returns ErrExecutorRevoked if the executor has been
// permanently rejected — the caller should not retry, and the
// executor should be told to self-decommission.
//
// R-I.1.d.
func (d *SqlDb) HeartbeatExecutor(
	executorID string,
	status string,
	executorVersion string,
	ansibleVersion string,
	activeJobCount int,
) (exec db.Executor, err error) {
	now := tz.Now()

	// active_job_count is not persisted on the executor row in v2.19.17,
	// so we use it as a pass-through sanity check (1..1024) but do not
	// store it. R-I.2 may add a column if the platform starts caring.
	if activeJobCount < 0 || activeJobCount > 1024 {
		err = db.ErrInvalidOperation
		return
	}

	tx, err := d.Sql().Begin()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Read the row first to surface ErrExecutorRevoked cleanly.
	row := tx.QueryRow(d.PrepareQuery(
		"select revoked_at from executor where executor_id=?"), executorID)
	var revokedAt *time.Time
	if scanErr := row.Scan(&revokedAt); scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			err = db.ErrNotFound
			return
		}
		err = scanErr
		return
	}
	if revokedAt != nil {
		err = db.ErrExecutorRevoked
		return
	}

	if _, execErr := tx.Exec(d.PrepareQuery(
		"update executor set status=?, last_heartbeat_at=?, executor_version=?, ansible_version=? "+
			"where executor_id=?"),
		status, now, executorVersion, ansibleVersion, executorID,
	); execErr != nil {
		err = execErr
		return
	}

	row = tx.QueryRow(d.PrepareQuery(
		"select "+strings.Join(executorColumns, ", ")+" from executor where executor_id=?"),
		executorID)
	err = d.scanExecutorRow(row, &exec)
	if err != nil {
		return
	}

	err = tx.Commit()
	return
}

// scanExecutorRow reads the executorColumns-shaped result row into
// the Executor struct. Pulled out so HeartbeatExecutor can fetch
// the post-UPDATE row inside the same transaction that did the
// UPDATE.
//
// R-I.1.d.
func (d *SqlDb) scanExecutorRow(row *sql.Row, exec *db.Executor) error {
	var lastHeartbeatAt sql.NullTime
	var revokedAt sql.NullTime
	var registrationAt time.Time
	var affinityWindowStart sql.NullTime
	var authTokenHash sql.NullString
	var authTokenExpiresAt sql.NullTime

	if err := row.Scan(
		&exec.ID,
		&exec.ExecutorID,
		&exec.Name,
		&exec.TenantID,
		&exec.DeploymentZoneID,
		&exec.PlatformsSupportedJSON,
		&exec.ExecutorVersion,
		&exec.AnsibleVersion,
		&exec.Hostname,
		&exec.Status,
		&lastHeartbeatAt,
		&registrationAt,
		&revokedAt,
		&exec.RevokeReason,
		&exec.AffinityViolationCount,
		&affinityWindowStart,
		&authTokenHash,
		&authTokenExpiresAt,
	); err != nil {
		return err
	}

	if lastHeartbeatAt.Valid {
		t := lastHeartbeatAt.Time
		exec.LastHeartbeatAt = &t
	} else {
		exec.LastHeartbeatAt = nil
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		exec.RevokedAt = &t
	} else {
		exec.RevokedAt = nil
	}
	if affinityWindowStart.Valid {
		t := affinityWindowStart.Time
		exec.AffinityViolationWindowStart = &t
	} else {
		exec.AffinityViolationWindowStart = nil
	}
	if authTokenHash.Valid {
		s := authTokenHash.String
		exec.AuthTokenHash = &s
	} else {
		exec.AuthTokenHash = nil
	}
	if authTokenExpiresAt.Valid {
		t := authTokenExpiresAt.Time
		exec.AuthTokenExpiresAt = &t
	} else {
		exec.AuthTokenExpiresAt = nil
	}
	exec.RegistrationAt = registrationAt
	return nil
}

// GetClaimableTasksForTenantAndZone implements ExecutorManager.
// Returns the IDs of waiting tasks for projects whose tenant_id +
// deployment_zone_id match the executor's bind. The platform-side
// platform intersection happens in the caller's Go code (we don't
// model inventories' platforms as a joinable column in v2.19.18 —
// it would be R-I.2 work).
//
// R-I.1.d.
func (d *SqlDb) GetClaimableTasksForTenantAndZone(
	tenantID string,
	zoneID string,
	maxCount int,
	_ []string,
) (tasks []db.Task, err error) {
	if maxCount <= 0 || maxCount > 100 {
		maxCount = 10
	}

	// Per design doc §4.3: tasks eligible for claim are tasks where
	//   - project.tenant_id == tenantID
	//   - project.deployment_zone_id == zoneID
	//   - task.status is a waiting/pending status
	//   - task.claimed_by IS NULL
	// Indexed by idx_task_claimable (partial index on
	// claimed_by IS NULL).
	query, args, err := squirrel.Select(
		"t.id",
		"t.template_id",
		"t.project_id",
		"t.status",
		"t.claimed_by",
		"t.claimed_at",
		"t.result_outcome",
		"t.result_error_class",
		"t.playbook",
		"t.environment",
		"t.created",
		"t.start",
		"t.`end`",
		"t.user_id",
		"t.message",
		"t.commit_hash",
		"t.commit_message",
		"t.build_task_id",
		"t.arguments",
		"t.inventory_id",
		"t.integration_id",
		"t.schedule_id",
		"t.git_branch",
		"t.params",
		"t.version",
		"t.workflow_run_id",
		"t.workflow_node_id",
		"t.artifacts",
		"t.runner_id",
	).
		From("task t").
		Join("project p on p.id = t.project_id").
		Where("p.tenant_id=?", tenantID).
		Where("p.deployment_zone_id=?", zoneID).
		Where("t.claimed_by IS NULL").
		Where("t.status IN ('waiting', 'pending')").
		OrderBy("t.id ASC").
		Limit(uint64(maxCount)).
		ToSql()
	if err != nil {
		return
	}

	_, err = d.selectAll(&tasks, query, args...)
	if err != nil {
		return
	}

	// Defensive: filter out any rows whose created timestamp is null
	// (cannot happen in practice but keeps the json serializer happy).
	for i := range tasks {
		if tasks[i].Created.IsZero() {
			tasks[i].Created = tz.Now()
		}
	}
	return
}

// ClaimTask implements ExecutorManager. Atomic UPDATE — sets
// claimed_by + claimed_at only if claimed_by is currently NULL.
// The driver returns ErrNotFound on a 0-row update when there's no
// task with that id; we normalise that to ErrAlreadyClaimed when
// the row DOES exist but is already claimed by another executor.
//
// R-I.1.d.
func (d *SqlDb) ClaimTask(taskID int, executorID string) (claimed bool, err error) {
	if executorID == "" {
		err = db.ErrInvalidOperation
		return
	}

	now := tz.Now()

	res, err := d.Sql().Exec(d.PrepareQuery(
		"update task set claimed_by=?, claimed_at=? where id=? and claimed_by IS NULL"),
		executorID, now, taskID)
	if err != nil {
		return
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return
	}

	if affected == 1 {
		claimed = true
		return
	}

	// 0 rows affected — either the task does not exist or it has
	// already been claimed by someone else. Distinguish via a
	// follow-up SELECT so we can return ErrNotFound vs ErrAlreadyClaimed.
	var claimedBy *string
	err = d.Sql().QueryRow(d.PrepareQuery(
		"select claimed_by from task where id=?"), taskID,
	).Scan(&claimedBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = db.ErrNotFound
		}
		return
	}

	err = db.ErrAlreadyClaimed
	return
}

// RecordExecutorTaskResult implements ExecutorManager. Stamps the
// task row with the executor's reported outcome + error_class and
// only succeeds if the executor is still the claim holder. Status
// transitions to 'success' / 'failed' based on the outcome.
//
// R-I.1.d.
func (d *SqlDb) RecordExecutorTaskResult(
	taskID int,
	executorID string,
	outcome string,
	errorClass string,
) (err error) {
	if executorID == "" {
		err = db.ErrInvalidOperation
		return
	}
	switch outcome {
	case "success":
		// errorClass is ignored on success.
	case "failed":
		// errorClass may be empty (unknown error).
	default:
		err = db.ErrInvalidOperation
		return
	}

	now := tz.Now()
	status := outcome
	if status == "failed" {
		status = "failed"
	}

	var errClassVal *string
	if errorClass != "" {
		errClassVal = &errorClass
	}

	res, err := d.Sql().Exec(d.PrepareQuery(
		"update task set status=?, result_outcome=?, result_error_class=?, end=? "+
			"where id=? and claimed_by=?"),
		status, outcome, errClassVal, now, taskID, executorID)
	if err != nil {
		return
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return
	}
	if affected == 0 {
		// Either the task does not exist or the executor does not
		// hold the claim. Same OUTCOME in either case; the caller
		// logs + audits.
		err = db.ErrInvalidOperation
	}
	return
}

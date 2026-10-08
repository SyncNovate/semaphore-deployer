package db

import (
	"encoding/json"
	"time"
)

// Executor is the customer-side deployment executor entity. It is distinct
// from Semaphore's "Runner" (which is a task runner on a target host); an
// Executor is a service that lives on the customer's network, claims
// deployment jobs from the platform, runs Ansible locally, and reports
// results back. See docs/architecture/2026-10-07-semaphore-fork-design.md §3.3.
type Executor struct {
	// ID is the surrogate primary key. Use ExecutorID (the public id) when
	// talking to the wire; the surrogate key is an internal detail.
	ID int `db:"id" json:"id" backup:"-"`

	// ExecutorID is the public, ULID-style id (e.g. "EXEC-01HZX2N3K9ABCDEF0456").
	// Generated at registration. Used in every claim + result.
	ExecutorID string `db:"executor_id" json:"executor_id" binding:"required"`

	// Name is a human-readable label set by the operator.
	Name string `db:"name" json:"name" binding:"required"`

	// TenantID is the bound tenant. Set at registration, immutable.
	TenantID string `db:"tenant_id" json:"tenant_id" binding:"required"`

	// DeploymentZoneID is the bound deployment zone. Set at registration,
	// immutable. Executors for the wrong zone cannot claim a project's tasks.
	DeploymentZoneID string `db:"deployment_zone_id" json:"deployment_zone_id" binding:"required"`

	// PlatformsSupportedJSON is the JSON-encoded list of supported OS
	// platforms (e.g. `["windows","linux"]`). Stored as TEXT to keep the
	// schema portable across SQLite / MySQL / Postgres. Use Platforms() to
	// decode; SetPlatforms() to encode.
	PlatformsSupportedJSON string `db:"platforms_supported" json:"-"`

	// ExecutorVersion is the customer-side executor binary version
	// (semver, reported at registration + on every heartbeat).
	ExecutorVersion string `db:"executor_version" json:"executor_version" binding:"required"`

	// AnsibleVersion is the bundled Ansible version on the executor host.
	AnsibleVersion string `db:"ansible_version" json:"ansible_version" binding:"required"`

	// Hostname is the executor's host name. The unique index
	// (tenant_id, deployment_zone_id, hostname) prevents accidental
	// double-registration of the same host.
	Hostname string `db:"hostname" json:"hostname" binding:"required"`

	// Status is the current executor state. Updated on heartbeat. One of:
	//   - ExecutorStatusOnline  : heartbeats within the freshness window
	//   - ExecutorStatusOffline : no heartbeat within the freshness window
	//   - ExecutorStatusDegraded: online but degraded (e.g. credential
	//                            resolution failing on the executor side)
	Status string `db:"status" json:"status" binding:"required"`

	// LastHeartbeatAt is updated on every heartbeat. NULL until the first
	// heartbeat arrives.
	LastHeartbeatAt *time.Time `db:"last_heartbeat_at" json:"last_heartbeat_at,omitempty"`

	// RegistrationAt is set at registration and never changes.
	RegistrationAt time.Time `db:"registration_at" json:"registration_at" backup:"-"`

	// RevokedAt is the wall-clock time the executor was permanently rejected.
	// NULL while the executor is active. A revoked executor cannot claim any
	// jobs (claim endpoint returns 403 with `executor_revoked`).
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`

	// RevokeReason is the human-readable reason for revocation (set by the
	// operator or by the auto-revoke rule). Empty while the executor is active.
	RevokeReason string `db:"revoke_reason" json:"revoke_reason,omitempty"`

	// AffinityViolationCount is the count of affinity violations observed
	// within the current AffinityViolationWindowStart window. Reset when
	// the window expires. Used by the auto-revoke rule (design doc §6 +
	// decision 5: 5 in 10 min).
	AffinityViolationCount int `db:"affinity_violation_count" json:"affinity_violation_count"`

	// AffinityViolationWindowStart is the start of the current violation
	// window. NULL when the counter is zero.
	AffinityViolationWindowStart *time.Time `db:"affinity_violation_window_start" json:"-"`

	// AuthTokenHash is the SHA-256 hash of the short-lived bearer token the
	// executor uses on subsequent calls. Plaintext is NEVER persisted; the
	// plaintext is returned exactly once at registration / refresh and
	// never stored. Mirrors the runner's registration-token storage pattern.
	AuthTokenHash *string `db:"auth_token_hash" json:"-"`

	// AuthTokenExpiresAt is the wall-clock time the bearer token expires
	// (24h TTL per design doc §5.1). NULL until the token is issued.
	AuthTokenExpiresAt *time.Time `db:"auth_token_expires_at" json:"-"`
}

// ExecutorStatus values.
const (
	ExecutorStatusOnline   = "online"
	ExecutorStatusOffline  = "offline"
	ExecutorStatusDegraded = "degraded"
)

// DefaultAfffinityViolationWindow is the 10-minute window used by the
// auto-revoke rule (5 violations in 10 minutes per design doc §6).
const DefaultAfffinityViolationWindow = 10 * time.Minute

// AffinityViolationThreshold is the number of violations within the window
// that triggers auto-revoke. Locked to 5 per decision 5.
const AffinityViolationThreshold = 5

// Platforms returns the decoded list of supported platforms. Returns nil
// on empty or on decode error (the platform list is non-critical for
// audit; a corrupt value should not break reads).
func (e Executor) Platforms() []string {
	if e.PlatformsSupportedJSON == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(e.PlatformsSupportedJSON), &out); err != nil {
		return nil
	}
	return out
}

// SetPlatforms encodes the platform list as JSON for storage. Empty input
// is stored as the empty string (NOT "[]" — keeps the column nullable-clean).
func (e *Executor) SetPlatforms(p []string) error {
	if len(p) == 0 {
		e.PlatformsSupportedJSON = ""
		return nil
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	e.PlatformsSupportedJSON = string(b)
	return nil
}

// IsRevoked reports whether the executor has been permanently rejected.
func (e Executor) IsRevoked() bool {
	return e.RevokedAt != nil
}

// SupportsPlatform reports whether the executor has the given platform in
// its declared support set (case-insensitive). An executor that does not
// declare a platform supports it (conservative; the API should always set
// platforms explicitly at registration).
func (e Executor) SupportsPlatform(platform string) bool {
	if platform == "" {
		return true
	}
	for _, p := range e.Platforms() {
		if equalFold(p, platform) {
			return true
		}
	}
	return false
}

// equalFold is a case-insensitive string compare that avoids pulling in
// strings.ToLower (which allocates). Fine here because the platform list
// is tiny.
func equalFold(a, b string) bool {
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

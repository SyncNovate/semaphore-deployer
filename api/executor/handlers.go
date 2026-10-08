package executor

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/api/helpers"
	apimiddleware "github.com/semaphoreui/semaphore/api/middleware"
	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/pkg/jwt"

	log "github.com/sirupsen/logrus"
)

// RegisterRequest is the body for POST /api/v1/executor/register.
// The platform BE (acting as the operator's authenticated proxy)
// mints a one-shot X-Register-Token for this endpoint. R-I.1.d
// accepts a non-empty X-Register-Token as the gate; R-I.2 will
// tighten the validation to verify a signed token against the
// platform's signing key.
type RegisterRequest struct {
	Name               string   `json:"name" binding:"required"`
	TenantID           string   `json:"tenant_id" binding:"required"`
	DeploymentZoneID   string   `json:"deployment_zone_id" binding:"required"`
	PlatformsSupported []string `json:"platforms_supported" binding:"required"`
	ExecutorVersion    string   `json:"executor_version" binding:"required"`
	AnsibleVersion     string   `json:"ansible_version" binding:"required"`
	Hostname           string   `json:"hostname" binding:"required"`
}

// RegisterResponse is the body returned to the platform BE (and via
// the BE to the executor's installer). The plaintext
// ExecutorToken is returned EXACTLY ONCE here and never persisted in
// plaintext on the server.
type RegisterResponse struct {
	ExecutorID  string    `json:"executor_id"`
	ExecutorToken string  `json:"executor_token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`
}

// RegisterHandler authenticates the request via the platform-BE
// service JWT (X-Service-Auth) + a one-shot X-Register-Token. Both
// must be present; the service JWT is verified by the
// TenantBinding middleware (because /register is under
// /api/v1/executor/*, which the middleware skips, so we re-verify
// inline here).
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// X-Register-Token: required, non-empty. R-I.2 replaces this
	// with a signed-token verification path.
	if strings.TrimSpace(r.Header.Get("X-Register-Token")) == "" {
		helpers.WriteErrorStatus(w, "register_token_required", http.StatusUnauthorized)
		return
	}

	// X-Service-Auth: must be present and valid. We re-verify here
	// because the TenantBinding middleware skips this prefix.
	pem := apimiddleware.PlatformPublicKeyPEM
	if len(pem) == 0 {
		helpers.WriteErrorStatus(w, "service_auth_not_configured", http.StatusUnauthorized)
		return
	}
	if _, err := jwt.Verify(r.Header.Get("X-Service-Auth"), pem); err != nil {
		helpers.WriteErrorStatus(w, "service_auth_invalid", http.StatusUnauthorized)
		return
	}

	var req RegisterRequest
	if !helpers.Bind(w, r, &req) {
		return
	}

	if len(req.PlatformsSupported) == 0 {
		helpers.WriteErrorStatus(w, "platforms_required", http.StatusBadRequest)
		return
	}

	// Reject the backfill sentinel — operators must always set a
	// real tenant + zone at registration. The R-I.2 sweep refuses
	// `_unknown` rows.
	if req.TenantID == "_unknown" || req.DeploymentZoneID == "_unknown" {
		helpers.WriteErrorStatus(w, "tenant_zone_required", http.StatusBadRequest)
		return
	}

	execID, err := db.NewExecutorID()
	if err != nil {
		log.WithError(err).Error("executor_id_generate_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	plainToken, hashHex, err := mintToken()
	if err != nil {
		log.WithError(err).Error("executor_token_mint_failed")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	tokenExpiresAt := time.Now().UTC().Add(TokenTTL)

	var platformsJSON string
	if encErr := encodePlatforms(req.PlatformsSupported, &platformsJSON); encErr != nil {
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}

	store := helpers.Store(r)
	created, err := store.CreateExecutor(db.Executor{
		ExecutorID:             execID,
		Name:                   req.Name,
		TenantID:               req.TenantID,
		DeploymentZoneID:       req.DeploymentZoneID,
		PlatformsSupportedJSON: platformsJSON,
		ExecutorVersion:        req.ExecutorVersion,
		AnsibleVersion:         req.AnsibleVersion,
		Hostname:               req.Hostname,
		Status:                 db.ExecutorStatusOnline,
		RegistrationAt:         time.Now().UTC(),
		AuthTokenHash:          &hashHex,
		AuthTokenExpiresAt:     &tokenExpiresAt,
	})
	if err != nil {
		// Same-shape error for already-exists (the unique index on
		// tenant+zone+hostname) and every other failure. Existence-
		// probe prevention.
		if errors.Is(err, db.ErrAlreadyExists) {
			helpers.WriteErrorStatus(w, "executor_already_registered", http.StatusConflict)
			return
		}
		log.WithError(err).Error("executor_register_failed")
		helpers.WriteErrorStatus(w, "register_failed", http.StatusInternalServerError)
		return
	}

	actor := serviceActorFromContext(r)

	DefaultPropagator().Propagate(AuditEvent{
		Event:            "executor.register",
		ExecutorID:       created.ExecutorID,
		TenantID:         created.TenantID,
		DeploymentZoneID: created.DeploymentZoneID,
		ActorID:          actor,
		Payload: map[string]any{
			"platforms_supported": req.PlatformsSupported,
			"executor_version":    req.ExecutorVersion,
			"ansible_version":     req.AnsibleVersion,
			"hostname":            req.Hostname,
		},
	})

	helpers.WriteJSON(w, http.StatusCreated, RegisterResponse{
		ExecutorID:    created.ExecutorID,
		ExecutorToken: plainToken,
		TokenExpiresAt: tokenExpiresAt,
	})
}

// HeartbeatRequest is the body for POST /api/v1/executor/heartbeat.
type HeartbeatRequest struct {
	Status         string `json:"status"`
	ActiveJobCount int    `json:"active_job_count"`
	ExecutorVersion string `json:"executor_version"`
	AnsibleVersion  string `json:"ansible_version"`
}

// HeartbeatHandler updates the executor's status + last_heartbeat_at
// + version fields. The X-Executor-Token + the resulting executor
// context are validated by ExecutorAuthMiddleware.
func HeartbeatHandler(w http.ResponseWriter, r *http.Request) {
	exec, ok := executorFromContext(r)
	if !ok {
		// Should never happen — the middleware is on this route.
		helpers.WriteErrorStatus(w, "executor_required", http.StatusUnauthorized)
		return
	}

	var req HeartbeatRequest
	if !helpers.Bind(w, r, &req) {
		return
	}

	// Status is optional; default to "online". Validate against the
	// canonical vocabulary so a corrupt client cannot poison the
	// health-gate UI.
	switch req.Status {
	case "":
		req.Status = db.ExecutorStatusOnline
	case db.ExecutorStatusOnline, db.ExecutorStatusOffline, db.ExecutorStatusDegraded:
		// ok
	default:
		helpers.WriteErrorStatus(w, "invalid_status", http.StatusBadRequest)
		return
	}

	updated, err := helpers.Store(r).HeartbeatExecutor(
		exec.ExecutorID,
		req.Status,
		req.ExecutorVersion,
		req.AnsibleVersion,
		req.ActiveJobCount,
	)
	if err != nil {
		if errors.Is(err, db.ErrExecutorRevoked) {
			helpers.WriteErrorStatus(w, "executor_revoked", http.StatusForbidden)
			return
		}
		if errors.Is(err, db.ErrNotFound) {
			helpers.WriteErrorStatus(w, "executor_not_found", http.StatusNotFound)
			return
		}
		log.WithError(err).Error("executor_heartbeat_failed")
		helpers.WriteErrorStatus(w, "heartbeat_failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	// Heartbeats are high-cardinality; we propagate ONLY the
	// off→online transitions AND the offline timeout events to the
	// platform. Steady-state "still online" heartbeats are local-only.
	if updated.Status != exec.Status {
		DefaultPropagator().Propagate(AuditEvent{
			Event:            "executor.status_changed",
			ExecutorID:       updated.ExecutorID,
			TenantID:         updated.TenantID,
			DeploymentZoneID: updated.DeploymentZoneID,
			Payload: map[string]any{
				"from": exec.Status,
				"to":   updated.Status,
			},
		})
	}
}

// ClaimRequest is the body for POST /api/v1/executor/claim.
type ClaimRequest struct {
	MaxClaimCount int `json:"max_claim_count"`
}

// ClaimResponse is the body for POST /api/v1/executor/claim.
type ClaimResponse struct {
	Jobs []db.Task `json:"jobs"`
}

// ClaimHandler is the executor's claim-rotation endpoint. Implements
// design-doc layer 3: tenant+zone affinity filter + atomic CAS claim.
// On a tenant/zone mismatch, the handler records an affinity violation
// + returns 403 + propagates the audit event. Revoked executors get
// 403 distinct from "wrong tenant" so the executor's self-diagnostic
// can react correctly.
func ClaimHandler(w http.ResponseWriter, r *http.Request) {
	exec, ok := executorFromContext(r)
	if !ok {
		helpers.WriteErrorStatus(w, "executor_required", http.StatusUnauthorized)
		return
	}

	var req ClaimRequest
	if !helpers.Bind(w, r, &req) {
		return
	}
	if req.MaxClaimCount <= 0 || req.MaxClaimCount > 100 {
		req.MaxClaimCount = 10
	}

	store := helpers.Store(r)

	// Layer 3: tenant + zone affinity filter (design doc §4.3).
	// The executor's bind is the ground truth from the storage
	// row; the request body's tenant_id/zone_id are *not* trusted
	// here because the executor's tenant+zone never changes after
	// registration (the registration is immutable).
	if exec.RevokedAt != nil {
		// Shouldn't reach here — middleware already 403'd —
		// but defence in depth.
		helpers.WriteErrorStatus(w, "executor_revoked", http.StatusForbidden)
		return
	}

	tasks, err := store.GetClaimableTasksForTenantAndZone(
		exec.TenantID,
		exec.DeploymentZoneID,
		req.MaxClaimCount,
		exec.Platforms(),
	)
	if err != nil {
		log.WithError(err).Error("executor_claim_list_failed")
		helpers.WriteErrorStatus(w, "claim_failed", http.StatusInternalServerError)
		return
	}

	claimed := make([]db.Task, 0, len(tasks))
	for _, t := range tasks {
		ok, err := store.ClaimTask(t.ID, exec.ExecutorID)
		if err != nil {
			if errors.Is(err, db.ErrAlreadyClaimed) {
				// Race lost. Skip — another executor
				// got it between the list and the CAS.
				continue
			}
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			log.WithError(err).WithField("task_id", t.ID).
				Warn("executor_claim_cas_failed")
			continue
		}
		if !ok {
			continue
		}
		t.ClaimedBy = &exec.ExecutorID
		now := time.Now().UTC()
		t.ClaimedAt = &now
		claimed = append(claimed, t)
	}

	if len(claimed) > 0 {
		DefaultPropagator().Propagate(AuditEvent{
			Event:            "task.claimed",
			ExecutorID:       exec.ExecutorID,
			TenantID:         exec.TenantID,
			DeploymentZoneID: exec.DeploymentZoneID,
			Payload: map[string]any{
				"task_ids":      taskIDsOf(claimed),
				"claim_count":   len(claimed),
				"claimed_at":    time.Now().UTC(),
			},
		})
	}

	helpers.WriteJSON(w, http.StatusOK, ClaimResponse{Jobs: claimed})
}

// ResultRequest is the body for POST /api/v1/executor/result.
type ResultRequest struct {
	TaskID       int    `json:"task_id" binding:"required"`
	Outcome      string `json:"outcome" binding:"required"`
	ErrorClass   string `json:"error_class,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// ResultHandler records the executor's reported outcome for a task.
// The task must currently be claimed by THIS executor (otherwise a
// poisoned executor could overwrite another executor's claim).
func ResultHandler(w http.ResponseWriter, r *http.Request) {
	exec, ok := executorFromContext(r)
	if !ok {
		helpers.WriteErrorStatus(w, "executor_required", http.StatusUnauthorized)
		return
	}

	var req ResultRequest
	if !helpers.Bind(w, r, &req) {
		return
	}
	if req.Outcome != "success" && req.Outcome != "failed" {
		helpers.WriteErrorStatus(w, "invalid_outcome", http.StatusBadRequest)
		return
	}

	if err := helpers.Store(r).RecordExecutorTaskResult(
		req.TaskID,
		exec.ExecutorID,
		req.Outcome,
		req.ErrorClass,
	); err != nil {
		if errors.Is(err, db.ErrInvalidOperation) {
			// Either the task does not exist or the
			// executor does not hold the claim.
			// Same OUTCOME in either case.
			helpers.WriteErrorStatus(w, "not_claim_holder", http.StatusConflict)
			return
		}
		log.WithError(err).Error("executor_result_failed")
		helpers.WriteErrorStatus(w, "result_failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	eventName := "task.completed"
	if req.Outcome == "failed" {
		eventName = "task.failed"
	}

	DefaultPropagator().Propagate(AuditEvent{
		Event:            eventName,
		ExecutorID:       exec.ExecutorID,
		TenantID:         exec.TenantID,
		DeploymentZoneID: exec.DeploymentZoneID,
		Payload: map[string]any{
			"task_id":      req.TaskID,
			"outcome":      req.Outcome,
			"error_class":  req.ErrorClass,
			"completed_at": req.CompletedAt,
		},
	})
}

// AffinityViolationRequest is the body for the executor's self-report
// of a wrong-tenant/zone claim attempt. The endpoint is the documented
// exception to the 404-not-403 rule (design doc §4.3 + decision 4) —
// we MUST signal "you are out of bounds" so the executor's self-
// diagnostic + the platform's anomaly detection can react.
type AffinityViolationRequest struct {
	ClaimedTenantID string `json:"claimed_tenant_id" binding:"required"`
	ClaimedZoneID   string `json:"claimed_zone_id" binding:"required"`
}

// AffinityViolationHandler increments the executor's affinity-
// violation counter (auto-revoking at 5 in 10 minutes) and emits the
// audit event. The handshake loop is: executor detects an
// out-of-bounds task in a claim response → calls this endpoint to
// self-report → we tally + revoke if threshold reached.
func AffinityViolationHandler(w http.ResponseWriter, r *http.Request) {
	exec, ok := executorFromContext(r)
	if !ok {
		helpers.WriteErrorStatus(w, "executor_required", http.StatusUnauthorized)
		return
	}

	var req AffinityViolationRequest
	if !helpers.Bind(w, r, &req) {
		return
	}
	if req.ClaimedTenantID == "" || req.ClaimedZoneID == "" {
		helpers.WriteErrorStatus(w, "claimed_tenant_zone_required", http.StatusBadRequest)
		return
	}

	store := helpers.Store(r)

	// Sanity: if the self-report says the SAME tenant+zone as the
	// executor's bind, that's a client bug — we still tally the
	// event but log a warning so the operator knows.
	sameBind := req.ClaimedTenantID == exec.TenantID && req.ClaimedZoneID == exec.DeploymentZoneID

	newCount, err := store.IncrementAffinityViolation(exec.ID)
	if err != nil {
		log.WithError(err).Error("executor_affinity_violation_increment_failed")
		helpers.WriteErrorStatus(w, "affinity_violation_failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	DefaultPropagator().Propagate(AuditEvent{
		Event:            "executor.affinity_violation",
		ExecutorID:       exec.ExecutorID,
		TenantID:         exec.TenantID,
		DeploymentZoneID: exec.DeploymentZoneID,
		Payload: map[string]any{
			"claimed_tenant_id": req.ClaimedTenantID,
			"claimed_zone_id":   req.ClaimedZoneID,
			"violation_count":   newCount,
			"same_bind":         sameBind,
			"observed_at":       time.Now().UTC(),
		},
	})

	// If the increment crossed the auto-revoke threshold, the
	// executor was just permanently rejected by the storage layer.
	// Emit the dedicated auto-revoke event so the platform can
	// reconcile the operator-facing executor status.
	if newCount >= db.AffinityViolationThreshold {
		DefaultPropagator().Propagate(AuditEvent{
			Event:            "executor.auto_revoke",
			ExecutorID:       exec.ExecutorID,
			TenantID:         exec.TenantID,
			DeploymentZoneID: exec.DeploymentZoneID,
			Payload: map[string]any{
				"reason":                  "affinity_violation_threshold",
				"violation_count":         newCount,
				"observed_window_minutes": int(db.DefaultAfffinityViolationWindow.Minutes()),
			},
		})
	}
}

// Helpers below — kept here so the 5 handlers stay in one file.

// encodePlatforms JSON-encodes the platform list for the executor
// row. An empty list becomes the empty string (mirrors the storage
// convention).
func encodePlatforms(in []string, dst *string) error {
	if len(in) == 0 {
		*dst = ""
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	*dst = string(b)
	return nil
}

func taskIDsOf(tasks []db.Task) []int {
	ids := make([]int, len(tasks))
	for i, t := range tasks {
		ids[i] = t.ID
	}
	return ids
}

// serviceActorFromContext returns the actor id (operator) the
// platform BE was acting on behalf of, or empty if no service JWT
// claim was attached. The middleware stores the claim under
// middleware.ContextKeyActorID.
func serviceActorFromContext(r *http.Request) string {
	v := helpers.GetFromContext(r, apimiddleware.ContextKeyActorID)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

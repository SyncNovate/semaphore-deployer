package executor

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/api/helpers"
	apimiddleware "github.com/semaphoreui/semaphore/api/middleware"
	"github.com/semaphoreui/semaphore/pkg/enrollment/mint"
	"github.com/semaphoreui/semaphore/pkg/jwt"
	"github.com/semaphoreui/semaphore/pkg/tz"

	log "github.com/sirupsen/logrus"
)

// HeaderRegisterToken is the same shared-secret header RegisterHandler
// already enforces. R-I.9 re-uses it as the platform-BE-side gate:
// the SOC console drives /enroll-token with the platform BE's mTLS
// identity + a service JWT for audit attribution; the X-Register-Token
// is the same shared secret the platform BE carries for /register.
const HeaderRegisterToken = "X-Register-Token"

// EnrollTokenRequest is the body POSTed by the platform BE to
// /api/v1/executor/enroll-token. The BE is the actor here, not the
// customer's executor — the customer's install flow is driven by the
// plaintext token in the response, not by anything in this request.
type EnrollTokenRequest struct {
	// TenantID is the surrogate key (``sentraops_groups.id``) the
	// operator is bound to. Mandatory.
	TenantID string `json:"tenant_id"`
	// DeploymentZoneIDs is optional; an empty list is a valid
	// starting state (the executor can claim only after zones
	// are assigned via /api/v1/executors/{id}).
	DeploymentZoneIDs []string `json:"deployment_zone_ids"`
	// ExecutorName is optional; the executor_id is the fallback.
	ExecutorName string `json:"executor_name"`
	// Hostname is optional; the customer's first-boot agent fills
	// it in via /enroll's hostname header.
	Hostname string `json:"hostname"`
	// TTLMinutes defaults to 5 (the shared helper's default) when
	// 0; bounded to ≤60 by the shared helper.
	TTLMinutes int `json:"ttl_minutes"`
	// InstallBaseURL is required. The platform BE computes it from
	// the SOC console's public URL (sentraops.5-189-177-170.sslip.io)
	// rather than re-deriving it server-side — the SOC console
	// knows the URL the customer will see in their browser, the
	// fork binary does not.
	InstallBaseURL string `json:"install_base_url"`
}

// EnrollTokenResponse is the body returned on success. Stable wire
// shape consumed by the R-I.9 SOC console's Send Executor modal.
type EnrollTokenResponse struct {
	Token        string    `json:"token"`         // plaintext, shown once
	TokenHash    string    `json:"token_hash"`
	TenantID     string    `json:"tenant_id"`
	ZoneIDs      []string  `json:"zone_ids"`
	ExecutorName string    `json:"executor_name"`
	Hostname     string    `json:"hostname"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	InstallLink  string    `json:"install_link"`
}

// EnrollTokenHandler is the platform-BE-facing mint endpoint (R-I.9).
//
// It is the counterpart of ``mint-token`` CLI but driven by HTTP
// from the SOC console's Send Executor modal. The actual mint work
// is shared with the CLI via ``pkg/enrollment/mint.Token`` so the
// two surfaces cannot drift on TTL math, URL shape, or row contents.
//
// Auth posture (same shape as RegisterHandler — R-I.1.d):
//
//   - missing X-Register-Token            → 401 register_token_required
//   - missing / empty service JWT        → 401 service_auth_required
//   - service JWT tenant != body.tenant_id → 403 tenant_mismatch
//                                         (the BE's service JWT must
//                                         bind to the tenant it's
//                                         minting on behalf of)
//   - body validation failure           → 400 invalid_request
//   - shared mint helper rejects            → 400 invalid_request
//                                         (e.g. ttl > MaxTTL,
//                                          malformed URL, missing
//                                          tenant)
//   - store insert failure               → 500 internal_error
//   - success                            → 200 + EnrollTokenResponse
//
// The handler is mounted OUTSIDE the executor-auth middleware
// because the BE (not the customer's executor) is the actor.
func EnrollTokenHandler(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get(HeaderRegisterToken)) == "" {
		helpers.WriteErrorStatus(w, "register_token_required", http.StatusUnauthorized)
		return
	}
	rawJWT := strings.TrimSpace(r.Header.Get(apimiddleware.HeaderServiceAuth))
	if rawJWT == "" {
		helpers.WriteErrorStatus(w, "service_auth_required", http.StatusUnauthorized)
		return
	}
	pem := apimiddleware.PlatformPublicKeyPEM
	if len(pem) == 0 {
		helpers.WriteErrorStatus(w, "service_auth_not_configured", http.StatusUnauthorized)
		return
	}
	claims, err := jwt.Verify(rawJWT, pem)
	if err != nil {
		// Same posture as RegisterHandler: don't leak which field
		// failed; collapse to service_auth_invalid.
		helpers.WriteErrorStatus(w, "service_auth_invalid", http.StatusUnauthorized)
		return
	}
	// Publish the verified claims into the request context so
	// downstream audit propagation reads the same actor the
	// TenantBinding middleware would have published.
	if claims.ActorID != "" {
		r = helpers.SetContextValue(r, apimiddleware.ContextKeyActorID, claims.ActorID)
	}
	if claims.TenantID != "" {
		r = helpers.SetContextValue(r, apimiddleware.ContextKeyTenantID, claims.TenantID)
	}
	if len(claims.DeploymentZoneIDs) > 0 {
		r = helpers.SetContextValue(r, apimiddleware.ContextKeyDeploymentZoneIDs, claims.DeploymentZoneIDs)
	}

	// Read body.
	body := EnrollTokenRequest{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		helpers.WriteErrorStatus(w, "invalid_request", http.StatusBadRequest)
		return
	}
	body.TenantID = strings.TrimSpace(body.TenantID)
	body.InstallBaseURL = strings.TrimSpace(body.InstallBaseURL)
	if body.TenantID == "" {
		helpers.WriteErrorStatus(w, "tenant_id_required", http.StatusBadRequest)
		return
	}
	if body.InstallBaseURL == "" {
		helpers.WriteErrorStatus(w, "install_base_url_required", http.StatusBadRequest)
		return
	}
	// Cross-claim guard: the BE's service JWT must bind to the
	// tenant it's minting on behalf of. (Matches RegisterHandler's
	// posture in handlers.go.)
	if strings.TrimSpace(claims.TenantID) == "" {
		helpers.WriteErrorStatus(w, "service_auth_invalid", http.StatusUnauthorized)
		return
	}
	if claims.TenantID != body.TenantID {
		helpers.WriteErrorStatus(w, "tenant_mismatch", http.StatusForbidden)
		return
	}

	// Resolve TTL: 0 → default 5 min, anything > 60 → shared helper
	// rejects (same guard the CLI enforces). The shared helper is
	// the authoritative validator.
	ttl := time.Duration(body.TTLMinutes) * time.Minute

	// Mint via the shared helper.
	store := helpers.Store(r)
	if store == nil {
		log.Error("enroll_token: store not configured")
		helpers.WriteErrorStatus(w, "internal_error", http.StatusInternalServerError)
		return
	}
	res, err := mint.Token(store, mint.Request{
		TenantID:       body.TenantID,
		DeploymentZone: body.DeploymentZoneIDs,
		ExecutorName:   body.ExecutorName,
		Hostname:       body.Hostname,
		TTL:            ttl,
		InstallBaseURL: body.InstallBaseURL,
		Now:            tz.Now(),
	})
	if err != nil {
		// The shared helper's errors are descriptive but
		// SOC-neutral (no internal state, no row contents). Map
		// any of them to 400 + the message; the UI surfaces it
		// verbatim.
		helpers.WriteErrorStatus(w, "invalid_request", http.StatusBadRequest)
		log.WithError(err).WithField("tenant_id", body.TenantID).
			Warn("enroll_token: mint rejected")
		return
	}

	// Audit event. The "actor" is the BE operator (from the service
	// JWT's ActorID); the BE sees the actor's email in the SOC
	// console's top bar so this audit chain end-to-end traces back
	// to a human identity, not "the platform service".
	DefaultPropagator().Propagate(AuditEvent{
		Event:    "enrollment_token.minted",
		TenantID: res.TenantID,
		// ExecutorID is empty here — the token pre-dates the
		// executor row (the row is created at /enroll time, not
		// at mint time).
		Payload: map[string]any{
			"actor":         strings.TrimSpace(claims.ActorID),
			"token_hash":    res.TokenHash,
			"zone_ids":      res.ZoneIDs,
			"executor_name": res.ExecutorName,
			"hostname":      res.Hostname,
			"install_link":  res.InstallLink,
			"ttl_minutes":   int(ttl.Minutes()),
			"observed_at":   tz.Now(),
		},
	})

	helpers.WriteJSON(w, http.StatusOK, EnrollTokenResponse{
		Token:        res.Token,
		TokenHash:    res.TokenHash,
		TenantID:     res.TenantID,
		ZoneIDs:      res.ZoneIDs,
		ExecutorName: res.ExecutorName,
		Hostname:     res.Hostname,
		ExpiresAt:    res.ExpiresAt,
		CreatedAt:    res.CreatedAt,
		InstallLink:  res.InstallLink,
	})
}
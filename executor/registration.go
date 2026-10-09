package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// RegistrationRequest is the body the executor POSTs to
// /api/v1/executor/register on startup. The shape is per
// design doc §7.1.
type RegistrationRequest struct {
	ExecutorID         string   `json:"executor_id"`
	TenantID           string   `json:"tenant_id"`
	DeploymentZoneID   string   `json:"deployment_zone_id"`
	PlatformsSupported []string `json:"platforms_supported"`
	ExecutorVersion    string   `json:"executor_version"`
	AnsibleVersion     string   `json:"ansible_version,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	RegistrationAt     string   `json:"registration_at"`
}

// RegistrationResponse is what the server returns on a
// successful registration. The `executor_token` is the bearer
// the executor uses for every subsequent call (heartbeat, claim,
// result). The `expires_at` is a server-side hint; the executor
// refreshes when it sees a 401 with `token expired` in the
// response body.
type RegistrationResponse struct {
	ExecutorToken string    `json:"executor_token"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// Registration registers the executor with the
// `semaphore-deployer` fork. The server validates the body:
// `tenant_id` + `deployment_zone_id` are mandatory; both must be
// non-empty. Anything else is hard-rejected (fail-closed).
//
// The call is authenticated with a service JWT signed by the
// executor's Ed25519 key — proving possession of the private
// key without exposing it. The server's R-I.1.d verifier
// (`pkg/jwt.Verify`) accepts Ed25519 keys for this exact case.
func Registration(
	ctx context.Context,
	client *HTTPClient,
	signer Signer,
	req RegistrationRequest,
) (*RegistrationResponse, error) {
	if client == nil {
		return nil, errors.New("executor/registration: client is required")
	}
	if signer == nil {
		return nil, errors.New("executor/registration: signer is required")
	}
	if req.TenantID == "" {
		return nil, errors.New("executor/registration: tenant_id is required")
	}
	if req.DeploymentZoneID == "" {
		return nil, errors.New("executor/registration: deployment_zone_id is required")
	}
	if req.ExecutorID == "" {
		return nil, errors.New("executor/registration: executor_id is required")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("executor/registration: marshal request: %w", err)
	}

	token, err := signer.Sign(ExecutorClaims{
		ExecutorID:       req.ExecutorID,
		TenantID:         req.TenantID,
		DeploymentZoneID: req.DeploymentZoneID,
	})
	if err != nil {
		return nil, fmt.Errorf("executor/registration: sign JWT: %w", err)
	}

	httpResp, err := client.Do(ctx, http.MethodPost, "/api/v1/executor/register", token, body)
	if err != nil {
		return nil, fmt.Errorf("executor/registration: POST: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusCreated && httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("executor/registration: server returned %d (expected 200/201)",
			httpResp.StatusCode)
	}

	var resp RegistrationResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("executor/registration: decode response: %w", err)
	}
	if resp.ExecutorToken == "" {
		return nil, errors.New("executor/registration: server returned empty executor_token")
	}
	return &resp, nil
}

// RegistrationError classifies why a registration attempt
// failed. The lifecycle code uses this to decide between
// RETRY (transient: 5xx, network error) and FAIL (4xx: config
// problem the operator must fix).
type RegistrationError struct {
	// StatusCode is the HTTP status code from the server, or
	// 0 for a network / non-HTTP failure.
	StatusCode int
	// Transient is true for retriable failures (5xx, network
	// errors, timeouts) and false for permanent ones
	// (4xx: the server said "this request is invalid" or
	// "you are not authorized", which retries won't fix).
	Transient bool
	// Underlying is the raw error from the transport layer
	// (or the HTTP status text, if the request did complete).
	Underlying error
}

func (e *RegistrationError) Error() string {
	if e.Underlying == nil {
		return fmt.Sprintf("executor/registration: status=%d transient=%v",
			e.StatusCode, e.Transient)
	}
	return fmt.Sprintf("executor/registration: status=%d transient=%v: %v",
		e.StatusCode, e.Transient, e.Underlying)
}

func (e *RegistrationError) Unwrap() error { return e.Underlying }

// IsTransient returns true if the registration error is
// retriable. The caller (lifecycle) uses this to decide
// whether to back off + retry or fail the daemon.
func IsTransientRegistrationError(err error) bool {
	var re *RegistrationError
	if errors.As(err, &re) {
		return re.Transient
	}
	// Any non-classified error is treated as transient
	// (network blip, DNS, etc.) — better to retry than to
	// crash on a transient hiccup.
	return true
}

// ClassifyHTTPResponseError converts a server HTTP response
// with a non-2xx status into a typed RegistrationError.
// 4xx (except 408 + 429) is permanent; 5xx + 408 + 429 +
// network errors are transient.
func ClassifyHTTPResponseError(statusCode int, body []byte) error {
	transient := statusCode >= 500 ||
		statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusTooManyRequests
	return &RegistrationError{
		StatusCode: statusCode,
		Transient:  transient,
		Underlying: fmt.Errorf("status %d: %s", statusCode, string(bytes.TrimSpace(body))),
	}
}

// registrationRequestWithDefaults applies defaults to a
// RegistrationRequest so a minimal config (executor_id +
// tenant_id + deployment_zone_id) is enough to register.
// Returns the augmented request + a list of warnings about
// fields that were defaulted.
func registrationRequestWithDefaults(
	req RegistrationRequest,
	defaultPlatforms []string,
	defaultVersion string,
	hostname string,
) RegistrationRequest {
	if len(req.PlatformsSupported) == 0 {
		req.PlatformsSupported = defaultPlatforms
	}
	if req.ExecutorVersion == "" {
		req.ExecutorVersion = defaultVersion
	}
	if req.Hostname == "" {
		req.Hostname = hostname
	}
	if req.RegistrationAt == "" {
		req.RegistrationAt = time.Now().UTC().Format(time.RFC3339)
	}
	return req
}

// logRegistrationResult is a small helper so the lifecycle
// loop can log success/failure without re-implementing the
// field list. We pass the logger explicitly (no globals) so
// tests can capture the output.
func logRegistrationResult(logger *logrus.Logger, ok bool, executorID string, latency time.Duration, err error) {
	fields := logrus.Fields{
		"executor_id": executorID,
		"latency_ms":  latency.Milliseconds(),
	}
	if ok {
		logger.WithFields(fields).Info("executor: registered")
		return
	}
	fields["error"] = err.Error()
	logger.WithFields(fields).Error("executor: registration failed")
}

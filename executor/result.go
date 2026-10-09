package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ResultRequest is the body the executor POSTs to
// /api/v1/executor/result. Shape per design doc §7.3.
// InstallLogExcerpt is the SANITIZED log slice (see
// sanitize.go); secrets must NEVER appear here.
type ResultRequest struct {
	JobID            string `json:"task_id"`
	CampaignID       string `json:"campaign_id"`
	TenantID         string `json:"tenant_id"`
	ZoneID           string `json:"deployment_zone_id"`
	ExecutorID       string `json:"executor_id"`
	TargetSystemID   string `json:"target_system_id"`
	Outcome          string `json:"outcome"`
	StartedAt        string `json:"started_at"`
	CompletedAt      string `json:"completed_at"`
	InstallLogExcerpt string `json:"install_log_excerpt"`
	ErrorClass       string `json:"error_class,omitempty"`
	ErrorMessage     string `json:"error_message,omitempty"`
	// SentAt is the audit envelope: every result carries the
	// wall-clock time at which the executor constructed the
	// POST. The server uses this for ordering + deduplication
	// when retries overlap with the offline-timeout window.
	SentAt string `json:"sent_at"`
}

// Result reports the outcome of a single job to the server.
// The server updates the campaign's `installed_count` /
// `failed_count` / `wave_history` based on this payload. If
// the executor never sends a result (e.g. crash), the
// server's offline timeout (5 min default) releases the
// claimed job back to the claim pool and may transition the
// campaign to DEGRADED.
//
// The call is idempotent: re-sending the same result with
// the same `task_id` is a no-op (server-side dedup). The
// executor retries on 5xx with exponential backoff but
// gives up on 4xx (the result is malformed and retrying
// won't fix it).
func Result(
	ctx context.Context,
	client *HTTPClient,
	bearer string,
	signer Signer,
	req ResultRequest,
) error {
	if client == nil {
		return errors.New("executor/result: client is required")
	}
	if signer == nil {
		return errors.New("executor/result: signer is required")
	}
	if req.JobID == "" {
		return errors.New("executor/result: task_id is required")
	}
	if req.CampaignID == "" {
		return errors.New("executor/result: campaign_id is required")
	}
	if req.ExecutorID == "" {
		return errors.New("executor/result: executor_id is required")
	}
	if req.TargetSystemID == "" {
		return errors.New("executor/result: target_system_id is required")
	}
	if req.TenantID == "" {
		return errors.New("executor/result: tenant_id is required")
	}
	if req.ZoneID == "" {
		return errors.New("executor/result: deployment_zone_id is required")
	}
	if req.Outcome == "" {
		return errors.New("executor/result: outcome is required")
	}
	if req.SentAt == "" {
		req.SentAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Defensive sanitize (in case the caller passed a raw log
	// that bypassed the Sanitize helper). The contract is that
	// InstallLogExcerpt is sanitized at the boundary; this
	// double-checks the contract.
	req.InstallLogExcerpt = Sanitize(req.InstallLogExcerpt)

	token, err := signer.Sign(ExecutorClaims{
		ExecutorID:       req.ExecutorID,
		TenantID:         req.TenantID,
		DeploymentZoneID: req.ZoneID,
	})
	if err != nil {
		return fmt.Errorf("executor/result: sign JWT: %w", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("executor/result: marshal request: %w", err)
	}

	httpResp, err := client.Do(ctx, http.MethodPost, "/api/v1/executor/result", token, body)
	if err != nil {
		return fmt.Errorf("executor/result: POST: %w", err)
	}
	defer httpResp.Body.Close()

	// 204 = no content (the server recorded the result; no
	// response body). 200 is also acceptable. 4xx is permanent
	// (malformed result, will not succeed on retry); 5xx is
	// transient (server hiccup; retry with backoff).
	if httpResp.StatusCode == http.StatusNoContent ||
		httpResp.StatusCode == http.StatusOK {
		return nil
	}
	if httpResp.StatusCode >= 500 {
		return fmt.Errorf("executor/result: server returned %d (transient, will retry)",
			httpResp.StatusCode)
	}
	return fmt.Errorf("executor/result: server returned %d (permanent, will not retry)",
		httpResp.StatusCode)
}

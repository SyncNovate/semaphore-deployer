package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ClaimRequest is the body the executor POSTs to
// /api/v1/executor/claim on every poll. The executor
// intentionally sends ONLY its bound (tenant_id,
// deployment_zone_id) — the server's R-I.1.d executor
// middleware filters server-side; the executor cannot ask
// for jobs outside its scope (UI-level filtering is never
// the only check, per design doc §7.2).
type ClaimRequest struct {
	ExecutorID     string `json:"executor_id"`
	TenantID       string `json:"tenant_id"`
	ZoneID         string `json:"deployment_zone_id"`
	MaxClaimCount  int    `json:"max_claim_count"`
	ClaimedSinceTs int64  `json:"claimed_since_ts,omitempty"` // server hint; not used by executor yet
	// SentAt is the audit envelope: every claim carries the
	// wall-clock time at which the executor constructed the
	// request. The server uses this for ordering / forensic
	// analysis if a job is multi-claimed. RFC3339 UTC.
	SentAt string `json:"sent_at"`
}

// ClaimJob is a single job the executor can run. The shape
// mirrors design doc §7.2; the executor fills the local
// `(claimed_at, claimed_by)` on a successful claim and
// re-emits them in the result payload.
type ClaimJob struct {
	JobID         string                 `json:"job_id"`
	CampaignID    string                 `json:"campaign_id"`
	TargetSystemID string                `json:"target_system_id"`
	TenantID      string                 `json:"tenant_id"`
	ZoneID        string                 `json:"deployment_zone_id"`
	Platform      string                 `json:"platform"`
	Playbook      PlaybookRef            `json:"playbook"`
	CredentialRef string                 `json:"credential_ref"`
	Extra         map[string]interface{} `json:"extra,omitempty"`
}

// PlaybookRef points the executor at the playbook file the
// server's repo shipped for this job. The executor reads
// the file locally (R-I.5 + R-I.6 write the Windows / Linux
// playbooks; this skeleton just runs whatever path the
// server returned).
type PlaybookRef struct {
	Path     string            `json:"path"`
	SHA256   string            `json:"sha256"`
	Env      map[string]string `json:"env,omitempty"`
}

// ClaimResponse is the server's response. The server is
// allowed to return ZERO jobs (the empty list is a valid
// response — "nothing for you right now, try again in
// `claim_poll_interval_seconds`").
type ClaimResponse struct {
	Jobs []ClaimJob `json:"jobs"`
}

// Claim polls the server for claimable jobs. Returns the
// list of jobs (possibly empty), or an error. The caller is
// responsible for the poll loop (every `claim_poll_interval_seconds`).
func Claim(
	ctx context.Context,
	client *HTTPClient,
	bearer string,
	signer Signer,
	req ClaimRequest,
) ([]ClaimJob, error) {
	if client == nil {
		return nil, errors.New("executor/claim: client is required")
	}
	if signer == nil {
		return nil, errors.New("executor/claim: signer is required")
	}
	if req.ExecutorID == "" {
		return nil, errors.New("executor/claim: executor_id is required")
	}
	if req.TenantID == "" {
		return nil, errors.New("executor/claim: tenant_id is required")
	}
	if req.ZoneID == "" {
		return nil, errors.New("executor/claim: deployment_zone_id is required")
	}
	if req.MaxClaimCount < 1 {
		req.MaxClaimCount = 1
	}
	if req.MaxClaimCount > 10 {
		req.MaxClaimCount = 10
	}
	if req.SentAt == "" {
		req.SentAt = time.Now().UTC().Format(time.RFC3339)
	}

	// The claim request itself is authenticated with a fresh
	// service JWT. The bearer token from registration is for
	// the executor's stable identity; the service JWT proves
	// possession of the Ed25519 private key for this specific
	// call (replay protection via the jti + 60s TTL).
	token, err := signer.Sign(ExecutorClaims{
		ExecutorID:       req.ExecutorID,
		TenantID:         req.TenantID,
		DeploymentZoneID: req.ZoneID,
	})
	if err != nil {
		return nil, fmt.Errorf("executor/claim: sign JWT: %w", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("executor/claim: marshal request: %w", err)
	}

	httpResp, err := client.Do(ctx, http.MethodPost, "/api/v1/executor/claim", token, body)
	if err != nil {
		return nil, fmt.Errorf("executor/claim: POST: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("executor/claim: server returned %d (expected 200)",
			httpResp.StatusCode)
	}

	var resp ClaimResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("executor/claim: decode response: %w", err)
	}
	return resp.Jobs, nil
}

// Package commands is the executor-side surface for the
// SentraOps command inbox (R-I.12.b).
//
// Wire model: the platform BE stores rows in
// `sentraops_executor_commands` (BE v53 migration). The SOC
// operator's "Uninstall" click writes a row via
// `POST /api/v1/admin/executors/{id}/uninstall`. The executor
// polls the inbox on a heartbeat-sized interval, picks up
// pending + unexpired rows, dispatches each to a typed
// handler, and acks the result. The payload is JSONB so a
// future command type (rotate_cert, fetch_diagnostics, ...)
// ships without a schema migration.
//
// This file is the wire layer only — `command_loop.go` is the
// goroutine that drives it on a ticker.
package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CommandTypeUninstall is the only command type the executor
// understands today. Future sub-slices add rotate_cert,
// fetch_diagnostics, etc. The executor MUST reject unknown
// command types (no auto-dispatch to a noop handler) so a
// future command type that the executor does not know about
// surfaces as an error instead of a silent no-op.
const CommandTypeUninstall = "uninstall"

// Ack statuses. Mirrors the BE's ack.status validator set
// (IssueUninstallRequest + AckCommandRequest validators).
const (
	AckStatusSuccess = "success"
	AckStatusError   = "error"
	AckStatusRejected = "rejected"
)

// UninstallPayload is the JSONB payload of an uninstall
// command. Today it's just a free-form reason string the
// operator types into the SOC modal. Future fields
// (confirmation_token, forced, etc.) land here.
type UninstallPayload struct {
	Reason string `json:"reason"`
}

// Command is the wire shape of one inbox row. Field names
// match the BE's `ExecutorCommand` Pydantic model (snake_case
// in JSON, matching the dataclass / Pydantic field names
// verbatim).
type Command struct {
	CommandID   string                 `json:"command_id"`
	ExecutorID  string                 `json:"executor_id"`
	TenantID    string                 `json:"tenant_id"`
	CommandType string                 `json:"command_type"`
	Payload     map[string]interface{} `json:"payload"`
	IssuedBy    string                 `json:"issued_by"`
	IssuedAt    time.Time              `json:"issued_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	AckedAt     *time.Time             `json:"acked_at,omitempty"`
	AckStatus   *string                `json:"ack_status,omitempty"`
	AckMessage  *string                `json:"ack_message,omitempty"`
}

// ListResponse mirrors the BE's list endpoint envelope
// (`{"executor_id": ..., "commands": [...], "count": N}`).
// Bare arrays used to crash the FE dashboard (R-I.9 lesson
// re-applied to the executor side) — every list endpoint
// returns this envelope even when empty.
type ListResponse struct {
	ExecutorID string    `json:"executor_id"`
	Commands   []Command `json:"commands"`
	Count      int       `json:"count"`
}

// AckRequest is the body of `POST /api/v1/executors/{id}/
// commands/{cid}/ack`. The BE accepts `status` + `message`
// in any combination.
type AckRequest struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// AckResponse is the updated row returned on a successful
// ack. The BE returns the full row so the executor can log
// the chain-linked `ack_at` timestamp.
type AckResponse struct {
	CommandID  string    `json:"command_id"`
	ExecutorID string    `json:"executor_id"`
	AckedAt    time.Time `json:"acked_at"`
	AckStatus  string    `json:"ack_status"`
	AckMessage string    `json:"ack_message"`
}

// HTTPDoer is the minimal client surface this package needs.
// PlatformClient implements it. Tests pass a stub.
type HTTPDoer interface {
	Do(ctx context.Context, method, path string, body []byte) (*http.Response, error)
}

// Client is the typed wrapper around the platform BE's
// command-inbox endpoints. It is constructed once and
// shared across the executor's command loop + tests.
type Client struct {
	doer HTTPDoer
}

// NewClient wires a typed inbox client to a transport. The
// transport is typically PlatformClient (executor package),
// but tests can inject an httptest.Server-backed stub.
func NewClient(doer HTTPDoer) *Client {
	if doer == nil {
		panic("commands: HTTPDoer is required")
	}
	return &Client{doer: doer}
}

// ListPending fetches the inbox rows for one executor that
// are unacked AND unexpired. The BE's route returns rows in
// issuance order. An empty list is a normal "no work right
// now" result, NOT an error.
func (c *Client) ListPending(ctx context.Context, executorID string) ([]Command, error) {
	if executorID == "" {
		return nil, errors.New("commands: executorID is required")
	}
	resp, err := c.doer.Do(ctx, http.MethodGet, "/api/v1/executors/"+executorID+"/commands", nil)
	if err != nil {
		return nil, fmt.Errorf("commands: list GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// 401 from require_api_key. The shared key is wrong
		// or missing — surface a clear error so the operator
		// knows to re-install.
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return nil, fmt.Errorf("commands: list GET returned status %d: %s",
			resp.StatusCode, string(body))
	}

	var out ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("commands: list GET decode: %w", err)
	}
	return out.Commands, nil
}

// ErrUnauthorized is the typed error returned when the
// platform BE rejects the shared key. The command loop
// surfaces this as a hard stop (the operator must re-install
// to refresh the key) rather than a backoff retry.
var ErrUnauthorized = errors.New("commands: platform BE rejected the API key (401); the executor's /etc/sentraops-executor/api_key is wrong or stale — re-run install.sh to refresh")

// Ack posts the result of a command back to the BE. The
// BE records the ack + emits the executor.uninstall.complete
// audit event (chain-linked). Idempotency: re-acking the same
// command_id returns the original ack with no duplicate audit
// event (BE service is the source of truth).
func (c *Client) Ack(ctx context.Context, executorID, commandID, status, message string) (*AckResponse, error) {
	if executorID == "" {
		return nil, errors.New("commands: executorID is required")
	}
	if commandID == "" {
		return nil, errors.New("commands: commandID is required")
	}
	if status == "" {
		return nil, errors.New("commands: status is required")
	}
	// Validate status against the BE's allowed set. The BE
	// also validates, but catching it here produces a
	// clearer Go-side log line and avoids a wasted round
	// trip.
	switch status {
	case AckStatusSuccess, AckStatusError, AckStatusRejected:
		// OK
	default:
		return nil, fmt.Errorf("commands: invalid ack status %q (allowed: success, error, rejected)", status)
	}

	body, err := json.Marshal(AckRequest{Status: status, Message: message})
	if err != nil {
		return nil, fmt.Errorf("commands: marshal ack body: %w", err)
	}

	path := "/api/v1/executors/" + executorID + "/commands/" + commandID + "/ack"
	resp, err := c.doer.Do(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, fmt.Errorf("commands: ack POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Either the executor_id is wrong (operator typo)
		// or the command has been deleted by the platform.
		// The ack is a no-op; surface a typed error so the
		// caller can decide to drop the local handler.
		return nil, ErrCommandNotFound
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024))
		return nil, fmt.Errorf("commands: ack POST returned status %d: %s",
			resp.StatusCode, string(bodyBytes))
	}

	var out AckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("commands: ack POST decode: %w", err)
	}
	return &out, nil
}

// ErrCommandNotFound is the typed error when the BE 404s the
// ack (the command was deleted or never existed). The command
// loop treats this as "drop the handler" — no point retrying.
var ErrCommandNotFound = errors.New("commands: command not found on the platform BE (404)")

// DecodeUninstallPayload unmarshals a command's payload into
// UninstallPayload. Today the payload only has a reason
// string; future fields (forced, etc.) land here. Returns
// an error if the payload is missing the reason.
func DecodeUninstallPayload(c Command) (UninstallPayload, error) {
	var out UninstallPayload
	if c.Payload == nil {
		return out, errors.New("commands: payload is nil")
	}
	raw, err := json.Marshal(c.Payload)
	if err != nil {
		return out, fmt.Errorf("commands: re-marshal payload: %w", err)
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&out); err != nil {
		return out, fmt.Errorf("commands: decode uninstall payload: %w", err)
	}
	return out, nil
}

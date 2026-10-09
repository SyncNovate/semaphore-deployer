package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HeartbeatRequest is the body the executor POSTs to
// /api/v1/executor/heartbeat on every tick. The `active_job_count`
// is the number of jobs the executor currently has claimed but
// not yet reported a result for. The server uses it for
// observability (capacity planning) and to detect an executor
// that is online but stuck (e.g. claimed jobs that never
// report).
type HeartbeatRequest struct {
	ExecutorID     string `json:"executor_id"`
	Status         string `json:"status"` // "online" | "degraded" | "shutting_down"
	ActiveJobCount int    `json:"active_job_count"`
	Timestamp      string `json:"timestamp"`
}

// HeartbeatRunner sends a heartbeat to the server every
// `interval` until its context is cancelled. The runner is
// idempotent: multiple HeartbeatRunner instances can coexist
// for the same executor if the lifecycle code chooses (we run
// exactly one in the daemon).
//
// The runner is single-goroutine; Start blocks until ctx is
// done. Tests inject a clock + small interval to keep test
// runtime under a second.
type HeartbeatRunner struct {
	client       *HTTPClient
	bearer       string
	request      HeartbeatRequest
	interval     time.Duration
	timeout      time.Duration // per-call HTTP timeout
	logger       *logrus.Logger
	clock        func() time.Time
	mu           sync.Mutex
	lastError    error
	lastSentAt   time.Time
}

// NewHeartbeatRunner builds a runner with the given config. The
// clock defaults to time.Now; tests override for determinism.
func NewHeartbeatRunner(
	client *HTTPClient,
	bearer string,
	request HeartbeatRequest,
	interval time.Duration,
	timeout time.Duration,
	logger *logrus.Logger,
) *HeartbeatRunner {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if logger == nil {
		logger = logrus.New()
	}
	return &HeartbeatRunner{
		client:   client,
		bearer:   bearer,
		request:  request,
		interval: interval,
		timeout:  timeout,
		logger:   logger,
		clock:    time.Now,
	}
}

// SetClock replaces the clock. Tests use this to advance time
// without sleeping. Production code never calls this.
func (h *HeartbeatRunner) SetClock(clock func() time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clock = clock
}

// LastError returns the most recent error from the heartbeat
// loop. nil if the last send succeeded. Tests inspect this to
// verify error-classification logic.
func (h *HeartbeatRunner) LastError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastError
}

// LastSentAt returns the timestamp of the most recent
// successful send. Zero if no send has succeeded yet.
func (h *HeartbeatRunner) LastSentAt() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastSentAt
}

// Start blocks until ctx is cancelled, sending a heartbeat
// every `interval`. The first send is immediate (per
// industry-standard "heartbeat on connect" pattern) so the
// server knows the executor is alive within `interval` of
// startup, not `2 * interval`.
//
// On a 5xx response or a network error, the runner logs a
// WARN and continues. The server's offline-detection logic
// kicks in only if `offline_timeout_minutes` pass without a
// successful heartbeat.
func (h *HeartbeatRunner) Start(ctx context.Context) error {
	if h.client == nil {
		return errors.New("executor/heartbeat: client is required")
	}
	if h.bearer == "" {
		return errors.New("executor/heartbeat: bearer is required")
	}
	if h.request.ExecutorID == "" {
		return errors.New("executor/heartbeat: executor_id is required")
	}

	// Send the first heartbeat immediately so the server knows
	// we're alive ASAP. Subsequent sends are every `interval`.
	if err := h.sendOnce(ctx); err != nil {
		// Don't bail — the server may have been temporarily
		// down at registration time. Heartbeats are best-effort;
		// the offline timeout is the real backstop.
		h.logger.WithError(err).Warn("executor: initial heartbeat failed; will retry on interval")
	}

	t := time.NewTicker(h.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := h.sendOnce(ctx); err != nil {
				h.logger.WithError(err).Warn("executor: heartbeat failed; will retry next tick")
			}
		}
	}
}

// sendOnce executes a single heartbeat send. Updates the
// lastError / lastSentAt fields for tests to inspect.
func (h *HeartbeatRunner) sendOnce(ctx context.Context) error {
	h.mu.Lock()
	h.request.Timestamp = h.clock().UTC().Format(time.RFC3339)
	request := h.request // copy under lock
	bearer := h.bearer
	client := h.client
	timeout := h.timeout
	logger := h.logger
	h.mu.Unlock()

	body, err := json.Marshal(request)
	if err != nil {
		h.recordResult(fmt.Errorf("executor/heartbeat: marshal: %w", err))
		return h.lastError
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resp, err := client.Do(callCtx, http.MethodPost, "/api/v1/executor/heartbeat", bearer, body)
	if err != nil {
		wrapped := fmt.Errorf("executor/heartbeat: POST: %w", err)
		logger.WithError(wrapped).Debug("executor/heartbeat: transport error")
		h.recordResult(wrapped)
		return wrapped
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		wrapped := fmt.Errorf("executor/heartbeat: server returned %d", resp.StatusCode)
		h.recordResult(wrapped)
		return wrapped
	}
	h.recordResult(nil)
	return nil
}

// recordResult updates the lastError / lastSentAt under lock so
// concurrent test goroutines see a consistent snapshot.
func (h *HeartbeatRunner) recordResult(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastError = err
	if err == nil {
		h.lastSentAt = h.clock()
	}
}

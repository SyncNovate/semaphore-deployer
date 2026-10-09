package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Executor is the top-level customer-side process. It owns the
// HTTP client, the signer, the bearer token from registration,
// and the SecretStore. Service orchestrates:
//
//   1. Registration (once at startup; on 5xx, exponential
//      backoff and retry up to a hard ceiling)
//   2. Heartbeat (every HeartbeatInterval until ctx cancelled)
//   3. Claim-and-execute loop (polls every ClaimPollInterval;
//      for every claimed job, runs it and reports the result;
//      backoff on transient errors)
//
// The orchestrator is the integration test target for R-I.4.e.
// Unit tests for the individual pieces live in
// registration_test.go, heartbeat_test.go, claim_test.go, etc.
//
// Why a struct (not a free function): the orchestrator owns
// mutable state (the bearer token from registration, the
// heartbeat runner, the claim loop). A struct with explicit
// Start / Shutdown is the simplest design that supports the
// lifecycle we'd want in production without leaking goroutines.
type Executor struct {
	cfg          Config
	client       *HTTPClient
	signer       Signer
	secrets      SecretStore
	bearerToken  string
	executorID   string
	tenantID     string
	zoneID       string
	logger       *logrus.Logger
	logTailBytes int

	// startOnce + stopOnce enforce the "Start once, Shutdown
	// once" contract; a panic from `go executor.Start()`
	// re-calls is caught by the sync.Once.
	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
	doneCh    chan struct{}

	// heartbeats / claims counters for tests + observability.
	claimsAttempted int
	claimsSucceeded int
	jobsExecuted    int
	jobsReported    int

	mu sync.Mutex
}

// NewExecutor builds the orchestrator from validated config +
// its dependencies. The returned Executor is NOT yet running;
// call Start to begin the registration + heartbeat + claim
// loops and Shutdown (or cancel ctx) to stop.
func NewExecutor(
	cfg Config,
	client *HTTPClient,
	signer Signer,
	secrets SecretStore,
	logger *logrus.Logger,
) (*Executor, error) {
	if logger == nil {
		logger = logrus.New()
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("executor/orchestrator: invalid config: %w", err)
	}
	if client == nil {
		return nil, errors.New("executor/orchestrator: HTTPClient is required")
	}
	if signer == nil {
		return nil, errors.New("executor/orchestrator: Signer is required")
	}
	if secrets == nil {
		// Default to NoopSecretStore so the executor still
		// RUNS in V1; the playbook will fail at run time with
		// a clear error (NoopSecretStore errors are loud).
		secrets = NoopSecretStore{}
	}
	if cfg.ExecutorID == "" {
		// ExecutorID may be auto-assigned at registration.
		// The orchestrator reads it from the registration
		// response; here we treat empty as "let
		// registration assign one".
	}
	return &Executor{
		cfg:          cfg,
		client:       client,
		signer:       signer,
		secrets:      secrets,
		tenantID:     cfg.TenantID,
		zoneID:       cfg.DeploymentZoneID,
		executorID:   cfg.ExecutorID,
		logger:       logger,
		logTailBytes: 64 * 1024,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}, nil
}

// BearerToken returns the bearer token from a successful
// registration (empty until registration completes). Tests
// use this to verify the registration handshake worked.
func (e *Executor) BearerToken() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bearerToken
}

// ExecutorID returns the executor's stable identifier (from
// registration response if it was auto-assigned; otherwise from
// the config).
func (e *Executor) ExecutorID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.executorID
}

// Stats returns a snapshot of orchestrator-level counters for
// tests + observability.
func (e *Executor) Stats() (claimed, jobs, reported int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.claimsAttempted, e.jobsExecuted, e.jobsReported
}

// Start kicks off the registration + heartbeat + claim loops
// in their own goroutines. Returns when ctx is cancelled OR
// Shutdown is called. Idempotent under concurrent calls.
func (e *Executor) Start(ctx context.Context) error {
	if e == nil {
		return errors.New("executor/orchestrator: nil executor")
	}
	registered := false
	e.startOnce.Do(func() {
		// 1. Register (with backoff). We retry up to 5
		// minutes on 5xx / network errors; on 4xx we exit
		// immediately because retrying won't help (the
		// request is malformed or unauthenticated).
		if err := e.registerWithBackoff(ctx); err != nil {
			e.logger.WithError(err).Error("executor/orchestrator: registration failed permanently")
			close(e.doneCh)
			return
		}
		registered = true

		// 2. Heartbeat loop (background goroutine).
		go e.heartbeatLoop(ctx)

		// 3. Claim loop (blocking). The orchestrator blocks
		// here until ctx is cancelled; the heartbeat loop
		// runs independently in the background.
		e.claimLoop(ctx)

		close(e.doneCh)
	})

	if !registered {
		return errors.New("executor/orchestrator: registration failed; see logs")
	}
	return nil
}

// Done returns a channel that's closed when Start's main
// goroutine exits. Callers (and tests) wait on this to ensure
// clean shutdown.
func (e *Executor) Done() <-chan struct{} {
	return e.doneCh
}

// Shutdown signals the executor to stop. Safe to call multiple
// times; the first call closes stopCh, subsequent calls are
// no-ops.
func (e *Executor) Shutdown() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
	})
}

// registerWithBackoff performs the initial registration. On
// transient errors (5xx, network), it backs off and retries up
// to 5 minutes total elapsed. On permanent errors (4xx), it
// returns immediately.
func (e *Executor) registerWithBackoff(ctx context.Context) error {
	backoff, err := NewBackoff(500*time.Millisecond, 30*time.Second)
	if err != nil {
		return fmt.Errorf("create backoff: %w", err)
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req := RegistrationRequest{
			ExecutorID:       e.executorID,
			TenantID:         e.tenantID,
			DeploymentZoneID: e.zoneID,
		}
		resp, err := Registration(ctx, e.client, e.signer, req)
		if err == nil {
			e.mu.Lock()
			e.bearerToken = resp.ExecutorToken
			e.mu.Unlock()
			e.logger.WithFields(logrus.Fields{
				"executor_id": e.executorID,
				"expires_at":  resp.ExpiresAt,
			}).Info("executor/orchestrator: registered")
			return nil
		}
		// Check if it's transient or permanent.
		if !IsTransientRegistrationError(err) {
			return err // 4xx — don't retry
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("registration retries exhausted after 5min: %w", err)
		}
		delay := backoff.Next()
		e.logger.WithError(err).WithField("retry_in", delay).Warn("executor/orchestrator: registration failed; retrying")
		if err := Sleep(ctx, delay); err != nil {
			return err
		}
	}
}

// heartbeatLoop is the background heartbeat goroutine.
func (e *Executor) heartbeatLoop(ctx context.Context) {
	bearer := e.BearerToken()
	if bearer == "" {
		e.logger.Error("executor/orchestrator: heartbeat cannot start without bearer token")
		return
	}
	runner := NewHeartbeatRunner(
		e.client,
		bearer,
		HeartbeatRequest{
			ExecutorID: e.ExecutorID(),
			Status:     "online",
		},
		e.cfg.HeartbeatInterval(),
		5*time.Second,
		e.logger,
	)
	if err := runner.Start(ctx); err != nil {
		e.logger.WithError(err).Error("executor/orchestrator: heartbeat runner exited with error")
	}
}

// claimLoop is the foreground claim + execute + result loop.
// One iteration polls the server; if there are jobs, runs each
// in series and reports the result. On 5xx, backs off and
// retries the poll.
func (e *Executor) claimLoop(ctx context.Context) {
	backoff, _ := NewBackoff(500*time.Millisecond, 10*time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		default:
		}

		e.mu.Lock()
		e.claimsAttempted++
		e.mu.Unlock()

		req := ClaimRequest{
			ExecutorID:    e.ExecutorID(),
			TenantID:      e.tenantID,
			ZoneID:        e.zoneID,
			MaxClaimCount: 5,
		}
		token, err := e.signer.Sign(ExecutorClaims{
			ExecutorID:       req.ExecutorID,
			TenantID:         req.TenantID,
			DeploymentZoneID: req.ZoneID,
		})
		if err != nil {
			e.logger.WithError(err).Error("executor/orchestrator: sign claim JWT failed")
			continue
		}
		jobs, err := Claim(ctx, e.client, e.bearerToken, e.signer, req)
		_ = token // Claim signs internally; we already use the configured signer
		if err != nil {
			e.logger.WithError(err).Warn("executor/orchestrator: claim failed")
			if IsTransientRegistrationError(err) {
				delay := backoff.Next()
				if sleepErr := Sleep(ctx, delay); sleepErr != nil {
					return
				}
				continue
			}
			// Permanent error: still try a non-server-side
			// one — we don't want one bad request to kill
			// the loop. Continue with backoff reset.
			backoff.Reset()
			continue
		}
		backoff.Reset()

		if len(jobs) == 0 {
			// No jobs; sleep for the poll interval.
			if err := Sleep(ctx, e.cfg.ClaimPollInterval()); err != nil {
				return
			}
			continue
		}

		e.mu.Lock()
		e.claimsSucceeded++
		e.mu.Unlock()

		for _, job := range jobs {
			e.executeAndReport(ctx, job)
		}
	}
}

// executeAndReport runs a single job and posts the result.
// Errors are logged + reported as a Result with outcome=failed.
// This is the integration point that is exercised by R-I.4.e.
func (e *Executor) executeAndReport(ctx context.Context, job ClaimJob) {
	e.mu.Lock()
	e.jobsExecuted++
	e.mu.Unlock()

	runResult := Run(ctx, job, e.secrets, e.logTailBytes)

	req := ResultRequest{
		JobID:            job.JobID,
		CampaignID:       job.CampaignID,
		TenantID:         job.TenantID,
		ZoneID:           job.ZoneID,
		ExecutorID:       e.ExecutorID(),
		TargetSystemID:   job.TargetSystemID,
		Outcome:          string(runResult.Outcome),
		StartedAt:        runResult.StartedAt,
		CompletedAt:      runResult.CompletedAt,
		InstallLogExcerpt: runResult.InstallLogExcerpt,
		ErrorClass:       runResult.ErrorClass,
		ErrorMessage:     runResult.ErrorMessage,
	}

	if err := Result(ctx, e.client, e.bearerToken, e.signer, req); err != nil {
		e.logger.WithError(err).WithField("job_id", job.JobID).
			Error("executor/orchestrator: result POST failed")
		return
	}
	e.mu.Lock()
	e.jobsReported++
	e.mu.Unlock()
	e.logger.WithField("job_id", job.JobID).
		WithField("outcome", runResult.Outcome).
		Info("executor/orchestrator: job reported")
}

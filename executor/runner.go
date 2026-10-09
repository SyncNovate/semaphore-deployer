package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// RunResult is the structured outcome of a single job run.
// Mirrors the result payload that the executor POSTs back
// to the server (per design doc §7.3). The InstallLogExcerpt
// is the SANITIZED slice of the ansible-playbook stdout/stderr —
// secrets are stripped before this field is constructed.
type RunResult struct {
	Outcome          Outcome `json:"outcome"`
	StartedAt        string  `json:"started_at"`
	CompletedAt      string  `json:"completed_at"`
	InstallLogExcerpt string  `json:"install_log_excerpt"`
	ErrorClass       string  `json:"error_class,omitempty"`
	ErrorMessage     string  `json:"error_message,omitempty"`
	// ExitedNormally is true if the process exited with code 0
	// and the timeout was not hit. False otherwise.
	ExitedNormally bool `json:"-"`
}

// Outcome is the wire-format result enum.
type Outcome string

const (
	// OutcomeSucceeded means the playbook ran to completion
	// with exit code 0 and no error class.
	OutcomeSucceeded Outcome = "succeeded"
	// OutcomeFailed means the playbook failed (non-zero exit,
	// timeout, or a runtime error before the process started).
	OutcomeFailed Outcome = "failed"
	// OutcomePartial is reserved for future use (e.g. playbook
	// succeeded for some targets but failed for others). V1
	// does not emit it.
	OutcomePartial Outcome = "partial"
)

// Run executes the ansible playbook for a single job and
// returns a sanitized RunResult. The executor is the ONLY
// component that touches the playbook's stdout/stderr — the
// server never sees the raw output. The Sanitize step
// strips any line that contains a secret-shaped substring
// (passwords, tokens, private keys) before the result leaves
// the customer's network.
//
// Why exec.Command (not os/exec via a wrapper script): the
// executor is the trust boundary. We must run the playbook
// with the executor's privileges, capture its output
// directly, and apply the sanitizer BEFORE the result is
// assembled. A wrapper script would split the sanitization
// step away from the executor, opening a log-leak surface.
func Run(ctx context.Context, job ClaimJob, secrets SecretStore, logTailBytes int) RunResult {
	startedAt := time.Now().UTC().Format(time.RFC3339)

	// Resolve the credential_ref into a secret. The SecretStore
	// interface is the contract; V1 ships a no-op stub and R-I.10
	// wires the real backends.
	secret, err := secrets.Resolve(ctx, job.CredentialRef)
	if err != nil {
		now := time.Now().UTC().Format(time.RFC3339)
		return RunResult{
			Outcome:          OutcomeFailed,
			StartedAt:        startedAt,
			CompletedAt:      now,
			InstallLogExcerpt: "",
			ErrorClass:       "credential_resolve_failed",
			ErrorMessage:     err.Error(),
		}
	}
	_ = secret // passed via env to the playbook (see cmd.Env below)

	// Build the ansible-playbook command. We use `-i` for an
	// ad-hoc inventory (single target) + the playbook path
	// from the job. The credential is passed via env so it
	// never appears on the command line (where it would land
	// in `ps` output and process listings).
	cmd := exec.CommandContext(ctx, "ansible-playbook", job.Playbook.Path)
	cmd.Env = append(os.Environ(),
		"SENTRAOPS_EXECUTOR_TARGET_ID="+job.TargetSystemID,
		"SENTRAOPS_EXECUTOR_CAMPAIGN_ID="+job.CampaignID,
		"SENTRAOPS_EXECUTOR_CREDENTIAL="+secret,
	)
	for k, v := range job.Playbook.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	// Cap the log excerpt at `logTailBytes` bytes so a noisy
	// playbook cannot balloon the result payload. We capture
	// full stdout/stderr in a buffer (capped to a hard 10 MB
	// to prevent disk-fill attacks on a misbehaving playbook)
	// and tail the last `logTailBytes` for the excerpt.
	const hardCapBytes = 10 * 1024 * 1024
	var stdout, stderr bytes.Buffer
	stdout.Grow(64 * 1024)
	stderr.Grow(64 * 1024)
	cmd.Stdout = &limitedWriter{w: &stdout, max: hardCapBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, max: hardCapBytes}

	// Enforce a per-job timeout. The heartbeat interval is
	// 10s; a job that doesn't finish in 5 minutes is stuck.
	// The server's offline timeout (5 min default, tunable)
	// catches jobs the executor crashed on; this is the
	// happy-path timeout for jobs that just take too long.
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Re-create the command with the timeout context. We
	// can't mutate cmd in place; the exec.CommandContext
	// returns a *exec.Cmd that wraps the parent cmd with
	// the timeout ctx. We rebuild the env to match what we
	// set above (the original cmd.Env is preserved by
	// CommandContext, so this is defensive belt-and-braces).
	cmd = exec.CommandContext(runCtx, cmd.Args[0], cmd.Args[1:]...)
	cmd.Env = append(os.Environ(),
		"SENTRAOPS_EXECUTOR_TARGET_ID="+job.TargetSystemID,
		"SENTRAOPS_EXECUTOR_CAMPAIGN_ID="+job.CampaignID,
		"SENTRAOPS_EXECUTOR_CREDENTIAL="+secret,
	)
	for k, v := range job.Playbook.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdout = &limitedWriter{w: &stdout, max: hardCapBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, max: hardCapBytes}

	completedAt := time.Now().UTC().Format(time.RFC3339)
	exitedNormally := true
	runErr := cmd.Run()
	if runErr != nil {
		exitedNormally = false
	}

	// Compose the install log excerpt. Combine stdout + stderr
	// (ansible writes to both depending on the plugin), then
	// tail to the configured size, then SANITIZE.
	combined := stdout.String() + stderr.String()
	tail := tailBytes([]byte(combined), logTailBytes)
	excerpt := Sanitize(string(tail))

	result := RunResult{
		Outcome:          OutcomeSucceeded,
		StartedAt:        startedAt,
		CompletedAt:      completedAt,
		InstallLogExcerpt: excerpt,
		ExitedNormally:   exitedNormally,
	}
	if runErr != nil {
		result.Outcome = OutcomeFailed
		result.ErrorClass = classifyError(runErr)
		result.ErrorMessage = runErr.Error()
	}
	return result
}

// tailBytes returns the last `n` bytes of b. If b is shorter than
// n, returns b unchanged. Used to cap the log excerpt at a
// wire-friendly size.
func tailBytes(b []byte, n int) []byte {
	if n <= 0 || len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}

// classifyError maps a process-execution error to a short
// `error_class` string the server can use for routing /
// alerting. Stable identifiers (not human-readable text);
// human text goes in `error_message`.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, exec.ErrNotFound):
		return "executable_not_found"
	}
	// exec.ExitError is the "non-zero exit" case. The
	// sub-classes (ErrNotFound, etc.) cover the
	// exec.Command-level failures; ExitError means the
	// process ran but exited non-zero.
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("exit_%d", exitErr.ExitCode())
	}
	return "exec_error"
}

// limitedWriter is an io.Writer that caps the buffer at `max`
// bytes. Anything past the cap is silently dropped (the
// playbook can keep writing; we just don't capture more
// than `max`). This is the defense against a misbehaving
// playbook that floods the executor's memory.
type limitedWriter struct {
	w       *bytes.Buffer
	max     int
	dropped int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.w.Len() >= l.max {
		l.dropped += len(p)
		return len(p), nil
	}
	remaining := l.max - l.w.Len()
	if len(p) > remaining {
		l.w.Write(p[:remaining])
		l.dropped += len(p) - remaining
		return len(p), nil
	}
	l.w.Write(p)
	return len(p), nil
}

// Sanitize is the public function applied to log excerpts
// before they leave the customer network. Implementation
// lives in sanitize.go; declared here for the executor's
// internal callers.
var Sanitize = sanitizeLog

// SecretStore is the contract for the customer's secret
// resolution. V1 ships a no-op stub (always returns the empty
// string); R-I.10 wires the real backends (env-file,
// HashiCorp Vault, AWS Secrets Manager, etc.).
//
// Why an interface: the executor must work for customers
// using ANY of those stores. Per R-I.4 design decision
// (2026-10-09): stub interface in R-I.4, real backends
// in R-I.10. The interface is the seam.
type SecretStore interface {
	// Resolve returns the plaintext secret for the given
	// `credential_ref`. The reference is the same string
	// the server-side `DeploymentCampaignV1.credential_refs`
	// list contains. The implementation decides how to map
	// that string to a secret (env var, file path, Vault
	// path, etc.).
	Resolve(ctx context.Context, credentialRef string) (string, error)
}

// NoopSecretStore is the V1 default: no secret resolution.
// The playbook gets an empty credential env var. R-I.10
// replaces this with a real backend in customer deployments.
type NoopSecretStore struct{}

func (NoopSecretStore) Resolve(_ context.Context, _ string) (string, error) {
	return "", errors.New("executor/secret: no SecretStore configured (set Config.SecretStore; R-I.10 wires the real backends)")
}

// sanitizeLog is the package-internal implementation. It is
// referenced via the Sanitize variable above so tests can
// override the implementation if they need a tighter /
// looser rule (e.g. for capturing a specific kind of
// redacted output).
func sanitizeLog(s string) string {
	return sanitize(s)
}

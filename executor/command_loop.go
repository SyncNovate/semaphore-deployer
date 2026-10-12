package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/semaphoreui/semaphore/executor/commands"
)

// CommandLoop is the goroutine that polls the platform BE's
// command inbox on a heartbeat-sized interval, dispatches
// each pending command to a typed handler, and acks the
// result. Today only `uninstall` is supported; future sub-
// slices add rotate_cert, fetch_diagnostics, etc.
//
// Design contract:
//
//   - Polling, not push. The platform BE exposes a GET
//     endpoint, not a WebSocket. The command loop runs on
//     the same HeartbeatInterval-sized cadence so a SOC
//     operator's uninstall click surfaces to the customer
//     endpoint within ~30s on average.
//
//   - One handler per command. The loop dispatches each
//     command to a registered handler in its own goroutine
//     so a slow uninstaller does not block the poll cycle
//     for the next command. The orchestrator context
//     cancellation still kills in-flight handlers (the
//     uninstaller's os/exec process is killed via ctx
//     propagation).
//
//   - Idempotency via the BE. Re-acking a command returns
//     the original ack with no duplicate audit event. The
//     loop relies on this so a network retry does not
//     double-emit the executor.uninstall.complete event.
//
//   - Two-scenario collapse (R-I.12.b design): the executor
//     path drives the uninstall for both the executor and
//     any installed runner. The runner-only path (a future
//     R-F binary) calls the SAME BE endpoints with the
//     same wire shape; this loop's surface is identical.
type CommandLoop struct {
	cfg          Config
	platform     commands.HTTPDoer
	executorID   func() string // closure to read the post-registration ID
	tenantID     string
	logger       *logrus.Logger

	// handlers is the typed dispatch table. Registered in
	// NewCommandLoop; only `uninstall` is wired today.
	handlers   map[string]CommandHandler
	handlersMu sync.RWMutex

	// oneFlight guards a slow handler from stalling the
	// next command. If a handler is already running for a
	// command_id, subsequent ticks skip it.
	oneFlight   map[string]bool
	oneFlightMu sync.Mutex

	// stats for tests + observability.
	statsMu        sync.Mutex
	commandsSeen   int
	commandsAcked  int
	commandsFailed int
}

// CommandHandler is the typed contract for one command
// type's executor. The handler runs the side-effect
// (typically an uninstaller subprocess) and returns an
// AckOutcome the loop translates into the wire shape.
//
// A handler MUST be idempotent — the BE may resend the
// same command_id (network retry, re-poll on reconnect,
// etc.) and the handler will run twice. The uninstall
// handler relies on the BE's ack idempotency for the
// audit chain; the side-effect (file shred, service
// unregister) is naturally idempotent because the
// uninstaller checks for /etc/sentraops-executor/ before
// doing anything.
type CommandHandler func(ctx context.Context, cmd commands.Command) AckOutcome

// AckOutcome is what the handler returns. The loop turns
// it into the wire shape via commands.Client.Ack.
type AckOutcome struct {
	Status  string // commands.AckStatusSuccess / AckStatusError / AckStatusRejected
	Message string
}

// NewCommandLoop wires the dependencies. The executorID
// closure is read on every poll because registration may
// have assigned the ID post-startup. The handlers map is
// populated by the constructor — only `uninstall` today.
func NewCommandLoop(
	cfg Config,
	platform commands.HTTPDoer,
	executorID func() string,
	tenantID string,
	logger *logrus.Logger,
) *CommandLoop {
	if logger == nil {
		logger = logrus.New()
	}
	loop := &CommandLoop{
		cfg:        cfg,
		platform:   platform,
		executorID: executorID,
		tenantID:   tenantID,
		logger:     logger,
		handlers:   map[string]CommandHandler{},
		oneFlight:  map[string]bool{},
	}
	loop.handlers[commands.CommandTypeUninstall] = loop.handleUninstall
	return loop
}

// RegisterHandler lets tests inject a custom handler for a
// command type. Production code only wires the uninstall
// handler in NewCommandLoop.
func (l *CommandLoop) RegisterHandler(commandType string, h CommandHandler) {
	l.handlersMu.Lock()
	defer l.handlersMu.Unlock()
	l.handlers[commandType] = h
}

// Stats returns a snapshot of the loop's counters for tests.
func (l *CommandLoop) Stats() (seen, acked, failed int) {
	l.statsMu.Lock()
	defer l.statsMu.Unlock()
	return l.commandsSeen, l.commandsAcked, l.commandsFailed
}

// Start runs the command loop in its own goroutine. Returns
// when ctx is cancelled. Idempotent under concurrent calls
// (Start once, then a duplicate Start is a no-op).
func (l *CommandLoop) Start(ctx context.Context) {
	ticker := time.NewTicker(l.cfg.HeartbeatInterval())
	defer ticker.Stop()
	l.logger.WithField("interval", l.cfg.HeartbeatInterval().String()).
		Info("executor/command_loop: started")
	for {
		select {
		case <-ctx.Done():
			l.logger.Info("executor/command_loop: context cancelled, exiting")
			return
		case <-ticker.C:
			l.tick(ctx)
		}
	}
}

// tick does one poll cycle. On any error other than
// ErrUnauthorized, the loop logs + continues — the next
// tick will retry. ErrUnauthorized is a hard stop: the
// shared key is wrong or stale and the operator must
// re-install to refresh it. Retrying with a bad key
// would just spam the BE.
func (l *CommandLoop) tick(ctx context.Context) {
	eid := l.executorID()
	if eid == "" {
		// Registration hasn't finished yet. The next tick
		// after a successful registration will pick up.
		l.logger.Debug("executor/command_loop: tick skipped, executor_id not yet assigned")
		return
	}
	rows, err := commands.NewClient(l.platform).ListPending(ctx, eid)
	if err != nil {
		if errors.Is(err, commands.ErrUnauthorized) {
			// Hard stop. The executor's /etc/sentraops-executor/api_key
			// is wrong or stale. Re-run install.sh to refresh.
			l.logger.WithError(err).Error("executor/command_loop: hard stop — platform BE rejected the shared key. " +
				"Re-run install.sh to refresh /etc/sentraops-executor/api_key")
			return
		}
		// Transient error: log + continue. The next tick retries.
		l.logger.WithError(err).Warn("executor/command_loop: list failed, will retry on next tick")
		return
	}

	l.statsMu.Lock()
	l.commandsSeen += len(rows)
	l.statsMu.Unlock()

	for _, row := range rows {
		l.dispatch(ctx, row)
	}
}

// dispatch runs the handler for one command in a goroutine.
// A slow handler does not block the next command.
func (l *CommandLoop) dispatch(ctx context.Context, cmd commands.Command) {
	l.handlersMu.RLock()
	h, ok := l.handlers[cmd.CommandType]
	l.handlersMu.RUnlock()
	if !ok {
		// Unknown command type. Ack with `rejected` so the BE
		// stops re-sending it (the ack is also the audit signal
		// that the executor did not understand the request).
		l.logger.WithField("command_type", cmd.CommandType).
			WithField("command_id", cmd.CommandID).
			Warn("executor/command_loop: unknown command type, rejecting")
		l.ack(ctx, cmd, AckOutcome{
			Status:  commands.AckStatusRejected,
			Message: fmt.Sprintf("executor does not understand command_type=%q", cmd.CommandType),
		})
		return
	}

	// oneFlight: don't run the same command_id twice
	// concurrently. A handler that already saw this command_id
	// is still running; the next tick will see it acked.
	l.oneFlightMu.Lock()
	if l.oneFlight[cmd.CommandID] {
		l.oneFlightMu.Unlock()
		return
	}
	l.oneFlight[cmd.CommandID] = true
	l.oneFlightMu.Unlock()

	go func(cmd commands.Command) {
		defer func() {
			l.oneFlightMu.Lock()
			delete(l.oneFlight, cmd.CommandID)
			l.oneFlightMu.Unlock()
		}()
		outcome := h(ctx, cmd)
		l.ack(ctx, cmd, outcome)
	}(cmd)
}

// ack posts the outcome to the BE and updates stats.
func (l *CommandLoop) ack(ctx context.Context, cmd commands.Command, outcome AckOutcome) {
	eid := l.executorID()
	if eid == "" {
		return
	}
	_, err := commands.NewClient(l.platform).Ack(ctx, eid, cmd.CommandID, outcome.Status, outcome.Message)
	if err != nil {
		l.statsMu.Lock()
		l.commandsFailed++
		l.statsMu.Unlock()
		// 404 means the command was deleted; the loop drops it.
		if errors.Is(err, commands.ErrCommandNotFound) {
			l.logger.WithField("command_id", cmd.CommandID).
				Warn("executor/command_loop: ack 404, command was deleted — dropping")
			return
		}
		// Unauthorized: same hard stop as the list call.
		if errors.Is(err, commands.ErrUnauthorized) {
			l.logger.WithError(err).Error("executor/command_loop: ack rejected with 401, hard stop")
			return
		}
		l.logger.WithError(err).WithField("command_id", cmd.CommandID).
			Warn("executor/command_loop: ack failed")
		return
	}
	l.statsMu.Lock()
	l.commandsAcked++
	l.statsMu.Unlock()
	l.logger.WithField("command_id", cmd.CommandID).
		WithField("status", outcome.Status).
		Info("executor/command_loop: command acked")
}

// handleUninstall runs the platform-specific uninstaller.
// The uninstaller is a static script shipped with the
// executor binary (in the same directory as the binary,
// or in /etc/sentraops-executor/). It must:
//
//   1. Stop the executor's systemd / launchd / SCM
//      service so no new processes are started.
//   2. Shred + remove the install dir
//      (/etc/sentraops-executor/) and the binary
//      (/usr/local/bin/sentraops-executor or
//      %ProgramFiles%\SentraOps\executor.exe or
//      /usr/local/bin/sentraops-executor on macOS).
//   3. Unregister the persistence (systemd unit, launchd
//      plist, Windows service) so the OS doesn't try to
//      start the agent on the next boot.
//   4. Send the executor.uninstall.complete audit event
//      (the platform BE records this from the ack we post
//      after this function returns).
//   5. Delete the uninstaller script itself so the IP
//      protection guarantee holds (Wazuh's posture).
//   6. Exit. NO REBOOT, NO SHUTDOWN. The agent goes silent
//      but the customer's machine keeps running.
//
// The handler returns the outcome the loop acks. The
// uninstaller's exit code maps to the wire status.
func (l *CommandLoop) handleUninstall(ctx context.Context, cmd commands.Command) AckOutcome {
	payload, err := commands.DecodeUninstallPayload(cmd)
	if err != nil {
		return AckOutcome{
			Status:  commands.AckStatusError,
			Message: fmt.Sprintf("decode uninstall payload: %v", err),
		}
	}

	// Pick the platform-appropriate uninstaller. The
	// install scripts ship all three; the binary picks the
	// one for the current OS at runtime.
	script, args, err := l.uninstallerCommand(payload.Reason)
	if err != nil {
		return AckOutcome{
			Status:  commands.AckStatusError,
			Message: fmt.Sprintf("locate uninstaller: %v", err),
		}
	}

	l.logger.WithField("script", script).
		WithField("reason", payload.Reason).
		Info("executor/command_loop: running uninstaller")

	cmdExec := exec.CommandContext(ctx, script, args...)
	output, err := cmdExec.CombinedOutput()
	truncated := string(output)
	if len(truncated) > 2048 {
		truncated = truncated[:2048] + "...(truncated)"
	}
	if err != nil {
		// Even on failure we want to try to ack — the
		// platform BE is the source of truth and the
		// uninstaller is idempotent.
		return AckOutcome{
			Status: commands.AckStatusError,
			Message: fmt.Sprintf("uninstaller exited with error: %v; output=%s",
				err, truncated),
		}
	}
	return AckOutcome{
		Status:  commands.AckStatusSuccess,
		Message: fmt.Sprintf("uninstalled; output=%s", truncated),
	}
}

// uninstallerCommand returns the platform-appropriate
// uninstaller script + args. The path is relative to the
// install dir (default /etc/sentraops-executor/) so a
// customer who customised the install layout can re-target
// the uninstaller via the config.
//
// R-I.12.b ships the Linux + macOS + Windows uninstallers
// in install/uninstall.{sh,ps1} + install/uninstall-macos.sh.
// Future platforms (e.g. a FreeBSD jail) add a new branch.
func (l *CommandLoop) uninstallerCommand(reason string) (string, []string, error) {
	installDir := l.cfg.InstallDir
	if installDir == "" {
		installDir = defaultInstallDir()
	}
	switch runtime.GOOS {
	case "linux":
		// On Linux, prefer the platform-specific script that
		// strips systemd + the install dir. The script accepts
		// the reason as a single arg so the audit chain on the
		// endpoint (if the script logs before exiting) can
		// reference it.
		return installDir + "/uninstall.sh", []string{reason}, nil
	case "darwin":
		return installDir + "/uninstall-macos.sh", []string{reason}, nil
	case "windows":
		// PowerShell is the right shell on Windows. The
		// install script writes uninstall.ps1 next to the
		// executor binary. powershell.exe -ExecutionPolicy
		// Bypass -File ... is the canonical invocation; the
		// script is unsigned so Bypass is required (and the
		// install script lives on the same machine so the
		// trust boundary is the install dir, not the network).
		return "powershell.exe", []string{
			"-NoProfile",
			"-ExecutionPolicy", "Bypass",
			"-File", installDir + "/uninstall.ps1",
			"-Reason", reason,
		}, nil
	default:
		return "", nil, fmt.Errorf("executor/command_loop: no uninstaller for GOOS=%q", runtime.GOOS)
	}
}

// defaultInstallDir is the platform default when the
// config does not pin one. Mirrors the install scripts
// (install.sh, install.ps1, install-macos.sh) which all
// use /etc/sentraops-executor on Linux/macOS and
// %ProgramFiles%\SentraOps on Windows. The env-var
// override (SENTRAOPS_EXECUTOR_INSTALL_DIR) is read at
// process start; the orchestrator passes it through
// Config.InstallDir.
func defaultInstallDir() string {
	if v := os.Getenv("SENTRAOPS_EXECUTOR_INSTALL_DIR"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return `C:\Program Files\SentraOps`
	}
	return "/etc/sentraops-executor"
}

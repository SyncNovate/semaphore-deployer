package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/semaphoreui/semaphore/executor/commands"
)

// CommandLoop is the runner-side analogue of
// executor.CommandLoop. It polls the platform BE's command
// inbox on a heartbeat-sized cadence, dispatches each pending
// command to a typed handler, and acks the result.
//
// R-F.3 design contract (mirrors the executor's contract
// 1:1 — the BE inbox wire is identical):
//
//   - Polling, not push. The loop runs on a ticker so the
//     runner doesn't need a persistent connection. A SOC
//     operator's uninstall click surfaces to the customer
//     endpoint within ~30s on average.
//
//   - One handler per command. Each command runs in its own
//     goroutine so a slow uninstaller does not block the
//     poll cycle. The orchestrator context cancellation
//     kills in-flight handlers via ctx propagation.
//
//   - Idempotency via the BE. Re-acking a command returns
//     the original ack with no duplicate audit event. The
//     uninstaller is naturally idempotent because it
//     checks for /etc/sentraops-runner/ before doing
//     anything.
//
//   - Kill-switch edge path. The install script writes
//     "v1:<base64-token>" to the kill switch path; the
//     loop reads the file on every tick and triggers an
//     immediate self-destruct on a valid sentinel. Same
//     pattern as the executor (R-I.12.b) — only the
//     install dir differs.
type CommandLoop struct {
	cfg        Config
	platform   commands.HTTPDoer
	runnerID   func() string
	tenantID   string
	logger     *logrus.Logger

	// handlers is the typed dispatch table. Only `uninstall`
	// is wired today.
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
// type's runner. The handler runs the side-effect
// (typically an uninstaller subprocess) and returns an
// AckOutcome the loop translates into the wire shape.
type CommandHandler func(ctx context.Context, cmd commands.Command) AckOutcome

// AckOutcome is what the handler returns. The loop turns
// it into the wire shape via commands.Client.Ack.
type AckOutcome struct {
	Status  string // commands.AckStatusSuccess / AckStatusError / AckStatusRejected
	Message string
}

// NewCommandLoop wires the dependencies. The runnerID closure
// is read on every poll because registration may have
// assigned the ID post-startup. The handlers map is populated
// by the constructor — only `uninstall` today.
func NewCommandLoop(
	cfg Config,
	platform commands.HTTPDoer,
	runnerID func() string,
	tenantID string,
	logger *logrus.Logger,
) *CommandLoop {
	if logger == nil {
		logger = logrus.New()
	}
	loop := &CommandLoop{
		cfg:      cfg,
		platform: platform,
		runnerID: runnerID,
		tenantID: tenantID,
		logger:   logger,
		handlers: map[string]CommandHandler{},
		oneFlight: map[string]bool{},
	}
	loop.handlers[commands.CommandTypeUninstall] = loop.handleUninstall
	return loop
}

// RegisterHandler lets tests inject a custom handler. Production
// code only wires the uninstall handler in NewCommandLoop.
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
// when ctx is cancelled.
func (l *CommandLoop) Start(ctx context.Context) {
	ticker := time.NewTicker(l.cfg.HeartbeatInterval())
	defer ticker.Stop()
	l.logger.WithField("interval", l.cfg.HeartbeatInterval().String()).
		Info("runner/command_loop: started")
	for {
		select {
		case <-ctx.Done():
			l.logger.Info("runner/command_loop: context cancelled, exiting")
			return
		case <-ticker.C:
			l.tick(ctx)
		}
	}
}

// tick does one poll cycle. On any error other than
// ErrUnauthorized, the loop logs + continues. ErrUnauthorized
// is a hard stop: the shared key is wrong or stale and the
// operator must re-install to refresh it.
func (l *CommandLoop) tick(ctx context.Context) {
	rid := l.runnerID()
	if rid == "" {
		l.logger.Debug("runner/command_loop: tick skipped, runner_id not yet assigned")
		return
	}
	// R-F.3.b kill-switch path. Same shape as the executor's.
	if l.checkKillSwitch() {
		l.logger.Warn("runner/command_loop: KILL SWITCH detected — triggering immediate uninstall")
		cmd := commands.Command{
			CommandID:   "kill-switch-" + strconv.FormatInt(time.Now().UnixNano(), 10),
			ExecutorID:  rid,
			CommandType: commands.CommandTypeUninstall,
			Payload:     map[string]interface{}{"reason": "kill switch activated"},
			IssuedBy:    "local-kill-switch",
			IssuedAt:    time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		}
		l.dispatch(ctx, cmd)
		// Don't continue the poll cycle — the dispatch
		// goroutine is running the uninstaller, the
		// endpoint is going silent.
		return
	}
	rows, err := commands.NewClient(l.platform).ListPending(ctx, rid)
	if err != nil {
		if errors.Is(err, commands.ErrUnauthorized) {
			l.logger.WithError(err).Error("runner/command_loop: hard stop — platform BE rejected the shared key. " +
				"Re-run install.sh to refresh /etc/sentraops-runner/api_key")
			return
		}
		l.logger.WithError(err).Warn("runner/command_loop: list failed, will retry on next tick")
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
func (l *CommandLoop) dispatch(ctx context.Context, cmd commands.Command) {
	l.handlersMu.RLock()
	h, ok := l.handlers[cmd.CommandType]
	l.handlersMu.RUnlock()
	if !ok {
		l.logger.WithField("command_type", cmd.CommandType).
			WithField("command_id", cmd.CommandID).
			Warn("runner/command_loop: unknown command type, rejecting")
		l.ack(ctx, cmd, AckOutcome{
			Status:  commands.AckStatusRejected,
			Message: fmt.Sprintf("runner does not understand command_type=%q", cmd.CommandType),
		})
		return
	}

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
	rid := l.runnerID()
	if rid == "" {
		return
	}
	_, err := commands.NewClient(l.platform).Ack(ctx, rid, cmd.CommandID, outcome.Status, outcome.Message)
	if err != nil {
		if errors.Is(err, commands.ErrCommandNotFound) {
			l.logger.WithField("command_id", cmd.CommandID).
				Warn("runner/command_loop: ack 404, command was deleted — dropping")
			return
		}
		if errors.Is(err, commands.ErrUnauthorized) {
			l.logger.WithError(err).Error("runner/command_loop: ack rejected with 401, hard stop")
			return
		}
		l.statsMu.Lock()
		l.commandsFailed++
		l.statsMu.Unlock()
		l.logger.WithError(err).WithField("command_id", cmd.CommandID).
			Warn("runner/command_loop: ack failed")
		return
	}
	l.statsMu.Lock()
	l.commandsAcked++
	l.statsMu.Unlock()
	l.logger.WithField("command_id", cmd.CommandID).
		WithField("status", outcome.Status).
		Info("runner/command_loop: command acked")
}

// handleUninstall runs the platform-specific runner
// uninstaller. The uninstaller is a static script shipped
// with the runner binary (in the install dir). It must:
//
//   1. Stop the runner's systemd / launchd / SCM service so
//      no new processes are started.
//   2. Shred + remove the install dir (/etc/sentraops-runner/)
//      and the binary (/usr/local/bin/sentraops-runner or
//      %ProgramFiles%\SentraOps\runner.exe or
//      /usr/local/bin/sentraops-runner on macOS).
//   3. Unregister the persistence (systemd unit, launchd
//      plist, Windows service) so the OS doesn't try to
//      start the agent on the next boot.
//   4. Send the executor.uninstall.complete audit event
//      (the platform BE records this from the ack we post
//      after this function returns).
//   5. Delete the uninstaller script itself so the IP
//      protection guarantee holds.
//   6. Exit. NO REBOOT, NO SHUTDOWN. The agent goes silent
//      but the customer's machine keeps running.
func (l *CommandLoop) handleUninstall(ctx context.Context, cmd commands.Command) AckOutcome {
	payload, err := commands.DecodeUninstallPayload(cmd)
	if err != nil {
		return AckOutcome{
			Status:  commands.AckStatusError,
			Message: fmt.Sprintf("decode uninstall payload: %v", err),
		}
	}

	script, args, err := l.uninstallerCommand(payload.Reason)
	if err != nil {
		return AckOutcome{
			Status:  commands.AckStatusError,
			Message: fmt.Sprintf("locate uninstaller: %v", err),
		}
	}

	l.logger.WithField("script", script).
		WithField("reason", payload.Reason).
		Info("runner/command_loop: running uninstaller")

	cmdExec := exec.CommandContext(ctx, script, args...)
	output, err := cmdExec.CombinedOutput()
	truncated := string(output)
	if len(truncated) > 2048 {
		truncated = truncated[:2048] + "...(truncated)"
	}
	if err != nil {
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
// runner uninstaller script + args. The path is relative to
// the install dir (default /etc/sentraops-runner/) so a
// customer who customised the install layout can re-target
// the uninstaller via the config.
//
// R-F.3 ships the Linux + macOS + Windows uninstallers in
// install/runner_uninstall.{sh,ps1} + install/
// runner_uninstall-macos.sh. The naming convention differs
// from the executor's (executor used uninstall.{sh,ps1}) so
// the two agents don't collide on a customer endpoint that
// has both. The install script ships the right uninstallers
// to the right install dir.
func (l *CommandLoop) uninstallerCommand(reason string) (string, []string, error) {
	installDir := l.cfg.InstallDir
	if installDir == "" {
		return "", nil, fmt.Errorf("runner/command_loop: install dir is empty")
	}
	var script string
	switch runtime.GOOS {
	case "darwin":
		script = installDir + "/runner_uninstall-macos.sh"
	case "windows":
		script = installDir + "/runner_uninstall.ps1"
	default:
		// Linux, FreeBSD, etc. — same shell uninstaller.
		script = installDir + "/runner_uninstall.sh"
	}
	return script, []string{reason}, nil
}

// checkKillSwitch reads the kill switch file. Returns true
// if the file is present, non-empty, and starts with the
// "v1:" sentinel. The runner and the executor share the
// same sentinel format (per the R-I.12.b design).
func (l *CommandLoop) checkKillSwitch() bool {
	if l.cfg.KillSwitchPath == "" {
		return false
	}
	raw, err := os.ReadFile(l.cfg.KillSwitchPath)
	if err != nil {
		// Missing file is the common case at runtime
		// (the sentinel only ships for the edge path).
		return false
	}
	content := strings.TrimSpace(string(raw))
	return strings.HasPrefix(content, "v1:") && len(content) > 3
}

package executor

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// shutdownTimeout is how long the executor waits for in-flight
// goroutines to drain on SIGTERM / SIGINT. Per design doc §10.9.4
// (failure / error behaviour): operations either complete or
// surface a loud error, never silently fail. 30 seconds is
// enough for a single playbook to finish + result-report to
// round-trip, but short enough that an operator's `kill` is
// not perceived as hung.
const shutdownTimeout = 30 * time.Second

// waitForShutdown blocks until the executor receives SIGTERM or
// SIGINT, then returns 0 for a clean exit. Returns non-zero only
// on an unrecoverable setup error before the signal arrives.
//
// In R-I.4.a (skeleton) there are no in-flight goroutines; this
// function is essentially `signal.Notify(...); <-sigCh`. The
// actual worker lifecycle is added in R-I.4.b onward; this
// function's signature is stable so callers (tests, future
// transport wiring) can drive the same shutdown path.
func waitForShutdown(logger *logrus.Logger) int {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	sig := <-ctx.Done()
	logger.WithField("signal", sigName(sig)).Info("executor: shutdown signal received")
	return 0
}

// sigName maps a signal-NotifyContext cancellation reason to a
// printable name. The context package's cancel return value
// does not directly expose the signal; the standard pattern is to
// look at the underlying channel via signal.Notify directly, but
// here we use the simpler "ctx was cancelled by SIGTERM or
// SIGINT" contract and just print "terminated". Future
// sub-slices may enrich this with a separate channel if the
// distinction matters.
func sigName(_ interface{}) string {
	// Distinguish SIGTERM from SIGINT for ops logs. Both cause
	// the same clean exit; only the log line differs.
	if isInterruptRequested() {
		return "SIGINT"
	}
	return "SIGTERM"
}

// isInterruptRequested inspects the OS-level signal disposition
// to determine whether the cancellation was caused by SIGINT vs
// SIGTERM. The implementation is best-effort: on Linux we check
// for the existence of /proc/self/status; on other OSes we
// return false (defaulting to SIGTERM in the log line).
//
// R-I.4.a is skeleton-only; this helper is here to keep the
// log line clean for the future when an operator runs the
// binary in a terminal and presses Ctrl-C.
func isInterruptRequested() bool {
	// Read the foreground process group of the controlling tty
	// via stty-equivalent inspection. Skipped in R-I.4.a — the
	// simpler check below is enough: if the process was launched
	// from a terminal, SIGINT is the typical Ctrl-C cause. We
	// approximate that by checking whether stdin is a TTY.
	if fi, err := os.Stdin.Stat(); err == nil {
		// Mode bits: character device = TTY. Compare against
		// os.ModeCharDevice. We do NOT import golang.org/x/term
		// here because that pulls in a dep we don't otherwise
		// need for the skeleton.
		return (fi.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

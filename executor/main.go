// Package executor implements the customer-side deployment executor
// for the SentraOps `semaphore-deployer` fork. The executor is a
// small daemon that runs inside a customer's network and connects
// outbound to our Semaphore fork over mTLS. It claims jobs for the
// (tenant_id, deployment_zone_id) it was registered with, runs the
// Ansible playbook locally, and reports the result back.
//
// R-I.4.a ships the binary skeleton: main.go (entry point),
// config.go (YAML + env config), logging.go (structured JSON),
// lifecycle.go (SIGTERM / SIGINT graceful shutdown). The actual
// mTLS transport (R-I.4.b), registration + heartbeat (R-I.4.c),
// job claim + execute + result (R-I.4.d), and cross-cutting test
// surface (R-I.4.e) are added in subsequent sub-slices.
//
// The `executor` package is a library; the `main` package lives
// in `cmd/executor/main.go` and imports this package to drive
// the actual binary. This split lets tests exercise Main() with
// controlled args + stdio without a `package main` linkage.
package executor

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

// Version is overridden at build time via -ldflags "-X .../executor.Version=v1.2.3".
// The empty string means "unreleased / dev build".
var Version = ""

// Main is the entry point invoked from cmd/executor/main.go's
// func main(). Kept as a function (not inlined) so tests can
// drive the same startup path that production does, including
// flag parsing + config loading + logger init + signal wiring.
//
// The args + stdout + stderr parameters are explicit (rather than
// reading package globals like os.Args / os.Stdout / os.Stderr)
// so tests can drive the full path with controlled inputs.
func Main(args []string, stdout, stderr io.Writer) int {
	// Build a local FlagSet instead of using flag.CommandLine.
	// This keeps Main's flag parsing isolated from the host
	// package's flag setup (so a test running `go test` does
	// not see the executor's flags and vice versa).
	fs := flag.NewFlagSet("sentraops-executor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "/etc/sentraops-executor/config.yaml",
		"path to the executor YAML config file")
	showVersion := fs.Bool("version", false,
		"print the executor version and exit")
	dryRun := fs.Bool("dry-run", false,
		"load + validate the config, print it as JSON, then exit "+
			"(no network calls, no registration, no claim loop)")
	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError already wrote the error message
		// to stderr. Return 2 (the standard exit code for
		// command-line argument errors per BSD sysexits.h).
		return 2
	}

	// Cast stdout to *os.File for the logger. The logger writes
	// every record to stdout (daemon convention: single stream
	// for the SIEM pipeline; downstream filters by `level`).
	stdoutFile := writerToFile(stdout)

	logger := newLogger(stdoutFile)

	if *showVersion {
		fmt.Fprintf(stdout, "sentraops-executor %s\n", versionString())
		return 0
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logger.WithError(err).WithField("config_path", *configPath).
			Error("executor: failed to load config")
		return 1
	}
	if err := cfg.validate(); err != nil {
		logger.WithError(err).Error("executor: config validation failed")
		return 1
	}
	applyLogLevel(logger, cfg.LogLevel)

	if *dryRun {
		// Print the config as JSON for the operator. Sensitive
		// fields (private key paths) are shown by path only — the
		// contents of those files are never loaded into memory
		// during dry-run, so there's nothing to redact.
		out, err := cfg.toRedactedJSON()
		if err != nil {
			logger.WithError(err).Error("executor: failed to render config as JSON")
			return 1
		}
		fmt.Fprintln(stdout, string(out))
		return 0
	}

	logger.WithFields(logrus.Fields{
		"version":             versionString(),
		"server_url":          cfg.ServerURL,
		"tenant_id":           cfg.TenantID,
		"deployment_zone_id":  cfg.DeploymentZoneID,
		"executor_id":         cfg.ExecutorID,
		"offline_timeout_min": cfg.OfflineTimeoutMinutes,
		"config_path":         *configPath,
	}).Info("executor: starting (skeleton)")

	// R-I.4.a ends here. The transport / claim / execute wiring
	// lives in R-I.4.b onward; until then the binary just blocks
	// on a signal so operators can install + start it without it
	// exiting immediately.
	return waitForShutdown(logger)
}

// versionString returns the build-time version, or "<dev>" if empty.
func versionString() string {
	if Version == "" {
		return "<dev>"
	}
	return Version
}

// writerToFile normalizes the io.Writer interface (which
// flag.Parse + fmt.Fprintf accept) to *os.File for the logger.
// If the caller passes a non-File writer (a *bytes.Buffer in a
// test, for example), we substitute os.Stdout so the logger
// still has a working file to write to.
func writerToFile(w io.Writer) *os.File {
	if f, ok := w.(*os.File); ok {
		return f
	}
	return os.Stdout
}

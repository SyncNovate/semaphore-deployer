package runner

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/semaphoreui/semaphore/executor"
)

// Version is overridden at build time via -ldflags "-X .../runner.Version=v1.2.3".
// The empty string means "unreleased / dev build".
var Version = ""

// Main is the entry point invoked from cmd/runner/main.go's
// func main(). Same pattern as executor.Main (R-I.4.a) — kept
// as a function (not inlined) so tests can drive the full
// startup path with controlled args + stdio.
//
// R-F.3 start-up flow:
//   1. Parse --config, --version, --dry-run flags.
//   2. Load + validate the config (server_url + tenant_id are
//      required; the rest have sane defaults).
//   3. Apply the log level.
//   4. Build the platform HTTP client (reads the shared key
//      from disk, fails fast on a missing / mode-relaxed file).
//   5. Construct the command loop.
//   6. Start the loop on its own goroutine.
//   7. Block on SIGINT / SIGTERM and exit cleanly.
func Main(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sentraops-runner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "/etc/sentraops-runner/config.yaml",
		"path to the runner YAML config file")
	showVersion := fs.Bool("version", false,
		"print the runner version and exit")
	dryRun := fs.Bool("dry-run", false,
		"load + validate the config, print it as JSON, then exit "+
			"(no network calls, no platform client, no command loop)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	stdoutFile := writerToFile(stdout)
	logger := newLogger(stdoutFile)

	if *showVersion {
		fmt.Fprintf(stdout, "sentraops-runner %s\n", versionString())
		return 0
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		logger.WithError(err).WithField("config_path", *configPath).
			Error("runner: failed to load config")
		return 1
	}
	if err := cfg.validate(); err != nil {
		logger.WithError(err).Error("runner: config validation failed")
		return 1
	}
	applyLogLevel(logger, cfg.LogLevel)

	if *dryRun {
		out, err := cfg.toRedactedJSON()
		if err != nil {
			logger.WithError(err).Error("runner: failed to render config as JSON")
			return 1
		}
		fmt.Fprintln(stdout, string(out))
		return 0
	}

	// R-F.3.a: build the platform client. The runner reuses
	// the executor's PlatformClient (R-I.12.b) since the wire
	// is identical. A leaked file is a fully-scoped shared
	// secret, not a session for a different system.
	platformCfg := executor.Config{
		ServerURL: cfg.ServerURL,
		TenantID:  cfg.TenantID,
	}
	platform, err := executor.NewPlatformClient(platformCfg, cfg.PlatformAPIKeyPath, 30*time.Second)
	if err != nil {
		logger.WithError(err).Error("runner: platform client init failed")
		return 1
	}
	// Set the user agent to the runner version so the platform
	// can distinguish runner-side from executor-side in the
	// audit chain.
	executor.SetExecutorVersion("sentraops-runner/" + versionString())

	logger.WithFields(logrus.Fields{
		"version":         versionString(),
		"server_url":      cfg.ServerURL,
		"tenant_id":       cfg.TenantID,
		"runner_id":       cfg.RunnerID,
		"install_dir":     cfg.InstallDir,
		"config_path":     *configPath,
		"heartbeat_sec":   cfg.HeartbeatIntervalSec,
	}).Info("runner: starting")

	// R-F.3.a: command loop is the entire surface for the
	// runner. There's no claim / execute / register path
	// (those belong to the executor). The loop runs on its
	// own goroutine; this function blocks on signal.
	loop := NewCommandLoop(
		cfg,
		platform,
		func() string { return cfg.RunnerID },
		cfg.TenantID,
		logger,
	)

	// Context cancellation wired to SIGINT + SIGTERM so a
	// clean shutdown kills in-flight handlers via ctx
	// propagation.
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()
	go loop.Start(ctx)
	<-ctx.Done()
	logger.Info("runner: shutdown signal received, exiting")
	return 0
}

// versionString returns the build-time version, or "<dev>" if empty.
func versionString() string {
	if Version == "" {
		return "<dev>"
	}
	return Version
}

// writerToFile normalizes the io.Writer interface to *os.File.
// Same helper as executor.main (kept here so the package is
// self-contained for tests).
func writerToFile(w io.Writer) *os.File {
	if f, ok := w.(*os.File); ok {
		return f
	}
	return os.Stdout
}

// newLogger builds a structured JSON logger. The runner and
// executor use the same shape so an operator piping both
// binaries' logs into the SIEM gets uniform records.
func newLogger(stdout *os.File) *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(stdout)
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "ts",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "msg",
		},
	})
	return logger
}

// applyLogLevel translates a string log level into the
// logrus level. Defaults to info on an unknown value.
func applyLogLevel(logger *logrus.Logger, level string) {
	switch level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}
}

// toRedactedJSON renders the config as JSON for the
// --dry-run output. The api_key file path is shown by path
// only — the key contents are never loaded into memory
// during dry-run.
func (c *Config) toRedactedJSON() ([]byte, error) {
	type redacted struct {
		ServerURL          string `json:"server_url"`
		TenantID           string `json:"tenant_id"`
		RunnerID           string `json:"runner_id"`
		InstallDir         string `json:"install_dir"`
		PlatformAPIKeyPath string `json:"platform_api_key_path"`
		KillSwitchPath     string `json:"kill_switch_path"`
		HeartbeatIntervalSec int  `json:"heartbeat_interval_sec"`
		LogLevel           string `json:"log_level"`
	}
	return yaml.Marshal(redacted{
		ServerURL:          c.ServerURL,
		TenantID:           c.TenantID,
		RunnerID:           c.RunnerID,
		InstallDir:         c.InstallDir,
		PlatformAPIKeyPath: c.PlatformAPIKeyPath,
		KillSwitchPath:     c.KillSwitchPath,
		HeartbeatIntervalSec: c.HeartbeatIntervalSec,
		LogLevel:           c.LogLevel,
	})
}

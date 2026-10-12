// Package runner implements the customer-side runner-only daemon for
// the SentraOps `semaphore-deployer` fork (R-F.3).
//
// The runner-only binary is a minimal endpoint agent that:
//   1. Polls the platform BE's command inbox on a heartbeat-sized
//      interval (R-F.3.a, R-F.3.b).
//   2. Dispatches each command to a typed handler. Today only
//      `uninstall` is wired (R-F.3.b); future sub-slices add
//      rotate_cert, fetch_diagnostics, etc.
//   3. Acks the result back to the BE so the SOC profile surfaces
//      the new state.
//
// The runner-only path is a SUBSET of the executor path. The
// runner has no job-claim / run-playbook / register-with-server
// surface (those belong to the executor, R-I.4+). The runner is
// a lean agent whose primary job is to receive a remote
// uninstall and self-destruct silently — no reboot, no
// shutdown, per the R-I.12 design locked in by the user's
// 2026-10-11 annotations.
//
// Wire reuse: the runner's command loop imports the executor's
// `executor/commands` package (the BE inbox wire is identical
// for executor-side and runner-side rows). The runner adds
// nothing to the wire; it adds only:
//   - A typed handler for `command_type=uninstall` that calls
//     the platform-specific runner uninstaller.
//   - A kill switch path (R-I.12.b edge case) — the same
//     sentinel file pattern, scoped to the runner's install
//     dir.
//   - A runner_id-shaped identifier (the BE stores the row
//     keyed by `executor_id` regardless of the underlying
//     agent type; the wire is what the BE sees).
//
// The runner package is a library; the `main` package lives in
// `cmd/runner/main.go` and imports this package to drive the
// actual binary. Same pattern as the executor (R-I.4.a).
package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the runner's YAML config. Mirrors executor.Config
// for the fields both agents share (server URL, tenant, install
// dir, log level, API key path, kill switch path). The runner
// does NOT need deployment_zone_id, mTLS cert / key / CA —
// those are executor-side. The runner is registered with the
// platform BE via the same /api/v1/executor/enroll path
// (R-I.10.re2) so the platform has a runner_id (== executor_id
// row key) to address.
type Config struct {
	// ServerURL is the platform BE root (e.g.
	// "https://sentraops.example.com"). The wire is mounted at
	// /api/v1/...
	ServerURL string `yaml:"server_url"`

	// TenantID is the customer's tenant UUID. The platform BE
	// scopes the runner's commands to this tenant; the
	// uninstaller sends the final audit event with this id.
	TenantID string `yaml:"tenant_id"`

	// RunnerID is the platform-assigned identifier returned by
	// /api/v1/executor/enroll. Empty at first-boot; populated
	// after a successful bootstrap exchange. The command loop
	// uses this to address the inbox row; empty means "not yet
	// registered, skip ticks" (same convention as the
	// executor's pre-registration phase).
	RunnerID string `yaml:"runner_id"`

	// InstallDir is where the runner binary + config +
	// platform API key + kill switch live. Default:
	// /etc/sentraops-runner. Mode 0700 enforced by the install
	// script; the binary never changes the mode at runtime.
	InstallDir string `yaml:"install_dir"`

	// PlatformAPIKeyPath is the absolute path of the shared
	// secret file the install script writes (mode 0600). The
	// PlatformClient reads it at startup; a missing file is
	// fatal.
	PlatformAPIKeyPath string `yaml:"platform_api_key_path"`

	// KillSwitchPath is the absolute path of the pre-shared
	// kill-switch sentinel. The install script writes
	// "v1:<base64-token>"; the command loop's tick reads it
	// and triggers an immediate self-destruct on a valid
	// sentinel.
	KillSwitchPath string `yaml:"kill_switch_path"`

	// HeartbeatIntervalSec is the poll cadence. Default 30s.
	// Bounds the SOC's uninstall click → customer endpoint
	// latency at ~30s on average.
	HeartbeatIntervalSec int `yaml:"heartbeat_interval_sec"`

	// LogLevel controls the structured logger. "info" / "warn"
	// / "debug" / "error". Default "info".
	LogLevel string `yaml:"log_level"`
}

// loadConfig reads + validates the YAML config from disk.
// Mirrors executor.loadConfig (R-I.4.a). The runner's config
// is intentionally a subset — fewer fields to misconfigure.
// Uses the same `gopkg.in/yaml.v3` library the executor uses
// so behaviour is uniform across both binaries.
func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("runner: read config: %w", err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("runner: parse YAML: %w", err)
	}
	return cfg, nil
}

// validate applies the cross-field rules. Returns the first
// error so the operator gets a single, clear failure on a
// bad config.
func (c *Config) validate() error {
	if c.ServerURL == "" {
		return errors.New("runner: server_url is required")
	}
	if c.TenantID == "" {
		return errors.New("runner: tenant_id is required")
	}
	if c.InstallDir == "" {
		c.InstallDir = "/etc/sentraops-runner"
	}
	if c.PlatformAPIKeyPath == "" {
		c.PlatformAPIKeyPath = filepath.Join(c.InstallDir, "api_key")
	}
	if c.KillSwitchPath == "" {
		c.KillSwitchPath = filepath.Join(c.InstallDir, "kill_switch")
	}
	if c.HeartbeatIntervalSec <= 0 {
		c.HeartbeatIntervalSec = 30
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return nil
}

// HeartbeatInterval returns the time.Duration representation
// of the configured cadence. Tickers throughout the runner
// use this method so tests can override the config without
// hardcoding durations.
func (c *Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSec) * time.Second
}

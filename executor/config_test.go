package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadConfigFromYAML checks the happy-path: a minimal valid
// YAML file is loaded into a Config and all required fields are
// populated.
func TestLoadConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server_url: "https://semaphore.example.com"
tenant_id: "ORG-001"
deployment_zone_id: "HQ"
client_cert_path: "/etc/sentraops-executor/client.crt"
client_key_path: "/etc/sentraops-executor/client.key"
server_ca_file: "/etc/sentraops-executor/server-ca.pem"
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ServerURL != "https://semaphore.example.com" {
		t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://semaphore.example.com")
	}
	if cfg.TenantID != "ORG-001" {
		t.Errorf("TenantID = %q, want %q", cfg.TenantID, "ORG-001")
	}
	if cfg.DeploymentZoneID != "HQ" {
		t.Errorf("DeploymentZoneID = %q, want %q", cfg.DeploymentZoneID, "HQ")
	}
	if cfg.OfflineTimeoutMinutes != 5 {
		t.Errorf("OfflineTimeoutMinutes default = %d, want %d", cfg.OfflineTimeoutMinutes, 5)
	}
	if cfg.HeartbeatIntervalSeconds != 10 {
		t.Errorf("HeartbeatIntervalSeconds default = %d, want %d", cfg.HeartbeatIntervalSeconds, 10)
	}
	if cfg.ClaimPollIntervalSeconds != 5 {
		t.Errorf("ClaimPollIntervalSeconds default = %d, want %d", cfg.ClaimPollIntervalSeconds, 5)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default = %q, want %q", cfg.LogLevel, "info")
	}
}

// TestLoadConfigEnvOverridesYAML verifies the precedence: env
// vars win over YAML values. Critical for ops who want to inject
// secrets via the environment without re-writing the YAML file.
func TestLoadConfigEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server_url: "https://yaml.example.com"
tenant_id: "ORG-YAML"
deployment_zone_id: "ZONE-YAML"
client_cert_path: "/yaml-cert"
client_key_path: "/yaml-key"
server_ca_file: "/yaml-ca"
offline_timeout_minutes: 99
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	t.Setenv("SENTRAOPS_EXECUTOR_SERVER_URL", "https://env.example.com")
	t.Setenv("SENTRAOPS_EXECUTOR_TENANT_ID", "ORG-ENV")
	t.Setenv("SENTRAOPS_EXECUTOR_DEPLOYMENT_ZONE_ID", "ZONE-ENV")
	t.Setenv("SENTRAOPS_EXECUTOR_OFFLINE_TIMEOUT_MINUTES", "7")

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ServerURL != "https://env.example.com" {
		t.Errorf("ServerURL = %q, env did not win over YAML", cfg.ServerURL)
	}
	if cfg.TenantID != "ORG-ENV" {
		t.Errorf("TenantID = %q, env did not win over YAML", cfg.TenantID)
	}
	if cfg.DeploymentZoneID != "ZONE-ENV" {
		t.Errorf("DeploymentZoneID = %q, env did not win over YAML", cfg.DeploymentZoneID)
	}
	if cfg.OfflineTimeoutMinutes != 7 {
		t.Errorf("OfflineTimeoutMinutes = %d, env override did not apply", cfg.OfflineTimeoutMinutes)
	}
}

// TestLoadConfigMissingFileIsOKWhenEnvProvidesAllFields verifies
// that a missing YAML file is not a hard error if the required
// fields are all present in the env. The operator may deploy the
// executor with a Kubernetes Secret-backed env-only config.
func TestLoadConfigMissingFileIsOKWhenEnvProvidesAllFields(t *testing.T) {
	t.Setenv("SENTRAOPS_EXECUTOR_SERVER_URL", "https://env-only.example.com")
	t.Setenv("SENTRAOPS_EXECUTOR_TENANT_ID", "ORG-001")
	t.Setenv("SENTRAOPS_EXECUTOR_DEPLOYMENT_ZONE_ID", "HQ")
	t.Setenv("SENTRAOPS_EXECUTOR_CLIENT_CERT_PATH", "/env-cert")
	t.Setenv("SENTRAOPS_EXECUTOR_CLIENT_KEY_PATH", "/env-key")
	t.Setenv("SENTRAOPS_EXECUTOR_SERVER_CA_FILE", "/env-ca")

	cfg, err := loadConfig("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("loadConfig should not error on missing file when env covers all fields, got: %v", err)
	}
	if cfg.ServerURL != "https://env-only.example.com" {
		t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://env-only.example.com")
	}
}

// TestValidateMissingFieldsReturnsError verifies the fail-closed
// contract: every required field is checked, and the first
// violation is reported. Operators fix one thing at a time
// rather than chasing a list of 6 errors.
func TestValidateMissingFieldsReturnsError(t *testing.T) {
	cfg := defaults() // all required fields empty
	err := cfg.validate()
	if err == nil {
		t.Fatal("validate should error on a default Config (all required fields empty)")
	}
	if !strings.Contains(err.Error(), "tenant_id") {
		t.Errorf("error message %q should mention tenant_id", err.Error())
	}
}

// TestValidateRejectsZeroIntervals checks the sanity floor on the
// three duration fields. A 0-second heartbeat would flood the
// server; a 0-minute offline timeout would release every job
// before the executor could report it.
func TestValidateRejectsZeroIntervals(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantSub string
	}{
		{
			name:    "heartbeat zero",
			mutate:  func(c *Config) { c.HeartbeatIntervalSeconds = 0 },
			wantSub: "heartbeat_interval_seconds",
		},
		{
			name:    "claim poll zero",
			mutate:  func(c *Config) { c.ClaimPollIntervalSeconds = 0 },
			wantSub: "claim_poll_interval_seconds",
		},
		{
			name:    "offline timeout zero",
			mutate:  func(c *Config) { c.OfflineTimeoutMinutes = 0 },
			wantSub: "offline_timeout_minutes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.validate()
			if err == nil {
				t.Fatalf("validate should reject %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q should mention %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestValidateRejectsUnknownLogLevel checks the log_level enum.
func TestValidateRejectsUnknownLogLevel(t *testing.T) {
	cfg := validConfig()
	cfg.LogLevel = "verbose"
	err := cfg.validate()
	if err == nil {
		t.Fatal("validate should reject unknown log_level")
	}
	if !strings.Contains(err.Error(), "log_level") {
		t.Errorf("error %q should mention log_level", err.Error())
	}
}

// TestOfflineTimeoutDefaultIs5Minutes pins the industry-standard
// default locked at the 2026-10-09 R-I.4 design decision. A future
// refactor that changes this default would silently shift the
// platform's offline-detection behavior; this test catches it.
func TestOfflineTimeoutDefaultIs5Minutes(t *testing.T) {
	cfg := defaults()
	if cfg.OfflineTimeoutMinutes != 5 {
		t.Fatalf("OfflineTimeoutMinutes default = %d, want 5 (industry standard: "+
			"AWS SSM 5 min, Intune 5 min; tunable per design doc §7.4)",
			cfg.OfflineTimeoutMinutes)
	}
}

// TestOfflineTimeoutDurationHelper verifies the time.Duration
// conversion is correct (1 minute = 60 seconds).
func TestOfflineTimeoutDurationHelper(t *testing.T) {
	cfg := validConfig()
	cfg.OfflineTimeoutMinutes = 7
	var want int64 = 7 * 60 * 1_000_000_000 // 7 minutes in nanoseconds
	if got := cfg.OfflineTimeout().Nanoseconds(); got != want {
		t.Errorf("OfflineTimeout() = %v ns, want %v ns", got, want)
	}
}

// validConfig returns a Config that passes validate(). Tests
// that need a starting point use this and then mutate.
func validConfig() Config {
	return Config{
		ServerURL:                 "https://semaphore.example.com",
		TenantID:                  "ORG-001",
		DeploymentZoneID:          "HQ",
		ClientCertPath:            "/c",
		ClientKeyPath:             "/k",
		ServerCAFile:              "/ca",
		HeartbeatIntervalSeconds:  10,
		ClaimPollIntervalSeconds:  5,
		OfflineTimeoutMinutes:     5,
		LogLevel:                  "info",
	}
}

package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the executor's runtime configuration. Every field has
// a non-zero default OR is required at startup — loadConfig +
// validate enforce that contract. Fields with `env:""` tags can be
// overridden via the SENTRAOPS_EXECUTOR_<FIELD> env var, applied
// AFTER the YAML file is loaded (env wins).
//
// The default OfflineTimeoutMinutes is 5 minutes per the
// 2026-10-09 R-I.4 design decision: 5 min default (industry
// standard: AWS SSM uses 5 min, Intune uses 5 min), tunable via
// config. The design doc said 10 min; we picked 5 min so a stuck
// job is detected faster, and operators with slow networks can
// raise it.
type Config struct {
	// ServerURL is the base URL of the `semaphore-deployer` fork
	// (e.g. https://semaphore.example.com). Used as the base for
	// /api/v1/executor/*.
	ServerURL string `yaml:"server_url" env:"SERVER_URL" json:"server_url"`

	// TenantID is the customer's tenant UUID. Hard-rejected by
	// the server if missing. The executor refuses to register
	// with an empty value (fail-closed).
	TenantID string `yaml:"tenant_id" env:"TENANT_ID" json:"tenant_id"`

	// DeploymentZoneID is the customer's deployment zone UUID.
	// Hard-rejected by the server if missing.
	DeploymentZoneID string `yaml:"deployment_zone_id" env:"DEPLOYMENT_ZONE_ID" json:"deployment_zone_id"`

	// ExecutorID is the executor's stable identifier. If empty,
	// the executor generates a fresh ULID at first start and
	// persists it to <config_path>.executor_id so subsequent
	// starts reuse the same ID (so the server's affinity binding
	// doesn't reset).
	ExecutorID string `yaml:"executor_id,omitempty" env:"EXECUTOR_ID" json:"executor_id,omitempty"`

	// ClientCertPath is the path to the executor's Ed25519
	// client certificate (PEM, mTLS).
	ClientCertPath string `yaml:"client_cert_path" env:"CLIENT_CERT_PATH" json:"client_cert_path"`

	// ClientKeyPath is the path to the executor's Ed25519
	// private key (PEM, mTLS). Never sent over the wire.
	ClientKeyPath string `yaml:"client_key_path" env:"CLIENT_KEY_PATH" json:"client_key_path"`

	// ServerCAFile is the path to the CA bundle that signs the
	// server's mTLS certificate. The executor pins against this
	// (no system CAs, no InsecureSkipVerify).
	ServerCAFile string `yaml:"server_ca_file" env:"SERVER_CA_FILE" json:"server_ca_file"`

	// HeartbeatIntervalSeconds is how often the executor sends
	// a heartbeat to the server. Default: 10 seconds.
	HeartbeatIntervalSeconds int `yaml:"heartbeat_interval_seconds,omitempty" env:"HEARTBEAT_INTERVAL_SECONDS" json:"heartbeat_interval_seconds,omitempty"`

	// ClaimPollIntervalSeconds is how often the executor polls
	// for claimable jobs. Default: 5 seconds.
	ClaimPollIntervalSeconds int `yaml:"claim_poll_interval_seconds,omitempty" env:"CLAIM_POLL_INTERVAL_SECONDS" json:"claim_poll_interval_seconds,omitempty"`

	// OfflineTimeoutMinutes is the threshold after which a
	// claimed-but-unreported job is released back to the claim
	// pool (server-side, not here). Default: 5 minutes. The
	// executor itself only consumes this to log a WARN when a
	// claim hasn't reported a result in this duration.
	OfflineTimeoutMinutes int `yaml:"offline_timeout_minutes,omitempty" env:"OFFLINE_TIMEOUT_MINUTES" json:"offline_timeout_minutes,omitempty"`

	// SecretStore is the customer-side secret store backend
	// that resolves `credential_ref` strings to plaintext
	// secrets. Stub interface only in R-I.4.a; R-I.10 wires the
	// real backends (env-file / vault-token / kms-token).
	SecretStore string `yaml:"secret_store,omitempty" env:"SECRET_STORE" json:"secret_store,omitempty"`

	// LogLevel is the structured-logger level (debug / info /
	// warn / error). Default: info.
	LogLevel string `yaml:"log_level,omitempty" env:"LOG_LEVEL" json:"log_level,omitempty"`
}

// defaults returns a Config with sensible defaults. Applied BEFORE
// YAML + env so the user's config wins where it sets a value.
func defaults() Config {
	return Config{
		HeartbeatIntervalSeconds: 10,
		ClaimPollIntervalSeconds:  5,
		OfflineTimeoutMinutes:     5,
		LogLevel:                  "info",
	}
}

// loadConfig reads a YAML file from path, applies env-var
// overrides, applies defaults, and returns a Config. The file is
// not required to exist if all required fields are provided via
// env — in that case path is ignored (logged at INFO).
func loadConfig(path string) (Config, error) {
	cfg := defaults()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				// No file is fine if env is providing the
				// values. Fall through; validate() will
				// fail if anything required is still empty.
			} else {
				return Config{}, fmt.Errorf("read config: %w", err)
			}
		} else {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return Config{}, fmt.Errorf("parse YAML at %s: %w", path, err)
			}
		}
	}

	applyEnvOverrides(&cfg)

	return cfg, nil
}

// applyEnvOverrides walks every tagged env field and overrides
// from the matching env var if it is set. Implemented as a
// hand-rolled switch because there is no reflection-based env
// loader in stdlib and pulling one in for ~10 fields is overkill.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("SENTRAOPS_EXECUTOR_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_TENANT_ID"); v != "" {
		cfg.TenantID = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_DEPLOYMENT_ZONE_ID"); v != "" {
		cfg.DeploymentZoneID = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_EXECUTOR_ID"); v != "" {
		cfg.ExecutorID = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_CLIENT_CERT_PATH"); v != "" {
		cfg.ClientCertPath = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_CLIENT_KEY_PATH"); v != "" {
		cfg.ClientKeyPath = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_SERVER_CA_FILE"); v != "" {
		cfg.ServerCAFile = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_HEARTBEAT_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.HeartbeatIntervalSeconds = n
		}
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_CLAIM_POLL_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ClaimPollIntervalSeconds = n
		}
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_OFFLINE_TIMEOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.OfflineTimeoutMinutes = n
		}
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_SECRET_STORE"); v != "" {
		cfg.SecretStore = v
	}
	if v := os.Getenv("SENTRAOPS_EXECUTOR_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

// validate enforces the required-field contract. Returns the
// first violation so operators fix one thing at a time.
func (c Config) validate() error {
	var missing []string
	if strings.TrimSpace(c.ServerURL) == "" {
		missing = append(missing, "server_url")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		missing = append(missing, "tenant_id")
	}
	if strings.TrimSpace(c.DeploymentZoneID) == "" {
		missing = append(missing, "deployment_zone_id")
	}
	if strings.TrimSpace(c.ClientCertPath) == "" {
		missing = append(missing, "client_cert_path")
	}
	if strings.TrimSpace(c.ClientKeyPath) == "" {
		missing = append(missing, "client_key_path")
	}
	if strings.TrimSpace(c.ServerCAFile) == "" {
		missing = append(missing, "server_ca_file")
	}
	if len(missing) > 0 {
		return fmt.Errorf("required fields missing or empty: %s",
			strings.Join(missing, ", "))
	}
	if c.HeartbeatIntervalSeconds < 1 {
		return fmt.Errorf("heartbeat_interval_seconds must be >= 1, got %d",
			c.HeartbeatIntervalSeconds)
	}
	if c.ClaimPollIntervalSeconds < 1 {
		return fmt.Errorf("claim_poll_interval_seconds must be >= 1, got %d",
			c.ClaimPollIntervalSeconds)
	}
	if c.OfflineTimeoutMinutes < 1 {
		return fmt.Errorf("offline_timeout_minutes must be >= 1, got %d",
			c.OfflineTimeoutMinutes)
	}
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "debug", "info", "warn", "error":
		// ok
	default:
		return fmt.Errorf("log_level must be one of debug/info/warn/error, got %q",
			c.LogLevel)
	}
	return nil
}

// OfflineTimeout returns the offline-timeout as a time.Duration.
// Convenience for callers that want to plug it into a timer.
func (c Config) OfflineTimeout() time.Duration {
	return time.Duration(c.OfflineTimeoutMinutes) * time.Minute
}

// HeartbeatInterval returns the heartbeat interval as a
// time.Duration. Convenience for callers that want to plug it
// into a ticker.
func (c Config) HeartbeatInterval() time.Duration {
	return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
}

// ClaimPollInterval returns the claim poll interval as a
// time.Duration. Convenience for callers that want to plug it
// into a ticker.
func (c Config) ClaimPollInterval() time.Duration {
	return time.Duration(c.ClaimPollIntervalSeconds) * time.Second
}

// toRedactedJSON renders the config as JSON. No redaction needed
// at the field level because the config struct holds PATHS, not
// the cert/key contents. The contents are loaded into memory only
// when the TLS client is constructed (R-I.4.b), and that path is
// not exercised during --dry-run.
func (c Config) toRedactedJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

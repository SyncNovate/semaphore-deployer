package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewSecretStoreFromConfigFailsOnUnknownBackend pins the
// fail-closed "unknown backend" behaviour. A typo in
// `SecretStore: vaultt` (double t) MUST surface at startup,
// not silently fall back to noop.
func TestNewSecretStoreFromConfigFailsOnUnknownBackend(t *testing.T) {
	cfg := validConfigForTest()
	cfg.SecretStore = "vaultt"
	_, err := NewSecretStoreFromConfig(cfg)
	if err == nil {
		t.Error("NewSecretStoreFromConfig should fail on unknown backend")
	} else if !strings.Contains(err.Error(), "unknown backend") {
		t.Errorf("err = %v, want '...unknown backend...'", err)
	}
}

// TestNewSecretStoreFromConfigNoopEmpty pins the empty
// default → NoopSecretStore contract. The historical V1
// behavior.
func TestNewSecretStoreFromConfigNoopEmpty(t *testing.T) {
	cfg := validConfigForTest()
	cfg.SecretStore = ""
	got, err := NewSecretStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewSecretStoreFromConfig: %v", err)
	}
	if _, ok := got.(NoopSecretStore); !ok {
		t.Errorf("got %T, want NoopSecretStore", got)
	}
}

// TestNewSecretStoreFromConfigProcessEnvResolvesHappyPath
// checks the end-to-end via the factory + the processenv
// backend.
func TestNewSecretStoreFromConfigProcessEnvResolvesHappyPath(t *testing.T) {
	t.Setenv("SENTRAOPS_EXECUTOR_CREDENTIAL_TEST_REF", "factory-value")
	cfg := validConfigForTest()
	cfg.SecretStore = SecretStoreBackendProcessEnv
	got, err := NewSecretStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewSecretStoreFromConfig: %v", err)
	}
	val, err := got.Resolve(context.Background(), "test-ref")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if val != "factory-value" {
		t.Errorf("Resolve = %q, want factory-value", val)
	}
}

// TestNewSecretStoreFromConfigEnvFileResolvesHappyPath
// checks the end-to-end via the factory + the env-file
// backend.
func TestNewSecretStoreFromConfigEnvFileResolvesHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.env")
	if err := os.WriteFile(path, []byte("TEST_REF=file-value\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	cfg := validConfigForTest()
	cfg.SecretStore = SecretStoreBackendEnvFile
	cfg.SecretStoreEnvFile = path
	got, err := NewSecretStoreFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewSecretStoreFromConfig: %v", err)
	}
	val, err := got.Resolve(context.Background(), "TEST_REF")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if val != "file-value" {
		t.Errorf("Resolve = %q, want file-value", val)
	}
}

// TestNewSecretStoreFromConfigEnvFileRequiresPath pins the
// fail-closed "no path provided" contract.
func TestNewSecretStoreFromConfigEnvFileRequiresPath(t *testing.T) {
	cfg := validConfigForTest()
	cfg.SecretStore = SecretStoreBackendEnvFile
	cfg.SecretStoreEnvFile = ""
	// Clear the env-var fallback path.
	os.Unsetenv("SENTRAOPS_EXECUTOR_CREDENTIALS_FILE")
	if _, err := NewSecretStoreFromConfig(cfg); err == nil {
		t.Error("NewSecretStoreFromConfig should fail when envfile backend has no path")
	}
}

// TestNewSecretStoreFromConfigVaultRequiresURL pins the
// fail-closed "Vault without URL" contract.
func TestNewSecretStoreFromConfigVaultRequiresURL(t *testing.T) {
	cfg := validConfigForTest()
	cfg.SecretStore = SecretStoreBackendVault
	cfg.SecretStoreVaultURL = ""
	cfg.SecretStoreVaultToken = "any-token"
	if _, err := NewSecretStoreFromConfig(cfg); err == nil {
		t.Error("NewSecretStoreFromConfig should fail when Vault URL is empty")
	}
}

// TestNewSecretStoreFromConfigVaultRequiresToken verifies the
// token requirement (and the env-var fallback works).
func TestNewSecretStoreFromConfigVaultRequiresToken(t *testing.T) {
	// Token via Config — should succeed at construction.
	t.Run("token from config", func(t *testing.T) {
		cfg := validConfigForTest()
		cfg.SecretStore = SecretStoreBackendVault
		cfg.SecretStoreVaultURL = "https://vault.invalid"
		cfg.SecretStoreVaultToken = "x"
		_, err := NewSecretStoreFromConfig(cfg)
		if err != nil {
			t.Errorf("NewSecretStoreFromConfig: %v", err)
		}
	})
	// Token via env — should succeed at construction.
	t.Run("token from env", func(t *testing.T) {
		cfg := validConfigForTest()
		cfg.SecretStore = SecretStoreBackendVault
		cfg.SecretStoreVaultURL = "https://vault.invalid"
		cfg.SecretStoreVaultToken = ""
		t.Setenv("SENTRAOPS_EXECUTOR_VAULT_TOKEN", "from-env")
		_, err := NewSecretStoreFromConfig(cfg)
		if err != nil {
			t.Errorf("NewSecretStoreFromConfig: %v", err)
		}
	})
	// Token missing — should fail.
	t.Run("token missing", func(t *testing.T) {
		cfg := validConfigForTest()
		cfg.SecretStore = SecretStoreBackendVault
		cfg.SecretStoreVaultURL = "https://vault.invalid"
		cfg.SecretStoreVaultToken = ""
		os.Unsetenv("SENTRAOPS_EXECUTOR_VAULT_TOKEN")
		if _, err := NewSecretStoreFromConfig(cfg); err == nil {
			t.Error("NewSecretStoreFromConfig should fail when Vault token is missing")
		}
	})
}

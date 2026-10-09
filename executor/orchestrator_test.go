package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// stubSecretStore is a SecretStore that returns a configured
// value, simulating a fully-wired backend. Production code uses
// real backends in R-I.10.
type stubSecretStore struct {
	value string
}

func (s *stubSecretStore) Resolve(_ context.Context, _ string) (string, error) {
	if s.value == "" {
		return "", errors.New("stubSecretStore: empty value")
	}
	return s.value, nil
}

// TestNewExecutorRejectsInvalidConfig pins the fail-closed
// constructor contract. Bad config must surface at startup,
// not after the first network call.
func TestNewExecutorRejectsInvalidConfig(t *testing.T) {
	cfg := Config{} // missing everything
	client := newInMemoryTestClientPointingAt(t, "https://localhost:8443")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")

	_, err := NewExecutor(cfg, client, signer, &stubSecretStore{value: "x"}, logrus.New())
	if err == nil {
		t.Error("NewExecutor should reject empty config")
	}
}

// TestNewExecutorRejectsNilDependencies pins the nil-check
// contract.
func TestNewExecutorRejectsNilDependencies(t *testing.T) {
	cfg := validConfigForTest()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")
	client := newInMemoryTestClientPointingAt(t, cfg.ServerURL)

	if _, err := NewExecutor(cfg, nil, signer, &stubSecretStore{value: "x"}, logrus.New()); err == nil {
		t.Error("NewExecutor(nil client) should fail")
	}
	if _, err := NewExecutor(cfg, client, nil, &stubSecretStore{value: "x"}, logrus.New()); err == nil {
		t.Error("NewExecutor(nil signer) should fail")
	}
}

// TestExecutorDefaultsToNoopSecretStoreWhenNil verifies the
// orchestrator's nil-SecretStore contract. A deployment that
// forgets to wire a backend still RUNS (the playbook fails at
// run time with a clear error), rather than crashing at
// startup.
func TestExecutorDefaultsToNoopSecretStoreWhenNil(t *testing.T) {
	cfg := validConfigForTest()
	client := newInMemoryTestClientPointingAt(t, cfg.ServerURL)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")

	_, err := NewExecutor(cfg, client, signer, nil, logrus.New())
	if err != nil {
		t.Errorf("NewExecutor(nil secrets) should default to NoopSecretStore, got %v", err)
	}
}

// TestExecutorOfflineTimeoutDefault5Minutes pins the
// industry-standard 5-minute default. Operators with slow
// networks can raise it via Config.OfflineTimeoutMinutes; the
// default must remain 5 unless the design doc changes.
func TestExecutorOfflineTimeoutDefault5Minutes(t *testing.T) {
	cfg := defaults()
	if cfg.OfflineTimeoutMinutes != 5 {
		t.Errorf("OfflineTimeoutMinutes default = %d, want 5", cfg.OfflineTimeoutMinutes)
	}
	if got := cfg.OfflineTimeout(); got != 5*time.Minute {
		t.Errorf("Config.OfflineTimeout() = %v, want 5m", got)
	}
}

// TestExecutorOfflineTimeoutTunable pins that operators can
// raise or lower the timeout via config (R-I.4 design decision:
// "5min default, tunable").
func TestExecutorOfflineTimeoutTunable(t *testing.T) {
	tests := []struct {
		name string
		set  func(*Config)
		want time.Duration
	}{
		{"10min raised", func(c *Config) { c.OfflineTimeoutMinutes = 10 }, 10 * time.Minute},
		{"3min lowered", func(c *Config) { c.OfflineTimeoutMinutes = 3 }, 3 * time.Minute},
		{"1min minimum sane", func(c *Config) { c.OfflineTimeoutMinutes = 1 }, 1 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaults()
			tc.set(&cfg)
			got := cfg.OfflineTimeout()
			if got != tc.want {
				t.Errorf("OfflineTimeout = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestConfigValidationRejectsZeroOfflineTimeout pins that a
// nonsensical OfflineTimeoutMinutes=0 fails at startup, not
// silently accepts a divide-by-zero-equivalent.
func TestConfigValidationRejectsZeroOfflineTimeout(t *testing.T) {
	cfg := validConfigForTest()
	cfg.OfflineTimeoutMinutes = 0
	if err := cfg.validate(); err == nil {
		t.Error("config with offline_timeout_minutes=0 should fail validation")
	}
}

// TestConfigValidationRejectsMissingCert is the (d) cross-cutting
// requirement: missing cert → fail at startup, not at first
// network call.
func TestConfigValidationRejectsMissingCert(t *testing.T) {
	cfg := validConfigForTest()
	cfg.ClientCertPath = ""
	if err := cfg.validate(); err == nil {
		t.Error("config with empty client_cert_path should fail validation")
	}
}

// TestConfigValidationRejectsBadInterval pins that a nonsensical
// interval (0 or negative) fails at startup.
func TestConfigValidationRejectsBadInterval(t *testing.T) {
	cfg := validConfigForTest()
	cfg.HeartbeatIntervalSeconds = 0
	if err := cfg.validate(); err == nil {
		t.Error("config with heartbeat_interval_seconds=0 should fail validation")
	}
	cfg2 := validConfigForTest()
	cfg2.ClaimPollIntervalSeconds = 0
	if err := cfg2.validate(); err == nil {
		t.Error("config with claim_poll_interval_seconds=0 should fail validation")
	}
}

// TestRegistrationWithBackoffEventuallySucceedsAfterRetries is
// the (b) cross-cutting requirement: transient errors → backoff
// and retry; eventually the call succeeds. We spin a small
// httptest that fails with 503 the first 2 calls then returns
// 200 with a token.
func TestRegistrationWithBackoffEventuallySucceedsAfterRetries(t *testing.T) {
	var calls int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if atomic.LoadInt32(&calls) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RegistrationResponse{
			ExecutorToken: "stable-token",
			ExpiresAt:     time.Now().Add(1 * time.Hour),
		})
	}))
	t.Cleanup(func() { srv.Close() })

	client := newInMemoryTestClientPointingAt(t, srv.URL)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")
	cfg := validConfigForTest()

	backoff, _ := NewBackoff(10*time.Millisecond, 50*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := Registration(context.Background(), client, signer, RegistrationRequest{
			ExecutorID:       "EXEC-001",
			TenantID:         cfg.TenantID,
			DeploymentZoneID: cfg.DeploymentZoneID,
		})
		if err != nil {
			if !IsTransientRegistrationError(err) {
				t.Fatalf("non-transient: %v", err)
			}
			_ = Sleep(context.Background(), backoff.Next())
			continue
		}
		if resp.ExecutorToken != "stable-token" {
			t.Errorf("token = %q, want stable-token", resp.ExecutorToken)
		}
		if atomic.LoadInt32(&calls) < 3 {
			t.Errorf("server got %d calls, want >= 3", calls)
		}
		return
	}
	t.Fatal("registration did not succeed within deadline")
}

// TestExecutorStatsCountClaimsAndJobs pins the Stats() surface
// for observability. Tests use it; production exports it.
func TestExecutorStatsCountClaimsAndJobs(t *testing.T) {
	cfg := validConfigForTest()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")
	client := newInMemoryTestClientPointingAt(t, cfg.ServerURL)
	e, err := NewExecutor(cfg, client, signer, &stubSecretStore{value: "x"}, logrus.New())
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	claimed, jobs, reported := e.Stats()
	if claimed != 0 || jobs != 0 || reported != 0 {
		t.Errorf("fresh Executor stats = (%d, %d, %d), want (0, 0, 0)", claimed, jobs, reported)
	}
}

// validConfigForTest returns a Config that passes validate()
// without needing any cert files (testing the config validation
// path in isolation).
func validConfigForTest() Config {
	return Config{
		ServerURL:                "https://localhost:8443",
		TenantID:                 "ORG-001",
		DeploymentZoneID:         "HQ",
		ExecutorID:               "EXEC-001",
		ClientCertPath:           "/tmp/dummy-cert.pem",
		ClientKeyPath:            "/tmp/dummy-key.pem",
		ServerCAFile:             "/tmp/dummy-ca.pem",
		HeartbeatIntervalSeconds: 10,
		ClaimPollIntervalSeconds: 5,
		OfflineTimeoutMinutes:    5,
		LogLevel:                 "info",
	}
}

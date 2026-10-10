package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// HeaderEnrollmentToken is the HTTP header the executor sends to
// /api/v1/executor/enroll. Mirrors the constant in
// api/executor/enroll.go so the contract is anchored on both sides.
const HeaderEnrollmentToken = "X-Enrollment-Token"

// PathCertFileMode is the file mode used for every bootstrap-written
// cert / key file. 0o600 = owner read+write only. World-readable
// certs are refused (matches the existing SecretStore refusal
// posture — R-I.10).
const PathCertFileMode = 0o600

// EnrollResponse is the body returned by POST /api/v1/executor/enroll.
// Mirrors api/executor.EnrollResponse — kept separate so the executor
// doesn't import the api package (which would create a cycle).
type EnrollResponse struct {
	ExecutorID    string `json:"executor_id"`
	ExecutorToken string `json:"executor_token"`
	CertPEM       string `json:"cert_pem"`
	KeyPEM        string `json:"key_pem"`
	CABundlePEM   string `json:"ca_bundle_pem"`
	SentraOpsURL  string `json:"sentraops_url"`
	TenantID      string `json:"tenant_id"`
	ExpiresAt     string `json:"cert_expires_at"`
}

// RunBootstrap is the `--bootstrap` subcommand body. It exchanges the
// short-lived `BootstrapToken` for a long-lived mTLS cert via
// /api/v1/executor/enroll, writes cert + key + CA bundle to the
// paths the normal-mode Config points at, and persists the updated
// config back to disk (with BootstrapToken cleared so a stolen disk
// image cannot replay it).
//
// Idempotent: if cert already exists at cfg.ClientCertPath, this is
// a no-op + log line. The customer's install.sh can safely call it on
// every restart.
//
// On failure the function logs a clear error and returns a non-nil
// error so the install script can surface it to the customer's IT
// admin. The config + bootstrap_token stay on disk so the operator
// can retry without re-running the bundle download.
func RunBootstrap(cfg Config, configPath string, logger *logrus.Logger) error {
	if logger == nil {
		logger = logrus.New()
	}
	if cfg.BootstrapToken == "" {
		// No token → nothing to do. This is the post-migration
		// steady state where the cert was already provisioned
		// by a prior run.
		logger.Info("bootstrap: no enrollment token in config; assuming already enrolled")
		return nil
	}
	if cfg.ServerURL == "" && cfg.BootstrapURL == "" {
		return errors.New("bootstrap: server_url (or bootstrap_url) is required when bootstrap_token is set")
	}
	if cfg.ClientCertPath == "" || cfg.ClientKeyPath == "" || cfg.ServerCAFile == "" {
		return errors.New("bootstrap: client_cert_path, client_key_path, and server_ca_file must all be set in the config")
	}

	// Idempotency: if cert already on disk, no-op. We check
	// ClientCertPath because that's the leaf — if the leaf
	// exists the executor is already enrolled.
	if _, err := os.Stat(cfg.ClientCertPath); err == nil {
		logger.WithField("cert_path", cfg.ClientCertPath).
			Info("bootstrap: cert already present; skipping exchange (idempotent)")
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("bootstrap: stat cert path: %w", err)
	}

	enrollURL := strings.TrimSpace(cfg.BootstrapURL)
	if enrollURL == "" {
		enrollURL = cfg.ServerURL
	}
	enrollURL = strings.TrimRight(enrollURL, "/") + "/api/v1/executor/enroll"

	logger.WithFields(logrus.Fields{
		"enroll_url":       redactURL(enrollURL),
		"tenant_id":        cfg.TenantID,
		"deployment_zone":  cfg.DeploymentZoneID,
		"cert_path":        cfg.ClientCertPath,
	}).Info("bootstrap: exchanging enrollment token for long-lived mTLS cert")

	res, err := postEnroll(enrollURL, cfg.BootstrapToken)
	if err != nil {
		return fmt.Errorf("bootstrap: enroll request failed: %w", err)
	}

	// Persist cert + key + CA bundle atomically (write to tmp,
	// rename). Fail loud if the OS doesn't let us enforce 0o600.
	if err := writeFileAtomic(cfg.ClientCertPath, []byte(res.CertPEM), PathCertFileMode); err != nil {
		return fmt.Errorf("bootstrap: write cert: %w", err)
	}
	if err := writeFileAtomic(cfg.ClientKeyPath, []byte(res.KeyPEM), PathCertFileMode); err != nil {
		// Roll back the cert so we don't leave a half-provisioned
		// state. install.sh will retry.
		_ = os.Remove(cfg.ClientCertPath)
		return fmt.Errorf("bootstrap: write key: %w", err)
	}
	if err := writeFileAtomic(cfg.ServerCAFile, []byte(res.CABundlePEM), PathCertFileMode); err != nil {
		_ = os.Remove(cfg.ClientCertPath)
		_ = os.Remove(cfg.ClientKeyPath)
		return fmt.Errorf("bootstrap: write ca bundle: %w", err)
	}

	// Clear the bootstrap_token in the on-disk config so a stolen
	// disk image cannot replay the exchange. We rewrite the YAML
	// in place rather than using gopkg.in/yaml.v3 because the file
	// may have comments + ordering that we want to preserve; we
	// only flip the line that starts with `bootstrap_token:`.
	if err := clearBootstrapTokenInConfig(configPath); err != nil {
		// Not fatal — the cert is on disk, the token still
		// works, the executor starts. But we want this caught
		// in logs so the operator can manually clean up.
		logger.WithError(err).Warn("bootstrap: could not clear bootstrap_token in config file; " +
			"manually edit " + configPath + " to remove the token")
	}

	// Hash + log the freshly-issued cert fingerprint so they can
	// pin against it later. No secret value is logged.
	if fp, err := fingerprint([]byte(res.CertPEM)); err == nil {
		logger.WithField("cert_fingerprint", fp).
			Info("bootstrap: cert provisioned; executor is ready for normal mode")
	} else {
		logger.Info("bootstrap: cert provisioned; executor is ready for normal mode")
	}
	return nil
}

// postEnroll calls /api/v1/executor/enroll with the supplied token.
// Returns the parsed EnrollResponse on 200; an error otherwise. The
// error wraps the HTTP status + body so the install script / logs
// have the message users see.
//
// Uses a plain HTTP client (no mTLS) because the exchange is
// pre-registration — we don't have a cert yet. The server's TLS
// cert is verified against the system CA pool (NOT InsecureSkipVerify).
func postEnroll(url, token string) (*EnrollResponse, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		},
	}
	defer httpClient.CloseIdleConnections()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(nil))
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderEnrollmentToken, strings.TrimSpace(token))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sentraops-executor/<dev>")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Include the body so the operator sees the server's
		// error message (e.g. enrollment_token_expired).
		return nil, fmt.Errorf("enroll returned HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var res EnrollResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, fmt.Errorf("decode response: %w (body=%q)", err, truncate(bodyBytes, 200))
	}
	if res.CertPEM == "" || res.KeyPEM == "" || res.CABundlePEM == "" {
		return nil, fmt.Errorf("enroll response missing cert_pem / key_pem / ca_bundle_pem")
	}
	if !strings.HasPrefix(res.CertPEM, "-----BEGIN CERTIFICATE-----") {
		return nil, errors.New("enroll response cert_pem is not PEM")
	}
	if !strings.HasPrefix(res.KeyPEM, "-----BEGIN PRIVATE KEY-----") {
		return nil, errors.New("enroll response key_pem is not PEM")
	}
	return &res, nil
}

// writeFileAtomic writes data to path with mode perm. Strategy:
// write to <path>.tmp, fsync, rename onto path. Refuses if the OS
// rejects the chmod (a fat-fingered permission table could
// otherwise silently downgrade the secret).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if perm == 0o000 {
		return errors.New("writeFileAtomic: refusing zero perm")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".sentraops-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup on any failure.
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("chmod tmp to %o: %w", perm, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename tmp → %s: %w", path, err)
	}
	return nil
}

// clearBootstrapTokenInConfig rewrites configPath in place with the
// `bootstrap_token:` line removed (or set to empty). Comments +
// ordering are kept intact. Returns nil when the line was already
// absent or absent (caller can pass an empty file).
func clearBootstrapTokenInConfig(path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	lines := strings.Split(string(data), "\n")
	kept := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "bootstrap_token:") || strings.HasPrefix(trimmed, "bootstrap_url:") {
			continue
		}
		kept = append(kept, line)
	}
	out := strings.Join(kept, "\n")
	// Preserve trailing newline if original had one.
	if strings.HasSuffix(string(data), "\n") && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), PathCertFileMode)
}

// fingerprint returns the SHA-256 hex digest of the supplied PEM
// data (the bytes are the entire PEM block, including the BEGIN/END
// lines — so two certs with the same DER but different PEM wrapping
// hash differently). Used for log-side pinning, not auth.
func fingerprint(data []byte) (string, error) {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// redactURL strips the path + query from a URL for safe logging.
func redactURL(u string) string {
	// Naive split — sufficient for the log-only use case.
	if i := strings.Index(u, "?"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "/api/"); i >= 0 {
		u = u[:i] + "/api/…"
	}
	return u
}

// truncate returns at most n bytes of b. Used in error messages so
// we don't accidentally log the full server response body.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
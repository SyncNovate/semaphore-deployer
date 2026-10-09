package executor

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// TestMainVersionFlag prints the version and exits 0.
func TestMainVersionFlag(t *testing.T) {
	stdout, errFile, closeFn := captureStdout(t)
	defer closeFn()
	stderr, errStderr, closeErr := captureStderr(t)
	defer closeErr()
	if errFile != nil || errStderr != nil {
		t.Fatalf("capture setup: %v / %v", errFile, errStderr)
	}

	rc := Main([]string{"--version"}, stdout, stderr)
	if rc != 0 {
		t.Errorf("--version exit code = %d, want 0", rc)
	}
	got := readCaptured(t, stdout)
	if !strings.Contains(got, "sentraops-executor") {
		t.Errorf("stdout = %q, want contains 'sentraops-executor'", got)
	}
}

// TestMainDryRunValidConfig exercises the dry-run happy path:
// a valid YAML file is loaded, validated, and printed to stdout
// as JSON. The exit code is 0; the config JSON should contain
// every field the YAML set.
func TestMainDryRunValidConfig(t *testing.T) {
	path := writeTempConfig(t, `
server_url: "https://semaphore.example.com"
tenant_id: "ORG-001"
deployment_zone_id: "HQ"
client_cert_path: "/etc/sentraops-executor/client.crt"
client_key_path: "/etc/sentraops-executor/client.key"
server_ca_file: "/etc/sentraops-executor/server-ca.pem"
`)

	stdout, _, closeFn := captureStdout(t)
	defer closeFn()
	stderr, _, closeErr := captureStderr(t)
	defer closeErr()

	rc := Main([]string{"--config", path, "--dry-run"}, stdout, stderr)
	if rc != 0 {
		t.Errorf("exit code = %d, want 0; stderr = %q", rc, readCaptured(t, stderr))
	}

	got := readCaptured(t, stdout)
	var parsed Config
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout = %q", err, got)
	}
	if parsed.TenantID != "ORG-001" {
		t.Errorf("dry-run JSON: TenantID = %q, want ORG-001", parsed.TenantID)
	}
	if parsed.OfflineTimeoutMinutes != 5 {
		t.Errorf("dry-run JSON: OfflineTimeoutMinutes = %d, want 5", parsed.OfflineTimeoutMinutes)
	}
}

// TestMainDryRunMissingConfigReturnsError checks the fail-closed
// contract on a completely empty config (no env, no YAML).
func TestMainDryRunMissingConfigReturnsError(t *testing.T) {
	// Clear every env var the executor reads so loadConfig + validate
	// start from a known-empty state. t.Setenv with empty value is
	// the supported way to clear an env var for the test duration.
	envVars := []string{
		"SENTRAOPS_EXECUTOR_SERVER_URL",
		"SENTRAOPS_EXECUTOR_TENANT_ID",
		"SENTRAOPS_EXECUTOR_DEPLOYMENT_ZONE_ID",
		"SENTRAOPS_EXECUTOR_CLIENT_CERT_PATH",
		"SENTRAOPS_EXECUTOR_CLIENT_KEY_PATH",
		"SENTRAOPS_EXECUTOR_SERVER_CA_FILE",
		"SENTRAOPS_EXECUTOR_EXECUTOR_ID",
		"SENTRAOPS_EXECUTOR_HEARTBEAT_INTERVAL_SECONDS",
		"SENTRAOPS_EXECUTOR_CLAIM_POLL_INTERVAL_SECONDS",
		"SENTRAOPS_EXECUTOR_OFFLINE_TIMEOUT_MINUTES",
		"SENTRAOPS_EXECUTOR_SECRET_STORE",
		"SENTRAOPS_EXECUTOR_LOG_LEVEL",
	}
	for _, e := range envVars {
		t.Setenv(e, "")
	}

	stdout, _, closeFn := captureStdout(t)
	defer closeFn()
	stderr, _, closeErr := captureStderr(t)
	defer closeErr()

	rc := Main([]string{"--config", "/nonexistent/path", "--dry-run"}, stdout, stderr)
	if rc == 0 {
		t.Errorf("exit code = 0, want non-zero; stdout = %q", readCaptured(t, stdout))
	}
	// The validation error is logged via the structured logger
	// which writes to stdout (daemon convention: single stream).
	// The 'stderr' param is accepted by Main for forward
	// compatibility (R-I.4.b may use it for non-logger error
	// output) but is empty in the skeleton.
	got := readCaptured(t, stdout)
	if !strings.Contains(got, "required fields missing") {
		t.Errorf("stdout = %q, want contains 'required fields missing'", got)
	}
}

// TestMainDryRunBadConfigReturnsError: a YAML that fails
// validation (tenant_id is empty after the YAML load) should
// exit non-zero with the validation error in stdout.
func TestMainDryRunBadConfigReturnsError(t *testing.T) {
	path := writeTempConfig(t, `
server_url: "https://semaphore.example.com"
# tenant_id missing on purpose
deployment_zone_id: "HQ"
client_cert_path: "/c"
client_key_path: "/k"
server_ca_file: "/ca"
`)

	stdout, _, closeFn := captureStdout(t)
	defer closeFn()
	stderr, _, closeErr := captureStderr(t)
	defer closeErr()

	rc := Main([]string{"--config", path, "--dry-run"}, stdout, stderr)
	if rc == 0 {
		t.Errorf("exit code = 0, want non-zero; stdout = %q", readCaptured(t, stdout))
	}
	got := readCaptured(t, stdout)
	if !strings.Contains(got, "tenant_id") {
		t.Errorf("stdout = %q, want mentions tenant_id", got)
	}
}

// TestMainBadArgsReturns2: a non-flag argument (or any arg
// flag.Parse does not recognize) returns exit code 2, matching
// the BSD sysexits.h convention.
func TestMainBadArgsReturns2(t *testing.T) {
	stdout, _, closeFn := captureStdout(t)
	defer closeFn()
	stderr, _, closeErr := captureStderr(t)
	defer closeErr()

	rc := Main([]string{"--this-is-not-a-flag"}, stdout, stderr)
	if rc != 2 {
		t.Errorf("exit code = %d, want 2 (BSD sysexits.h EX_USAGE)", rc)
	}
}

// captureStdout / captureStderr return a real *os.File in
// the test temp dir + a cleanup func. The logger writes
// structured JSON to whatever File we give it; the test reads
// the resulting bytes via readCaptured.
//
// We use a real File (not a *bytes.Buffer) because
// logrus.SetOutput requires an *os.File (or anything with
// io.Writer, but the writerToFile helper specifically casts
// to *os.File and falls back to os.Stdout for non-File inputs).
func captureStdout(t *testing.T) (*os.File, error, func()) {
	f, err := os.CreateTemp(t.TempDir(), "executor-stdout-*.txt")
	return f, err, func() { f.Close() }
}

func captureStderr(t *testing.T) (*os.File, error, func()) {
	f, err := os.CreateTemp(t.TempDir(), "executor-stderr-*.txt")
	return f, err, func() { f.Close() }
}

// readCaptured reads the current contents of f and rewinds it.
// The logger appended to f; we read what it wrote.
func readCaptured(t *testing.T, f *os.File) string {
	t.Helper()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// writeTempConfig writes a YAML config to a temp file and
// returns its path. The file is auto-cleaned by t.TempDir().
func writeTempConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/config.yaml"
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

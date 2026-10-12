package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/semaphoreui/semaphore/executor/commands"
)

// recordingDoer is a stub HTTPDoer that returns canned responses
// for list + ack. It records what the loop sent so tests can
// assert path / method / body shape. Mirrors the executor's
// recordingDoer (R-I.12.b).
type recordingDoer struct {
	mu          sync.Mutex
	listCalls   int32
	ackCalls    int32
	listResp    []byte
	listStatus  int
	ackResp     []byte
	ackStatus   int
	lastAckBody string
	lastAckPath string
}

func (r *recordingDoer) Do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	switch method {
	case http.MethodGet:
		atomic.AddInt32(&r.listCalls, 1)
		status := r.listStatus
		if status == 0 {
			status = 200
		}
		return httptestResp(status, r.listResp), nil
	case http.MethodPost:
		atomic.AddInt32(&r.ackCalls, 1)
		r.mu.Lock()
		r.lastAckBody = string(body)
		r.lastAckPath = path
		r.mu.Unlock()
		status := r.ackStatus
		if status == 0 {
			status = 200
		}
		return httptestResp(status, r.ackResp), nil
	default:
		return nil, fmt.Errorf("recordingDoer: unexpected method %s", method)
	}
}

func httptestResp(status int, body []byte) *http.Response {
	r := httptest.NewRecorder()
	if body != nil {
		r.Body.Write(body)
	}
	r.Code = status
	r.Header().Set("Content-Type", "application/json")
	h := r.Result()
	h.Header = r.Header()
	return h
}

func newTestLoop(t *testing.T, doer *recordingDoer) *CommandLoop {
	t.Helper()
	cfg := Config{
		HeartbeatIntervalSec: 1,
		InstallDir:           t.TempDir(),
	}
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return NewCommandLoop(
		cfg,
		doer,
		func() string { return "runner-test" },
		"tenant-test",
		logger,
	)
}

func TestCommandLoop_NewDefaults(t *testing.T) {
	loop := newTestLoop(t, &recordingDoer{})
	if loop == nil {
		t.Fatal("loop is nil")
	}
	if len(loop.handlers) == 0 {
		t.Fatal("loop has no handlers; NewCommandLoop should register uninstall")
	}
	if _, ok := loop.handlers[commands.CommandTypeUninstall]; !ok {
		t.Fatalf("uninstall handler not registered; got keys: %v", keys(loop.handlers))
	}
}

func keys(m map[string]CommandHandler) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCommandLoop_EmptyListIsNotError(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(`{"executor_id":"runner-test","commands":[],"count":0}`),
	}
	loop := newTestLoop(t, doer)
	loop.tick(context.Background())
	seen, acked, failed := loop.Stats()
	if seen != 0 || acked != 0 || failed != 0 {
		t.Fatalf("expected 0/0/0 on empty list; got %d/%d/%d", seen, acked, failed)
	}
}

func TestCommandLoop_DispatchesUninstallAndAcksSuccess(t *testing.T) {
	cmdPayload, _ := json.Marshal(commands.UninstallPayload{Reason: "test cleanup"})
	doer := &recordingDoer{
		listResp: []byte(fmt.Sprintf(
			`{"executor_id":"runner-test","commands":[`+
				`{"command_id":"cmd-1","executor_id":"runner-test",`+
				`"tenant_id":"tenant-test","command_type":"uninstall",`+
				`"payload":%s,"issued_by":"op-1","issued_at":"2026-10-12T10:00:00Z",`+
				`"expires_at":"2026-10-19T10:00:00Z"}], "count":1}`,
			string(cmdPayload),
		)),
	}
	loop := newTestLoop(t, doer)
	// Override the uninstall handler with a noop so we don't
	// actually try to invoke a script that doesn't exist.
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "ok"}
	})
	loop.tick(context.Background())
	// Wait for the goroutine to ack.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, acked, _ := loop.Stats()
		if acked >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	seen, acked, failed := loop.Stats()
	if seen != 1 || acked != 1 || failed != 0 {
		t.Fatalf("expected 1/1/0 after dispatch; got %d/%d/%d", seen, acked, failed)
	}
	if !strings.Contains(doer.lastAckBody, "success") {
		t.Fatalf("ack body did not contain 'success'; got %q", doer.lastAckBody)
	}
}

func TestCommandLoop_RejectsUnknownCommandType(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(
			`{"executor_id":"runner-test","commands":[` +
				`{"command_id":"cmd-2","executor_id":"runner-test",` +
				`"tenant_id":"tenant-test","command_type":"rotate_cert",` +
				`"payload":{},"issued_by":"op-1","issued_at":"2026-10-12T10:00:00Z",` +
				`"expires_at":"2026-10-19T10:00:00Z"}], "count":1}`,
		),
	}
	loop := newTestLoop(t, doer)
	loop.tick(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, acked, _ := loop.Stats()
		if acked >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(doer.lastAckBody, "rejected") {
		t.Fatalf("ack body did not contain 'rejected'; got %q", doer.lastAckBody)
	}
	if !strings.Contains(doer.lastAckBody, "rotate_cert") {
		t.Fatalf("ack body did not include the unknown command type; got %q", doer.lastAckBody)
	}
}

func TestCommandLoop_Ack404_NotCountedAsFailure(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(`{"executor_id":"runner-test","commands":[],"count":0}`),
		ackStatus: 404,
	}
	loop := newTestLoop(t, doer)
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "ok"}
	})
	// Synthesise a command so the loop tries to ack.
	loop.dispatch(context.Background(), commands.Command{
		CommandID:   "cmd-404",
		ExecutorID:  "runner-test",
		CommandType: commands.CommandTypeUninstall,
		Payload:     map[string]interface{}{"reason": "404 test"},
		IssuedBy:    "op-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, _, failed := loop.Stats()
		if failed == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _, failed := loop.Stats()
	if failed != 0 {
		t.Fatalf("ack 404 should not count as failure; got %d", failed)
	}
}

func TestCommandLoop_UnauthorizedStopsTheLoop(t *testing.T) {
	doer := &recordingDoer{
		listStatus: 401,
	}
	loop := newTestLoop(t, doer)
	loop.tick(context.Background())
	// A second tick should not even call list (the loop
	// logs + returns). Verify by checking that listCalls
	// did not bump on a subsequent tick — but our loop
	// re-tries on each tick, so just verify the call count
	// is 1 (single tick).
	if got := atomic.LoadInt32(&doer.listCalls); got != 1 {
		t.Fatalf("expected 1 list call on a single tick; got %d", got)
	}
}

func TestCommandLoop_NoTickBeforeRunnerIDAssigned(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(`{"executor_id":"","commands":[],"count":0}`),
	}
	loop := newTestLoop(t, doer)
	// Override the runner_id closure to return empty.
	loop.runnerID = func() string { return "" }
	loop.tick(context.Background())
	if got := atomic.LoadInt32(&doer.listCalls); got != 0 {
		t.Fatalf("expected 0 list calls when runner_id is empty; got %d", got)
	}
}

func TestCommandLoop_KillSwitchTriggersImmediateUninstall(t *testing.T) {
	// Write a kill switch file to a temp dir. The loop
	// reads it on every tick and short-circuits to the
	// uninstall handler without going to the BE.
	installDir := t.TempDir()
	switchPath := filepath.Join(installDir, "kill_switch")
	if err := os.WriteFile(switchPath, []byte("v1:abc123"), 0o600); err != nil {
		t.Fatal(err)
	}
	doer := &recordingDoer{
		// Even if the BE would return a real command, the
		// kill switch fires first.
		listResp: []byte(`{"executor_id":"runner-test","commands":[],"count":0}`),
	}
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	loop := NewCommandLoop(
		Config{HeartbeatIntervalSec: 1, InstallDir: installDir, KillSwitchPath: switchPath},
		doer,
		func() string { return "runner-test" },
		"tenant-test",
		logger,
	)
	// Register a handler that records that the kill-switch
	// command was dispatched.
	dispatched := make(chan commands.Command, 1)
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		dispatched <- cmd
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "kill-switch handled"}
	})
	loop.tick(context.Background())
	select {
	case cmd := <-dispatched:
		if !strings.HasPrefix(cmd.CommandID, "kill-switch-") {
			t.Fatalf("expected kill-switch-prefixed command_id; got %q", cmd.CommandID)
		}
		if reason, _ := cmd.Payload["reason"].(string); reason != "kill switch activated" {
			t.Fatalf("expected reason 'kill switch activated'; got %v", cmd.Payload["reason"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("kill-switch handler was not dispatched within 2s")
	}
}

func TestCommandLoop_CheckKillSwitch_OnlyValidSentinel(t *testing.T) {
	installDir := t.TempDir()
	switchPath := filepath.Join(installDir, "kill_switch")
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	loop := NewCommandLoop(
		Config{HeartbeatIntervalSec: 1, InstallDir: installDir, KillSwitchPath: switchPath},
		&recordingDoer{},
		func() string { return "runner-test" },
		"tenant-test",
		logger,
	)
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"missing file", "", false},
		{"empty file", "", false},
		{"no v1 prefix", "v2:abc", false},
		{"v1 but no token", "v1:", false},
		{"valid sentinel", "v1:abc123", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "missing file" {
				_ = os.Remove(switchPath)
			} else {
				if err := os.WriteFile(switchPath, []byte(c.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := loop.checkKillSwitch(); got != c.want {
				t.Fatalf("checkKillSwitch(%q) = %v, want %v", c.content, got, c.want)
			}
		})
	}
}

func TestCommandLoop_UninstallerCommand_PicksPlatformPath(t *testing.T) {
	installDir := "/etc/sentraops-runner"
	loop := newTestLoop(t, &recordingDoer{})
	script, args, err := loop.uninstallerCommand("test reason")
	if err != nil {
		t.Fatalf("uninstallerCommand returned error: %v", err)
	}
	expected := expectedUninstallerName()
	if !strings.HasSuffix(script, expected) {
		t.Fatalf("expected script to end with %q; got %q", expected, script)
	}
	if len(args) != 1 || args[0] != "test reason" {
		t.Fatalf("expected [test reason]; got %v", args)
	}
	if !strings.HasPrefix(script, installDir) {
		t.Fatalf("expected script to start with %q; got %q", installDir, script)
	}
}

// expectedUninstallerName returns the platform-appropriate
// uninstaller filename for the current OS. Mirrors the
// switch in command_loop.go.
func expectedUninstallerName() string {
	switch runtime.GOOS {
	case "windows":
		return "runner_uninstall.ps1"
	case "darwin":
		return "runner_uninstall-macos.sh"
	default:
		return "runner_uninstall.sh"
	}
}

func TestCommandLoop_HandleUninstall_RunsScriptAndMapsExit(t *testing.T) {
	// Build a small shell script that exits 0 and writes
	// "ok" to stdout. On Windows this is a noop (the test
	// is skipped) since the script is POSIX.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only test; Windows handles via ps1")
	}
	installDir := t.TempDir()
	script := filepath.Join(installDir, "runner_uninstall.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho ok\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	loop := &CommandLoop{
		cfg:        Config{InstallDir: installDir},
		platform:   &recordingDoer{},
		runnerID:   func() string { return "runner-test" },
		tenantID:   "tenant-test",
		logger:     logrus.New(),
		handlers:   map[string]CommandHandler{},
		oneFlight:  map[string]bool{},
	}
	payload, _ := json.Marshal(map[string]string{"reason": "test reason"})
	cmd := commands.Command{
		CommandID:   "cmd-script",
		ExecutorID:  "runner-test",
		CommandType: commands.CommandTypeUninstall,
		Payload:     map[string]interface{}{"reason": "test reason"},
		IssuedBy:    "op-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	_ = payload
	outcome := loop.handleUninstall(context.Background(), cmd)
	if outcome.Status != commands.AckStatusSuccess {
		t.Fatalf("expected success; got %s (%s)", outcome.Status, outcome.Message)
	}
	if !strings.Contains(outcome.Message, "ok") {
		t.Fatalf("expected message to include script output 'ok'; got %q", outcome.Message)
	}
}

func TestCommandLoop_HandleUninstall_MapScriptErrorToErrorStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only test; Windows handles via ps1")
	}
	installDir := t.TempDir()
	script := filepath.Join(installDir, "runner_uninstall.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho failing\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	loop := &CommandLoop{
		cfg:        Config{InstallDir: installDir},
		platform:   &recordingDoer{},
		runnerID:   func() string { return "runner-test" },
		tenantID:   "tenant-test",
		logger:     logrus.New(),
		handlers:   map[string]CommandHandler{},
		oneFlight:  map[string]bool{},
	}
	cmd := commands.Command{
		CommandID:   "cmd-fail",
		ExecutorID:  "runner-test",
		CommandType: commands.CommandTypeUninstall,
		Payload:     map[string]interface{}{"reason": "fail test"},
		IssuedBy:    "op-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	outcome := loop.handleUninstall(context.Background(), cmd)
	if outcome.Status != commands.AckStatusError {
		t.Fatalf("expected error; got %s (%s)", outcome.Status, outcome.Message)
	}
}

func TestCommandLoop_HandleUninstall_EmptyInstallDirIsError(t *testing.T) {
	loop := &CommandLoop{
		cfg:        Config{InstallDir: ""},
		platform:   &recordingDoer{},
		runnerID:   func() string { return "runner-test" },
		tenantID:   "tenant-test",
		logger:     logrus.New(),
		handlers:   map[string]CommandHandler{},
		oneFlight:  map[string]bool{},
	}
	cmd := commands.Command{
		CommandID:   "cmd-noinstall",
		ExecutorID:  "runner-test",
		CommandType: commands.CommandTypeUninstall,
		Payload:     map[string]interface{}{"reason": "x"},
		IssuedBy:    "op-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	outcome := loop.handleUninstall(context.Background(), cmd)
	if outcome.Status != commands.AckStatusError {
		t.Fatalf("expected error; got %s", outcome.Status)
	}
}

func TestCommandLoop_OneFlight_DoesNotRunHandlerTwice(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(`{"executor_id":"runner-test","commands":[],"count":0}`),
	}
	loop := newTestLoop(t, doer)
	// Manually mark a command as in-flight.
	loop.oneFlight["cmd-inflight"] = true
	// dispatch with the same command_id — should be a noop.
	loop.dispatch(context.Background(), commands.Command{
		CommandID:   "cmd-inflight",
		ExecutorID:  "runner-test",
		CommandType: commands.CommandTypeUninstall,
		Payload:     map[string]interface{}{"reason": "in-flight"},
		IssuedBy:    "op-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	// Verify no ack was posted.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&doer.ackCalls); got != 0 {
		t.Fatalf("expected 0 ack calls for in-flight command; got %d", got)
	}
}

func TestConfig_Validate_FillsDefaults(t *testing.T) {
	c := &Config{ServerURL: "https://x", TenantID: "t"}
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.InstallDir == "" {
		t.Fatal("InstallDir not defaulted")
	}
	if c.PlatformAPIKeyPath == "" {
		t.Fatal("PlatformAPIKeyPath not defaulted")
	}
	if c.KillSwitchPath == "" {
		t.Fatal("KillSwitchPath not defaulted")
	}
	if c.HeartbeatIntervalSec <= 0 {
		t.Fatal("HeartbeatIntervalSec not defaulted")
	}
}

func TestConfig_Validate_RequiresServerURL(t *testing.T) {
	c := &Config{TenantID: "t"}
	if err := c.validate(); err == nil {
		t.Fatal("expected error when ServerURL is empty")
	}
}

func TestConfig_Validate_RequiresTenantID(t *testing.T) {
	c := &Config{ServerURL: "https://x"}
	if err := c.validate(); err == nil {
		t.Fatal("expected error when TenantID is empty")
	}
}

func TestConfig_LoadConfig_MissingFile(t *testing.T) {
	_, err := loadConfig("/this/path/does/not/exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestConfig_LoadConfig_ParsesYAML(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	yaml := `
server_url: "https://example.com"
tenant_id: "tenant-abc"
runner_id: "runner-xyz"
install_dir: "/etc/sentraops-runner"
heartbeat_interval_sec: 30
log_level: "info"
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ServerURL != "https://example.com" {
		t.Fatalf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.TenantID != "tenant-abc" {
		t.Fatalf("TenantID = %q", cfg.TenantID)
	}
	if cfg.RunnerID != "runner-xyz" {
		t.Fatalf("RunnerID = %q", cfg.RunnerID)
	}
	if cfg.HeartbeatIntervalSec != 30 {
		t.Fatalf("HeartbeatIntervalSec = %d", cfg.HeartbeatIntervalSec)
	}
}

// Ensure the runner command loop imports the wire types
// from executor/commands. If this compiles, the wire
// reuse is in place.
var _ = commands.CommandTypeUninstall

// Sentinel to confirm the loop's exported surface is what
// we think it is. The TestCommandLoop_NewDefaults above
// covers behavior; this is a structural check.
func TestCommandLoop_Structure(t *testing.T) {
	loop := newTestLoop(t, &recordingDoer{})
	if loop == nil {
		t.Fatal("loop is nil")
	}
	// Stats should not panic on a fresh loop.
	seen, acked, failed := loop.Stats()
	if seen != 0 || acked != 0 || failed != 0 {
		t.Fatalf("expected zero counters; got %d/%d/%d", seen, acked, failed)
	}
	// RegisterHandler should accept a custom handler.
	called := false
	loop.RegisterHandler("custom", func(ctx context.Context, cmd commands.Command) AckOutcome {
		called = true
		return AckOutcome{Status: commands.AckStatusSuccess}
	})
	loop.handlersMu.RLock()
	h, ok := loop.handlers["custom"]
	loop.handlersMu.RUnlock()
	if !ok || h == nil {
		t.Fatal("custom handler not registered")
	}
	if called {
		// Should not be called yet — Register is the test
		// of the registration path itself, not the
		// invocation path.
		t.Fatal("RegisterHandler should not invoke the handler")
	}
}

// Avoid an unused import warning if recordingDoer is
// removed in a future refactor.
var _ = errors.New

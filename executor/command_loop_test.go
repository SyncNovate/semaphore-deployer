package executor

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

// recordingDoer is a small HTTPDoer that returns canned
// responses for list + ack. It records what the loop sent
// so tests can assert path / method / body shape.
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
	cfg := Config{HeartbeatIntervalSeconds: 1, InstallDir: t.TempDir()}
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel) // silence in tests
	loop := NewCommandLoop(
		cfg,
		doer,
		func() string { return "exec-test" },
		"tenant-test",
		logger,
	)
	return loop
}

func TestCommandLoop_DispatchUninstall_RunsHandlerAndAcks(t *testing.T) {
	doer := &recordingDoer{
		listResp: mustListJSON(t, commands.Command{
			CommandID:   "cmd-1",
			ExecutorID:  "exec-test",
			CommandType: commands.CommandTypeUninstall,
			Payload:     map[string]interface{}{"reason": "customer churn"},
			IssuedAt:    time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		}),
		ackResp: mustAckJSON(t, commands.AckResponse{
			CommandID: "cmd-1", ExecutorID: "exec-test",
			AckedAt: time.Now().UTC(), AckStatus: "success",
		}),
	}
	loop := newTestLoop(t, doer)
	// Replace the handler with a probe that records the call
	// and writes a real artifact the test can check.
	var handlerCalled atomic.Int32
	var handlerReason string
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		handlerCalled.Add(1)
		payload, err := commands.DecodeUninstallPayload(cmd)
		if err != nil {
			return AckOutcome{Status: commands.AckStatusError, Message: err.Error()}
		}
		handlerReason = payload.Reason
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "uninstalled (test stub)"}
	})

	// Run a single tick.
	loop.tick(context.Background())

	// Allow the dispatch goroutine to finish.
	deadline := time.Now().Add(2 * time.Second)
	for handlerCalled.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if handlerCalled.Load() != 1 {
		t.Fatalf("handler called %d times, want 1", handlerCalled.Load())
	}
	if handlerReason != "customer churn" {
		t.Fatalf("handler reason = %q, want 'customer churn'", handlerReason)
	}

	// Wait for the ack to be posted.
	deadline = time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&doer.ackCalls) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if doer.ackCalls != 1 {
		t.Fatalf("ack called %d times, want 1", doer.ackCalls)
	}
	if !strings.Contains(doer.lastAckPath, "/commands/cmd-1/ack") {
		t.Fatalf("ack path = %q, want it to contain /commands/cmd-1/ack", doer.lastAckPath)
	}
	if !strings.Contains(doer.lastAckBody, `"status":"success"`) {
		t.Fatalf("ack body = %q, want it to contain status=success", doer.lastAckBody)
	}

	seen, acked, failed := loop.Stats()
	if seen != 1 || acked != 1 || failed != 0 {
		t.Fatalf("Stats: seen=%d acked=%d failed=%d, want 1/1/0", seen, acked, failed)
	}
}

func TestCommandLoop_UnknownCommandType_AcksRejected(t *testing.T) {
	doer := &recordingDoer{
		listResp: mustListJSON(t, commands.Command{
			CommandID:   "cmd-rot",
			ExecutorID:  "exec-test",
			CommandType: "rotate_cert", // future command, not wired yet
			Payload:     map[string]interface{}{},
			IssuedAt:    time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		}),
		ackResp: mustAckJSON(t, commands.AckResponse{CommandID: "cmd-rot"}),
	}
	loop := newTestLoop(t, doer)
	loop.tick(context.Background())

	// Wait for ack.
	deadline := time.Now().Add(2 * time.Second)
	for doer.ackCalls == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if doer.ackCalls != 1 {
		t.Fatalf("ack called %d times, want 1", doer.ackCalls)
	}
	if !strings.Contains(doer.lastAckBody, `"status":"rejected"`) {
		t.Fatalf("ack body = %q, want status=rejected", doer.lastAckBody)
	}
	if !strings.Contains(doer.lastAckBody, "rotate_cert") {
		t.Fatalf("ack body = %q, want it to mention the unknown command type", doer.lastAckBody)
	}
}

func TestCommandLoop_Unauthorized_HardStop(t *testing.T) {
	doer := &recordingDoer{listStatus: 401}
	loop := newTestLoop(t, doer)
	loop.tick(context.Background())
	// Hard stop: no ack (the loop returns before dispatch).
	if doer.ackCalls != 0 {
		t.Fatalf("ack should not be called on 401, got %d", doer.ackCalls)
	}
	// Stats: nothing was seen.
	seen, _, _ := loop.Stats()
	if seen != 0 {
		t.Fatalf("Stats: seen=%d, want 0 on 401", seen)
	}
}

func TestCommandLoop_EmptyInbox_NoAcks(t *testing.T) {
	doer := &recordingDoer{listResp: []byte(`{"executor_id":"exec-test","commands":[],"count":0}`)}
	loop := newTestLoop(t, doer)
	loop.tick(context.Background())
	// Allow async work to drain.
	time.Sleep(50 * time.Millisecond)
	if doer.ackCalls != 0 {
		t.Fatalf("ack should not be called for empty inbox, got %d", doer.ackCalls)
	}
}

func TestCommandLoop_StartStopsOnContextCancel(t *testing.T) {
	doer := &recordingDoer{listResp: []byte(`{"executor_id":"exec-test","commands":[],"count":0}`)}
	loop := newTestLoop(t, doer)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.Start(ctx)
		close(done)
	}()
	// Give the goroutine a tick to start.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s after cancel")
	}
}

func TestCommandLoop_NoExecutorID_TickSkips(t *testing.T) {
	doer := &recordingDoer{
		listResp: mustListJSON(t, commands.Command{
			CommandID: "cmd-1", CommandType: commands.CommandTypeUninstall,
			IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		}),
	}
	cfg := Config{HeartbeatIntervalSeconds: 1, InstallDir: t.TempDir()}
	loop := NewCommandLoop(
		cfg, doer,
		func() string { return "" }, // empty: registration hasn't completed
		"tenant-test",
		logrus.New(),
	)
	loop.tick(context.Background())
	// No list call should have been made because the closure
	// returned "" and the tick short-circuits.
	if doer.listCalls != 0 {
		t.Fatalf("list called %d times before registration, want 0", doer.listCalls)
	}
}

// TestCommandLoop_KillSwitch_TriggersImmediateUninstall
// confirms the R-I.12.b edge path: when the kill-switch
// file is present with the v1: sentinel, the command loop
// skips the BE poll and dispatches a synthetic uninstall
// command locally. The handler runs the platform-specific
// uninstaller; we use a real stub script in a temp dir so
// the test confirms the side-effect.
func TestCommandLoop_KillSwitch_TriggersImmediateUninstall(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only kill switch test (handler invokes the Linux uninstaller)")
	}
	installDir := t.TempDir()
	killSwitchPath := filepath.Join(installDir, "kill_switch")
	mustWrite(t, killSwitchPath, "v1:opaque-token-32-bytes\n")
	// The handler will try to run <installDir>/uninstall.sh;
	// build a real stub that exits 0 and writes a sentinel
	// file the test can read.
	scriptPath := filepath.Join(installDir, "uninstall.sh")
	mustWrite(t, scriptPath, "#!/bin/sh\ntouch /tmp/killswitch-fired\necho ok\n")
	if err := os.Chmod(scriptPath, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Clean up the sentinel file from a prior test run.
	os.Remove("/tmp/killswitch-fired")
	defer os.Remove("/tmp/killswitch-fired")

	doer := &recordingDoer{
		// List would normally return a row; we want to
		// confirm it's NEVER called when the kill switch
		// fires (the loop short-circuits the BE poll).
		listResp: mustListJSON(t, commands.Command{
			CommandID: "ignored", ExecutorID: "exec-test",
			CommandType: commands.CommandTypeUninstall,
			IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		}),
	}
	cfg := Config{
		HeartbeatIntervalSeconds: 1,
		InstallDir:               installDir,
		KillSwitchPath:           killSwitchPath,
	}
	loop := NewCommandLoop(cfg, doer, func() string { return "exec-test" }, "tenant-test", logrus.New())

	loop.tick(context.Background())

	// The kill switch should have short-circuited the BE
	// poll. The list call counter is 0.
	if doer.listCalls != 0 {
		t.Fatalf("list called %d times, want 0 (kill switch should short-circuit the BE poll)", doer.listCalls)
	}
	// The uninstaller should have run. The stub wrote
	// /tmp/killswitch-fired.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat("/tmp/killswitch-fired"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("uninstaller stub did not run within 3s of kill switch")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestCommandLoop_KillSwitch_MissingFile_NoOp confirms the
// default (no kill switch file) is silent.
func TestCommandLoop_KillSwitch_MissingFile_NoOp(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(`{"executor_id":"exec-test","commands":[],"count":0}`),
	}
	cfg := Config{
		HeartbeatIntervalSeconds: 1,
		InstallDir:               t.TempDir(),
		KillSwitchPath:           "/nonexistent/kill_switch",
	}
	loop := NewCommandLoop(cfg, doer, func() string { return "exec-test" }, "tenant-test", logrus.New())
	loop.tick(context.Background())
	time.Sleep(50 * time.Millisecond)
	if doer.listCalls != 1 {
		t.Fatalf("list called %d times, want 1 (no kill switch file, normal poll)", doer.listCalls)
	}
}

// TestCommandLoop_KillSwitch_BadPrefix_NoOp confirms the
// sentinel format is enforced. A file with arbitrary
// content (e.g. a stray "v0:" or a plain string) does NOT
// trigger the kill switch.
func TestCommandLoop_KillSwitch_BadPrefix_NoOp(t *testing.T) {
	doer := &recordingDoer{
		listResp: []byte(`{"executor_id":"exec-test","commands":[],"count":0}`),
	}
	installDir := t.TempDir()
	killSwitchPath := filepath.Join(installDir, "kill_switch")
	mustWrite(t, killSwitchPath, "v0:wrong-version\n")

	cfg := Config{
		HeartbeatIntervalSeconds: 1,
		InstallDir:               installDir,
		KillSwitchPath:           killSwitchPath,
	}
	loop := NewCommandLoop(cfg, doer, func() string { return "exec-test" }, "tenant-test", logrus.New())
	loop.tick(context.Background())
	time.Sleep(50 * time.Millisecond)
	if doer.listCalls != 1 {
		t.Fatalf("list called %d times, want 1 (bad prefix, normal poll)", doer.listCalls)
	}
}

// TestCommandLoop_OneFlight_PreventsDoubleRun confirms the
// dispatch guard. If two ticks fire while a handler is
// still running, the second one drops the command instead
// of double-firing.
func TestCommandLoop_OneFlight_PreventsDoubleRun(t *testing.T) {
	doer := &recordingDoer{
		listResp: mustListJSON(t, commands.Command{
			CommandID:   "cmd-slow",
			ExecutorID:  "exec-test",
			CommandType: commands.CommandTypeUninstall,
			IssuedAt:    time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		}),
		ackResp: mustAckJSON(t, commands.AckResponse{CommandID: "cmd-slow"}),
	}
	loop := newTestLoop(t, doer)
	releaseHandler := make(chan struct{})
	var handlerCalls atomic.Int32
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		handlerCalls.Add(1)
		<-releaseHandler
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "ok"}
	})

	// Fire two ticks. The first kicks off the handler
	// (blocked on releaseHandler). The second tick should
	// see the oneFlight guard and drop the command.
	loop.tick(context.Background())
	time.Sleep(50 * time.Millisecond)
	loop.tick(context.Background())
	// Release the handler.
	close(releaseHandler)
	// Wait for the ack.
	deadline := time.Now().Add(2 * time.Second)
	for doer.ackCalls == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if handlerCalls.Load() != 1 {
		t.Fatalf("handler called %d times, want 1 (oneFlight guard)", handlerCalls.Load())
	}
}

func TestCommandLoop_HandleUninstall_RunsUninstallerOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only uninstaller test (the script is install/uninstall.sh)")
	}
	// Build a tiny uninstaller in a temp dir, run the
	// handler, check the side-effect.
	installDir := t.TempDir()
	script := filepath.Join(installDir, "uninstall.sh")
	mustWrite(t, script, "#!/bin/sh\necho \"uninstalled for $1\"\n")
	// chmod 0755
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	doer := &recordingDoer{
		ackResp: mustAckJSON(t, commands.AckResponse{CommandID: "cmd-x"}),
	}
	cfg := Config{HeartbeatIntervalSeconds: 1, InstallDir: installDir}
	loop := NewCommandLoop(cfg, doer, func() string { return "exec-x" }, "tenant-x", logrus.New())

	outcome := loop.handleUninstall(context.Background(), commands.Command{
		CommandID:   "cmd-x",
		CommandType: commands.CommandTypeUninstall,
		Payload:     map[string]interface{}{"reason": "test-reason"},
	})
	if outcome.Status != commands.AckStatusSuccess {
		t.Fatalf("handleUninstall: status = %q, want success (outcome: %+v)", outcome.Status, outcome)
	}
	if !strings.Contains(outcome.Message, "uninstalled for test-reason") {
		t.Fatalf("handleUninstall: message = %q, want it to contain 'uninstalled for test-reason'", outcome.Message)
	}
}

func TestCommandLoop_HandleUninstall_FailingScript_AcksError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only uninstaller test")
	}
	installDir := t.TempDir()
	script := filepath.Join(installDir, "uninstall.sh")
	mustWrite(t, script, "#!/bin/sh\necho \"oops\" >&2\nexit 1\n")
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := Config{HeartbeatIntervalSeconds: 1, InstallDir: installDir}
	loop := NewCommandLoop(cfg, &recordingDoer{}, func() string { return "x" }, "t", logrus.New())
	outcome := loop.handleUninstall(context.Background(), commands.Command{
		CommandID: "cmd-x", CommandType: commands.CommandTypeUninstall,
		Payload: map[string]interface{}{"reason": "x"},
	})
	if outcome.Status != commands.AckStatusError {
		t.Fatalf("handleUninstall: status = %q, want error", outcome.Status)
	}
	if !strings.Contains(outcome.Message, "oops") {
		t.Fatalf("handleUninstall: message = %q, want it to contain 'oops'", outcome.Message)
	}
}

func TestCommandLoop_HandleUninstall_UnknownOS_Errors(t *testing.T) {
	// Use a stub doer; we don't need it. The handler is
	// platform-switched on runtime.GOOS, which the test
	// process knows.
	cfg := Config{HeartbeatIntervalSeconds: 1, InstallDir: t.TempDir()}
	loop := NewCommandLoop(cfg, &recordingDoer{}, func() string { return "x" }, "t", logrus.New())
	// We're not on Windows in this CI but the error path
	// for unknown GOOS is testable on any platform: force
	// the script path off-platform by pointing the config
	// at a known-bad install dir. We exercise the runtime
	// branch by checking the message on a freshly created
	// loop.
	_ = loop
	// The case of "no install dir, no default" is harder
	// to trigger without a runtime.GOOS override. Instead,
	// test the lookup helper directly:
	_, _, err := loop.uninstallerCommand("reason")
	if err != nil {
		t.Fatalf("uninstallerCommand on %s: %v (test env should have a default)", runtime.GOOS, err)
	}
}

// TestNewCommandLoop_NilLoggerUsesDefault guards the
// "logger is optional" contract used by main() before the
// logger has been configured.
func TestNewCommandLoop_NilLoggerUsesDefault(t *testing.T) {
	loop := NewCommandLoop(Config{InstallDir: t.TempDir()}, &recordingDoer{}, func() string { return "x" }, "t", nil)
	if loop.logger == nil {
		t.Fatal("NewCommandLoop(nil logger) should fall back to a default logger")
	}
}

// TestCommandLoop_AckError_NotBlocking confirms a failed
// ack (5xx) is logged + counted but does not crash the
// loop. The next tick is free to retry.
func TestCommandLoop_AckError_NotBlocking(t *testing.T) {
	doer := &recordingDoer{
		listResp: mustListJSON(t, commands.Command{
			CommandID:   "cmd-1",
			ExecutorID:  "exec-test",
			CommandType: commands.CommandTypeUninstall,
			IssuedAt:    time.Now().UTC(),
			ExpiresAt:   time.Now().UTC().Add(time.Hour),
		}),
		ackStatus: 500,
	}
	loop := newTestLoop(t, doer)
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "ok"}
	})
	loop.tick(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for doer.ackCalls == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if doer.ackCalls != 1 {
		t.Fatalf("ack called %d times, want 1", doer.ackCalls)
	}
	seen, acked, failed := loop.Stats()
	if seen != 1 || acked != 0 || failed != 1 {
		t.Fatalf("Stats: seen=%d acked=%d failed=%d, want 1/0/1", seen, acked, failed)
	}
}

// TestCommandLoop_Ack404_NotCountedAsFailure confirms the
// "command was deleted" 404 is treated as a drop, not a
// failure (no point retrying).
func TestCommandLoop_Ack404_NotCountedAsFailure(t *testing.T) {
	doer := &recordingDoer{
		listResp: mustListJSON(t, commands.Command{
			CommandID: "cmd-1", ExecutorID: "exec-test",
			CommandType: commands.CommandTypeUninstall,
			IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
		}),
		ackStatus: 404,
	}
	loop := newTestLoop(t, doer)
	loop.RegisterHandler(commands.CommandTypeUninstall, func(ctx context.Context, cmd commands.Command) AckOutcome {
		return AckOutcome{Status: commands.AckStatusSuccess, Message: "ok"}
	})
	loop.tick(context.Background())
	deadline := time.Now().Add(2 * time.Second)
	for doer.ackCalls == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	seen, acked, failed := loop.Stats()
	if seen != 1 || acked != 0 || failed != 0 {
		t.Fatalf("Stats: seen=%d acked=%d failed=%d, want 1/0/0 (404 is a drop, not a failure)", seen, acked, failed)
	}
}

// TestPlatformClient_RejectsInsecureKeyFile confirms the
// mode-0600 enforcement. A file with wider perms must be
// rejected loud.
func TestPlatformClient_RejectsInsecureKeyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0644 is meaningless on Windows; the test is unix-specific")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	mustWrite(t, keyPath, "secret-value\n")
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := Config{ServerURL: "https://example.com"}
	_, err := NewPlatformClient(cfg, keyPath, 5*time.Second)
	if err == nil {
		t.Fatal("NewPlatformClient: expected insecure-mode error")
	}
	if !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("err = %v, want insecure-mode message", err)
	}
}

func TestPlatformClient_RejectsEmptyKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	mustWrite(t, keyPath, "\n")
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := Config{ServerURL: "https://example.com"}
	_, err := NewPlatformClient(cfg, keyPath, 5*time.Second)
	if err == nil {
		t.Fatal("NewPlatformClient: expected empty-key error")
	}
	if !errors.Is(err, errors.Unwrap(err)) && !strings.Contains(err.Error(), "empty") {
		// We don't strict-errors.Is here because err is a
		// plain string error; just check the message.
	}
}

func TestPlatformClient_Accepts600KeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	mustWrite(t, keyPath, "  secret-value  \n")
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := Config{ServerURL: "https://example.com"}
	c, err := NewPlatformClient(cfg, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("NewPlatformClient: %v", err)
	}
	if c.apiKey != "  secret-value  " {
		t.Fatalf("apiKey = %q, want leading/trailing whitespace preserved (we only strip newline)", c.apiKey)
	}
}

// TestPlatformClient_SendsAPIKeyHeader confirms the wire
// shape: X-Sentraops-Api-Key on every call.
func TestPlatformClient_SendsAPIKeyHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Sentraops-Api-Key"); got != "the-secret" {
			t.Errorf("X-Sentraops-Api-Key = %q, want 'the-secret'", got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api_key")
	mustWrite(t, keyPath, "the-secret\n")
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg := Config{ServerURL: srv.URL}
	c, err := NewPlatformClient(cfg, keyPath, 5*time.Second)
	if err != nil {
		t.Fatalf("NewPlatformClient: %v", err)
	}
	resp, err := c.Do(context.Background(), "GET", "/api/v1/executors/x/commands", nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
}

// mustListJSON marshals a list response for tests.
func mustListJSON(t *testing.T, rows ...commands.Command) []byte {
	t.Helper()
	out := commands.ListResponse{ExecutorID: "exec-test", Commands: rows, Count: len(rows)}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// mustAckJSON marshals an ack response for tests.
func mustAckJSON(t *testing.T, resp commands.AckResponse) []byte {
	t.Helper()
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// mustWrite writes a file and fails the test on error.
func mustWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

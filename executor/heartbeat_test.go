package executor

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// TestHeartbeatRunnerSendsOnFirstTick verifies the
// industry-standard "heartbeat on connect" pattern: Start
// triggers an immediate send (not interval-delayed). Critical
// for the offline-detection path — a fresh executor that
// doesn't heartbeat for `interval` seconds would already be
// considered offline.
func TestHeartbeatRunnerSendsOnFirstTick(t *testing.T) {
	var serverHits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	runner := NewHeartbeatRunner(client, "tok", HeartbeatRequest{
		ExecutorID:     "EXEC-001",
		Status:         "online",
		ActiveJobCount: 0,
	}, 100*time.Millisecond, 1*time.Second, logrus.New())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = runner.Start(ctx) // returns when ctx fires; 1 send happens before then

	// The first send is immediate, so we expect at least 1.
	if got := atomic.LoadInt32(&serverHits); got < 1 {
		t.Errorf("server hits = %d, want >= 1 (first heartbeat is immediate)", got)
	}
}

// TestHeartbeatRunnerSendsRepeatedlyOnInterval verifies the
// tick rate: with interval=20ms, a 60ms run should produce
// roughly 3-4 sends.
func TestHeartbeatRunnerSendsRepeatedlyOnInterval(t *testing.T) {
	var serverHits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	runner := NewHeartbeatRunner(client, "tok", HeartbeatRequest{
		ExecutorID: "EXEC-001",
		Status:     "online",
	}, 20*time.Millisecond, 1*time.Second, logrus.New())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = runner.Start(ctx)

	got := atomic.LoadInt32(&serverHits)
	// First send is immediate; then roughly 100ms / 20ms = 5
	// more. Allow [2..15] for CI jitter.
	if got < 2 || got > 15 {
		t.Errorf("server hits = %d, want in [2..15] over 100ms with 20ms interval", got)
	}
}

// TestHeartbeatRunnerAttachesBearerToken verifies the
// Authorization header carries the registered executor token.
func TestHeartbeatRunnerAttachesBearerToken(t *testing.T) {
	var receivedAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	runner := NewHeartbeatRunner(client, "TOK-XYZ", HeartbeatRequest{
		ExecutorID: "EXEC-001",
		Status:     "online",
	}, 50*time.Millisecond, 1*time.Second, logrus.New())

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_ = runner.Start(ctx)

	if !strings.HasPrefix(receivedAuth, "Bearer TOK-XYZ") {
		t.Errorf("Authorization = %q, want 'Bearer TOK-XYZ'", receivedAuth)
	}
}

// TestHeartbeatRunnerSurvivesServerError verifies the
// resilience contract: a 5xx from the server does not kill the
// runner; the next tick retries. The runner's LastError
// records the failure for ops visibility.
func TestHeartbeatRunnerSurvivesServerError(t *testing.T) {
	var serverHits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	runner := NewHeartbeatRunner(client, "tok", HeartbeatRequest{
		ExecutorID: "EXEC-001",
		Status:     "online",
	}, 20*time.Millisecond, 1*time.Second, logrus.New())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = runner.Start(ctx)

	if got := atomic.LoadInt32(&serverHits); got < 2 {
		t.Errorf("server hits = %d, want >= 2 (runner should retry after 5xx)", got)
	}
	if err := runner.LastError(); err == nil {
		t.Error("LastError = nil, want a 5xx error after a server failure")
	}
}

// TestHeartbeatRunnerRequiresClientAndBearer pins the
// constructor invariants.
func TestHeartbeatRunnerRequiresClientAndBearer(t *testing.T) {
	runner := NewHeartbeatRunner(nil, "tok", HeartbeatRequest{}, 1*time.Second, 1*time.Second, logrus.New())
	if err := runner.Start(context.Background()); err == nil {
		t.Error("Start should error on nil client")
	}

	client := newHTTPClientWithTLSConfig(
		"https://example.invalid",
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13},
		1*time.Second,
	)
	runner = NewHeartbeatRunner(client, "", HeartbeatRequest{ExecutorID: "x"}, 1*time.Second, 1*time.Second, logrus.New())
	if err := runner.Start(context.Background()); err == nil {
		t.Error("Start should error on empty bearer")
	}

	runner = NewHeartbeatRunner(client, "tok", HeartbeatRequest{ /* missing ExecutorID */ }, 1*time.Second, 1*time.Second, logrus.New())
	if err := runner.Start(context.Background()); err == nil {
		t.Error("Start should error on missing executor_id")
	}
}

// TestHeartbeatRunnerDefaultsIntervalTo10s pins the
// config-driven default. The Config.validate step already
// checks the field; this is the belt-and-braces check on the
// runner side.
func TestHeartbeatRunnerDefaultsIntervalTo10s(t *testing.T) {
	runner := NewHeartbeatRunner(nil, "tok", HeartbeatRequest{ExecutorID: "x"}, 0, 1*time.Second, logrus.New())
	if runner.interval != 10*time.Second {
		t.Errorf("default interval = %v, want 10s", runner.interval)
	}
}

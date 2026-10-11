package commands

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubDoer is a tiny test double for HTTPDoer. Each test
// builds a server, records what came in, and returns the
// canned response. atomic.Int32 is used as a hit counter
// instead of plain int so the parallel-test guard doesn't
// race with the test goroutine.
type stubDoer struct {
	requests atomic.Int32
	lastReq  atomic.Pointer[recordedRequest]
	// next is a function that returns the response for the
	// next call. Tests set this to vary the response by
	// call number.
	next func(call int32) (int, []byte, http.Header)
}

type recordedRequest struct {
	method string
	path   string
	body   string
}

func (s *stubDoer) Do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	n := s.requests.Add(1)
	s.lastReq.Store(&recordedRequest{
		method: method,
		path:   path,
		body:   string(body),
	})
	if s.next == nil {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("{}")),
		}, nil
	}
	code, payload, hdr := s.next(n)
	if hdr == nil {
		hdr = http.Header{}
	}
	hdr.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: code,
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader(string(payload))),
	}, nil
}

// okListBody returns a ListResponse JSON with the given
// command rows. Centralised so the test surface is uniform.
func okListBody(rows ...Command) []byte {
	out := ListResponse{
		ExecutorID: "exec-1",
		Commands:   rows,
		Count:      len(rows),
	}
	b, _ := json.Marshal(out)
	return b
}

func TestListPending_HappyPath(t *testing.T) {
	want := Command{
		CommandID:   "cmd-1",
		ExecutorID:  "exec-1",
		TenantID:    "tenant-A",
		CommandType: CommandTypeUninstall,
		IssuedBy:    "SYN-SU-0001-6TGN",
		IssuedAt:    time.Now().UTC().Truncate(time.Millisecond),
		ExpiresAt:   time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Millisecond),
		Payload: map[string]interface{}{
			"reason": "customer churn",
		},
	}
	stub := &stubDoer{
		next: func(_ int32) (int, []byte, http.Header) {
			return 200, okListBody(want), nil
		},
	}
	c := NewClient(stub)
	got, err := c.ListPending(context.Background(), "exec-1")
	if err != nil {
		t.Fatalf("ListPending returned err: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ListPending: want 1 row, got %d", len(got))
	}
	if got[0].CommandID != "cmd-1" {
		t.Fatalf("ListPending: want cmd-1, got %q", got[0].CommandID)
	}
	if got[0].CommandType != CommandTypeUninstall {
		t.Fatalf("ListPending: want uninstall, got %q", got[0].CommandType)
	}
	if got[0].Payload["reason"] != "customer churn" {
		t.Fatalf("ListPending: payload reason lost: %v", got[0].Payload)
	}
	// Path shape: must hit /api/v1/executors/{id}/commands.
	req := stub.lastReq.Load()
	if req == nil {
		t.Fatal("ListPending: no recorded request")
	}
	if req.method != http.MethodGet {
		t.Fatalf("ListPending: method = %q, want GET", req.method)
	}
	if req.path != "/api/v1/executors/exec-1/commands" {
		t.Fatalf("ListPending: path = %q, want /api/v1/executors/exec-1/commands", req.path)
	}
}

func TestListPending_EmptyIsOK(t *testing.T) {
	// An empty inbox is a normal "no work right now" result,
	// not an error. The BE returns 200 + empty list.
	stub := &stubDoer{
		next: func(_ int32) (int, []byte, http.Header) {
			return 200, okListBody(), nil
		},
	}
	c := NewClient(stub)
	got, err := c.ListPending(context.Background(), "exec-1")
	if err != nil {
		t.Fatalf("ListPending: empty list returned err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListPending: empty list returned %d rows", len(got))
	}
}

func TestListPending_RequiresExecutorID(t *testing.T) {
	c := NewClient(&stubDoer{})
	if _, err := c.ListPending(context.Background(), ""); err == nil {
		t.Fatal("ListPending(\"\"): want err, got nil")
	}
}

func TestListPending_401_typed_error(t *testing.T) {
	stub := &stubDoer{
		next: func(_ int32) (int, []byte, http.Header) {
			return 401, []byte(`{"detail":"Invalid or missing SentraOps API key"}`), nil
		},
	}
	c := NewClient(stub)
	_, err := c.ListPending(context.Background(), "exec-1")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ListPending: 401 should surface ErrUnauthorized, got %v", err)
	}
}

func TestListPending_500_with_body(t *testing.T) {
	stub := &stubDoer{
		next: func(_ int32) (int, []byte, http.Header) {
			return 500, []byte("internal server error"), nil
		},
	}
	c := NewClient(stub)
	_, err := c.ListPending(context.Background(), "exec-1")
	if err == nil {
		t.Fatal("ListPending: 500 should produce err")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "internal server error") {
		t.Fatalf("ListPending: err should include status + body, got %v", err)
	}
}

func TestAck_HappyPath(t *testing.T) {
	stub := &stubDoer{
		next: func(_ int32) (int, []byte, http.Header) {
			resp := AckResponse{
				CommandID:  "cmd-1",
				ExecutorID: "exec-1",
				AckedAt:    time.Now().UTC().Truncate(time.Millisecond),
				AckStatus:  AckStatusSuccess,
				AckMessage: "shredded + service unregistered",
			}
			b, _ := json.Marshal(resp)
			return 200, b, nil
		},
	}
	c := NewClient(stub)
	got, err := c.Ack(context.Background(), "exec-1", "cmd-1", AckStatusSuccess, "shredded + service unregistered")
	if err != nil {
		t.Fatalf("Ack returned err: %v", err)
	}
	if got.CommandID != "cmd-1" || got.AckStatus != AckStatusSuccess {
		t.Fatalf("Ack response malformed: %+v", got)
	}
	// Path shape: /api/v1/executors/{id}/commands/{cid}/ack
	req := stub.lastReq.Load()
	if req.method != http.MethodPost {
		t.Fatalf("Ack: method = %q, want POST", req.method)
	}
	if req.path != "/api/v1/executors/exec-1/commands/cmd-1/ack" {
		t.Fatalf("Ack: path = %q, want /api/v1/executors/exec-1/commands/cmd-1/ack", req.path)
	}
	// Body shape: status + message as JSON
	var sent AckRequest
	if err := json.NewDecoder(strings.NewReader(req.body)).Decode(&sent); err != nil {
		t.Fatalf("Ack: body not JSON: %v", err)
	}
	if sent.Status != AckStatusSuccess || sent.Message != "shredded + service unregistered" {
		t.Fatalf("Ack: body = %+v, want status=success message=...", sent)
	}
}

func TestAck_404_typed_error(t *testing.T) {
	stub := &stubDoer{
		next: func(_ int32) (int, []byte, http.Header) {
			return 404, []byte(`{"detail":"command not found"}`), nil
		},
	}
	c := NewClient(stub)
	_, err := c.Ack(context.Background(), "exec-1", "ghost", AckStatusSuccess, "x")
	if !errors.Is(err, ErrCommandNotFound) {
		t.Fatalf("Ack: 404 should surface ErrCommandNotFound, got %v", err)
	}
}

func TestAck_ValidatesStatus(t *testing.T) {
	c := NewClient(&stubDoer{})
	_, err := c.Ack(context.Background(), "exec-1", "cmd-1", "not-a-status", "x")
	if err == nil {
		t.Fatal("Ack: invalid status should err")
	}
	if !strings.Contains(err.Error(), "invalid ack status") {
		t.Fatalf("Ack: err should mention invalid status, got %v", err)
	}
}

func TestAck_RequiresFields(t *testing.T) {
	c := NewClient(&stubDoer{})
	_, err := c.Ack(context.Background(), "", "cmd-1", AckStatusSuccess, "x")
	if err == nil {
		t.Fatal("Ack: empty executorID should err")
	}
	_, err = c.Ack(context.Background(), "exec-1", "", AckStatusSuccess, "x")
	if err == nil {
		t.Fatal("Ack: empty commandID should err")
	}
	_, err = c.Ack(context.Background(), "exec-1", "cmd-1", "", "x")
	if err == nil {
		t.Fatal("Ack: empty status should err")
	}
}

func TestDecodeUninstallPayload(t *testing.T) {
	c := Command{
		CommandType: CommandTypeUninstall,
		Payload: map[string]interface{}{
			"reason": "offboarding",
		},
	}
	p, err := DecodeUninstallPayload(c)
	if err != nil {
		t.Fatalf("DecodeUninstallPayload: %v", err)
	}
	if p.Reason != "offboarding" {
		t.Fatalf("DecodeUninstallPayload: reason = %q, want offboarding", p.Reason)
	}
}

func TestDecodeUninstallPayload_NilPayloadErrors(t *testing.T) {
	c := Command{CommandType: CommandTypeUninstall}
	if _, err := DecodeUninstallPayload(c); err == nil {
		t.Fatal("DecodeUninstallPayload(nil payload) should err")
	}
}

// TestNewClient_NilDoerPanics guards against a wiring
// mistake. A nil doer is a programmer error, not a runtime
// one; panic is the right answer.
func TestNewClient_NilDoerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewClient(nil) should panic")
		}
	}()
	_ = NewClient(nil)
}

// TestEndToEnd_ViaHTTPServer exercises the wire shape via a
// real httptest.Server. Confirms the GET + POST + envelope
// + ack roundtrip works against a production-shaped
// server. This is the closest-to-production unit test we
// have without spinning up Postgres.
func TestEndToEnd_ViaHTTPServer(t *testing.T) {
	var (
		listHits atomic.Int32
		ackHits  atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/executors/exec-e2e/commands":
			if r.Method != http.MethodGet {
				w.WriteHeader(500)
				return
			}
			listHits.Add(1)
			row := Command{
				CommandID:   "cmd-e2e",
				ExecutorID:  "exec-e2e",
				CommandType: CommandTypeUninstall,
				Payload:     map[string]interface{}{"reason": "e2e"},
				IssuedAt:    time.Now().UTC(),
				ExpiresAt:   time.Now().UTC().Add(time.Hour),
			}
			out := ListResponse{ExecutorID: "exec-e2e", Commands: []Command{row}, Count: 1}
			b, _ := json.Marshal(out)
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		case "/api/v1/executors/exec-e2e/commands/cmd-e2e/ack":
			if r.Method != http.MethodPost {
				w.WriteHeader(500)
				return
			}
			ackHits.Add(1)
			var sent AckRequest
			if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
				w.WriteHeader(400)
				return
			}
			if sent.Status != AckStatusSuccess {
				t.Errorf("ack status = %q, want %q", sent.Status, AckStatusSuccess)
			}
			out := AckResponse{
				CommandID:  "cmd-e2e",
				ExecutorID: "exec-e2e",
				AckedAt:    time.Now().UTC(),
				AckStatus:  AckStatusSuccess,
				AckMessage: sent.Message,
			}
			b, _ := json.Marshal(out)
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Use the real HTTPClient (not stub) for the roundtrip.
	// We use NewHTTPClientForTest to skip the cert pinning
	// for this test transport — this test verifies the
	// commands.Client wire surface, not the cert pinning.
	//
	// Wire a thin HTTPDoer adapter that uses srv.Client().
	// This shape mirrors what the production PlatformClient
	// will provide.
	adapter := &httpServerAdapter{serverURL: srv.URL, http: srv.Client()}
	c := NewClient(adapter)

	rows, err := c.ListPending(context.Background(), "exec-e2e")
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListPending: want 1, got %d", len(rows))
	}
	if rows[0].CommandID != "cmd-e2e" {
		t.Fatalf("ListPending: wrong command id")
	}
	if rows[0].CommandType != CommandTypeUninstall {
		t.Fatalf("ListPending: wrong command type")
	}

	ack, err := c.Ack(context.Background(), "exec-e2e", "cmd-e2e", AckStatusSuccess, "shredded")
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if ack.AckStatus != AckStatusSuccess {
		t.Fatalf("Ack response: status = %q, want success", ack.AckStatus)
	}

	if listHits.Load() != 1 {
		t.Errorf("list endpoint hit %d times, want 1", listHits.Load())
	}
	if ackHits.Load() != 1 {
		t.Errorf("ack endpoint hit %d times, want 1", ackHits.Load())
	}
}

// httpServerAdapter is a tiny shim that lets commands.Client
// drive a real httptest.Server. It implements HTTPDoer
// without pulling in the full PlatformClient (which requires
// the api-key file at construction time).
type httpServerAdapter struct {
	serverURL string
	http      *http.Client
}

func (a *httpServerAdapter) Do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	// httptest.Server.URL is something like http://127.0.0.1:PORT.
	// We strip the leading http:// and rebuild the URL with
	// the test path.
	stripped := a.serverURL
	// path is something like /api/v1/executor/...; we want
	// to replace the host with the test server.
	idx := 0
	for i, c := range stripped {
		if c == ':' && i > 0 {
			// advance past the second colon (port)
			idx = i + 1
		}
	}
	_ = idx
	// simpler: just build url as serverURL + path
	url := stripped + path
	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return a.http.Do(req)
}

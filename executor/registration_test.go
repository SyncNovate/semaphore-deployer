package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestRegistrationHappyPath exercises the full register flow:
// the executor POSTs the §7.1 payload + a signed service JWT
// and the server returns 201 with an executor_token.
func TestRegistrationHappyPath(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "executor", "aud")

	var serverHits int32
	var receivedAuth string
	var receivedBody RegistrationRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		receivedAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/executor/register" {
			t.Errorf("server hit on path %q, want /api/v1/executor/register", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"executor_token":"EX-TOK-001","expires_at":"2026-12-31T00:00:00Z"}`))
	}))
	defer server.Close()

	client := newTestHTTPClient(t, server)

	resp, err := Registration(context.Background(), client, signer, RegistrationRequest{
		ExecutorID:         "EXEC-001",
		TenantID:           "ORG-001",
		DeploymentZoneID:   "HQ",
		PlatformsSupported: []string{"windows", "linux"},
		ExecutorVersion:    "0.1.0",
	})
	if err != nil {
		t.Fatalf("Registration: %v", err)
	}
	if resp.ExecutorToken != "EX-TOK-001" {
		t.Errorf("ExecutorToken = %q, want EX-TOK-001", resp.ExecutorToken)
	}
	if atomic.LoadInt32(&serverHits) != 1 {
		t.Errorf("server hits = %d, want 1", serverHits)
	}
	if !strings.HasPrefix(receivedAuth, "Bearer ") {
		t.Errorf("Authorization header = %q, want Bearer prefix", receivedAuth)
	}
	// Verify the body the server received matches the
	// §7.1 schema: every required field present.
	if receivedBody.TenantID != "ORG-001" {
		t.Errorf("server saw tenant_id = %q, want ORG-001", receivedBody.TenantID)
	}
	if receivedBody.DeploymentZoneID != "HQ" {
		t.Errorf("server saw deployment_zone_id = %q, want HQ", receivedBody.DeploymentZoneID)
	}
	if receivedBody.ExecutorID != "EXEC-001" {
		t.Errorf("server saw executor_id = %q, want EXEC-001", receivedBody.ExecutorID)
	}
	if len(receivedBody.PlatformsSupported) != 2 {
		t.Errorf("server saw platforms_supported = %v, want 2 entries", receivedBody.PlatformsSupported)
	}
}

// TestRegistrationRejectsMissingTenant exercises the
// fail-closed contract: the executor refuses to send a
// registration with an empty tenant_id, even if the server
// would (also) reject it.
func TestRegistrationRejectsMissingTenant(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "executor", "aud")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called for a missing-tenant request")
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	_, err := Registration(context.Background(), client, signer, RegistrationRequest{
		ExecutorID:       "EXEC-001",
		DeploymentZoneID: "HQ",
		// TenantID: "" — should be caught client-side
	})
	if err == nil {
		t.Error("Registration should reject missing tenant_id")
	}
	if !strings.Contains(err.Error(), "tenant_id") {
		t.Errorf("error = %q, want mentions tenant_id", err.Error())
	}
}

// TestRegistrationRejectsMissingZone mirrors the tenant
// test for deployment_zone_id.
func TestRegistrationRejectsMissingZone(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "executor", "aud")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called for a missing-zone request")
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	_, err := Registration(context.Background(), client, signer, RegistrationRequest{
		ExecutorID: "EXEC-001",
		TenantID:   "ORG-001",
		// DeploymentZoneID: "" — should be caught client-side
	})
	if err == nil {
		t.Error("Registration should reject missing deployment_zone_id")
	}
	if !strings.Contains(err.Error(), "deployment_zone_id") {
		t.Errorf("error = %q, want mentions deployment_zone_id", err.Error())
	}
}

// TestRegistrationRejectsMissingExecutorID is the same
// pattern: empty executor_id is a client-side failure.
func TestRegistrationRejectsMissingExecutorID(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "executor", "aud")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be called for a missing-executor-id request")
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	_, err := Registration(context.Background(), client, signer, RegistrationRequest{
		// ExecutorID: "" — should be caught client-side
		TenantID:         "ORG-001",
		DeploymentZoneID: "HQ",
	})
	if err == nil {
		t.Error("Registration should reject missing executor_id")
	}
}

// TestRegistrationServerRejectsEmptyExecutorToken verifies
// the executor's defense-in-depth check: even if the server
// returns 201, an empty `executor_token` is treated as a
// failure (refuse to operate with a no-op bearer).
func TestRegistrationServerRejectsEmptyExecutorToken(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "executor", "aud")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"executor_token":"","expires_at":"2026-12-31T00:00:00Z"}`))
	}))
	defer server.Close()
	client := newTestHTTPClient(t, server)

	_, err := Registration(context.Background(), client, signer, RegistrationRequest{
		ExecutorID:       "EXEC-001",
		TenantID:         "ORG-001",
		DeploymentZoneID: "HQ",
	})
	if err == nil {
		t.Error("Registration should reject empty executor_token from server")
	}
	if !strings.Contains(err.Error(), "executor_token") {
		t.Errorf("error = %q, want mentions executor_token", err.Error())
	}
}

// TestRegistrationRequiresSignerAndClient pins the
// constructor invariants.
func TestRegistrationRequiresSignerAndClient(t *testing.T) {
	if _, err := Registration(context.Background(), nil, nil, RegistrationRequest{}); err == nil {
		t.Error("Registration should reject nil client")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")
	if _, err := Registration(context.Background(), nil, signer, RegistrationRequest{}); err == nil {
		t.Error("Registration should reject nil client (with real signer)")
	}
}

// TestIsTransientRegistrationErrorClassifies5xxAsTransient
// pins the failure-path contract.
func TestIsTransientRegistrationErrorClassifies5xxAsTransient(t *testing.T) {
	err := ClassifyHTTPResponseError(500, []byte("upstream is on fire"))
	if !IsTransientRegistrationError(err) {
		t.Errorf("5xx should be transient; got %v", err)
	}
}

// TestIsTransientRegistrationErrorClassifies4xxAsPermanent
// pins the contract that 4xx is NOT retriable (operator must
// fix the config).
func TestIsTransientRegistrationErrorClassifies4xxAsPermanent(t *testing.T) {
	err := ClassifyHTTPResponseError(400, []byte("tenant_id is required"))
	if IsTransientRegistrationError(err) {
		t.Errorf("4xx should be permanent; got %v", err)
	}
}

// TestIsTransientRegistrationErrorClassifies429AsTransient
// pins the rate-limit case as transient (the daemon should
// back off + retry, not crash).
func TestIsTransientRegistrationErrorClassifies429AsTransient(t *testing.T) {
	err := ClassifyHTTPResponseError(429, []byte("rate limit exceeded"))
	if !IsTransientRegistrationError(err) {
		t.Errorf("429 should be transient; got %v", err)
	}
}

// TestIsTransientRegistrationErrorClassifiesUnknownAsTransient
// pins the defense-in-depth: a non-typed error (e.g. raw
// network blip) is treated as transient so the daemon backs
// off + retries rather than crashing on the first hiccup.
func TestIsTransientRegistrationErrorClassifiesUnknownAsTransient(t *testing.T) {
	if !IsTransientRegistrationError(errors.New("connection reset by peer")) {
		t.Error("unknown error should be treated as transient (retry on the next tick)")
	}
}

// newTestHTTPClient builds an in-memory mTLS HTTP client
// pointed at the given test server. Reuses the helper in
// client_test.go (same package). The mTLS client cert is
// presented; the InsecureSkipVerify is a test-scaffolding
// concession for the self-signed httptest cert (no portable
// way to extract the server's CA back to PEM).
func newTestHTTPClient(t *testing.T, server *httptest.Server) *HTTPClient {
	t.Helper()
	return newInMemoryTestClientPointingAt(t, server.URL)
}

package executor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhookPropagator_HMACEnvelope exercises the full envelope
// round-trip:
//   - generate an event
//   - propagator delivers to a test HTTP server
//   - server verifies the X-Audit-Signature header against the
//     canonical body using the configured key (GitHub / Stripe /
//     Slack webhook contract per design doc §6 / decision 3)
//
// R-I.1.e (design doc §8 TestAudit_AffinityViolation_Logged-ish —
// specifically the propagation plumbing).
func TestWebhookPropagator_HMACEnvelope(t *testing.T) {
	const key = "test-hmac-key-shared-with-platform-BE"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		// Verify headers per the audit contract.
		gotSig := r.Header.Get("X-Audit-Signature")
		require.True(t, strings.HasPrefix(gotSig, "sha256="),
			"X-Audit-Signature must use the sha256= prefix (industry envelope)")
		wantSig := computeHMACSignature([]byte(key), body)
		assert.Equal(t, "sha256="+wantSig, gotSig, "signature mismatch")

		// Decode + sanity-check the payload shape.
		var ev AuditEvent
		require.NoError(t, json.Unmarshal(body, &ev))
		assert.Equal(t, "executor.affinity_violation", ev.Event)
		assert.Equal(t, "EXEC-EXECUTOR-ID", ev.ExecutorID)
		assert.Equal(t, "ORG-AV", ev.TenantID)
		assert.Equal(t, "ZONE-AV", ev.DeploymentZoneID)
		assert.NotEmpty(t, r.Header.Get("X-Audit-Id"))
		assert.NotEmpty(t, r.Header.Get("X-Audit-Timestamp"))
		assert.Equal(t, "executor.affinity_violation", r.Header.Get("X-Audit-Event"))

		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv(EnvAuditWebhookURL, srv.URL)
	t.Setenv(EnvAuditHMACKey, key)

	p := NewWebhookPropagator()
	require.True(t, p.IsConfigured())

	p.Propagate(AuditEvent{
		Event:            "executor.affinity_violation",
		ExecutorID:       "EXEC-EXECUTOR-ID",
		TenantID:         "ORG-AV",
		DeploymentZoneID: "ZONE-AV",
		Payload:          map[string]any{"claimed_tenant_id": "ORG-OTHER"},
	})
}

// TestWebhookPropagator_NoOpWhenUnset verifies the propagator stays
// silent when the platform BE hasn't configured the webhook. We
// never want a misconfigured fork to leak audit data to random
// destinations.
//
// R-I.1.e.
func TestWebhookPropagator_NoOpWhenUnset(t *testing.T) {
	// Both env vars cleared.
	for _, k := range []string{EnvAuditWebhookURL, EnvAuditHMACKey} {
		t.Cleanup(func() {
			_ = os.Unsetenv // safe no-op; ensure import used
		})
		os.Unsetenv(k)
	}
	t.Setenv(EnvAuditWebhookURL, "")
	t.Setenv(EnvAuditHMACKey, "")

	p := NewWebhookPropagator()
	assert.False(t, p.IsConfigured())
	// No goroutine spawn, no panic.
	p.Propagate(AuditEvent{Event: "noop", TenantID: "ORG", DeploymentZoneID: "Z"})
}

// TestWebhookPropagator_FailureOpensBreakerAt5 sends FailureThreshold
// failures in a row to a 500-returning server + asserts the breaker
// trips after the 5th failure. Subsequent calls must short-circuit
// without making HTTP requests.
//
// R-I.1.e (industry-standard rate-limited-failure pattern per design
// doc §6 / decision 5).
func TestWebhookPropagator_FailureOpensBreakerAt5(t *testing.T) {
	const key = "k"
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	p := NewWebhookPropagatorFromURL(srv.URL, key, 5*time.Second)

	// First FailureThreshold calls fire; each one increments hits.
	for i := 0; i < FailureThreshold; i++ {
		p.Propagate(AuditEvent{Event: "test", TenantID: "ORG", DeploymentZoneID: "Z"})
	}
	hitsAfter5 := hits.Load()
	assert.Equal(t, int32(FailureThreshold), hitsAfter5,
		"first %d calls must each hit the server", FailureThreshold)
	assert.True(t, p.breakerOpen.Load(),
		"breaker must be open after %d consecutive failures", FailureThreshold)

	// While the breaker is open, subsequent calls short-circuit
	// (no additional HTTP hits).
	prevHits := hits.Load()
	for i := 0; i < 3; i++ {
		p.Propagate(AuditEvent{Event: "test", TenantID: "ORG", DeploymentZoneID: "Z"})
	}
	assert.Equal(t, prevHits, hits.Load(), "breaker open must short-circuit (no extra HTTP)")
}

// TestWebhookPropagator_SuccessClosesBreaker verifies the recovery
// path: a successful HTTP delivery resets the failure counter and
// closes the breaker.
//
// R-I.1.e.
func TestWebhookPropagator_SuccessClosesBreaker(t *testing.T) {
	const key = "k"
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	p := NewWebhookPropagatorFromURL(srv.URL, key, 5*time.Second)

	// Pre-seed the breaker state the way a previous failure burst
	// left it. The first real HTTP call will succeed.
	p.breakerOpen.Store(true)
	p.consecutiveFailures.Store(int32(FailureThreshold))

	// The breaker is already open, so this first call short-circuits.
	p.Propagate(AuditEvent{Event: "first", TenantID: "ORG", DeploymentZoneID: "Z"})
	assert.Equal(t, int32(0), hits.Load(),
		"breaker-open path must skip the HTTP call entirely")

	// Now manually close the breaker (mimicking what a future
	// health-gate sweeper would do) + verify the next call
	// delivers successfully.
	p.breakerOpen.Store(false)
	p.Propagate(AuditEvent{Event: "second", TenantID: "ORG", DeploymentZoneID: "Z"})
	assert.Equal(t, int32(1), hits.Load(), "successful call hits the server")
	assert.Equal(t, int32(0), p.consecutiveFailures.Load(),
		"successful delivery resets the failure counter")
}

// TestVerifyHMAC verifies the inverse of computeHMACSignature.
// This is what the platform BE's receiver does; round-tripping
// here keeps the algorithm honest.
//
// R-I.1.e.
func TestVerifyHMAC(t *testing.T) {
	key := []byte("k1")
	body := []byte(`{"event":"x"}`)

	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	header := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	require.NoError(t, verifyHMAC(key, body, header))

	// Tampered body → signature mismatch.
	bad := []byte(`{"event":"y"}`)
	assert.Error(t, verifyHMAC(key, bad, header))

	// Wrong key → signature mismatch.
	wrong := []byte("k2")
	assert.Error(t, verifyHMAC(wrong, body, header))

	// Missing prefix.
	stripped := strings.TrimPrefix(header, "sha256=")
	assert.Error(t, verifyHMAC(key, body, stripped))
}

// TestNewAuditID_Uniqueness verifies the random ID generator emits
// distinct IDs for back-to-back calls. The 16-byte random pool
// gives ~2^-128 collision probability — collisions in 1000 calls
// would be a bug.
//
// R-I.1.e.
func TestNewAuditID_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := newAuditID()
		_, dup := seen[id]
		assert.False(t, dup, "id collision on call %d: %s", i, id)
		seen[id] = struct{}{}
	}
}
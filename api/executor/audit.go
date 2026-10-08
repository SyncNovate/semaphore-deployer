// Audit propagation webhook — outbound from the fork to the SentraOps
// platform BE.
//
// The fork logs every security-relevant executor event in its own
// structured log + propagates the subset the platform cares about over
// an HMAC-signed HTTP webhook. This file implements the webhook side:
//
//   - POST to `SENTRAOPS_AUDIT_WEBHOOK_URL`
//   - Body = canonical JSON of the AuditEvent
//   - Signature = HMAC-SHA256(body, SENTRAOPS_AUDIT_HMAC_KEY)
//   - Headers: X-Audit-Signature: <hex>, X-Audit-Timestamp: <unix>,
//     X-Audit-Id: <uuid>, X-Audit-Event: <event name>
//
// Industry citation: GitHub + Stripe + Slack webhook envelopes (HMAC
// over the request body + constant-time compare + timestamp for replay
// protection). See docs/architecture/2026-10-07-semaphore-fork-design.md
// §6 + design doc decision 3.
//
// SentraOps fork (R-I.1.d).
package executor

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// EnvAuditWebhookURL is the env-var name that configures the
// outbound audit webhook target. Empty value disables the webhook
// entirely (logs still emit; replay is the operator's choice).
const EnvAuditWebhookURL = "SENTRAOPS_AUDIT_WEBHOOK_URL"

// EnvAuditHMACKey is the env-var name that carries the shared secret
// for the HMAC envelope. Empty value disables the webhook (refusing
// to sign with an empty key — fail closed).
const EnvAuditHMACKey = "SENTRAOPS_AUDIT_HMAC_KEY"

// EnvAuditTimeoutMS overrides the per-event HTTP timeout. Default 5s.
const EnvAuditTimeoutMS = "SENTRAOPS_AUDIT_TIMEOUT_MS"

// FailureThreshold is the number of consecutive failures that flips
// the breaker open. Per design doc §6, after 5 consecutive failures
// the fork logs `audit_propagation_backlog_growing` and the operator
// is notified via the existing Semaphore alerting mechanism.
const FailureThreshold = 5

// AuditEvent is the payload envelope the fork sends to the platform.
// The shape matches `docs/architecture/2026-10-07-semaphore-fork-design.md`
// §6 table.
type AuditEvent struct {
	// ID is the unique identifier for this audit event. The platform
	// uses it for dedup + audit-chain ordering.
	ID string `json:"id"`
	// Timestamp is the wall-clock time the event was emitted (UTC).
	Timestamp time.Time `json:"timestamp"`
	// Event is the dotted event name (e.g. `executor.affinity_violation`).
	Event string `json:"event"`
	// ExecutorID is the public ULID of the executor this event is
	// about. Empty for fork-wide events.
	ExecutorID string `json:"executor_id,omitempty"`
	// TenantID is the bound tenant.
	TenantID string `json:"tenant_id"`
	// DeploymentZoneID is the bound zone.
	DeploymentZoneID string `json:"deployment_zone_id"`
	// Payload is the per-event-specific data (see design doc §6).
	Payload map[string]any `json:"payload"`
	// ActorID is the operator id the BE was acting on behalf of, if
	// available. Populated from the service JWT's `actor_id` claim
	// when the originating API request was service-to-service.
	ActorID string `json:"actor_id,omitempty"`
}

// Propagator is the interface the executor handlers use. Concrete
// implementation is `WebhookPropagator` below; tests can supply a fake.
type Propagator interface {
	Propagate(event AuditEvent)
}

// Default is the package-level propagator handlers use when they have
// not been configured with a custom implementation (R-I.1.d +
// design doc §6). The binary calls SetDefaultPropagator at boot. If
// never set, DefaultPropagator() returns a no-op (logs still emit
// but no webhook fires).
var Default Propagator

// SetDefaultPropagator swaps the package-level default propagator.
// Wire this from main.go at boot. Tests swap in fakes via this.
func SetDefaultPropagator(p Propagator) {
	Default = p
}

// DefaultPropagator returns Default, or a no-op when Default is nil
// (no env vars set / R-I.1.d startup hasn't configured the target).
func DefaultPropagator() Propagator {
	if Default != nil {
		return Default
	}
	return noopPropagator{}
}

type noopPropagator struct{}

func (noopPropagator) Propagate(AuditEvent) {}

// WebhookPropagator delivers audit events over HMAC-signed HTTP
// POSTs. Safe for concurrent use.
type WebhookPropagator struct {
	url    string
	key    []byte
	client *http.Client

	// consecutiveFailures counts back-to-back delivery failures.
	// When it reaches FailureThreshold, the breaker flips open and
	// subsequent calls short-circuit until the next successful
	// delivery resets it.
	consecutiveFailures atomic.Int32
	breakerOpen         atomic.Bool
}

// NewWebhookPropagator returns a propagator wired against the env-vars
// at the time of construction. If SENTRAOPS_AUDIT_WEBHOOK_URL is
// empty, the returned propagator is a no-op (logs still emit but no
// webhook fires).
func NewWebhookPropagator() *WebhookPropagator {
	return newWebhookPropagator(
		os.Getenv(EnvAuditWebhookURL),
		os.Getenv(EnvAuditHMACKey),
		os.Getenv(EnvAuditTimeoutMS),
	)
}

// NewWebhookPropagatorFromURL is the test-friendly constructor. It
// takes the URL + key + timeout-ms directly (rather than reading
// env), so unit tests can override each field independently.
//
// SentraOps fork (R-I.1.e).
func NewWebhookPropagatorFromURL(url string, key string, timeout time.Duration) *WebhookPropagator {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	p := &WebhookPropagator{
		url:    url,
		key:    []byte(key),
		client: &http.Client{Timeout: timeout},
	}
	return p
}

// newWebhookPropagator is the shared constructor that
// NewWebhookPropagator delegates to.
func newWebhookPropagator(url, key, timeoutMS string) *WebhookPropagator {
	p := &WebhookPropagator{
		url: url,
		key: []byte(key),
	}
	if p.url != "" && len(p.key) > 0 {
		timeout := 5 * time.Second
		if timeoutMS != "" {
			if d, err := time.ParseDuration(timeoutMS + "ms"); err == nil && d > 0 && d < 60*time.Second {
				timeout = d
			}
		}
		p.client = &http.Client{Timeout: timeout}
	}
	return p
}

// IsConfigured reports whether the propagator has both a URL and a
// key. Endpoint handlers use this to decide whether to bother
// computing the payload (skips work when the propagation target is
// not set).
func (p *WebhookPropagator) IsConfigured() bool {
	return p != nil && p.url != "" && len(p.key) > 0
}

// Propagate emits the event. Failures are logged + counted; the
// breaker opens after FailureThreshold consecutive failures. The
// platform's anomaly detector picks up the `audit_propagation_backlog_growing`
// log line after the breaker opens.
func (p *WebhookPropagator) Propagate(event AuditEvent) {
	if p == nil || !p.IsConfigured() {
		return
	}
	if p.breakerOpen.Load() {
		// Breaker open: short-circuit to avoid amplifying the
		// backlog. The platform's anomaly detector picks up the
		// `audit_propagation_backlog_growing` log line emitted at
		// threshold-crossing time.
		return
	}
	if event.ID == "" {
		event.ID = newAuditID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	canonicalBody, err := json.Marshal(event)
	if err != nil {
		log.WithError(err).WithField("audit_id", event.ID).
			Error("audit_propagation_marshal_failed")
		return
	}

	signature := computeHMACSignature(p.key, canonicalBody)
	timestamp := fmt.Sprintf("%d", event.Timestamp.Unix())
	auditID := event.ID

	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(canonicalBody))
	if err != nil {
		p.recordFailure(auditID, event.Event, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Audit-Signature", "sha256="+signature)
	req.Header.Set("X-Audit-Timestamp", timestamp)
	req.Header.Set("X-Audit-Id", auditID)
	req.Header.Set("X-Audit-Event", event.Event)

	resp, err := p.client.Do(req)
	if err != nil {
		p.recordFailure(auditID, event.Event, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		p.recordFailure(auditID, event.Event,
			fmt.Errorf("non-2xx: %d", resp.StatusCode))
		return
	}

	p.consecutiveFailures.Store(0)
	if p.breakerOpen.CompareAndSwap(true, false) {
		log.WithField("audit_id", auditID).
			Info("audit_propagation_recovered")
	}
}

// recordFailure increments the breaker counter and trips it open if
// the threshold has been reached. Logs every failure at WARN so the
// operator sees it in the structured log; logs the breaker opening
// at ERROR with the dossier event name.
func (p *WebhookPropagator) recordFailure(auditID, event string, err error) {
	count := p.consecutiveFailures.Add(1)
	log.WithError(err).WithFields(log.Fields{
		"audit_id":     auditID,
		"event":        event,
		"failure_seq":  count,
		"webhook_url":  p.url,
	}).
		Warn("audit_propagation_failed")

	if count >= FailureThreshold && p.breakerOpen.CompareAndSwap(false, true) {
		log.WithFields(log.Fields{
			"event":              event,
			"consecutive_failed": count,
			"threshold":          FailureThreshold,
		}).
			Error("audit_propagation_backlog_growing")
	}
}

// verifyHMAC is the inverse of computeHMACSignature, used by the
// platform BE to validate the signature header. Exposed for the
// future integration test that round-trips through a fake server.
//
// SentraOps fork (R-I.1.d).
func verifyHMAC(key []byte, body []byte, header string) error {
	if !strings.HasPrefix(header, "sha256=") {
		return errors.New("audit: missing sha256 prefix")
	}
	want, err := hex.DecodeString(header[len("sha256="):])
	if err != nil {
		return fmt.Errorf("audit: hex decode: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	got := mac.Sum(nil)
	if !hmac.Equal(want, got) {
		return errors.New("audit: signature mismatch")
	}
	return nil
}

// computeHMACSignature returns the lowercase hex HMAC-SHA256 of the
// canonical body keyed by key.
func computeHMACSignature(key, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// newAuditID returns a 128-bit random id encoded as hex. Used to give
// every audit event a unique id without pulling in uuid.
func newAuditID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read should never fail on Linux; fall back
		// to a timestamp-derived id rather than panicking.
		ts := time.Now().UnixNano()
		return fmt.Sprintf("%016x", ts)
	}
	return hex.EncodeToString(b[:])
}

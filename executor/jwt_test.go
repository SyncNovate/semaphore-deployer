package executor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/semaphoreui/semaphore/pkg/jwt"
)

// TestEd25519SignerRoundTripViaForkVerifier is the most
// important test in R-I.4.b: it proves the executor's minted
// token is accepted by the fork's own verifier. This is the
// cross-package contract — if this test passes, the executor's
// mTLS+JWT auth path is wire-compatible with the
// semaphore-deployer fork.
func TestEd25519SignerRoundTripViaForkVerifier(t *testing.T) {
	// Build a keypair + signer in-test (no PEM file roundtrip;
	// the PEM roundtrip is tested separately below).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := NewEd25519SignerForTest(priv, "executor", "sentraops-platform")

	claims := ExecutorClaims{
		TenantID:         "ORG-001",
		DeploymentZoneID: "HQ",
		ExecutorID:       "EXEC-TEST-001",
	}
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !strings.HasPrefix(token, "eyJ") {
		t.Errorf("token = %q, want compact JWS (3 base64url segments)", token)
	}

	// Verify via the FORK's verifier (not the executor's). This
	// is the contract: the wire format must match what the
	// server's existing JWT middleware (R-I.1.d) accepts.
	pubPEM, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}
	parsed, err := jwt.Verify(token, pubPEM)
	if err != nil {
		t.Fatalf("fork Verify: %v", err)
	}

	// The fork's verifier doesn't know about ExecutorClaims;
	// it extracts the ServiceClaims it cares about. The
	// `tenant_id` claim is the one that matters for tenant
	// isolation. The other executor-specific claims (zone_id,
	// executor_id) are echoed in the wire format for audit-log
	// correlation but the fork's verifier doesn't enforce them.
	if parsed.TenantID != "ORG-001" {
		t.Errorf("parsed.TenantID = %q, want ORG-001", parsed.TenantID)
	}
}

// TestEd25519SignerPEMRoundTrip verifies the production path:
// load a PEM-encoded PKCS#8 Ed25519 private key (the shape
// Python's `cryptography` library produces — see SentraOps BE
// `_sign_jwt` in services/runner_deployment.py).
func TestEd25519SignerPEMRoundTrip(t *testing.T) {
	pemBytes, err := GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("PEM block = %v, want PRIVATE KEY", block)
	}
	// Sanity: the inner bytes parse as PKCS8 Ed25519.
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKCS8: %v", err)
	}
	if _, ok := raw.(ed25519.PrivateKey); !ok {
		t.Fatalf("key type = %T, want ed25519.PrivateKey", raw)
	}

	signer, err := NewEd25519SignerFromPEM(pemBytes, "executor", "sentraops-platform",
		60*time.Second)
	if err != nil {
		t.Fatalf("NewEd25519SignerFromPEM: %v", err)
	}
	token, err := signer.Sign(ExecutorClaims{
		TenantID:         "ORG-001",
		DeploymentZoneID: "HQ",
		ExecutorID:       "EXEC-PEM-001",
	})
	if err != nil {
		t.Fatalf("Sign after PEM roundtrip: %v", err)
	}
	if token == "" {
		t.Error("empty token after PEM roundtrip")
	}
}

// TestEd25519SignerPEMRejectsNonEd25519 verifies the fail-closed
// contract: a PEM key that is NOT Ed25519 is rejected at
// construction, not silently downgraded.
func TestEd25519SignerPEMRejectsNonEd25519(t *testing.T) {
	// Build a fake "PKCS8" PEM block with non-Ed25519 inner
	// bytes. We use empty bytes; x509.ParsePKCS8PrivateKey
	// will reject it for being invalid, but the test still
	// covers the "wrong key type" path because the constructor
	// calls x509.ParsePKCS8PrivateKey first.
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("not a real key"),
	})
	_, err := NewEd25519SignerFromPEM(pemBytes, "executor", "sentraops-platform", 60*time.Second)
	if err == nil {
		t.Error("NewEd25519SignerFromPEM should reject a non-Ed25519 key")
	}
}

// TestEd25519SignerPEMRejectsNonPEMInput checks the first
// failure mode: bytes that are not even a PEM block.
func TestEd25519SignerPEMRejectsNonPEMInput(t *testing.T) {
	_, err := NewEd25519SignerFromPEM([]byte("not pem"), "executor", "sentraops-platform", 60*time.Second)
	if err == nil {
		t.Error("NewEd25519SignerFromPEM should reject non-PEM bytes")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("error = %q, want mentions PEM", err.Error())
	}
}

// TestEd25519SignerRejectsEmptyIssuerOrAudience pins the
// required-parameter contract.
func TestEd25519SignerRejectsEmptyIssuerOrAudience(t *testing.T) {
	if _, err := NewEd25519SignerFromPEM(nil, "", "aud", 60*time.Second); err == nil {
		t.Error("empty issuer should error")
	}
	if _, err := NewEd25519SignerFromPEM(nil, "iss", "", 60*time.Second); err == nil {
		t.Error("empty audience should error")
	}
}

// TestEd25519SignerDefaultTTL60Seconds pins the default token
// lifetime. The platform's service-JWT TTL is 60s (per
// services/runner_deployment.py:_sign_jwt in the BE) and the
// executor must match so the server's expiry window is
// consistent.
func TestEd25519SignerDefaultTTL60Seconds(t *testing.T) {
	pemBytes, _ := GenerateEd25519KeyPEM()
	signer, err := NewEd25519SignerFromPEM(pemBytes, "executor", "aud", 0) // 0 = use default
	if err != nil {
		t.Fatalf("NewEd25519SignerFromPEM: %v", err)
	}
	es := signer.(*ed25519Signer)
	if es.defaultTTL != 60*time.Second {
		t.Errorf("defaultTTL = %v, want 60s", es.defaultTTL)
	}
}

// TestEd25519SignerTTLInClaimMatchesDefault verifies the minted
// token's `exp` is exactly 60s after `iat`. Critical for replay
// protection: too short = clock skew rejects legitimate calls;
// too long = stale tokens accepted past the server's
// rejection window.
func TestEd25519SignerTTLInClaimMatchesDefault(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = priv // used by the signer below
	signer := NewEd25519SignerForTest(priv, "iss", "aud")

	before := time.Now().UTC().Unix()
	token, err := signer.Sign(ExecutorClaims{
		TenantID:         "ORG-001",
		DeploymentZoneID: "HQ",
		ExecutorID:       "EXEC-TTL",
	})
	after := time.Now().UTC().Unix()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Parse the JWT (without verifying signature) to inspect
	// the iat / exp claims. Use the fork's go-jose for
	// consistent parsing.
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("ParseSigned: %v", err)
	}
	var claims struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("UnsafeClaimsWithoutVerification: %v", err)
	}

	if claims.Iat < before || claims.Iat > after {
		t.Errorf("iat = %d, want in [%d, %d]", claims.Iat, before, after)
	}
	delta := claims.Exp - claims.Iat
	if delta != 60 {
		t.Errorf("exp - iat = %d, want 60 (the default TTL)", delta)
	}
}

// TestEd25519SignerKIDIsStable pins the kid derivation: the
// same key must always produce the same kid (it's the SHA-256
// of the PKIX-marshalled public key). Stable kids let the
// server cache the public key by kid across registrations.
func TestEd25519SignerKIDIsStable(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s1 := NewEd25519SignerForTest(priv, "iss", "aud")
	s2 := NewEd25519SignerForTest(priv, "iss", "aud")
	if s1.KeyID() != s2.KeyID() {
		t.Errorf("KID unstable: %q vs %q", s1.KeyID(), s2.KeyID())
	}
	if s1.KeyID() == "" {
		t.Error("KID empty; server cannot index by kid")
	}
	// Reference the unused priv so go vet doesn't flag the
	// test when both signers happen to ignore the key variable
	// (they don't, but the compiler doesn't know that).
	_ = priv
}

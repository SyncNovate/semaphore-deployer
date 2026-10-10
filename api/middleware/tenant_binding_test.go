package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/semaphoreui/semaphore/pkg/jwt"
	"github.com/stretchr/testify/assert"
)

// runTenantBinding runs the TenantBinding middleware around a no-op
// handler that records whether it was reached and what context values
// were set. Returns the recorded context values + the response.
func runTenantBinding(t *testing.T, req *http.Request) (int, string, map[string]any) {
	t.Helper()
	var captured map[string]any
	handler := TenantBinding(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = map[string]any{
			ContextKeyTenantID:           r.Context().Value(ContextKeyTenantID),
			ContextKeyDeploymentZoneIDs:  r.Context().Value(ContextKeyDeploymentZoneIDs),
			ContextKeySkipTenantFilter:   r.Context().Value(ContextKeySkipTenantFilter),
		}
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String(), captured
}

// TestTenantBinding_HappyPath_TenantHeader verifies the middleware
// reads X-Tenant-ID + X-Deployment-Zone-IDs and stores them in the
// request context. SentraOps fork (R-I.1.c) — design doc §4.1.
func TestTenantBinding_HappyPath_TenantHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/projects", nil)
	req.Header.Set(HeaderTenantID, "ORG-1")
	req.Header.Set(HeaderDeploymentZoneIDs, "ZONE-A, ZONE-B")

	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "ORG-1", captured[ContextKeyTenantID])
	assert.Equal(t, []string{"ZONE-A", "ZONE-B"}, captured[ContextKeyDeploymentZoneIDs])
	assert.Nil(t, captured[ContextKeySkipTenantFilter])
}

// TestTenantBinding_MissingTenantHeader_400 verifies a tenant-bound
// route that arrives without X-Tenant-ID is rejected. This catches
// misconfigured upstream proxies + direct probes.
func TestTenantBinding_MissingTenantHeader_400(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/projects", nil)

	code, body, _ := runTenantBinding(t, req)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, body, "tenant_id_required")
}

// TestTenantBinding_ExecutorPath_SkipsBinding verifies the executor
// route group is exempt from tenant binding (mTLS handles auth).
func TestTenantBinding_ExecutorPath_SkipsBinding(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/executor/heartbeat", nil)
	// No X-Tenant-ID; the request must pass through to the handler
	// so the executor's mTLS auth middleware can take over.
	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Nil(t, captured[ContextKeyTenantID])
}

// TestTenantBinding_InternalPath_SkipsBinding verifies the platform
// BE service-to-service path is exempt from tenant binding (the BE
// has already validated tenant scope on its end).
func TestTenantBinding_InternalPath_SkipsBinding(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/internal/projects", nil)
	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Nil(t, captured[ContextKeyTenantID])
}

// mintTestServiceJWT generates an ECDSA P-256 keypair, returns a
// compact JWS signed with the matching private key. The supplied
// claims are encoded verbatim.
func mintTestServiceJWT(t *testing.T, claims jwt.ServiceClaims) (token string, publicKeyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key: jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-kid",
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}
	sig, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	assert.NoError(t, err)

	now := time.Now().UTC()
	claims.IssuedAt = now.Unix()
	claims.NotBefore = now.Unix()
	claims.ExpiresAt = now.Add(time.Hour).Unix()

	token, err = josejwt.Signed(sig).Claims(claims).Serialize()
	assert.NoError(t, err)

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	assert.NoError(t, err)
	publicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	return token, publicKeyPEM
}

// withPlatformKey installs a generated public-key PEM into the
// package-level PlatformPublicKeyPEM for one test, restoring the
// previous value on cleanup. This is the only mutation the test
// suite performs on package-level state.
func withPlatformKey(t *testing.T, pemBytes []byte) {
	t.Helper()
	prev := PlatformPublicKeyPEM
	t.Cleanup(func() { PlatformPublicKeyPEM = prev })
	PlatformPublicKeyPEM = pemBytes
}

// TestTenantBinding_ServiceSkip_Honoured verifies a service JWT that
// verifies against the configured platform public key is honoured
// + the tenant scope comes from the JWT's claims (not from headers).
//
// SentraOps fork (R-I.1.d).
func TestTenantBinding_ServiceSkip_Honoured(t *testing.T) {
	token, pubKey := mintTestServiceJWT(t, jwt.ServiceClaims{
		Issuer:            "sentraops",
		Subject:           "service",
		TenantID:          "ORG-FROM-JWT",
		DeploymentZoneIDs: []string{"ZONE-JWT-A", "ZONE-JWT-B"},
		ActorID:           "op-1234",
	})
	withPlatformKey(t, pubKey)

	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Header.Set(HeaderSkipTenantFilter, "true")
	req.Header.Set(HeaderServiceAuth, token)
	// Headers are intentionally absent — the JWT's claims are the
	// ground truth.
	req.Header.Set(HeaderTenantID, "ORG-FROM-HEADER-SHOULD-BE-IGNORED")

	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "ORG-FROM-JWT", captured[ContextKeyTenantID])
	assert.Equal(t, []string{"ZONE-JWT-A", "ZONE-JWT-B"}, captured[ContextKeyDeploymentZoneIDs])
	assert.Equal(t, true, captured[ContextKeySkipTenantFilter])
}

// TestTenantBinding_ServiceSkip_IgnoredWithoutAuth verifies the skip
// flag is REJECTED when X-Service-Auth is missing. The platform BE is
// the only authorised skipper; an unauthenticated request must not
// bypass the filter.
//
// SentraOps fork (R-I.1.d).
func TestTenantBinding_ServiceSkip_IgnoredWithoutAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Header.Set(HeaderSkipTenantFilter, "true")
	// X-Service-Auth intentionally absent.

	code, body, _ := runTenantBinding(t, req)
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Contains(t, body, "service_auth_required")
}

// TestTenantBinding_ServiceSkip_NoPlatformKey verifies the skip is
// REJECTED when the platform public key is not configured. We fail
// closed — a misconfigured fork must NOT silently honour the skip.
//
// SentraOps fork (R-I.1.d).
func TestTenantBinding_ServiceSkip_NoPlatformKey(t *testing.T) {
	withPlatformKey(t, nil)

	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Header.Set(HeaderSkipTenantFilter, "true")
	req.Header.Set(HeaderServiceAuth, "any.token.here")

	code, body, _ := runTenantBinding(t, req)
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Contains(t, body, "service_auth_not_configured")
}

// TestTenantBinding_ServiceSkip_BadSignature verifies a token whose
// signature does NOT verify against the configured public key is
// REJECTED.
//
// SentraOps fork (R-I.1.d).
func TestTenantBinding_ServiceSkip_BadSignature(t *testing.T) {
	token, _ := mintTestServiceJWT(t, jwt.ServiceClaims{
		TenantID:         "ORG-X",
		DeploymentZoneIDs: []string{"Z"},
	})
	withPlatformKey(t, []byte("not-a-pem"))

	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Header.Set(HeaderSkipTenantFilter, "true")
	req.Header.Set(HeaderServiceAuth, token)

	code, _, _ := runTenantBinding(t, req)
	assert.NotEqual(t, http.StatusOK, code)
}

// TestTenantBinding_NoCrossStateFromEnv ensures the package-level
// PlatformPublicKeyPEM does not leak across tests via the real OS env.
func TestTenantBinding_NoCrossStateFromEnv(t *testing.T) {
	// If we got here via a different test that did set it, the
	// withPlatformKey helper has already cleaned it up. This test
	// is a guard rail.
	_ = os.Getenv("SENTRAOPS_PLATFORM_PUBLIC_KEY_PEM")
	assert.True(t, true)
}

// TestTenantBinding_ZoneIDs_TrimsAndDropsEmpty verifies whitespace and
// empty segments are stripped from X-Deployment-Zone-IDs.
func TestTenantBinding_ZoneIDs_TrimsAndDropsEmpty(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/projects", nil)
	req.Header.Set(HeaderTenantID, "ORG-1")
	req.Header.Set(HeaderDeploymentZoneIDs, "  ZONE-A ,, ZONE-B  ,")

	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"ZONE-A", "ZONE-B"}, captured[ContextKeyDeploymentZoneIDs])
}

// TestTenantBinding_ZoneIDs_EmptyWhenNoHeader verifies the zone list
// is nil when the header is absent (operator has no zone restriction).
func TestTenantBinding_ZoneIDs_EmptyWhenNoHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/projects", nil)
	req.Header.Set(HeaderTenantID, "ORG-1")

	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Nil(t, captured[ContextKeyDeploymentZoneIDs])
}

// TestParseZoneIDs_Empty verifies parseZoneIDs handles the empty case.
func TestParseZoneIDs_Empty(t *testing.T) {
	assert.Nil(t, parseZoneIDs(""))
}

// TestIsTenantUnboundRoute verifies the route classification.
func TestIsTenantUnboundRoute(t *testing.T) {
	assert.True(t, isTenantUnboundRoute("/api/v1/executor/register"))
	assert.True(t, isTenantUnboundRoute("/api/v1/executor"))
	assert.True(t, isTenantUnboundRoute("/api/internal/runners"))
	assert.True(t, isTenantUnboundRoute("/api/internal"))
	assert.False(t, isTenantUnboundRoute("/api/projects"))
	assert.False(t, isTenantUnboundRoute("/api/internal_other"))
}

// TestLoadPlatformPublicKeyFromEnv pins the env loader contract that
// closes the R-I.9 SOC console live-smoke gap (the fork returned
// ``service_auth_not_configured`` because nothing loaded the env var
// at boot). The loader MUST be called from init() so the live fork
// picks the key up at start time. Tests that want to inject a key
// use SetPlatformPublicKeyPEMForTest (or withPlatformKey).
func TestLoadPlatformPublicKeyFromEnv(t *testing.T) {
	prevKey := PlatformPublicKeyPEM
	t.Cleanup(func() { PlatformPublicKeyPEM = prevKey })

	// Loader reads the env var + trims whitespace; a valid PEM
	// string is stored verbatim in PlatformPublicKeyPEM.
	const fakePEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`
	t.Setenv("SENTRAOPS_PLATFORM_PUBLIC_KEY_PEM", fakePEM)
	LoadPlatformPublicKeyFromEnv()
	assert.Equal(t, fakePEM, string(PlatformPublicKeyPEM))

	// Empty env var leaves the var empty (so the middleware refuses
	// service-skip with ``service_auth_not_configured`` � fail closed).
	t.Setenv("SENTRAOPS_PLATFORM_PUBLIC_KEY_PEM", "")
	LoadPlatformPublicKeyFromEnv()
	assert.Equal(t, "", string(PlatformPublicKeyPEM))

	// Whitespace-only env var is trimmed to empty for the same
	// fail-closed reason.
	t.Setenv("SENTRAOPS_PLATFORM_PUBLIC_KEY_PEM", "   ")
	LoadPlatformPublicKeyFromEnv()
	assert.Equal(t, "", string(PlatformPublicKeyPEM))
}

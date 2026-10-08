package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

// TestTenantBinding_ServiceSkip_Honoured verifies that
// X-Skip-Tenant-Filter is honoured only when X-Service-Auth is also
// present (placeholder check tightened in R-I.2).
func TestTenantBinding_ServiceSkip_Honoured(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Header.Set(HeaderSkipTenantFilter, "true")
	req.Header.Set(HeaderServiceAuth, "service-jwt-placeholder")

	code, _, captured := runTenantBinding(t, req)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, true, captured[ContextKeySkipTenantFilter])
}

// TestTenantBinding_ServiceSkip_IgnoredWithoutAuth verifies the skip
// flag is ignored when X-Service-Auth is missing. The platform BE is
// the only authorised skipper; an unauthenticated request must not
// bypass the filter even if it sets the header.
func TestTenantBinding_ServiceSkip_IgnoredWithoutAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/projects", nil)
	req.Header.Set(HeaderSkipTenantFilter, "true")
	// X-Service-Auth intentionally absent.

	code, body, _ := runTenantBinding(t, req)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Contains(t, body, "tenant_id_required")
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

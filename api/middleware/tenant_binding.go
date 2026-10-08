package middleware

import (
	"net/http"
	"strings"

	"github.com/semaphoreui/semaphore/api/helpers"
)

// Context keys under which the tenant binding is stored in the request
// context. Handlers read these via helpers.GetFromContext(r, ...).
//
// SentraOps fork (R-I.1.c) — three enforcement layers per design doc
// §4. This is layer 1: the request-time middleware.
const (
	// ContextKeyTenantID is the bound tenant for the current request.
	// Empty string when the route is tenant-unbound (executor / internal).
	ContextKeyTenantID = "tenant_id"

	// ContextKeyDeploymentZoneIDs is the list of deployment zones the
	// operator is scoped to within the tenant. Empty slice when
	// tenant-unbound or when the operator has no zone restriction.
	ContextKeyDeploymentZoneIDs = "deployment_zone_ids"

	// ContextKeySkipTenantFilter is the flag that allows a request to
	// bypass the storage-layer tenant filter. Only the platform BE on
	// service-to-service mTLS is allowed to set this (R-I.2). The
	// middleware only honours it when X-Service-Auth is also present.
	ContextKeySkipTenantFilter = "skip_tenant_filter"

	// HeaderTenantID is the request header that carries the bound tenant
	// for the current request. Set by the upstream proxy in production
	// (R-I.2) or by the platform BE on service-to-service mTLS calls.
	HeaderTenantID = "X-Tenant-ID"

	// HeaderDeploymentZoneIDs is the request header that carries the
	// comma-separated list of deployment zones the operator can see.
	HeaderDeploymentZoneIDs = "X-Deployment-Zone-IDs"

	// HeaderSkipTenantFilter is the service-to-service bypass flag.
	// Must be set alongside the service mTLS handshake + service JWT
	// (R-I.2) to be honoured.
	HeaderSkipTenantFilter = "X-Skip-Tenant-Filter"

	// HeaderServiceAuth is the service-to-service JWT that proves the
	// caller is the platform BE. When present + valid, X-Skip-Tenant-Filter
	// is honoured. R-I.2 wires the JWT validator; for R-I.1.c we only
	// assert that the header is non-empty (a placeholder check, tightened
	// in R-I.2).
	HeaderServiceAuth = "X-Service-Auth"
)

// TenantBinding is the request-time middleware that resolves the
// operator's tenant scope and stores it in the request context.
//
// Three enforcement layers per design doc §4:
//   1. Request-time middleware (THIS file): reads tenant_id from
//      X-Tenant-ID (set by the upstream proxy in production). Stores
//      the scope in helpers.SetContextValue so downstream handlers
//      can pull it via helpers.GetFromContext.
//   2. Storage-layer filter (db/sql/{project,inventory,access_key}.go):
//      the GetXForTenant variants enforce the same tenant_id at the
//      store layer, even if a handler forgets.
//   3. Executor claim filter (R-I.1.d — api/Executor.go).
//
// The middleware SKIPS tenant binding for:
//   - /api/v1/executor/* routes (mTLS auth, not session).
//   - /api/internal/* routes (platform-BE service-to-service, the
//     BE has already validated tenant scope on its end).
//
// In both cases, the skip is structural: the route group has its own
// auth middleware (mTLS) that runs BEFORE the storage layer is reached.
func TenantBinding(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isTenantUnboundRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Service-to-service path: the platform BE has already
		// validated the operator's tenant scope. We honour the
		// skip flag when the service-auth header is also present
		// (placeholder check; the JWT validator lands in R-I.2).
		skip := r.Header.Get(HeaderSkipTenantFilter) == "true" &&
			r.Header.Get(HeaderServiceAuth) != ""

		if skip {
			r = helpers.SetContextValue(r, ContextKeySkipTenantFilter, true)
			next.ServeHTTP(w, r)
			return
		}

		tenantID := strings.TrimSpace(r.Header.Get(HeaderTenantID))
		if tenantID == "" {
			// No tenant scope on the request and not a
			// service-to-service call. Refuse: a tenant-bound
			// route that arrives without a tenant scope is
			// either a misconfigured upstream proxy or a
			// direct probe. Either way, reject.
			helpers.WriteErrorStatus(w, "tenant_id_required", http.StatusBadRequest)
			return
		}

		zoneIDs := parseZoneIDs(r.Header.Get(HeaderDeploymentZoneIDs))

		r = helpers.SetContextValue(r, ContextKeyTenantID, tenantID)
		r = helpers.SetContextValue(r, ContextKeyDeploymentZoneIDs, zoneIDs)
		next.ServeHTTP(w, r)
	})
}

// isTenantUnboundRoute reports whether the request path belongs to a
// route group that authenticates via mTLS (not session) and therefore
// does not need the session-derived tenant scope.
func isTenantUnboundRoute(path string) bool {
	// The /api/v1/executor/* and /api/internal/* paths are placeholders
	// for the R-I.1.d + R-I.2 sub-slices. We match on the path prefix
	// before any subrouter matching so a request that does not match a
	// known handler still gets the right default.
	return strings.HasPrefix(path, "/api/v1/executor/") ||
		strings.HasPrefix(path, "/api/internal/") ||
		path == "/api/v1/executor" ||
		path == "/api/internal"
}

// parseZoneIDs splits a comma-separated list of deployment zone ids,
// trimming whitespace and dropping empty entries. An empty / missing
// header returns an empty slice (the operator has no zone restriction).
func parseZoneIDs(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

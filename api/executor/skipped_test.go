// Skip-marker tests for surfaces that are deferred to follow-on
// sub-slices. We do NOT omit them entirely — the skip markers
// document the intent so the future slice that lands the surface
// can find them and replace the Skip with assertions.
//
// R-I.1.e.
package executor

import (
	"testing"
)

// TestServiceToService_RequiresMTLS is the design-doc §8 test for
// the service-to-service mTLS path. The actual mTLS handshake is
// implemented by the upstream proxy in R-I.2 (the deploy strategy
// layer). For now the middleware refuses non-mTLS requests with
// 401 + `service_auth_invalid` regardless.
//
// To re-enable: implement the mTLS listener + extend
// middleware.TenantBinding to gate X-Skip-Tenant-Filter on a
// verified peer-cert (rather than just the platform public key
// alone). Update this test to assert a 401-with-mTLS-missing
// response shape distinct from the JWT-missing one.
//
// R-I.1.e placeholder for R-I.2.
func TestServiceToService_RequiresMTLS(t *testing.T) {
	t.Skip("service-to-service mTLS is R-I.2 work (upstream-proxy layer). Re-enable this test alongside that implementation.")
}

// TestExecutor_Offline_AfterTimeout asserts that an executor which
// has not heartbeat for the freshness window (per design doc §6)
// flips its status to `offline`. This requires a periodic sweeper
// that scans for stale executors. The sweeper is R-I.8 work
// (deployments-stage health gate); R-I.1.d ships the heartbeat path
// but not the offline-transition worker.
//
// To re-enable: land a sweeper (e.g. `services/server/executor_sweeper.go`)
// that runs every minute, queries `WHERE last_heartbeat_at < now() - INTERVAL
// '60 seconds' AND status='online' AND revoked_at IS NULL`, and
// transitions each row to status='offline'. Update this test to
// create an executor with a stale heartbeat and assert the sweeper
// flips its status.
//
// R-I.1.e placeholder for R-I.8.
func TestExecutor_Offline_AfterTimeout(t *testing.T) {
	t.Skip("executor offline-timeout sweeper is R-I.8 health-gate work. Re-enable once `services/server/executor_sweeper.go` ships.")
}

// TestProject_ZoneFilter_EnforcedOnList verifies that operators scoped
// to a single deployment zone cannot see projects in another zone
// via `GET /api/projects`. R-I.1.c added the tenant+zone middleware
// + per-row zone filtering in `db/sql/project.go`. R-I.1.e covers
// the storage half; the HTTP surface test lives in the
// `api/projects/` package (see `TestProject_List_FilteredByTenant`).
//
// R-I.1.e (full coverage note — already addressed upstream).
func TestProject_ZoneFilter_EnforcedOnList(t *testing.T) {
	t.Skip("zone-list enforcement is asserted at the storage layer in db/sql/tenant_filter_test.go. The HTTP surface test lives in api/projects/. This entry exists for design-doc §8 parity only.")
}

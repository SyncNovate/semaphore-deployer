# FORK_NOTES — SentraOps `semaphore-deployer` fork

This repo is a **fork** of [`semaphoreui/semaphore`](https://github.com/semaphoreui/semaphore) at tag **`v2.19.16`** (released 2026-10-07). We diverge from upstream to add tenant + zone binding enforcement, executor registration, and audit propagation hooks for the SentraOps deployment engine.

## Why a fork (not stock, not a wrapper)

Upstream Semaphore is a general-purpose deployment engine. It does NOT enforce:

- `tenant_id` on every project / task / inventory / access key
- `deployment_zone_id` binding for executors
- Server-side `tenant_id + deployment_zone_id` check on every claim (UI filtering is not enough)
- Audit propagation hooks for an external BE
- Service-to-service mTLS from a separate BE
- A first-class "executor" entity distinct from Semaphore's "runner"

The spec (§14.6 of the AI_SOC_Engineering_Handoff_FINAL.md) mandates these as required modifications. We fork rather than wrap, per the spec's "do not copy the entire Semaphore codebase into the AiSOC fork unless there is a compelling build/deployment reason" rule.

## Upstream pin + sync policy

| Field | Value |
|---|---|
| Upstream | `github.com/semaphoreui/semaphore` |
| Pinned tag | `v2.19.16` |
| Sync cadence | monthly |
| Sync policy | non-breaking; sync PRs land only when they do not break tenant-binding enforcement |
| `go.mod` | requires `go 1.26.4` |

## Divergence from upstream (per R-I.0.5 design + R-I.1 plan)

This file is the entry point; the actual divergence is split into a series of sub-chunks (R-I.1 through R-I.11) tracked in the SentraOps plan doc.

**As of 2026-10-08: this fork is at v2.19.16 with NO divergence yet. R-I.1 baseline landed.**

**As of R-I.1.b: this fork is at v2.19.17 with the data layer divergence. R-I.1.c (enforcement layers) and R-I.1.d (API endpoints) are next.**

**As of R-I.1.c: the storage-layer filter + request-time middleware land. R-I.1.d (the executor claim API + the platform-BE JWT validator for X-Skip-Tenant-Filter) was next.**

**As of R-I.1.d: the 5 executor endpoints + audit webhook + service-JWT validator land. R-I.1.e (15-test suite surface) is next.**

### Divergence landed (R-I.1.b)

| File | Change |
|---|---|
| `db/sql/migrations/v2.19.17.sql` | NEW. Adds `tenant_id` + `deployment_zone_id` to `project`; adds `tenant_id` to `project__inventory` and `access_key`; creates the new `executor` table. Backfills `_unknown` per design doc §3.4. |
| `db/sql/migrations/v2.19.17.err.sql` | NEW. Rollback (drops `executor` table + the new columns). |
| `db/Migration.go` | Adds `2.19.17` to the `commonScripts` list. |
| `db/Project.go` | Adds `TenantID` + `DeploymentZoneID` fields with `binding:"required"`. |
| `db/Inventory.go` | Adds `TenantID` field with `binding:"required"`. |
| `db/AccessKey.go` | Adds `TenantID` field with `binding:"required"`. |
| `db/Executor.go` | NEW. The customer-side deployment executor model. |
| `db/ulid.go` | NEW. Self-contained `NewExecutorID()` helper (Crockford-Base32 ULID, no new dep). |
| `db/Store.go` | Adds `ExecutorManager` interface, `ExecutorProps`, `ErrAlreadyExists`. |
| `db/sql/SqlDb.go` | Registers the `executor` table with gorp in `Connect()`. |
| `db/sql/executor.go` | NEW. `ExecutorManager` implementation (CRUD + heartbeat + affinity violation counter + revoke). |
| `db/sql/project.go` | Updates `CreateProject` + `UpdateProject` to include the new columns. |
| `db/sql/inventory.go` | Updates `CreateInventory` + `UpdateInventory` to include `tenant_id`. |
| `db/sql/access_key.go` | Updates `CreateAccessKey` + `UpdateAccessKey` to include `tenant_id` (both branches). |
| `db/Executor_test.go` | NEW. Model tests: Platforms round-trip, SupportsPlatform case-insensitive, IsRevoked, NewExecutorID format + uniqueness. |
| `db/sql/executor_test.go` | NEW. Store tests: CRUD, duplicate-hostname + duplicate-executor-id rejected, GetByTenant + zone filter, GetClaimable (status + platforms + revoked), Revoke, IncrementAffinityViolation (not-found, first-time, auto-revoke at threshold, no-op on revoked, window reset). |

### Divergence landed (R-I.1.c)

| File | Change |
|---|---|
| `db/Store.go` | Adds tenant-scoped methods to `ProjectStore` / `InventoryManager` / `AccessKeyManager` (GetXForTenant / GetXsForTenant / UpdateXForTenant / DeleteXForTenant). Storage-layer filter, per design doc §4.2. |
| `db/sql/project.go` | Implements the four project tenant-scoped wrappers. UpdateXForTenant + DeleteXForTenant verify the project first (defense in depth), so a cross-tenant write cannot succeed even if a handler forgets. |
| `db/sql/inventory.go` | Implements the four inventory tenant-scoped wrappers. GetInventoriesForTenant verifies the project first then applies a per-row `pe.tenant_id=?` filter (corruption guard). |
| `db/sql/access_key.go` | Implements the four access key tenant-scoped wrappers. UpdateAccessKeyForTenant rejects unbound keys (ProjectID == nil) — those are not project-scoped so the tenant filter cannot apply. |
| `db/sql/tenant_filter_test.go` | NEW. 11 store-level tests: happy path + cross-tenant 404 + per-row filter + list filter + cross-tenant write/delete protection. |
| `api/middleware/tenant_binding.go` | NEW. `TenantBinding` gorilla/mux middleware (request-time layer, design doc §4.1). Reads `X-Tenant-ID` + `X-Deployment-Zone-IDs` headers; skips `/api/v1/executor/*` + `/api/internal/*` (mTLS handles those). Honours `X-Skip-Tenant-Filter` only when `X-Service-Auth` is also present (placeholder; JWT validator lands in R-I.2). |
| `api/middleware/tenant_binding_test.go` | NEW. 10 middleware tests: happy path + missing header + executor/internal skip + service-skip honour/ignore + zone-id trim + route classification. |
| `api/router.go` | Adds `middleware.TenantBinding` to the `authenticatedAPI` subrouter middleware chain (after `authentication`). |
| `FORK_NOTES.md` | R-I.1.c divergence row + planned sub-chunks updated. |

The new columns are `NOT NULL DEFAULT '_unknown'`. Existing dev-instance rows backfill to `_unknown`; new rows from the API carry explicit values (enforced in R-I.1.c via `binding:"required"` + request-time middleware). The R-I.2 sweep removes any `_unknown` rows that survive to that point.

### Divergence landed (R-I.1.d)

| File | Change |
|---|---|
| `db/sql/migrations/v2.19.18.sql` | NEW. Adds `claimed_by` + `claimed_at` + `result_outcome` + `result_error_class` columns to `task`, plus a partial index `idx_task_claimable` (status, claimed_by, claimed_at) `WHERE claimed_by IS NULL`. |
| `db/sql/migrations/v2.19.18.err.sql` | NEW. Rollback (drops the new task columns + the index). |
| `db/Migration.go` | Adds `2.19.18` to the `commonScripts` list. |
| `db/Task.go` | Adds `ClaimedBy` + `ClaimedAt` + `ResultOutcome` + `ResultErrorClass` fields to the `db.Task` model. |
| `db/Store.go` | Extends `ExecutorManager` with `GetExecutorByTokenHash`, `HeartbeatExecutor`, `GetClaimableTasksForTenantAndZone`, `ClaimTask`, `RecordExecutorTaskResult`. New sentinel errors: `ErrAlreadyClaimed`, `ErrExecutorRevoked`, `ErrAffinityViolation`, `ErrExecutorTokenExpired`. |
| `db/sql/executor.go` | Implements the 5 new methods. `ClaimTask` is the atomic CAS update (UPDATE ... WHERE id=? AND claimed_by IS NULL → returns `ErrAlreadyClaimed` on race lost). `HeartbeatExecutor` returns `ErrExecutorRevoked` on a revoked executor. `IncrementAffinityViolation` carries the existing 5/10-min auto-revoke logic (R-I.1.b). |
| `db/sql/migration_2_19_14_test.go` | Seeds the task via raw SQL instead of `store.CreateTask` — the gorp-mapped Insert path includes every `db:` tag, which references the post-R-I.1.d task columns that don't exist at v2.19.12. Mirrors the existing pattern used for project + access_key seeding. |
| `pkg/jwt/verifier.go` | NEW. `Verify(token, publicKeyPEM)` parses a compact JWS and returns `*ServiceClaims{Issuer, Subject, Audience, ExpiresAt, NotBefore, IssuedAt, TenantID, DeploymentZoneIDs, ActorID}`. Accepts Ed25519 + ECDSA P-256 + RSA keys. Sentinel errors: `ErrInvalidToken`, `ErrTokenExpired`, `ErrKeyUnsupported`, `ErrKeyUnparseable` (all collapsed to the same generic 401 by callers). |
| `api/middleware/tenant_binding.go` | Now actually verifies the service JWT via `jwt.Verify`, requires the platform public key in `middleware.PlatformPublicKeyPEM`, and uses the JWT's `tenant_id` + `deployment_zone_ids` claims as the bound tenant scope. New context key `ContextKeyActorID` carries the operator id the BE acts on behalf of (audit propagation). Fail-closed on missing key, missing header, bad signature, or expiry. |
| `api/middleware/tenant_binding_test.go` | 4 new tests using a real ECDSA keypair + JWT: `_ServiceSkip_Honoured` (claims drive tenant scope), `_ServiceSkip_IgnoredWithoutAuth` (401 + `service_auth_required`), `_ServiceSkip_NoPlatformKey` (401 + `service_auth_not_configured` — fail-closed), `_ServiceSkip_BadSignature` (rejected). |
| `api/executor/controller.go` | NEW. `ExecutorAuthMiddleware` (SHA-256-hashed `X-Executor-Token` → executor row → context). `mintToken` (32 bytes crypto/rand → base64 URL-safe), `hashTokenHex` (SHA-256 → hex). |
| `api/executor/audit.go` | NEW. `WebhookPropagator` HMAC-SHA256 envelope over `SENTRAOPS_AUDIT_WEBHOOK_URL` with `SENTRAOPS_AUDIT_HMAC_KEY`. FailureThreshold=5 consecutive failures trips the breaker and emits the design-doc `audit_propagation_backlog_growing` audit event. Headers: `X-Audit-Signature: sha256=<hex>`, `X-Audit-Timestamp`, `X-Audit-Id`, `X-Audit-Event`. |
| `api/executor/handlers.go` | NEW. 5 endpoint handlers: `RegisterHandler` (requires X-Register-Token + X-Service-Auth verified JWT, mints + returns the bearer plaintext exactly once), `HeartbeatHandler`, `ClaimHandler` (atomic per-task CAS; affinity filter enforces tenant+zone match before claiming any task; `ErrExecutorRevoked` → 403), `ResultHandler` (only the claim holder may write the result), `AffinityViolationHandler` (increments the violation counter; the existing `IncrementAffinityViolation` auto-revokes at 5 in 10 min and emits `executor.auto_revoke`). Every audit-relevant event propagates through the webhook. |
| `api/router.go` | Mounts `/api/v1/executor/register` (no auth — pre-registration, gated on X-Service-Auth + X-Register-Token inline) and `/api/v1/executor/{heartbeat,claim,result,affinity-violation}` (under `ExecutorAuthMiddleware`). The `TenantBinding` middleware already skips `/api/v1/executor/*` from R-I.1.c, so the executor routes short-circuit straight to executor auth. |
| `FORK_NOTES.md` | R-I.1.d divergence row + planned sub-chunks updated. |

### Planned divergence (R-I sub-chunks)

| Sub-chunk | What changes |
|---|---|
| R-I.1.a | Fork baseline + `FORK_NOTES.md` + `api/public/` placeholder. DONE 2026-10-08. |
| R-I.1.b | DB migration `v2.19.17` + new `Executor` entity + storage-layer wiring. DONE 2026-10-08. |
| R-I.1.c | 3 enforcement layers (request-time middleware + storage-layer filter + executor claim filter). DONE 2026-10-08 (storage filter + middleware only; executor claim API endpoint is R-I.1.d). |
| R-I.1.d | 5 new executor API endpoints + audit propagation webhook + platform-BE JWT validator. **DONE in this commit.** |
| R-I.1.e | 15 unit tests in `db/` + `db/sql/` + `api/`. |
| R-I.4 | Customer-side deployment executor (lives in `executor/` subdirectory of THIS repo) |
| R-I.5 | Windows Ansible playbook (PSRP/Kerberos + cert-based WinRM) |
| R-I.6 | Linux Ansible playbook (SSH + verified host keys) |
| R-I.10 | Customer-side credential resolver (env-file / vault-token / kms-token backends) |

### NEVER changed from upstream

- Core deployment engine (Ansible / Terraform / PowerShell / OpenTofu runners)
- Web UI baseline (tenant-binding is enforced server-side; UI is hidden behind service-to-service mTLS)
- Project / Task / Template / Inventory / AccessKey / User models (we ADD fields, we do not remove)
- MySQL / Postgres / SQLite storage backends (BoltDB was removed upstream in 2.19; we don't reintroduce it)
- REST API surface (we ADD endpoints, we do not remove)

## How to build

```bash
# 1. Install Go 1.26.4 (or use Docker)
# 2. From this repo:
go build ./...
# 3. Run unit tests:
go test ./... -run 'TestExecutor|TestProject|TestStorage'
# 4. Run all tests (CI does this):
task test
# 5. Run the local server (BoltDB default):
./semaphore server
```

## How to test the tenant-binding enforcement

```bash
go test ./api/... -run 'TestExecutor|TestProject_Get_CrossTenant' -v
```

## Security: what NEVER to commit

Per the SentraOps plan doc §10.9 (no-leaky-code rule), the following must NEVER appear in this repo:

- Plaintext customer secrets, SSH keys, WinRM certs
- API keys, tokens, private keys
- Stack traces in user-facing responses
- Internal paths or class names in error messages
- Audit rows with `credential_ref` resolved to plaintext

The pre-commit hook (if added) scans for known secret patterns.

## CI

CI runs on every push + PR to `main`:
- `go build ./...`
- `task test` (unit tests)
- `golangci-lint run` (style + correctness)
- secret-pattern scan

A CI failure blocks merge.

## Contact

Owned by the SentraOps deployment engineering team. Questions / divergence requests: file an issue in the main `SyncNovate/SentraOps` repo and tag `@deployment-team`.

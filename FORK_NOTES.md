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

The new columns are `NOT NULL DEFAULT '_unknown'`. Existing dev-instance rows backfill to `_unknown`; new rows from the API carry explicit values (enforced in R-I.1.c via `binding:"required"` + request-time middleware). The R-I.2 sweep removes any `_unknown` rows that survive to that point.

### Planned divergence (R-I sub-chunks)

| Sub-chunk | What changes |
|---|---|
| R-I.1.a | Fork baseline + `FORK_NOTES.md` + `api/public/` placeholder. DONE 2026-10-08. |
| R-I.1.b | DB migration `v2.19.17` + new `Executor` entity + storage-layer wiring. **DONE in this commit.** |
| R-I.1.c | 3 enforcement layers (request-time middleware + storage-layer filter + executor claim filter). |
| R-I.1.d | 5 new executor API endpoints (`/api/v1/executor/{register,heartbeat,claim,result,affinity-violation}`) + audit propagation webhook (HMAC-SHA256). |
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

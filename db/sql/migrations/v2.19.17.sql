-- SentraOps fork migration v2.19.17 (R-I.1.b)
-- Phase 10 deployment engine: tenant + zone binding on every scoped entity,
-- plus the new executor entity (the customer-side deployment executor).
--
-- Industry citation: the binding enforcement is documented in
-- docs/architecture/2026-10-07-semaphore-fork-design.md §3.4 + §4
-- (NIST SP 800-204C defense-in-depth, three enforcement layers).
--
-- The new columns are NOT NULL with a `_unknown` default so existing rows
-- backfill cleanly. New rows from the API are validated to carry explicit
-- non-`_unknown` values (enforced in R-I.1.c). The R-I.2 sweep removes any
-- `_unknown` rows that survived to that point.

alter table project            add column tenant_id           text not null default '_unknown';
alter table project            add column deployment_zone_id  text not null default '_unknown';
alter table project__inventory add column tenant_id           text not null default '_unknown';
alter table access_key         add column tenant_id           text not null default '_unknown';

create table executor (
    id                              integer primary key autoincrement,
    executor_id                     text    unique not null,
    name                            text    not null,
    tenant_id                       text    not null,
    deployment_zone_id              text    not null,
    platforms_supported             text    not null,
    executor_version                text    not null,
    ansible_version                 text    not null,
    hostname                        text    not null,
    status                          text    not null,
    last_heartbeat_at               timestamp null,
    registration_at                 timestamp not null,
    revoked_at                      timestamp null,
    revoke_reason                   text    not null default '',
    -- Windowed counter for the auto-revoke rule
    -- (5 affinity violations in 10 minutes, per design doc §6 / AWS IAM
    -- Access Analyzer pattern, NIST SP 800-53 AC-7).
    affinity_violation_count        integer not null default 0,
    affinity_violation_window_start timestamp null,
    -- The short-lived bearer token the executor uses on subsequent calls
    -- (24h TTL per design doc §5.1). Stored as a SHA-256 hash, never plaintext,
    -- mirroring the runner's registration-token storage pattern.
    auth_token_hash                 text    null,
    auth_token_expires_at           timestamp null,
    UNIQUE (tenant_id, deployment_zone_id, hostname)
);

create index idx_executor_tenant_zone on executor(tenant_id, deployment_zone_id);
create index idx_executor_tenant on executor(tenant_id);
create index idx_executor_status on executor(status);
create index idx_executor_executor_id on executor(executor_id);

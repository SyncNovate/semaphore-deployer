-- SentraOps fork migration v2.19.19 (R-I.10.re1)
-- Phase 10 Wazuh-style "Send Executor" 1-click install: introduce the
-- enrollment_tokens table for short-lived, single-use tokens the
-- platform BE mints when a SOC admin clicks "Send Executor". The token
-- is the proof of tenant binding at /api/v1/executor/enroll time; the
-- handler never trusts a tenant_id from the request body.
--
-- Industry citation: the same single-use + TTL pattern used by
-- Let's Encrypt ACME (registration token + signed challenge) and AWS
-- IoT Core (provisioning claim + certificate issuance). The token
-- never carries the long-lived secret; the long-lived secret is
-- minted on consume.
--
-- We do NOT add a foreign key on consumed_by_executor_id → executor.executor_id.
-- Executor rows may outlive a rollback of this migration; the column
-- is intentionally a free-form VARCHAR mirror (mirrors the task.claimed_by
-- pattern from v2.19.18).

create table enrollment_tokens (
    token_hash                  text    primary key,            -- sha256 hex digest of the plaintext
    tenant_id                   text    not null,
    deployment_zone_ids         text    not null default '',    -- json-encoded []string
    executor_name                text    not null default '',
    hostname                    text    not null default '',
    expires_at                  timestamp not null,
    consumed_at                 timestamp    null,
    consumed_by_executor_id     text        null,
    created_at                  timestamp not null
);

create index idx_enrollment_tokens_expires_at on enrollment_tokens (expires_at);
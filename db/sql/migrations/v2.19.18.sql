-- SentraOps fork migration v2.19.18 (R-I.1.d)
-- Phase 10 deployment engine: extend the task table with executor claim
-- tracking so the deployment executor can atomically pick up tasks for
-- its tenant + deployment zone.
--
-- Industry citation: the atomic-claim pattern (UPDATE ... SET claimed_by
-- = ? WHERE id = ? AND claimed_by IS NULL) is the standard optimistic-lock
-- shape used by consumer queues + worker pools. See Stripe "Idempotency
-- Keys" pattern (request-uniqueness via conditional UPDATE) and
-- HashiCorp Nomad "allocations" (claim-by-id-with-checked-CAS).
--
-- We do NOT add a foreign key on claimed_by → executor.id. Executors are
-- tenant-bound; a claim row outlives the executor (the task continues to
-- carry the id of the executor that claimed it for the result endpoint
-- to look up). Keeping it as a free VARCHAR mirror of executor.executor_id
-- is intentional.

alter table task add column claimed_by text null;          -- executor.executor_id
alter table task add column claimed_at timestamp null;
alter table task add column result_outcome text null;      -- 'success' | 'failed' | null
alter table task add column result_error_class text null;  -- error class tag for `task.failed`

create index idx_task_claimable on task (status, claimed_by, claimed_at)
    where claimed_by is null;

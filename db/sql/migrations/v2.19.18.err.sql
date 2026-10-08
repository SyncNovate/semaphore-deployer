-- Rollback for v2.19.18 (R-I.1.d)
-- Removes the claim-tracking columns added to `task`. Operators running
-- this rollback must drain all in-flight claims first; any task still
-- carrying a `claimed_by` value becomes "lost" to the next claim sweep.

drop index if exists idx_task_claimable;

alter table task drop column result_error_class;
alter table task drop column result_outcome;
alter table task drop column claimed_at;
alter table task drop column claimed_by;

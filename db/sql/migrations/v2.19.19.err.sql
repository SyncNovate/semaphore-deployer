-- Rollback for v2.19.19 (R-I.10.re1).
-- Drops the enrollment_tokens table + the expires_at index. No data
-- loss concern: tokens are short-lived (5 min TTL) so any in-flight
-- exchange at rollback time is rare and the customer's install.sh
-- retries the bootstrap call (which will then surface
-- enrollment_token_not_found + a clear error).

drop index if exists idx_enrollment_tokens_expires_at;
drop table if exists enrollment_tokens;
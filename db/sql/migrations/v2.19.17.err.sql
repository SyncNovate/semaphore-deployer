-- Rollback for v2.19.17 (R-I.1.b)
-- Removes the executor table and the tenant_id / deployment_zone_id columns
-- added to project, project__inventory, and access_key.
--
-- Backfills are not reversed: rows created with explicit tenant/zone values
-- keep those values, but the column itself goes away. Operators running this
-- rollback must drain traffic first.

drop table executor;

alter table project            drop column tenant_id;
alter table project            drop column deployment_zone_id;
alter table project__inventory drop column tenant_id;
alter table access_key         drop column tenant_id;

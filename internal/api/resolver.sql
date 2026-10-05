-- SPDX-License-Identifier: Apache-2.0
--
-- The resolver role the API's alert-resolution half connects as (RM-330,
-- #506, ADR-0044's 2026-10-03 amendment).
--
-- The dashboard may resolve an alert after a fresh passkey ceremony. The
-- write it makes is the one the removed resolve-alert CLI made: one row in
-- innsegl.alert_resolutions. This role may make that write and nothing else.
-- It may read the two columns of innsegl.events that say whether an event_id
-- names an alert, and read and insert innsegl.alert_resolutions. It may not
-- update or delete a resolution, write any other ledger table, create
-- anything, or touch innsegl_auth.
--
-- internal/api.AssertResolverScope proves all of that at every process start.
--
-- %[1]s is the role identifier and %[2]s the database identifier, exactly as
-- readonly.sql's; EnsureResolverRole substitutes both after pgx sanitises
-- them, and db-init.sh substitutes them as psql variables.

REVOKE ALL PRIVILEGES ON DATABASE %[2]s FROM %[1]s;
REVOKE CREATE ON DATABASE %[2]s FROM PUBLIC;
GRANT CONNECT ON DATABASE %[2]s TO %[1]s;

REVOKE ALL ON SCHEMA public FROM %[1]s;
GRANT USAGE ON SCHEMA public TO %[1]s;

-- The ledger schema: usage, and nothing on any table but the two below.
REVOKE ALL ON SCHEMA innsegl FROM %[1]s;
GRANT USAGE ON SCHEMA innsegl TO %[1]s;
REVOKE ALL ON ALL TABLES IN SCHEMA innsegl FROM %[1]s;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA innsegl FROM %[1]s;

-- Whether an event_id names an alert: two columns, not the event body.
GRANT SELECT (event_id, event_type) ON innsegl.events TO %[1]s;

-- The one write. SELECT as well, because INSERT ... RETURNING reads the row
-- back and the batch checks which alerts are already resolved.
GRANT SELECT, INSERT ON innsegl.alert_resolutions TO %[1]s;

-- The auth schema: nothing. Sessions and passkeys are the auth writer's.
REVOKE ALL ON SCHEMA innsegl_auth FROM %[1]s;

-- No path to privilege of its own, the same posture every other role holds.
ALTER ROLE %[1]s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

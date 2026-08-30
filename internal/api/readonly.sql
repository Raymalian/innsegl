-- SPDX-License-Identifier: Apache-2.0
--
-- The read-only role the query API connects as (RM-040, FD §7).
--
-- FD §7: the dashboard "holds no credentials capable of writing anywhere".
-- #48 says what that has to mean: "enforced with a read-only database role —
-- not merely by the absence of write code. The role is the enforcement; the
-- missing code is a convention." A query API that simply contains no INSERT is
-- one refactor, one dependency, or one SQL-injection defect away from writing.
-- A role with no INSERT privilege is not.
--
-- %[1]s is the role identifier and %[2]s the database identifier; both are
-- substituted by EnsureReadOnlyRole after pgx sanitises them. Nothing else in
-- this file is interpolated.
--
-- WHAT THIS IS NOT. It does not stop the database owner, and it does not stop a
-- superuser: migration 0001 says the same thing about its append-only trigger,
-- for the same reason. The ledger's tamper evidence is the hash chain, the
-- sealed segments and the Rekor anchor (doc 05). This role stops the API — the
-- component that faces the public internet — from being the thing that writes.

-- The database. CONNECT and nothing else; in particular not CREATE, which
-- would let the role make a schema of its own and write inside it. Postgres 15
-- stopped granting CREATE on `public` to PUBLIC, but CREATE on the DATABASE is
-- still granted to PUBLIC by default, so revoking it from the role alone would
-- leave it reachable through PUBLIC.
REVOKE ALL PRIVILEGES ON DATABASE %[2]s FROM %[1]s;
REVOKE CREATE ON DATABASE %[2]s FROM PUBLIC;
GRANT CONNECT ON DATABASE %[2]s TO %[1]s;

-- The public schema. USAGE so the role can resolve built-ins through the
-- search path, never CREATE.
REVOKE ALL ON SCHEMA public FROM %[1]s;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO %[1]s;

-- The ledger schema. SELECT on every table, and explicitly nothing else: the
-- REVOKE is redundant against a role that was just created and load-bearing
-- against one that already existed with privileges somebody granted by hand.
REVOKE ALL ON SCHEMA innsegl FROM %[1]s;
GRANT USAGE ON SCHEMA innsegl TO %[1]s;
GRANT SELECT ON ALL TABLES IN SCHEMA innsegl TO %[1]s;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON ALL TABLES IN SCHEMA innsegl FROM %[1]s;

-- A table added by a later migration must arrive read-only too. Without this,
-- the role's posture would silently be "read-only as of the migrations that
-- existed when it was provisioned".
ALTER DEFAULT PRIVILEGES IN SCHEMA innsegl GRANT SELECT ON TABLES TO %[1]s;

-- Belt as well as braces. The GRANTs above are the enforcement — a session can
-- turn this setting off for itself, so it is a default and never a boundary —
-- but it makes an accidental write fail at the first statement rather than at
-- the ACL check of the fifth.
ALTER ROLE %[1]s SET default_transaction_read_only = on;

-- No path to privilege of its own.
ALTER ROLE %[1]s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- SPDX-License-Identifier: Apache-2.0
--
-- The auth-writer role the API's sign-in half connects as (RM-260/RM-261,
-- #409, ADR-0062).
--
-- ADR-0062: "The credential that answers a WebAuthn ceremony or issues a
-- session must never be able to write innsegl.events or any table
-- internal/api/readonly.go's AssertReadOnly already protects ... it may be
-- given SELECT on the new schema ... never INSERT, UPDATE or DELETE on it or
-- on anything ADR-0044 already covers." This role is the other half of that
-- sentence: full read/write on innsegl_auth, which is NOT the schema that
-- sentence is protecting, and nothing at all on innsegl, which is.
--
-- %[1]s is the role identifier and %[2]s the database identifier, exactly as
-- readonly.sql's; EnsureAuthWriterRole substitutes both after pgx sanitises
-- them.

REVOKE ALL PRIVILEGES ON DATABASE %[2]s FROM %[1]s;
REVOKE CREATE ON DATABASE %[2]s FROM PUBLIC;
GRANT CONNECT ON DATABASE %[2]s TO %[1]s;

REVOKE ALL ON SCHEMA public FROM %[1]s;
GRANT USAGE ON SCHEMA public TO %[1]s;

-- THE LEDGER SCHEMA: NOTHING. This is the other half of the split
-- internal/api/readonly.sql draws for the reader role, drawn the opposite
-- way: that role may SELECT and nothing else; this one may not even CONNECT
-- to the schema. internal/api.AssertCannotWriteLedger (reusing
-- AssertReadOnly's own write probes) proves this role cannot write any
-- ledger table at every process start, the same way AssertReadOnly proves
-- the reader cannot.
REVOKE ALL ON SCHEMA innsegl FROM %[1]s;

-- THE AUTH SCHEMA: full ordinary CRUD. This is ADDITIVE, mutable state --
-- users, passkeys, sessions, auth events, one-time enrolment codes and
-- pending WebAuthn ceremonies -- none of it covered by doc 02's protected
-- schema or by innsegl.events' append-only trigger (migration 0001 never
-- touches innsegl_auth).
GRANT USAGE ON SCHEMA innsegl_auth TO %[1]s;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA innsegl_auth TO %[1]s;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA innsegl_auth TO %[1]s;

-- A table or sequence added by a later migration to innsegl_auth arrives
-- writable by this role too, matching readonly.sql's own rule for the
-- reader's schema-wide SELECT.
ALTER DEFAULT PRIVILEGES IN SCHEMA innsegl_auth GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %[1]s;
ALTER DEFAULT PRIVILEGES IN SCHEMA innsegl_auth GRANT USAGE, SELECT ON SEQUENCES TO %[1]s;

-- The audit trail is append-only for this role too. The blanket grant above
-- covers it with UPDATE and DELETE; take those back where the table exists.
-- (Migration 0010 also puts a trigger on it, for a role provisioned before
-- the table did.)
DO $$
BEGIN
    IF to_regclass('innsegl_auth.audit') IS NOT NULL THEN
        REVOKE UPDATE, DELETE, TRUNCATE ON innsegl_auth.audit FROM %[1]s;
    END IF;
END;
$$;

-- No path to privilege of its own -- the same posture readonly.sql and
-- appendonly.sql both hold their roles to.
ALTER ROLE %[1]s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

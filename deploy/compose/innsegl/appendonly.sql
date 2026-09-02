-- SPDX-License-Identifier: Apache-2.0
--
-- The append-only role the MCP, the reconciler and the sealer connect as
-- (RM-076, #109, doc 05 §1).
--
-- doc 05 §1: "Network segmentation even in compose: spire-server admin API and
-- postgres write role reachable only from the services that need them [...]
-- Compose is where the least-privilege shape is first proven, not first
-- ignored." The write role it names is this one: a role that can APPEND to the
-- chain and cannot unmake it.
--
-- Until #109 nothing created it. The reference stack ran the MCP as the
-- database owner, `innsegl serve` printed DATABASE ROLE IS OVER-PRIVILEGED,
-- and an adopter's first contact with an attestation system was a message
-- saying its own database privileges were wrong.
--
-- :role is the role identifier and :db the database identifier, both supplied
-- by db-init.sh with psql's own identifier quoting. Nothing else here is
-- interpolated, and the role is created by db-init.sh rather than here — the
-- same split internal/api/readonly.go makes, for the same reason: the CREATE
-- needs a password that must never appear in a file.
--
-- WHAT THIS IS NOT. It does not stop the database owner and it does not stop a
-- superuser. migration 0001 says the same thing about its append-only trigger.
-- The ledger's tamper evidence is the hash chain, the sealed segments and the
-- Rekor anchor (doc 05 §2 — "losing Postgres loses convenience, not proof").
-- What this stops is the MCP — the component that faces the network and holds
-- the SPIRE admin credential — from being the thing that can delete.
--
-- MEASURED, and it is why verify-role.sh classifies by SQLSTATE rather than by
-- success: on postgres:16 an UPDATE, DELETE or TRUNCATE of innsegl.events is
-- refused for this role with 42501 (the ACL) and for the OWNER with IN001 (the
-- trigger). Both are refused. Only one of them is refused by privilege, and a
-- check that could not tell them apart would pass the owner.

-- ---------------------------------------------------------------------------
-- The database. CONNECT and nothing else — in particular not CREATE, which
-- would let the role make a schema of its own and write inside it. Postgres 15
-- stopped granting CREATE on `public` to PUBLIC, but CREATE on the DATABASE is
-- still granted to PUBLIC by default, so revoking it from the role alone would
-- leave it reachable through PUBLIC.
-- ---------------------------------------------------------------------------
REVOKE ALL PRIVILEGES ON DATABASE :"db" FROM :"role";
REVOKE CREATE ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO :"role";

-- The public schema. USAGE so built-ins resolve through the search path,
-- never CREATE.
REVOKE ALL ON SCHEMA public FROM :"role";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"role";

-- ---------------------------------------------------------------------------
-- The ledger schema. USAGE, and then table by table — never
-- GRANT ... ON ALL TABLES, because "everything in the schema" is how a table
-- added by a later migration silently arrives writable.
--
-- The REVOKE is redundant against a role that was just created and
-- load-bearing against one that already existed with privileges somebody
-- granted by hand. That case is the whole of #109: a role is provisioned once
-- and then lives in somebody's deployment.
-- ---------------------------------------------------------------------------
REVOKE ALL ON SCHEMA innsegl FROM :"role";
GRANT USAGE ON SCHEMA innsegl TO :"role";
REVOKE ALL ON ALL TABLES IN SCHEMA innsegl FROM :"role";

-- innsegl.events — THE CHAIN. Append and read. I4 admits no other verb, and
-- the absence of UPDATE, DELETE and TRUNCATE here is the control that
-- cmd/innsegl's -require-append-only-role measures at start-up.
GRANT SELECT, INSERT ON innsegl.events TO :"role";

-- innsegl.chain — the chain's own identity and its genesis constant, written
-- once by migration 0001. ledger.Open reads it on every start; nothing ever
-- writes it again.
GRANT SELECT ON innsegl.chain TO :"role";

-- innsegl.idempotency — NOT the ledger, and deliberately not append-only.
-- IP §6.6's replay record is a claim taken, leased, and then completed: the
-- same row transitions in_progress -> completed, so the role needs UPDATE, and
-- `SELECT ... FOR UPDATE` (internal/mcp/idempotency.go) needs it too. It still
-- gets no DELETE and no TRUNCATE — migration 0002 refuses TRUNCATE with a
-- trigger, and a trigger a superuser can disable is not by itself a boundary.
-- Pruning a completed claim is an operator action, taken as the owner.
GRANT SELECT, INSERT, UPDATE ON innsegl.idempotency TO :"role";

-- innsegl.schema_migrations — readable, so an operator debugging through the
-- MCP's own credential can see which migrations ran. Never writable: the
-- compose stack migrates as the owner, before this role is used at all.
GRANT SELECT ON innsegl.schema_migrations TO :"role";

-- A table added by a LATER migration must arrive append-only too. Without
-- this, the role's posture would silently be "append-only as of the migrations
-- that existed when it was provisioned" — and the next migration would hand it
-- whatever the owner's defaults happened to be.
ALTER DEFAULT PRIVILEGES IN SCHEMA innsegl GRANT SELECT, INSERT ON TABLES TO :"role";

-- No path to privilege of its own.
ALTER ROLE :"role" NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

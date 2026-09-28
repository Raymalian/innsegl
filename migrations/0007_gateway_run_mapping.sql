-- SPDX-License-Identifier: Apache-2.0
--
-- The gateway's run mapping (RM-233, #378, ADR-0060 decision 3).
--
-- WHAT THIS TABLE IS
--
-- One row per (session, agent, fingerprint) observation the E15 identity
-- lifecycle makes: which run a session's agent is currently talking as, and
-- how that run relates to others -- its parent (an ordinary spawn), the run
-- it was forked from, and the retired run it was adopted from (ADR-0058
-- decisions 3, 5 and 8). A resumed session's next request looks itself up
-- here; a gateway restart changes nothing about what it finds, because
-- nothing about a lookup lives in the gateway's own memory.
--
-- WHY IT IS INSERT-ONLY, AND MORE STRICTLY THAN innsegl.alert_resolutions
--
-- ADR-0044 (migration 0003) added a table beside innsegl.events for
-- index-like metadata that may be corrected or removed -- a human operator's
-- judgement about a permanent finding. This table is the opposite case,
-- stated by ADR-0060 decision 3 in as many words: "this mapping *is* the
-- record: a row here that could later be updated or deleted is exactly what
-- an actor trying to disown attributed work would want." So unlike
-- alert_resolutions, this table gets innsegl.events' own treatment (migration
-- 0001) -- a trigger refusing UPDATE, DELETE and TRUNCATE, and the writer
-- role's grant on those verbs revoked -- not merely a documented expectation.
-- A wrong row is superseded by a later one (a lookup always answers the
-- newest match, see internal/gateway/mapping_postgres.go), never rewritten in
-- place.
--
-- WHAT IT DELIBERATELY DOES NOT CARRY
--
-- No status column. Lifecycle state -- active, lapsed, abandoned, retired --
-- is derived at read time from the events already on the chain
-- (internal/ledger/runstate.go), never stored here (ADR-0060 decision 3): a
-- stored state would be a fact nobody appended (I4). No run token, either: a
-- token is held in memory only and re-derived after a restart
-- (internal/gateway/lifecycle_contract.go's RegisteredRun), so persisting one
-- here would be the one credential this table has no business being able to
-- leak.
--
-- WHY A SURROGATE id RATHER THAN recorded_at ALONE ORDERS "LATEST"
--
-- recorded_at is clock_timestamp(), and two rows written close enough
-- together can carry the same value. id is a strictly increasing identity
-- column that breaks that tie the same way innsegl.events.chain_position
-- breaks it for the chain -- insertion order, not clock resolution, decides
-- which row is "latest".
--
-- WHO WRITES IT
--
-- The same writer role internal/ledger.Store already holds
-- (innsegl_appender): deploy/compose/innsegl/appendonly.sql's
-- "ALTER DEFAULT PRIVILEGES IN SCHEMA innsegl GRANT SELECT, INSERT ON TABLES"
-- already covers a table this migration adds, the same way it already covers
-- migration 0003's alert_resolutions -- no change to that file is needed for
-- this table to arrive append-only-by-grant for that role. This migration
-- only has to make sure UPDATE, DELETE and TRUNCATE are refused for
-- everyone, PUBLIC included, which the REVOKE and the trigger below do.

CREATE TABLE innsegl.gateway_run_mapping (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    run_id              text NOT NULL
        CHECK (octet_length(run_id) BETWEEN 1 AND 256),
    session_id          text NOT NULL
        CHECK (octet_length(session_id) BETWEEN 1 AND 256),
    agent_id            text NOT NULL
        CHECK (octet_length(agent_id) BETWEEN 1 AND 256),

    -- Fingerprint (ADR-0058 decision 4). Empty until the conversation has a
    -- first assistant turn (lifecycle_contract.go's Fingerprint doc comment):
    -- stored as '', never NULL, and never matched by a lookup for '' --
    -- internal/gateway/mapping_postgres.go's ByFingerprint refuses to ask.
    fingerprint         text NOT NULL DEFAULT ''
        CHECK (octet_length(fingerprint) <= 256),

    -- The three links (ADR-0058 decisions 3, 5 and 8). Each is NULL for "no
    -- such link", never '': this table sits outside doc 02's protected
    -- schema and has no absent/empty distinction of its own to keep, so NULL
    -- is the ordinary SQL way to say "none" for an optional reference.
    parent_run_id       text
        CHECK (parent_run_id IS NULL OR octet_length(parent_run_id) BETWEEN 1 AND 256),
    forked_from_run_id  text
        CHECK (forked_from_run_id IS NULL OR octet_length(forked_from_run_id) BETWEEN 1 AND 256),
    adopted_from_run_id text
        CHECK (adopted_from_run_id IS NULL OR octet_length(adopted_from_run_id) BETWEEN 1 AND 256),

    -- Assigned by the database, never by a caller -- mirrors
    -- innsegl.events.ts (doc 02 §2: "client-supplied values are ignored").
    -- internal/gateway/mapping_postgres.go's Insert never sends this column.
    recorded_at         timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- A session's agent's current run: BySessionAgent runs this on every
-- request. recorded_at last, so an ORDER BY on it can use the index directly
-- once session_id and agent_id are pinned by equality.
CREATE INDEX gateway_run_mapping_session_agent_idx
    ON innsegl.gateway_run_mapping (session_id, agent_id, recorded_at);

-- A fingerprint's own history (ByFingerprint): partial, because a row with no
-- fingerprint yet is not what this lookup is for, and most rows carry one
-- only from their second request onward (ADR-0058 decision 4).
CREATE INDEX gateway_run_mapping_fingerprint_idx
    ON innsegl.gateway_run_mapping (fingerprint)
    WHERE fingerprint <> '';

-- ---------------------------------------------------------------------------
-- The append-only guard (ADR-0060 decision 3), mirroring migration 0001's
-- events_append_only in shape but not in function: the message below cites
-- this table's own rule, not doc 02 §2's, because a correction here is a
-- later row, never "a new event carrying supersedes".
--
-- SQLSTATE IN004 is a user-defined class (Postgres reserves classes
-- beginning 0-4 and A-H); IN001 and IN002 are the ledger's
-- (migration 0001), IN003 is innsegl.idempotency's (migration 0002).
--
-- Honest limit, the same one 0001 and 0002 state: a superuser can disable a
-- trigger. This stops accident, ordinary compromise and the operator with a
-- psql prompt. The ledger's chain -- not this table -- is the tamper-evident
-- record this project rests its proof on.
-- ---------------------------------------------------------------------------
CREATE FUNCTION innsegl.refuse_mapping_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'innsegl: % on %.% is refused: the run mapping is insert-only; a correction is a later row, never a rewrite (ADR-0060 decision 3)',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'IN004';
END;
$$;

CREATE TRIGGER gateway_run_mapping_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl.gateway_run_mapping
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl.refuse_mapping_mutation();
ALTER TABLE innsegl.gateway_run_mapping ENABLE ALWAYS TRIGGER gateway_run_mapping_append_only;

REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.gateway_run_mapping FROM PUBLIC;

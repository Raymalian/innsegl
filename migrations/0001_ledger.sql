-- SPDX-License-Identifier: Apache-2.0
--
-- The ledger hot tier: one hash chain, append-only, enforced by the database
-- and not only by the Go layer above it.
--
-- Scope of a chain (ADR-0005): one chain per database. There is no chain_id
-- column, because doc 02 §2's envelope has no chain_id member and §2 is a
-- protected surface. Everything in this database belongs to one chain, so
-- "strictly consecutive per chain" is "strictly consecutive in this table",
-- and every uniqueness constraint below is database-wide with no scope column
-- to get wrong.
--
-- What the Go layer must never be the only thing enforcing:
--   * no UPDATE, no DELETE, no TRUNCATE on a written event (I4);
--   * position 1 carries the genesis constant, and every later position
--     carries its predecessor's event_hash (doc 02 §4.4, §4.5);
--   * one event per idempotency_key (doc 02 §2, IP §6.6).
-- A guarantee that lives only in application code is a guarantee that ends at
-- the first psql prompt.

CREATE SCHEMA IF NOT EXISTS innsegl;

-- ---------------------------------------------------------------------------
-- Chain identity.
--
-- One row, forever: the CHECK on the primary key makes a second row
-- impossible rather than merely discouraged. chain_id names *this* chain so
-- that an operator, a backup, or a client pointed at the wrong database can
-- tell. It is storage-level metadata and is never part of a hashed event —
-- adding it to the envelope would be a new major schema_version (doc 02 §7).
-- ---------------------------------------------------------------------------
CREATE TABLE innsegl.chain (
    singleton  boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    chain_id   uuid        NOT NULL DEFAULT gen_random_uuid(),
    -- Written down here so that a database whose genesis constant differs from
    -- the running code is detected at open rather than at the first append.
    genesis_prev_event_hash text NOT NULL
        CHECK (genesis_prev_event_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO innsegl.chain (singleton, genesis_prev_event_hash)
VALUES (true, 'sha256:115073b347128337d7085e23cfaf0cc32d4cb60076610ee69d39faedaacf9362');

-- ---------------------------------------------------------------------------
-- Events.
--
-- canonical holds the RFC 8785 bytes of the event exactly as they were hashed
-- and nothing else; bytea rather than jsonb, because jsonb re-serializes and a
-- re-serialized record is a different preimage. Every other column is a
-- derived key or index over those bytes, and TestStoredColumnsAgreeWithTheCanonicalBytes
-- holds them to it.
-- ---------------------------------------------------------------------------
CREATE TABLE innsegl.events (
    chain_position  bigint PRIMARY KEY CHECK (chain_position >= 1),
    event_id        text NOT NULL UNIQUE
        CHECK (event_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    -- UNIQUE on event_hash: two events cannot be the same event.
    event_hash      text NOT NULL UNIQUE
        CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
    -- UNIQUE on prev_event_hash is the anti-fork constraint: an event can be
    -- the predecessor of at most one other event, so a second branch off any
    -- position is refused by the index rather than found later by a verifier.
    prev_event_hash text NOT NULL UNIQUE
        CHECK (prev_event_hash ~ '^sha256:[0-9a-f]{64}$'),
    event_type      text NOT NULL,
    source          text NOT NULL CHECK (source IN ('mcp', 'reconciler', 'reaper', 'system')),
    run_id          text,
    -- One event per key. NULLs are distinct in a UNIQUE index, so events with
    -- no key are unconstrained, which is what "conditional" means (ADR-0004).
    idempotency_key text UNIQUE CHECK (octet_length(idempotency_key) <= 128),
    ts              timestamptz NOT NULL,
    canonical       bytea NOT NULL CHECK (octet_length(canonical) <= 4096)
);

CREATE INDEX events_run_id_idx ON innsegl.events (run_id, chain_position)
    WHERE run_id IS NOT NULL;
CREATE INDEX events_event_type_idx ON innsegl.events (event_type, chain_position);
CREATE INDEX events_ts_idx ON innsegl.events (ts);

-- ---------------------------------------------------------------------------
-- The append-only guard (LED-003, I4).
--
-- A statement-level BEFORE trigger, so a DELETE that matches no row is refused
-- too: the refusal is of the *operation*, not of its effect. ENABLE ALWAYS so
-- it fires on a replica applying changes as well as on the origin.
--
-- SQLSTATE IN001 is a user-defined class (Postgres reserves classes beginning
-- 0-4 and A-H), so a caller can recognise the refusal without matching on
-- message text.
--
-- Honest limit: a superuser can disable a trigger, and privileges do not bind
-- the table owner. This stops accident, ordinary compromise and the operator
-- with a psql prompt. It does not stop the database administrator — that is
-- what the WORM segment store (RM-011) and the Rekor anchor (RM-012) are for,
-- and why losing Postgres loses the index and not the proof (doc 05).
-- ---------------------------------------------------------------------------
CREATE FUNCTION innsegl.refuse_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'innsegl: % on %.% is refused: the ledger is append-only; a correction is a new event carrying supersedes (I4, doc 02 §2)',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'IN001';
END;
$$;

CREATE TRIGGER events_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl.events
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl.refuse_mutation();
ALTER TABLE innsegl.events ENABLE ALWAYS TRIGGER events_append_only;

CREATE TRIGGER chain_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl.chain
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl.refuse_mutation();
ALTER TABLE innsegl.chain ENABLE ALWAYS TRIGGER chain_append_only;

REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.events FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.chain FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- The chain rule (doc 02 §4.4, §4.5), enforced on INSERT.
--
-- The Go layer computes prev_event_hash under a serialized append and would
-- have to be wrong for this to fire. That is the point: a gap or a fork is the
-- one corruption a hash chain cannot repair, so it is refused by the database
-- as well, and a second writer that never learned the rule cannot create one.
-- ---------------------------------------------------------------------------
CREATE FUNCTION innsegl.enforce_chain_link() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    expected text;
BEGIN
    IF NEW.chain_position = 1 THEN
        SELECT genesis_prev_event_hash INTO expected FROM innsegl.chain;
    ELSE
        SELECT event_hash INTO expected FROM innsegl.events
            WHERE chain_position = NEW.chain_position - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'innsegl: chain_position % has no predecessor at %: positions are strictly consecutive (doc 02 §2)',
                NEW.chain_position, NEW.chain_position - 1
                USING ERRCODE = 'IN002';
        END IF;
    END IF;

    IF NEW.prev_event_hash IS DISTINCT FROM expected THEN
        RAISE EXCEPTION
            'innsegl: chain_position % carries prev_event_hash %, its predecessor hashes to % (doc 02 §4.5)',
            NEW.chain_position, NEW.prev_event_hash, expected
            USING ERRCODE = 'IN002';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER events_chain_link
    BEFORE INSERT ON innsegl.events
    FOR EACH ROW EXECUTE FUNCTION innsegl.enforce_chain_link();
ALTER TABLE innsegl.events ENABLE ALWAYS TRIGGER events_chain_link;

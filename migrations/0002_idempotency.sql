-- SPDX-License-Identifier: Apache-2.0
--
-- The MCP tool-call idempotency store (RM-021, IP §6.6, ADR-0017).
--
-- WHY THIS IS A TABLE AND NOT A MAP IN A PROCESS
--
-- Doc 05 §2: "MCP replicas are stateless (idempotency store lives in
-- Postgres) — MCP-011's crash/replay property is what makes horizontal
-- scaling safe." An in-memory store satisfies every single-process test and
-- breaks the moment there are two replicas or one restart, silently, in the
-- direction that mints a second identity.
--
-- HOW THIS DIFFERS FROM innsegl.events.idempotency_key
--
-- The ledger's UNIQUE idempotency_key (0001, LED-008) dedupes an EVENT: the
-- same key appends at most one row, forever. That is the permanent guarantee
-- and it is what I3 and I4 rest on.
--
-- This table dedupes a TOOL CALL. A call is not an append: it can create a
-- SPIRE entry before any event exists, and its result can carry values no
-- event holds. IP §6.6 requires a replay to return "the original result", and
-- only a record of the reply can do that. The two never contradict, because
-- one key names one action at both layers.
--
-- Scope. One chain per database (ADR-0005), and this table is scoped the same
-- way: the key is the primary key, database-wide, with no scope column to get
-- wrong — exactly as innsegl.events.idempotency_key is.
--
-- Retention. Unlike innsegl.events, this table is prunable: it is a bounded
-- record of recent calls, not the ledger. The guard below refuses to delete a
-- claim that is still in flight, and refuses to rewrite a recorded response,
-- but a COMPLETED row may be pruned once it is older than the longest replay
-- window an operator is willing to serve. Pruning re-opens that key to
-- execution; the ledger's own UNIQUE key remains the backstop against a
-- second event.

CREATE TABLE innsegl.idempotency (
    -- doc 02 §2's "string ≤128", counted in bytes (ADR-0004). The same limit
    -- as innsegl.events.idempotency_key, because it is the same key: a key
    -- this table accepted and the ledger later refused would be a call with a
    -- recorded reply and no record of the action (I3).
    idempotency_key  text PRIMARY KEY
        CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),

    -- The MCP tool the key belongs to. Part of the request fingerprint too;
    -- carried as a column so an operator can see what a key named.
    tool             text NOT NULL CHECK (octet_length(tool) BETWEEN 1 AND 64),

    -- sha256 over the canonical (RFC 8785) form of {tool, params}. A replay
    -- must match it; anything else is DUPLICATE_REQUEST, never a wrong answer.
    request_digest   text NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),

    status           text NOT NULL CHECK (status IN ('in_progress', 'completed')),

    -- The reply, byte for byte, as the first completed call produced it. bytea
    -- rather than jsonb for the same reason innsegl.events.canonical is bytea:
    -- jsonb re-serializes, and a re-serialized reply is not the reply that was
    -- sent.
    response         bytea CHECK (octet_length(response) <= 65536),

    -- How many times this key has been claimed. 1 is the ordinary case; more
    -- means a lease expired and another caller took over, which is the visible
    -- trace of a crashed replica.
    claim_count      integer NOT NULL DEFAULT 1 CHECK (claim_count >= 1),

    -- Server clock throughout: clock_timestamp(), never a caller's value. Doc
    -- 04 residual risk #4 — a replica with a skewed clock must not be able to
    -- shorten or extend another replica's lease.
    claimed_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    lease_expires_at timestamptz NOT NULL,
    completed_at     timestamptz,

    -- Absent and empty are distinct states (doc 02 §1), and so are these: a
    -- completed row has a response and a completion time, an in-flight row has
    -- neither. There is no third state to write a reader for.
    CONSTRAINT idempotency_response_iff_completed CHECK (
        (status = 'completed'   AND response IS NOT NULL AND completed_at IS NOT NULL) OR
        (status = 'in_progress' AND response IS NULL     AND completed_at IS NULL))
);

-- Claims whose lease has run out, for a takeover and for an operator's "what
-- is stuck?" query.
CREATE INDEX idempotency_in_flight_idx ON innsegl.idempotency (lease_expires_at)
    WHERE status = 'in_progress';
-- Pruning by age.
CREATE INDEX idempotency_completed_at_idx ON innsegl.idempotency (completed_at)
    WHERE status = 'completed';

-- ---------------------------------------------------------------------------
-- The state machine, enforced by the database and not only by the Go layer.
--
-- Three rules, and each one is a way to break IP §6.6 from a psql prompt:
--
--   * a completed row is never rewritten or reopened — its response is the
--     answer every replay gets, so changing it changes history after the fact;
--   * a claim never changes which call it names — key, tool and request digest
--     are what a replay is matched against;
--   * a claim that is still in flight is never deleted or truncated away —
--     that is precisely how a replay would run the call a second time.
--
-- Deleting a COMPLETED row is allowed: see the retention note above.
--
-- SQLSTATE IN003 is a user-defined class (Postgres reserves classes beginning
-- 0-4 and A-H); IN001 and IN002 are the ledger's. A caller recognises the
-- refusal by code rather than by matching message text.
--
-- Honest limit, the same one 0001 states: a superuser can disable a trigger.
-- This stops accident, ordinary compromise and the operator with a prompt. The
-- ledger, not this table, is the tamper-evident record.
-- ---------------------------------------------------------------------------
CREATE FUNCTION innsegl.guard_idempotency() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status <> 'completed' THEN
            RAISE EXCEPTION
                'innsegl: idempotency_key % is still claimed; deleting it would let a replay run the call a second time (IP §6.6)',
                OLD.idempotency_key
                USING ERRCODE = 'IN003';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.status = 'completed' THEN
        RAISE EXCEPTION
            'innsegl: idempotency_key % has completed; its recorded response is what every replay must get, so it is never rewritten (IP §6.6)',
            OLD.idempotency_key
            USING ERRCODE = 'IN003';
    END IF;

    IF NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.tool IS DISTINCT FROM OLD.tool
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest THEN
        RAISE EXCEPTION
            'innsegl: idempotency_key % names one call; its tool and request digest never change (ADR-0017)',
            OLD.idempotency_key
            USING ERRCODE = 'IN003';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER idempotency_guard
    BEFORE UPDATE OR DELETE ON innsegl.idempotency
    FOR EACH ROW EXECUTE FUNCTION innsegl.guard_idempotency();
ALTER TABLE innsegl.idempotency ENABLE ALWAYS TRIGGER idempotency_guard;

-- TRUNCATE fires no row trigger, and would discard every in-flight claim in
-- one statement.
CREATE FUNCTION innsegl.refuse_idempotency_truncate() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'innsegl: TRUNCATE on innsegl.idempotency is refused: it would discard in-flight claims and let replayed calls run a second time (IP §6.6)'
        USING ERRCODE = 'IN003';
END;
$$;

CREATE TRIGGER idempotency_no_truncate
    BEFORE TRUNCATE ON innsegl.idempotency
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl.refuse_idempotency_truncate();
ALTER TABLE innsegl.idempotency ENABLE ALWAYS TRIGGER idempotency_no_truncate;

REVOKE TRUNCATE ON innsegl.idempotency FROM PUBLIC;

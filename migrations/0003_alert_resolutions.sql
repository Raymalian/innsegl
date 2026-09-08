-- SPDX-License-Identifier: Apache-2.0
--
-- Alert resolution (RM-102, #167, ADR-0044).
--
-- WHY THIS IS A SEPARATE TABLE AND NOT A TWELFTH EVENT TYPE
--
-- #167's decision comment: `unattributed_signature_detected` and
-- `ledger_drift_detected` are findings about integrity — exactly the class of
-- fact innsegl.events exists to make undeletable. Adding an `alert_resolved`
-- event type would need a new major schema_version (doc 02 §7, IP §2's
-- protected-strings rule), which is not a price closing this gap should cost.
-- So the alert events stay in innsegl.events, permanently and unchanged, and
-- an operator's judgement about one lives here instead: keyed by the alert's
-- event_id, carrying who resolved it, when, and why. "Open" is derived — an
-- alert event with no row here — rather than stored.
--
-- WHY THIS TABLE CARRIES NONE OF innsegl.events' GUARANTEES
--
-- It is deliberately NOT covered by events_append_only (migration 0001): a
-- resolution row may be updated or deleted. #167's decision states the honest
-- cost in as many words — "an operator's judgement about an integrity finding
-- is now less durable than the finding" — and accepts it for v0.1 because the
-- half that must never be lost (the alert itself) is the protected half. This
-- table is the mutable, prunable half, the same relationship
-- innsegl.idempotency (0002) has to innsegl.events.
--
-- A resolution names the alert, not a run: event_id names it directly, in
-- the same UUIDv7 grammar innsegl.events.event_id is CHECKed against (0001),
-- but deliberately WITHOUT a FOREIGN KEY to innsegl.events(event_id).
--
-- MEASURED, NOT ASSUMED: a first version of this migration did add that FK,
-- and TestLED003DirectSQLMutationIsRefused caught the interaction — Postgres
-- refuses TRUNCATE on a table another table's FK references (SQLSTATE 0A000,
-- "cannot truncate a table referenced in a foreign key constraint") BEFORE
-- 0001's events_append_only trigger gets a chance to raise its own IN001.
-- LED-003 measures that specific SQLSTATE, and I4's own proof is what a
-- direct SQL TRUNCATE is refused WITH, not merely whether it is refused. A
-- migration in this repository is not allowed to change that answer, so the
-- FK is gone: existence and type are checked in Go instead
-- (internal/ledger.Store.ResolveAlert selects innsegl.events.event_type
-- before it inserts here), and that check runs on every write this project's
-- own code makes, which is the only writer #167 gives this table.
CREATE TABLE innsegl.alert_resolutions (
    -- The alert event this resolves. PRIMARY KEY: at most one resolution per
    -- alert, which is what makes "no row" a well-defined "open".
    event_id     text PRIMARY KEY
        CHECK (event_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),

    -- Free text on purpose: "who resolved it" is an operator's name, email or
    -- ticket handle, not a SPIFFE ID or any of doc 02's identifier grammars —
    -- this table is outside doc 02's schema entirely.
    resolved_by  text NOT NULL CHECK (octet_length(resolved_by) BETWEEN 1 AND 256),

    -- Server clock, matching innsegl.events.ts and innsegl.idempotency's
    -- claimed_at: never a caller-supplied value.
    resolved_at  timestamptz NOT NULL DEFAULT clock_timestamp(),

    reason       text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 2048)
);

-- Recency ordering for an operator's "what did I resolve, and when" query.
CREATE INDEX alert_resolutions_resolved_at_idx
    ON innsegl.alert_resolutions (resolved_at);

-- No append-only trigger, no REVOKE of UPDATE/DELETE, no ENABLE ALWAYS guard:
-- their absence is the point, not an oversight. Contrast migration 0001's
-- events_append_only and 0002's idempotency_guard, both of which exist to stop
-- exactly the writes this table allows.

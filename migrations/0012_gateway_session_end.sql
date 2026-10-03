-- SPDX-License-Identifier: Apache-2.0
--
-- Session-end marks that survive a restart of the core.
--
-- The gateway marks a session when its harness says the session ended, and
-- retires the session's run once the mark has stood for a grace period with
-- no further traffic (ADR-0058 decision 7a). The marks lived in memory only:
-- measured 2026-10-03, thirty-seven sessions were signalled ended, the core
-- restarted inside the grace period, and every run stayed active until the
-- seven-day silence backstop.
--
-- Append-only, like innsegl.gateway_run_mapping: a cancellation is a later
-- row, never a deletion, and a session's latest row decides. Outside the
-- chain; nothing here is evidence, only the gateway's own bookkeeping.

CREATE TABLE innsegl.gateway_session_end (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id  text NOT NULL CHECK (octet_length(session_id) BETWEEN 1 AND 256),
    kind        text NOT NULL CHECK (kind IN ('signalled', 'cancelled')),
    -- When the event happened, by the gateway's clock: a reloaded mark
    -- resumes its grace period from here.
    at          timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX gateway_session_end_session_idx
    ON innsegl.gateway_session_end (session_id, at);
CREATE INDEX gateway_session_end_at_idx
    ON innsegl.gateway_session_end (at);

CREATE TRIGGER gateway_session_end_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl.gateway_session_end
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl.refuse_mapping_mutation();
ALTER TABLE innsegl.gateway_session_end ENABLE ALWAYS TRIGGER gateway_session_end_append_only;

REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.gateway_session_end FROM PUBLIC;

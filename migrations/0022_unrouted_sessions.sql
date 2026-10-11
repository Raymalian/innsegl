-- SPDX-License-Identifier: Apache-2.0
--
-- Sessions whose model traffic bypassed innsegl (RM-319, #579).
--
-- An enrolled machine's client service compares the harness's own session
-- transcripts with the traffic it forwarded. A session with model replies in
-- a recorded repository that never passed through innsegl is reported here,
-- once per session, and the newest report's activity is kept. The dashboard
-- lists them. Outside the chain: a finding about the machine, not evidence
-- about a run. No repository is stored: the machine and the session are
-- what an operator acts on, and a name here would be one erasure missed.

CREATE TABLE innsegl.unrouted_sessions (
    installation_id   text NOT NULL CHECK (octet_length(installation_id) BETWEEN 1 AND 256),
    session_id        text NOT NULL CHECK (octet_length(session_id) BETWEEN 1 AND 256),
    first_reported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reported_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_activity_at  timestamptz NOT NULL,
    PRIMARY KEY (installation_id, session_id)
);

CREATE INDEX unrouted_sessions_activity_idx
    ON innsegl.unrouted_sessions (last_activity_at DESC);

REVOKE DELETE, TRUNCATE ON innsegl.unrouted_sessions FROM PUBLIC;

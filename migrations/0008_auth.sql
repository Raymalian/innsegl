-- SPDX-License-Identifier: Apache-2.0
--
-- Operator sign-in (RM-260/RM-261, #409/#410, ADR-0062).
--
-- WHY THIS IS A SEPARATE SCHEMA AND NOT innsegl.* TABLES
--
-- ADR-0062: "auth state lives in its own tables/schema with its own grants
-- ... The ledger role stays append-only/read-only as today." innsegl.events
-- and innsegl.chain are doc 02's protected schema; a session cookie or a
-- passkey's public key has nothing to do with attribution and putting it
-- there would be a doc 02 change for no doc 02 reason. So this migration adds
-- a SECOND schema, innsegl_auth, that innsegl.events' own append-only
-- triggers (migration 0001) never apply to and never need to: it is ordinary,
-- mutable state, the same relationship innsegl.alert_resolutions (0003) has
-- to innsegl.events, one level up.
--
-- WHY IT HAS ITS OWN ROLE (internal/api/authwriter.sql, EnsureAuthWriterRole)
--
-- ADR-0062: "The credential that answers a WebAuthn ceremony or issues a
-- session must never be able to write innsegl.events or any table
-- internal/api/readonly.go's AssertReadOnly already protects." The query
-- API's existing read-only role (innsegl_reader) gains no grant here at all;
-- a new role, scoped to exactly this schema and nothing outside it, is what
-- the API process's auth half holds. internal/api.AssertCannotWriteLedger
-- proves the split at start-up by reusing the same write probes
-- AssertReadOnly already runs against innsegl_reader, pointed at this role
-- instead.
--
-- ADDITIVE-ONLY, PER THE ADR
--
-- "The data model is additive-only from here: users, passkeys and sessions
-- gain rows, and later work adds COLUMNS ELSEWHERE that reference
-- users.user_id -- it does not migrate what these tables already hold."
-- Nothing here is a FOREIGN KEY into innsegl.* (there is nothing to reference
-- there), so none of alert_resolutions' FK-vs-TRUNCATE lesson applies to this
-- migration; the FKs below are ordinary ones between tables in this same new,
-- unprotected schema.

CREATE SCHEMA innsegl_auth;

-- One entity, not an "operator" row with different treatment: ADR-0062
-- decision "Decided: a 'user' here is the account plan's principal -- one
-- entity, not two". user_id is generated at enrolment and never derived from
-- the display name, so the display name can change without touching
-- anything that references the user.
CREATE TABLE innsegl_auth.users (
    user_id       text PRIMARY KEY
        CHECK (octet_length(user_id) BETWEEN 1 AND 64),
    display_name  text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 256),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- "one or more passkeys" per user. credential_id is the authenticator's own
-- credential id, base64url text (WebAuthn's own wire form): stored as text
-- rather than bytea so the value that appears in a log line or an operator's
-- SELECT is the same string the client sent, nothing to decode to compare.
--
-- `credential` is the go-webauthn library's own webauthn.Credential, stored
-- whole as JSON: public key, sign count, flags, authenticator info and
-- attestation all round-trip exactly as the library produced and later
-- expects them back, rather than being re-split into columns this migration
-- would have to keep in step with the library's own struct by hand.
--
-- attestation_format is ALSO its own column, denormalised out of
-- `credential` at write time, because ADR-0062 asks for it specifically:
-- "the format an authenticator reports at registration is recorded on the
-- passkey's row, unenforced ... a fact available to review later rather than
-- information thrown away". RECORDED, NOT ENFORCED: no CHECK constrains its
-- value to a known format, because a future authenticator's format this
-- deployment has never seen must still be recordable.
CREATE TABLE innsegl_auth.passkeys (
    credential_id       text PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    user_id             text NOT NULL REFERENCES innsegl_auth.users (user_id),
    credential          jsonb NOT NULL,
    attestation_format  text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_used_at        timestamptz
);

CREATE INDEX passkeys_user_id_idx ON innsegl_auth.passkeys (user_id);

-- Sessions are looked up by the SHA-256 of the cookie value, never by the
-- cookie value itself: a leaked backup of this table then names no live
-- session any more than a leaked password hash names a live password.
-- ADR-0062: "server-side revocable (sign-out)" -- revoked_at is what a
-- sign-out sets, rather than deleting the row, so an auth-events join can
-- still explain a refused request after the fact.
CREATE TABLE innsegl_auth.sessions (
    session_id_hash  text PRIMARY KEY CHECK (octet_length(session_id_hash) = 64),
    user_id          text NOT NULL REFERENCES innsegl_auth.users (user_id),
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz
);

CREATE INDEX sessions_user_id_idx ON innsegl_auth.sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON innsegl_auth.sessions (expires_at);

-- ADR-0062: "Every enrolment, sign-in and refusal is recorded ... a table of
-- that shape (an 'auth events' table) ... which needs no doc 02 change
-- because it adds no field, type or grammar to the protected schema."
-- user_id is nullable: a refused sign-in or a refused enrolment often names
-- no user at all (the code was wrong, the socket denial was not in effect).
CREATE TABLE innsegl_auth.auth_events (
    id          bigserial PRIMARY KEY,
    event_type  text NOT NULL CHECK (octet_length(event_type) BETWEEN 1 AND 64),
    user_id     text REFERENCES innsegl_auth.users (user_id),
    detail      text NOT NULL DEFAULT '' CHECK (octet_length(detail) <= 2048),
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX auth_events_created_at_idx ON innsegl_auth.auth_events (created_at);

-- The one-time enrolment code (ADR-0062 decision (b)): "single-use and
-- short-lived", minted by `innsegl admin-credential enrol-code` through the
-- same human-presence admin path as every other admin action. Stored hashed
-- for the same reason sessions are: a row here does not hand out the code.
-- used_at is set atomically on the row that consumes it (UPDATE ... WHERE
-- used_at IS NULL, in internal/api.AuthStore.ConsumeEnrolmentCode), which is
-- what makes a second attempt with the same code a refusal rather than a
-- race.
CREATE TABLE innsegl_auth.enrolment_codes (
    code_hash   text PRIMARY KEY CHECK (octet_length(code_hash) = 64),
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

-- The pending state of one WebAuthn ceremony between Begin and Finish
-- (go-webauthn's own SessionData, opaque to this table -- see the package
-- doc comment on [webauthn.SessionData] for why it must round-trip
-- unmodified). Keyed by a server-minted ceremony id rather than the session
-- cookie: enrolment has no session yet to key against, and a login ceremony
-- must not be forgeable by guessing a user's session. expires_at bounds how
-- long a half-finished ceremony can be replayed against; AUTH-004 measures
-- that a ceremony past its bound, or already consumed, is refused.
CREATE TABLE innsegl_auth.webauthn_ceremonies (
    ceremony_id    text PRIMARY KEY CHECK (octet_length(ceremony_id) BETWEEN 1 AND 128),
    kind           text NOT NULL CHECK (kind IN ('register', 'login')),
    session_data   jsonb NOT NULL,
    pending_user_id    text,
    pending_display_name text,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at     timestamptz NOT NULL
);

CREATE INDEX webauthn_ceremonies_expires_at_idx ON innsegl_auth.webauthn_ceremonies (expires_at);

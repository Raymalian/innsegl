-- SPDX-License-Identifier: Apache-2.0
--
-- Accounts a person can manage (#445, ADR-0062's 2026-10-01 amendment:
-- "accounts a person can manage"). Sign-in schema only — the dashboard's own
-- pages are a separate change, and nothing here touches web/.
--
-- WHAT THIS ADDS, AND WHY IT IS ADDITIVE-ONLY LIKE 0008 BEFORE IT
--
--   * passkeys.name — a person's own label for a passkey ("YubiKey",
--     "laptop"), shown on the account page alongside when it was added and
--     when it was last used. DEFAULT '' so the single passkey minted by
--     first-user enrolment (which carries no user-chosen name of its own)
--     backfills cleanly rather than leaving an existing row NULL.
--     last_used_at already exists (migration 0008) and is already stamped
--     on every sign-in (AuthStore.UpdatePasskey) — nothing to add there.
--
--   * sessions.passkey_id — which passkey a session was ISSUED for, so
--     Account.passkeys[].current (internal/api/account.go) can be answered
--     without guessing. Nullable: a recovery-code session names no passkey
--     at all (the amendment's own words, "a recovery code is a one-time way
--     to reach the account page and add one"). ON DELETE SET NULL rather
--     than a hard FK failure — AuthStore.DeletePasskey revokes every
--     session using a passkey BEFORE it deletes the row, in the same
--     transaction, so by the time the row is gone the only sessions left
--     pointing at it are already revoked history, which should not block the
--     delete the way RESTRICT would.
--
--   * innsegl_auth.recovery_codes — ten single-use codes minted at first
--     enrolment and on demand from the account page, stored hashed the same
--     way enrolment_codes already are (AuthStore.hashToken): a leaked backup
--     of this table names no usable code any more than enrolment_codes does.
--     used_at is set atomically by the row that consumes it, the same
--     UPDATE ... WHERE used_at IS NULL shape ConsumeEnrolmentCode already
--     uses, which is what makes a reused code a refusal rather than a race.
--
--   * webauthn_ceremonies.kind gains 'add_passkey' — a signed-in user adding
--     a SECOND-OR-LATER passkey is a third kind of ceremony alongside
--     'register' (the first) and 'login'. It reuses pending_user_id and
--     pending_display_name exactly as they already are: pending_user_id
--     carries the signed-in user's id (never a NEW one, unlike 'register'),
--     and pending_display_name carries the NAME the person is giving this
--     new passkey — the same column, read for a different purpose by a
--     ceremony of a different kind, rather than a passkey-specific column
--     added only for this one case.
--
-- Nothing here is a FOREIGN KEY into innsegl.* (there is nothing to
-- reference there), matching 0008's own note that none of
-- alert_resolutions' FK-vs-TRUNCATE lesson applies to this schema.

ALTER TABLE innsegl_auth.passkeys
    ADD COLUMN name text NOT NULL DEFAULT '' CHECK (octet_length(name) <= 64);

ALTER TABLE innsegl_auth.sessions
    ADD COLUMN passkey_id text REFERENCES innsegl_auth.passkeys (credential_id) ON DELETE SET NULL;

CREATE INDEX sessions_passkey_id_idx ON innsegl_auth.sessions (passkey_id);

CREATE TABLE innsegl_auth.recovery_codes (
    code_hash   text PRIMARY KEY CHECK (octet_length(code_hash) = 64),
    user_id     text NOT NULL REFERENCES innsegl_auth.users (user_id),
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    used_at     timestamptz
);

CREATE INDEX recovery_codes_user_id_idx ON innsegl_auth.recovery_codes (user_id);

-- Widening a CHECK constraint is DROP then ADD — Postgres has no ALTER
-- CONSTRAINT for this. The name below is the one Postgres itself chose for
-- 0008's unnamed, column-level `CHECK (kind IN ('register', 'login'))`
-- (migrations_test.go's own fixed-string check on 0008 would catch either
-- of these drifting apart).
ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check CHECK (kind IN ('register', 'login', 'add_passkey'));

-- internal/api/authwriter.sql grants the auth-writer role
-- "SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA innsegl_auth" and
-- EnsureAuthWriterRole runs AFTER migrations (apiharness_test.go's
-- migratedWithAuth: ledger.Migrate, then EnsureAuthWriterRole) — so
-- recovery_codes exists before that blanket grant runs and needs no special
-- case. The ALTER DEFAULT PRIVILEGES two lines below it is what covers a
-- table a FUTURE migration adds without authwriter.sql being touched again;
-- authwriter_test.go's TestAuthWriterRoleCanWriteItsOwnSchema-style cases
-- prove the resulting grants hold for every column added here.

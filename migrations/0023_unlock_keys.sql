-- SPDX-License-Identifier: Apache-2.0
--
-- Unlock keys: hardware security keys that unlock the CA key store from the
-- dashboard (#613, ADR-0082).
--
-- ADDITIVE-ONLY. One new table in innsegl_auth, and five more WebAuthn
-- ceremony kinds. Nothing here touches the ledger schema.
--
-- WHAT A ROW HOLDS, AND WHAT IT NEVER HOLDS
--
-- A row is one enrolled security key: its WebAuthn credential (the public
-- key go-webauthn verifies an assertion against), the two salts the browser
-- passes as the PRF input, and the two age X25519 recipients the browser
-- derived from the PRF output (internal/unlockkey, format v1). All of it is
-- public. The PRF output and the identities derived from it never reach the
-- server (ADR-0082 decision 1), so no column could hold them.
--
-- HARDWARE KEYS ONLY (ADR-0082 decision 3)
--
-- The API refuses a credential whose backup-eligible flag is set. The CHECK
-- on credential below is the second line: a row whose stored flags say
-- backup-eligible is refused by the database too.
--
-- REVOCATION IS FORWARD-ONLY (ADR-0082 decision 8)
--
-- revoked_at is set once and never cleared, and a row is never deleted: a
-- revoked key still opens older sealed copies and older backups, so the
-- record of it is kept. The trigger below enforces both, for every role.
-- What a row may still change is its credential (the signature counter the
-- library writes back on every use) and last_used_at.

CREATE TABLE innsegl_auth.unlock_keys (
    credential_id      text PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    user_id            text NOT NULL REFERENCES innsegl_auth.users (user_id),
    label              text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    credential         jsonb NOT NULL
        CHECK (coalesce((credential -> 'flags' ->> 'backupEligible')::boolean, false) = false),
    -- A plain age X25519 recipient: "age1" and 58 bech32 characters.
    custody_recipient  text NOT NULL UNIQUE CHECK (custody_recipient ~ '^age1[02-9ac-hj-np-z]{58}$'),
    backup_recipient   text NOT NULL UNIQUE CHECK (backup_recipient ~ '^age1[02-9ac-hj-np-z]{58}$'),
    custody_salt       bytea NOT NULL CHECK (octet_length(custody_salt) = 32),
    backup_salt        bytea NOT NULL CHECK (octet_length(backup_salt) = 32),
    -- internal/unlockkey.FormatVersion: the derivation the recipients came from.
    format             text NOT NULL CHECK (format = 'innsegl unlock v1'),
    created_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    revoked_by         text REFERENCES innsegl_auth.users (user_id),
    CHECK (custody_recipient <> backup_recipient),
    CHECK (custody_salt <> backup_salt),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX unlock_keys_user_id_idx ON innsegl_auth.unlock_keys (user_id);

CREATE FUNCTION innsegl_auth.guard_unlock_key() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'innsegl: an unlock key is never deleted; revoke it'
            USING ERRCODE = 'IN009';
    END IF;
    IF OLD.revoked_at IS NOT NULL
       AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
            OR NEW.revoked_by IS DISTINCT FROM OLD.revoked_by) THEN
        RAISE EXCEPTION 'innsegl: a revoked unlock key stays revoked (ADR-0082 decision 8)'
            USING ERRCODE = 'IN009';
    END IF;
    IF NEW.credential_id IS DISTINCT FROM OLD.credential_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id
       OR NEW.custody_recipient IS DISTINCT FROM OLD.custody_recipient
       OR NEW.backup_recipient IS DISTINCT FROM OLD.backup_recipient
       OR NEW.custody_salt IS DISTINCT FROM OLD.custody_salt
       OR NEW.backup_salt IS DISTINCT FROM OLD.backup_salt
       OR NEW.format IS DISTINCT FROM OLD.format
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'innsegl: an unlock key''s identity, recipients and salts never change; enrol a new key'
            USING ERRCODE = 'IN009';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER unlock_keys_guard
    BEFORE UPDATE OR DELETE ON innsegl_auth.unlock_keys
    FOR EACH ROW EXECUTE FUNCTION innsegl_auth.guard_unlock_key();
ALTER TABLE innsegl_auth.unlock_keys ENABLE ALWAYS TRIGGER unlock_keys_guard;

CREATE FUNCTION innsegl_auth.refuse_unlock_key_truncate() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'innsegl: unlock keys are never truncated'
        USING ERRCODE = 'IN009';
END;
$$;

CREATE TRIGGER unlock_keys_no_truncate
    BEFORE TRUNCATE ON innsegl_auth.unlock_keys
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl_auth.refuse_unlock_key_truncate();
ALTER TABLE innsegl_auth.unlock_keys ENABLE ALWAYS TRIGGER unlock_keys_no_truncate;

REVOKE DELETE, TRUNCATE ON innsegl_auth.unlock_keys FROM PUBLIC;

-- Five ceremony kinds, each its own so a ceremony begun for one cannot finish
-- another: enrolling and revoking a key, unlocking the store, and the two
-- steps of a reseal.
ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check
    CHECK (kind IN ('register', 'login', 'add_passkey', 'resolve_alerts',
                    'mint_enrolment_token', 'revoke_installation',
                    'invite_member', 'change_member_role', 'remove_member',
                    'register_invited',
                    'suspend_installation', 'resume_installation',
                    'sso', 'configure_sso', 'remove_sso',
                    'add_unlock_key', 'revoke_unlock_key',
                    'ca_unlock', 'ca_reseal', 'ca_reseal_confirm'));

-- SPDX-License-Identifier: Apache-2.0
--
-- Step-up for the account's own sign-in, and idle sessions (#602).
--
-- ADDITIVE-ONLY. One column on innsegl_auth.sessions and four more WebAuthn
-- ceremony kinds. Nothing here touches the ledger schema.
--
--   * sessions.last_seen_at: when the session last answered a request. A
--     session whose last request is 30 minutes old is ended (the API sets
--     revoked_at), so a cookie left behind stops working on its own. A row
--     that exists before this migration starts its clock now.
--   * sessions.idle_ended: the idle bound is what ended it, so the
--     dashboard can say so on every later request with that cookie.
--   * Removing a passkey, regenerating recovery codes, and linking or
--     unlinking an organisation's sign-in each take a fresh passkey
--     assertion, each its own kind so a ceremony begun for one cannot finish
--     another. Adding a passkey keeps its kind, 'add_passkey'; its ceremony
--     now carries the confirmation beside the registration.

ALTER TABLE innsegl_auth.sessions
    ADD COLUMN last_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN idle_ended  boolean NOT NULL DEFAULT false;

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
                    'ca_unlock', 'ca_reseal', 'ca_reseal_confirm',
                    'remove_passkey', 'regenerate_recovery_codes',
                    'link_sso', 'unlink_sso'));

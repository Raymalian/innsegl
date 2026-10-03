-- SPDX-License-Identifier: Apache-2.0
--
-- Two more kinds of WebAuthn ceremony: connecting a machine and revoking one
-- from the account page (RM-333, #511, ADR-0062's 2026-10-03 amendment).
--
-- Minting an enrolment token admits a machine; revoking an installation
-- shuts one out. Each takes a fresh passkey ceremony of its own kind, never
-- 'login' and never each other's: LoadAndConsumeCeremony matches on kind, so
-- a sign-in challenge cannot mint a token and a revoke challenge cannot mint
-- one either. session_data carries the request the passkey confirms (the
-- organisation and the token's scope, or the machine) beside go-webauthn's
-- own SessionData.
--
-- Widening the CHECK is DROP then ADD, as 0009 and 0013 did, under 0009's
-- name. No grant changes: the auth-writer role already holds the table.
ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check
    CHECK (kind IN ('register', 'login', 'add_passkey', 'resolve_alerts',
                    'mint_enrolment_token', 'revoke_installation'));

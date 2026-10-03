-- SPDX-License-Identifier: Apache-2.0
--
-- A fourth kind of WebAuthn ceremony: confirming an alert resolution (RM-330,
-- #506, ADR-0044's 2026-10-03 amendment).
--
-- The dashboard resolves alerts only after the signed-in user completes a
-- fresh passkey ceremony. That ceremony is a kind of its own, never 'login',
-- so a sign-in challenge cannot finish a resolution and a resolution
-- challenge cannot open a session: LoadAndConsumeCeremony matches on kind.
-- Its session_data carries the request it confirms (the alerts and the
-- reason) beside go-webauthn's own SessionData, so the passkey confirms
-- exactly what began the ceremony.
--
-- Widening the CHECK is DROP then ADD, as 0009 did, under 0009's name.
ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check
    CHECK (kind IN ('register', 'login', 'add_passkey', 'resolve_alerts'));

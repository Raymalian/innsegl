-- SPDX-License-Identifier: Apache-2.0
--
-- Suspending and resuming a machine from the dashboard (#471, E28).
--
-- ADDITIVE-ONLY. Two more WebAuthn ceremony kinds: suspending and resuming a
-- machine each take a fresh passkey of their own kind, as revoking one does
-- (0014), so a confirmation begun for one change cannot finish another.
-- installations.status already allows 'suspended' (0010); nothing else
-- changes.

ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check
    CHECK (kind IN ('register', 'login', 'add_passkey', 'resolve_alerts',
                    'mint_enrolment_token', 'revoke_installation',
                    'invite_member', 'change_member_role', 'remove_member',
                    'register_invited',
                    'suspend_installation', 'resume_installation'));

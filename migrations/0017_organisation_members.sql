-- SPDX-License-Identifier: Apache-2.0
--
-- Organisations: members, roles and invitations (#480, #481, E27).
--
-- ADDITIVE-ONLY, as 0010 and 0015 before it. Nothing is rewritten:
--
--   * invitations.created_by becomes nullable. The operator's core CLI
--     (`innsegl accounts invite`) holds no user identity; its invitation
--     names no inviter, exactly as its other audit rows name no actor.
--     DROP NOT NULL is a catalogue change.
--
--   * invitations.accepted_by and invitations.revoked_at: who spent the
--     link, and when an admin withdrew it. Both NULL on every existing row
--     (0010 created the table and nothing has written it). Accepted means
--     used_at and accepted_by together.
--
--   * Four more WebAuthn ceremony kinds. Inviting a person, changing a
--     member's role and removing a member each take a fresh passkey of
--     their own kind (as 0014's machine changes do), and an invited person's
--     first passkey is registered under a kind of its own, never 'register':
--     a first-user enrolment ceremony cannot be finished as an invitation,
--     nor the other way round.
--
-- No email column, here or anywhere: an invitation is a link, and the person
-- who holds it is the person invited.
--
-- No grant changes: the auth-writer role already holds every table in
-- innsegl_auth.

ALTER TABLE innsegl_auth.invitations ALTER COLUMN created_by DROP NOT NULL;

ALTER TABLE innsegl_auth.invitations
    ADD COLUMN accepted_by text REFERENCES innsegl_auth.users (user_id),
    ADD COLUMN revoked_at  timestamptz,
    ADD CONSTRAINT invitations_accepted_pair
        CHECK ((used_at IS NULL) = (accepted_by IS NULL)),
    ADD CONSTRAINT invitations_used_or_withdrawn
        CHECK (used_at IS NULL OR revoked_at IS NULL);

CREATE INDEX invitations_account_idx ON innsegl_auth.invitations (account_id);

ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check
    CHECK (kind IN ('register', 'login', 'add_passkey', 'resolve_alerts',
                    'mint_enrolment_token', 'revoke_installation',
                    'invite_member', 'change_member_role', 'remove_member',
                    'register_invited'));

-- SPDX-License-Identifier: Apache-2.0
--
-- Signing in with an organisation's identity provider (#485, E30).
--
-- ADDITIVE-ONLY, as every auth migration before it. Two new tables, one
-- nullable column, three more ceremony kinds; no existing row is rewritten.
--
--   * sso_connections: at most one per organisation. The owner sets it from
--     the dashboard after a fresh passkey. sign_in_name is what a person types
--     on the sign-in page to find it. client_secret may be empty (a public
--     client, PKCE alone). Nothing about a person is stored here.
--
--   * oidc_identities: an identity provider's (issuer, subject) pair, joined
--     to an EXISTING user. One pair names one user; a user may hold several.
--     No email, no name, no password: the subject is the provider's stable
--     identifier and nothing else is kept. connection_id records which
--     organisation's sign-in linked it, for the account page; it is cleared,
--     not cascaded, when the connection goes.
--
--   * sessions.sso_connection_id: the connection a session was opened
--     through, NULL for every passkey and recovery-code session (and every
--     existing row). Removing a connection revokes the sessions it opened,
--     before the row goes; the FK only clears the reference afterwards.
--
--   * Ceremony kinds. 'sso' is one sign-in or link in flight: its id is the
--     OAuth state, single-use because loading it deletes it, and it holds the
--     nonce, the PKCE verifier and the hash of the browser's binding cookie.
--     'configure_sso' and 'remove_sso' are the owner's passkey confirmations.
--
-- No grant changes: the auth-writer role holds every table in innsegl_auth
-- by default privilege (authwriter.sql). The ledger roles hold nothing here.

CREATE TABLE innsegl_auth.sso_connections (
    connection_id text PRIMARY KEY
        CHECK (connection_id ~ '^[0-9a-f]{32}$'),
    account_id    text NOT NULL UNIQUE
        REFERENCES innsegl_auth.accounts (account_id),
    sign_in_name  text NOT NULL UNIQUE
        CHECK (sign_in_name ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    issuer        text NOT NULL
        CHECK (issuer ~ '^https://' AND octet_length(issuer) <= 2048),
    client_id     text NOT NULL
        CHECK (octet_length(client_id) BETWEEN 1 AND 512),
    client_secret text NOT NULL DEFAULT ''
        CHECK (octet_length(client_secret) <= 2048),
    created_by    text REFERENCES innsegl_auth.users (user_id),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at    timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE innsegl_auth.oidc_identities (
    identity_id   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer        text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    subject       text NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255),
    user_id       text NOT NULL REFERENCES innsegl_auth.users (user_id),
    connection_id text REFERENCES innsegl_auth.sso_connections (connection_id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_used_at  timestamptz,
    UNIQUE (issuer, subject)
);

CREATE INDEX oidc_identities_user_idx ON innsegl_auth.oidc_identities (user_id);

ALTER TABLE innsegl_auth.sessions
    ADD COLUMN sso_connection_id text
        REFERENCES innsegl_auth.sso_connections (connection_id) ON DELETE SET NULL;

CREATE INDEX sessions_sso_connection_idx ON innsegl_auth.sessions (sso_connection_id)
    WHERE sso_connection_id IS NOT NULL;

ALTER TABLE innsegl_auth.webauthn_ceremonies DROP CONSTRAINT webauthn_ceremonies_kind_check;
ALTER TABLE innsegl_auth.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_kind_check
    CHECK (kind IN ('register', 'login', 'add_passkey', 'resolve_alerts',
                    'mint_enrolment_token', 'revoke_installation',
                    'invite_member', 'change_member_role', 'remove_member',
                    'register_invited',
                    'suspend_installation', 'resume_installation',
                    'sso', 'configure_sso', 'remove_sso'));

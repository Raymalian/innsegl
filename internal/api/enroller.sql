-- SPDX-License-Identifier: Apache-2.0
--
-- The enroller role the core connects as (RM-355, #603).
--
-- The core enrols, renews and revokes client machines, and on their behalf
-- claims a repository on first use, pins the machine's operator author and
-- reads what the status, trust-backup and custody routes check. Until #603 it
-- did that as the auth-writer, which may read and write every sign-in table.
-- This role holds the statements those code paths issue and nothing else.
-- The list below was measured from internal/accounts, statement by statement:
--
--   Enrol           SELECT secret_hash FROM enrolment_tokens
--                   UPDATE enrolment_tokens SET used_at ... RETURNING account_id, created_by, repos, kind
--                   INSERT INTO installations (installation_id, account_id, created_by, name, kind, repos) RETURNING *
--                   UPDATE enrolment_tokens SET installation_id
--                   INSERT INTO audit (actor, account_id, action, subject, detail)
--   Renew           UPDATE installations SET last_renewed_at ... RETURNING *; INSERT INTO audit
--   disconnect      SELECT ... FROM installations FOR UPDATE
--                   UPDATE installations SET status, revoked_at; INSERT INTO audit
--   ClaimRepo       SELECT FROM installations
--                   INSERT INTO repo_grants (account_id, repo) ON CONFLICT DO NOTHING RETURNING grant_id
--                   SELECT account_id FROM repo_grants; INSERT INTO audit
--   PinOperatorAuthor  SELECT ... FROM installations FOR UPDATE
--                   UPDATE installations SET operator_author_name, operator_author_email; INSERT INTO audit
--   OperatorAuthor, GetInstallation, InScope   SELECT FROM installations, repo_grants
--   ListAccounts    SELECT FROM accounts, memberships, repo_grants
--   Memberships     SELECT FROM memberships, accounts
--
-- So: no grant at all on users, passkeys, sessions, recovery codes, auth
-- events, enrolment codes, WebAuthn ceremonies, invitations or organisation
-- sign-in; no DELETE anywhere; no minting of an enrolment token; no update of
-- an installation's name, owner, kind or repositories; and nothing on the
-- ledger schema. A table a later migration adds to innsegl_auth is not
-- granted to this role (no ALTER DEFAULT PRIVILEGES): it gets a grant here
-- when the core's own code needs it.
--
-- internal/api.AssertEnrollerScope asks the server about the edges of this at
-- every core start, and LED-049 measures every privilege against this list.
--
-- %[1]s is the role identifier and %[2]s the database identifier, exactly as
-- authwriter.sql's; EnsureEnrollerRole substitutes both after pgx sanitises
-- them, and db-init.sh substitutes them as psql variables.

REVOKE ALL PRIVILEGES ON DATABASE %[2]s FROM %[1]s;
REVOKE CREATE ON DATABASE %[2]s FROM PUBLIC;
GRANT CONNECT ON DATABASE %[2]s TO %[1]s;

REVOKE ALL ON SCHEMA public FROM %[1]s;
GRANT USAGE ON SCHEMA public TO %[1]s;

-- The ledger schema: nothing.
REVOKE ALL ON SCHEMA innsegl FROM %[1]s;

-- The auth schema: start from nothing, so that a re-run narrows a role an
-- operator widened by hand. A table-level REVOKE also takes back the column
-- grants on that table.
GRANT USAGE ON SCHEMA innsegl_auth TO %[1]s;
REVOKE ALL ON ALL TABLES IN SCHEMA innsegl_auth FROM %[1]s;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA innsegl_auth FROM %[1]s;

GRANT SELECT ON innsegl_auth.enrolment_tokens TO %[1]s;
GRANT UPDATE (used_at, installation_id) ON innsegl_auth.enrolment_tokens TO %[1]s;

GRANT SELECT ON innsegl_auth.installations TO %[1]s;
GRANT INSERT (installation_id, account_id, created_by, name, kind, repos)
    ON innsegl_auth.installations TO %[1]s;
GRANT UPDATE (last_renewed_at, status, revoked_at, operator_author_name, operator_author_email)
    ON innsegl_auth.installations TO %[1]s;

GRANT SELECT ON innsegl_auth.repo_grants TO %[1]s;
GRANT INSERT (account_id, repo) ON innsegl_auth.repo_grants TO %[1]s;

GRANT INSERT (actor, account_id, action, subject, detail) ON innsegl_auth.audit TO %[1]s;

GRANT SELECT ON innsegl_auth.accounts TO %[1]s;
GRANT SELECT ON innsegl_auth.memberships TO %[1]s;

-- No path to privilege of its own, the same posture every other role holds.
ALTER ROLE %[1]s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

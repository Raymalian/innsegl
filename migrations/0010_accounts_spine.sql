-- SPDX-License-Identifier: Apache-2.0
--
-- The accounts spine (#456): organisations, memberships, installations,
-- enrolment tokens, repository grants, invitations and an audit trail.
--
-- ADDITIVE-ONLY, LIKE 0008 AND 0009 BEFORE IT
--
-- Nothing here alters users, passkeys, sessions or the ledger's tables. The
-- one change to a table that already exists is a NULLABLE column on
-- innsegl.gateway_run_mapping (client_id), which carries no default and is
-- therefore a catalogue-only change: no row is rewritten, so the table's
-- statement-level insert-only trigger (migration 0007) has nothing to fire
-- on and stays exactly as effective as it was. ALTER TABLE ... ADD COLUMN is
-- not UPDATE, DELETE or TRUNCATE.
--
-- WHERE THE NEW TABLES LIVE
--
-- innsegl_auth, beside the tables they reference. The auth-writer role
-- already holds read and write on every table in that schema and no
-- privilege at all on innsegl, so this needs no new grant for the writer.
-- The ledger roles hold nothing on innsegl_auth: a role that may only
-- append events must not be able to rewrite who is allowed to.
--
-- IDENTIFIERS
--
-- account_id is 16 random bytes, hex-encoded, the same shape as
-- users.user_id. The data step below mints it with gen_random_uuid() with the
-- dashes removed (32 hex characters, built in from Postgres 13), because the
-- migration runs in SQL where the Go generator is not available.

CREATE TABLE innsegl_auth.accounts (
    account_id  text PRIMARY KEY
        CHECK (octet_length(account_id) BETWEEN 1 AND 64),
    name        text NOT NULL
        CHECK (octet_length(name) BETWEEN 1 AND 256),
    -- Opaque and internal: nothing outside the deployment reads this.
    shard       text NOT NULL DEFAULT ''
        CHECK (octet_length(shard) <= 256),
    -- The deployment's own organisation. At most one.
    operator    boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX accounts_one_operator
    ON innsegl_auth.accounts (operator) WHERE operator;

CREATE TABLE innsegl_auth.memberships (
    membership_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       text NOT NULL REFERENCES innsegl_auth.users (user_id),
    account_id    text NOT NULL REFERENCES innsegl_auth.accounts (account_id),
    role          text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    since         timestamptz NOT NULL DEFAULT clock_timestamp(),
    until         timestamptz
);

-- At most one LIVE membership per (user, account). Ended ones are history.
CREATE UNIQUE INDEX memberships_one_live
    ON innsegl_auth.memberships (user_id, account_id) WHERE until IS NULL;

CREATE INDEX memberships_account_idx ON innsegl_auth.memberships (account_id);

CREATE TABLE innsegl_auth.installations (
    installation_id text PRIMARY KEY
        CHECK (installation_id ~ '^[0-9a-f]{32}$'),
    account_id      text NOT NULL REFERENCES innsegl_auth.accounts (account_id),
    created_by      text NOT NULL REFERENCES innsegl_auth.users (user_id),
    name            text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 256),
    kind            text NOT NULL CHECK (kind IN ('workstation', 'service')),
    -- host/org/name entries, or the single entry '*'.
    repos           text[] NOT NULL
        CHECK (cardinality(repos) >= 1 AND array_position(repos, NULL) IS NULL),
    status          text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_renewed_at timestamptz,
    revoked_at      timestamptz
);

CREATE INDEX installations_account_idx ON innsegl_auth.installations (account_id);

-- Only a hash of the secret is stored: a leaked backup names no live token.
CREATE TABLE innsegl_auth.enrolment_tokens (
    token_id        text PRIMARY KEY
        CHECK (octet_length(token_id) BETWEEN 1 AND 64),
    secret_hash     text NOT NULL CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    account_id      text NOT NULL REFERENCES innsegl_auth.accounts (account_id),
    created_by      text NOT NULL REFERENCES innsegl_auth.users (user_id),
    repos           text[] NOT NULL
        CHECK (cardinality(repos) >= 1 AND array_position(repos, NULL) IS NULL),
    kind            text NOT NULL CHECK (kind IN ('workstation', 'service')),
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    installation_id text REFERENCES innsegl_auth.installations (installation_id)
);

CREATE TABLE innsegl_auth.repo_grants (
    grant_id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id  text NOT NULL REFERENCES innsegl_auth.accounts (account_id),
    repo        text NOT NULL
        CHECK (octet_length(repo) BETWEEN 1 AND 512 AND repo <> '*'),
    since       timestamptz NOT NULL DEFAULT clock_timestamp(),
    until       timestamptz
);

-- At most one LIVE holder per repository, enforced here and not in Go.
CREATE UNIQUE INDEX repo_grants_one_live_holder
    ON innsegl_auth.repo_grants (repo) WHERE until IS NULL;

CREATE INDEX repo_grants_account_idx ON innsegl_auth.repo_grants (account_id);

-- Created now; the flows that use it come later.
CREATE TABLE innsegl_auth.invitations (
    invitation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id    text NOT NULL REFERENCES innsegl_auth.accounts (account_id),
    role          text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    code_hash     text NOT NULL UNIQUE CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    created_by    text NOT NULL REFERENCES innsegl_auth.users (user_id),
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz
);

CREATE TABLE innsegl_auth.audit (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor       text,
    account_id  text,
    action      text NOT NULL CHECK (octet_length(action) BETWEEN 1 AND 128),
    subject     text NOT NULL DEFAULT '',
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_account_idx ON innsegl_auth.audit (account_id, id);

-- Append-only for every role, the way innsegl.gateway_run_mapping is. The
-- writer role's ACL (authwriter.sql) is the first line; this trigger is the
-- second, for a role provisioned before this table existed.
CREATE FUNCTION innsegl_auth.refuse_audit_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'innsegl: % on %.% is refused: the audit trail is append-only',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'IN004';
END;
$$;

CREATE TRIGGER audit_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl_auth.audit
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl_auth.refuse_audit_mutation();
ALTER TABLE innsegl_auth.audit ENABLE ALWAYS TRIGGER audit_append_only;

REVOKE UPDATE, DELETE, TRUNCATE ON innsegl_auth.audit FROM PUBLIC;

-- Which client machine or runner a mapped run came from. NULL for every row
-- written before this column existed. Nothing writes it yet.
ALTER TABLE innsegl.gateway_run_mapping
    ADD COLUMN client_id text
        CHECK (client_id IS NULL OR octet_length(client_id) BETWEEN 1 AND 256);

-- DATA STEP. Every existing user becomes the owner of an account of their
-- own; the earliest user's is the deployment's own (operator) organisation.
DO $$
DECLARE
    u        record;
    acct     text;
    is_first boolean := true;
BEGIN
    FOR u IN SELECT user_id, display_name FROM innsegl_auth.users
              ORDER BY created_at, user_id LOOP
        acct := replace(gen_random_uuid()::text, '-', '');
        INSERT INTO innsegl_auth.accounts (account_id, name, operator)
            VALUES (acct, left(u.display_name, 256), is_first);
        INSERT INTO innsegl_auth.memberships (user_id, account_id, role)
            VALUES (u.user_id, acct, 'owner');
        INSERT INTO innsegl_auth.audit (actor, account_id, action, subject, detail)
            VALUES (NULL, acct, 'account.created', acct,
                    jsonb_build_object('source', 'migration 0010',
                                       'owner', u.user_id,
                                       'operator', is_first));
        is_first := false;
    END LOOP;
END;
$$;

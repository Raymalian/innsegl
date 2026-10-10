-- SPDX-License-Identifier: Apache-2.0
--
-- Repository and branch pseudonyms (ADR-0080, #483, #484).
--
-- From schema 5 a deployment in pseudonymous repository mode writes `repo`
-- and `branch` as pn:<key-id>:<32 hex>. Three things live beside the chain to
-- make that work, and none of them is the chain:
--
--   innsegl.pseudonyms    the alias table: a pseudonym back to its literal.
--                         Written in the same transaction as the append that
--                         first carries the value. Not hash-covered, not in
--                         any segment, not anchored. The one table in this
--                         schema whose rows may be DELETED, and only by the
--                         erasure path: the append role is granted SELECT and
--                         INSERT on it by the schema's default privileges and
--                         nothing else.
--
--   innsegl.resolve_alias the read every SQL reader goes through: the literal
--                         for a pseudonym that still has an alias, the value
--                         itself otherwise (a literal, or an erased name).
--                         innsegl.resolved_body applies it to a whole body.
--
--   innsegl.repo_mode     the deployment's recorded switch to pseudonymous.
--                         One row, written by the core at its first start in
--                         that mode, refused UPDATE, DELETE and TRUNCATE to
--                         every role. A core in literal mode refuses to start
--                         once it exists, and a second account is refused
--                         until it does (ACC-008).

CREATE TABLE innsegl.pseudonyms (
    value      text PRIMARY KEY
               CHECK (value ~ '^pn:[a-z0-9][a-z0-9-]{0,62}:[0-9a-f]{32}$'),
    kind       text NOT NULL CHECK (kind IN ('repo', 'branch')),
    literal    text NOT NULL CHECK (octet_length(literal) BETWEEN 1 AND 512),
    -- For a branch, the pseudonym of its repository: erasing a repository
    -- erases its branches with it.
    repo_value text CHECK ((kind = 'branch') = (repo_value IS NOT NULL)),
    key_id     text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX pseudonyms_literal_idx ON innsegl.pseudonyms (kind, literal);
CREATE INDEX pseudonyms_repo_value_idx ON innsegl.pseudonyms (repo_value) WHERE kind = 'branch';

REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.pseudonyms FROM PUBLIC;

CREATE FUNCTION innsegl.resolve_alias(value text) RETURNS text
    LANGUAGE sql
    STABLE
    PARALLEL SAFE
    AS $$
        SELECT coalesce(
            (SELECT p.literal FROM innsegl.pseudonyms p WHERE p.value = resolve_alias.value),
            resolve_alias.value)
    $$;

-- innsegl.resolved_body is an event body with its repo and branch resolved:
-- what a reader that SHOWS a run reads. Never hashed, never verified: the
-- chain's bytes are canonical, and this is not them.
CREATE FUNCTION innsegl.resolved_body(body jsonb) RETURNS jsonb
    LANGUAGE sql
    STABLE
    PARALLEL SAFE
    AS $$
        SELECT CASE
            WHEN body ? 'repo' OR body ? 'branch' THEN
                body || jsonb_strip_nulls(jsonb_build_object(
                    'repo', innsegl.resolve_alias(body ->> 'repo'),
                    'branch', innsegl.resolve_alias(body ->> 'branch')))
            ELSE body
        END
    $$;

CREATE TABLE innsegl.repo_mode (
    singleton   boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode        text NOT NULL CHECK (mode = 'pseudonymous'),
    key_id      text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION innsegl.refuse_repo_mode_mutation() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'innsegl: % on %.% is refused: the switch to pseudonymous repositories is one-way (ADR-0080 decision 5)',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'IN005';
END;
$$;

CREATE TRIGGER repo_mode_one_way
    BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl.repo_mode
    FOR EACH STATEMENT EXECUTE FUNCTION innsegl.refuse_repo_mode_mutation();
ALTER TABLE innsegl.repo_mode ENABLE ALWAYS TRIGGER repo_mode_one_way;

REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.repo_mode FROM PUBLIC;

-- ACC-008: no account beyond the first until the switch is recorded.
--
-- In the database, so every path that creates an account -- the core's
-- command line today, a dashboard flow later -- meets the same check, asked
-- at the moment of creation. The deployment's own organisation (operator)
-- is never refused: it is the first account by definition. SECURITY DEFINER
-- so the role that creates accounts need not read the ledger schema. The
-- advisory lock serialises the check, so of two concurrent creations the
-- second sees the first once it commits.
CREATE FUNCTION innsegl_auth.refuse_second_account_while_literal() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog
    AS $$
BEGIN
    IF NEW.operator THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('innsegl-account-create'));
    IF EXISTS (SELECT 1 FROM innsegl_auth.accounts)
       AND NOT EXISTS (SELECT 1 FROM innsegl.repo_mode) THEN
        RAISE EXCEPTION
            'innsegl: a second account is refused while repository names are stored literally; set INNSEGL_REPO_MODE=pseudonymous and restart the core first (ADR-0080, ACC-008)'
            USING ERRCODE = 'IN006';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER accounts_second_needs_pseudonyms
    BEFORE INSERT ON innsegl_auth.accounts
    FOR EACH ROW EXECUTE FUNCTION innsegl_auth.refuse_second_account_while_literal();

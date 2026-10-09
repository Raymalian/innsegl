-- SPDX-License-Identifier: Apache-2.0
--
-- An installation's operator author, pinned on first use (#545).
--
-- A repository the operator sets to operator mode authors agent commits as
-- the operator, which I6 allows; the agent stays in the trailers and the
-- signature. The operator's machine reports who it pushes as, read from git,
-- and the first report is pinned here. The core's I6 gate then admits that
-- pair for commits signed for this installation, and nothing else beside
-- the agent address and the deployment's own configured pairs. A different
-- report is refused until an operator resets the pin on the core.
--
-- ADDITIVE-ONLY, as 0010: two NULLABLE columns with no default, a
-- catalogue-only change. Both or neither: a pin is a pair. The address must be
-- a GitHub noreply address, the one GitHub attaches to the account.
-- No grant changes: the auth-writer role already holds the table, and the
-- gateway's reader already SELECTs it.
ALTER TABLE innsegl_auth.installations
    ADD COLUMN operator_author_name  text
        CHECK (operator_author_name IS NULL OR octet_length(operator_author_name) BETWEEN 1 AND 256),
    ADD COLUMN operator_author_email text
        CHECK (operator_author_email IS NULL
               OR operator_author_email ~ '^[0-9]+\+[A-Za-z0-9-]+@users\.noreply\.github\.com$');

-- The name is the address's own login, never a person's name: it is
-- published on every commit the pair authors.
ALTER TABLE innsegl_auth.installations
    ADD CONSTRAINT installations_operator_author_pair
    CHECK ((operator_author_name IS NULL) = (operator_author_email IS NULL)
           AND (operator_author_email IS NULL
                OR operator_author_name = substring(operator_author_email
                                                    FROM '^[0-9]+\+([A-Za-z0-9-]+)@')));

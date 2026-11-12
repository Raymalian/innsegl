-- SPDX-License-Identifier: Apache-2.0
-- ADR-0085: public device proof and one bounded challenge per installation.
-- Private recovery keys never reach this database; the ledger is unchanged.
CREATE TABLE innsegl_auth.device_recovery (
    installation_id text PRIMARY KEY REFERENCES innsegl_auth.installations(installation_id),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz
);
CREATE TABLE innsegl_auth.device_recovery_challenges (
    installation_id text PRIMARY KEY REFERENCES innsegl_auth.device_recovery(installation_id),
    challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
    origin text NOT NULL CHECK (octet_length(origin) BETWEEN 1 AND 512),
    csr text NOT NULL CHECK (octet_length(csr) BETWEEN 1 AND 16384),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

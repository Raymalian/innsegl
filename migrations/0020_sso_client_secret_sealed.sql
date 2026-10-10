-- SPDX-License-Identifier: Apache-2.0
--
-- An organisation's sign-in client secret, stored encrypted (#574).
--
-- ADDITIVE-ONLY, as every auth migration before it: one new column, no row
-- rewritten here. 0019 kept the secret in client_secret as plain text. The
-- key that seals it is a per-host credential the database never holds
-- (ADR-0078), so SQL cannot seal it: the API seals every plain row at its
-- next start (accounts.Store.SealSSOSecrets) and from then on writes
-- client_secret as '' and the ciphertext here.
--
-- The sealed form is "v1:" and the base64url of the nonce and the AES-GCM
-- ciphertext; '' is a public client (PKCE alone).

ALTER TABLE innsegl_auth.sso_connections
    ADD COLUMN client_secret_sealed text NOT NULL DEFAULT ''
        CHECK (client_secret_sealed = ''
               OR (client_secret_sealed ~ '^v1:[A-Za-z0-9_-]+$' AND octet_length(client_secret_sealed) <= 4096));

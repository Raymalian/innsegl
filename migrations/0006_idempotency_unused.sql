-- SPDX-License-Identifier: Apache-2.0
--
-- A claim that had no effect frees its key (RM-186, #297).
--
-- A call refused BEFORE it wrote anything used to keep its claim bound to its
-- request digest, so a corrected request under the same key was refused as
-- DUPLICATE_REQUEST although nothing had happened. `unused` is that state: the
-- key was claimed, the call wrote nothing, and a later claim may take the key
-- over for any request. A call that failed AFTER an effect stays `in_progress`
-- and bound to its digest, exactly as before, because one key must never name
-- two different actions.
--
-- The role that serves the MCP already holds UPDATE on this table; DELETE is
-- still refused (verify-role.sh), which is why this is a status and not a
-- deletion.
ALTER TABLE innsegl.idempotency DROP CONSTRAINT IF EXISTS idempotency_status_check;
ALTER TABLE innsegl.idempotency ADD CONSTRAINT idempotency_status_check
    CHECK (status IN ('in_progress', 'completed', 'unused'));

-- The response rule names every status, so it learns the new one: an unused
-- claim, like an in-progress one, carries no response and no completion time.
ALTER TABLE innsegl.idempotency DROP CONSTRAINT IF EXISTS idempotency_response_iff_completed;
ALTER TABLE innsegl.idempotency ADD CONSTRAINT idempotency_response_iff_completed CHECK (
    (status = 'completed'                AND response IS NOT NULL AND completed_at IS NOT NULL) OR
    (status IN ('in_progress', 'unused') AND response IS NULL     AND completed_at IS NULL));

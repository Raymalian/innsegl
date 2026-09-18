-- SPDX-License-Identifier: Apache-2.0
--
-- The children of a run (RM-156, #259).
--
-- `parent_run_id` has been a member of `run_registered` since ADR-0045, and
-- nothing could ask the question it answers. This migration adds no member and
-- no event: it is an index over bytes the chain already holds, which is
-- unprotected database metadata rather than a change to doc 02's schema.
--
-- WHY A FUNCTION HAS TO EXIST BEFORE THE INDEX CAN
--
-- `canonical` is bytea, deliberately: it holds the RFC 8785 bytes exactly as
-- they were hashed, and jsonb would re-serialize them into a different
-- preimage (see 0001). Reading a member out of it therefore means decoding the
-- bytes, and `convert_from` is marked STABLE rather than IMMUTABLE by
-- Postgres, so it cannot appear in an index expression at all.
--
-- It is stable because its result depends on the DATABASE ENCODING as well as
-- on its arguments: the text it returns is in the database's encoding. That
-- encoding is fixed when the database is created and cannot be altered
-- afterwards, so within one database the expression below depends on nothing
-- but its input, which is what IMMUTABLE asserts. The wrapper says so once,
-- here, rather than at each index that needs it.
--
-- The honest limit, stated rather than discovered: restoring a dump of this
-- database into one with a DIFFERENT encoding would change what this function
-- returns for the same bytes, and the index would then be stale. That is a
-- reindex, and it is the same caveat every expression index over encoded text
-- carries. `innsegl.events` holds RFC 8785 bytes, which are UTF-8 by
-- construction (doc 02 §1), so a UTF-8 database is the only one that reads
-- them back unchanged in any case.
--
-- WHY IT IS PARTIAL
--
-- `parent_run_id` can only appear on `run_registered`. Every other event in
-- the chain -- and a chain is overwhelmingly `tool_call` -- would contribute a
-- NULL entry to a full index, so the partial predicate is not a size
-- optimisation over a rare value: it is the index describing what the member
-- actually is.
--
-- `chain_position` is the second column so that the children of one run come
-- back in chain order out of the index itself, with no sort.

CREATE FUNCTION innsegl.event_body(canonical bytea) RETURNS jsonb
    LANGUAGE sql
    IMMUTABLE
    PARALLEL SAFE
    STRICT
    AS $$ SELECT convert_from(canonical, 'UTF8')::jsonb $$;

CREATE INDEX events_parent_run_id_idx
    ON innsegl.events ((innsegl.event_body(canonical) ->> 'parent_run_id'), chain_position)
    WHERE event_type = 'run_registered';

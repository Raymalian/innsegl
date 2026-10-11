-- SPDX-License-Identifier: Apache-2.0
--
-- The writer lease and the freeze (RM-326, #580).
--
-- One core writes a ledger at a time. A core takes the lease before it serves
-- and renews it while it runs; a second core against the same database waits
-- until the lease is released or has expired. The append lock already keeps
-- the chain consecutive when two processes write; the lease is about which
-- core is the deployment, so an upgrade never has two of them running their
-- loops over one ledger.
--
-- The freeze is the other half. A frozen ledger refuses every append in the
-- database itself, whatever program asks. The mark lives in this table, so a
-- copy of the database taken after the freeze is frozen too, and never
-- writes until someone thaws it on purpose.
--
-- One row at most (id = 1). Outside the chain: bookkeeping, not evidence.

CREATE TABLE innsegl.writer_lease (
    id            smallint PRIMARY KEY CHECK (id = 1),
    -- Who holds it, and the epoch that names this holding. The epoch grows
    -- on every acquisition, so a holder that lost the lease cannot renew it
    -- back by name.
    holder        text CHECK (holder IS NULL OR octet_length(holder) BETWEEN 1 AND 256),
    epoch         bigint NOT NULL DEFAULT 0,
    acquired_at   timestamptz,
    renewed_at    timestamptz,
    expires_at    timestamptz,
    frozen_at     timestamptz,
    frozen_reason text CHECK (frozen_reason IS NULL OR octet_length(frozen_reason) BETWEEN 1 AND 1024),
    CHECK ((frozen_at IS NULL) = (frozen_reason IS NULL))
);

REVOKE DELETE, TRUNCATE ON innsegl.writer_lease FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- The fence, on every append.
--
-- Frozen: refused, always (IN007).
-- A session that names itself a writer (the innsegl.writer setting, which a
-- core that holds the lease sets on every connection): refused unless it is
-- the live holder (IN008). A session that names no writer -- a one-shot
-- command run beside the core -- is not fenced by the lease; it appends
-- through the same serialized path the core does.
--
-- SECURITY DEFINER so the check reads the lease whatever role appends; the
-- function reads one row and writes nothing.
-- ---------------------------------------------------------------------------
CREATE FUNCTION innsegl.fence_writer() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, innsegl AS $$
DECLARE
    l      innsegl.writer_lease%ROWTYPE;
    writer text := current_setting('innsegl.writer', true);
BEGIN
    SELECT * INTO l FROM innsegl.writer_lease WHERE id = 1;
    IF FOUND AND l.frozen_at IS NOT NULL THEN
        RAISE EXCEPTION 'innsegl: the ledger is frozen since % (%); thaw it to write',
            l.frozen_at, l.frozen_reason
            USING ERRCODE = 'IN007';
    END IF;
    IF writer IS NOT NULL AND writer <> '' THEN
        IF NOT FOUND OR l.holder IS DISTINCT FROM writer OR l.expires_at IS NULL
           OR l.expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'innsegl: % does not hold the writer lease (held by %, until %)',
                writer, coalesce(l.holder, 'nobody'), l.expires_at
                USING ERRCODE = 'IN008';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER events_fence_writer
    BEFORE INSERT ON innsegl.events
    FOR EACH ROW EXECUTE FUNCTION innsegl.fence_writer();
ALTER TABLE innsegl.events ENABLE ALWAYS TRIGGER events_fence_writer;

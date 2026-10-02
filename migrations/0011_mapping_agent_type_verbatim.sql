-- SPDX-License-Identifier: Apache-2.0
--
-- The harness's own agent-type name, beside the chain (RM-314).
--
-- A harness names subagent types as it likes: "Plan", "Explore",
-- "flutter-all:flutter-architect". doc 02 §5's identifier grammar is
-- protected, so the gateway folds the name into it (event.FoldIdentifier)
-- before register_agent, and the run's agent_type on the chain is the folded
-- one. The fold loses information, so the name as the harness sent it is kept
-- here, in the mapping row of the run it registered.
--
-- It is outside the chain, like every column of this table, and NOT a run
-- identity component: nothing reads it to decide anything.
--
-- A NULLABLE column with no default: a catalogue-only change, so no row is
-- rewritten and the statement-level insert-only trigger (migration 0007)
-- stays exactly as effective as it was. ALTER TABLE ... ADD COLUMN is not
-- UPDATE, DELETE or TRUNCATE. NULL for every row written before this column
-- existed, and for a run whose harness named no type. The writer role's
-- existing table-level SELECT and INSERT grant (appendonly.sql) covers the
-- new column.
--
-- The bound is the gateway's own (internal/gateway/agenttype.go): the string
-- is unauthenticated harness input.

ALTER TABLE innsegl.gateway_run_mapping
    ADD COLUMN agent_type_verbatim text
        CHECK (agent_type_verbatim IS NULL OR octet_length(agent_type_verbatim) BETWEEN 1 AND 256);

# TC-SER golden fixtures — `schema_version` 4

**These files are immutable**, on the same terms as [`../v1`](../v1/README.md),
[`../v2`](../v2/README.md) and [`../v3`](../v3/README.md). None is superseded by
this directory: doc 08 accepts a new version alongside all previous ones,
without exception, and
`TestSER024EveryReleasedVersionHasAFixtureSetThatStillVerifies` asserts all four
sets on every run.

## What version 4 changed

One accepted ADR (ADR-0061, #407 / RM-258), and nothing else. The serializer is
untouched, so `verify.py` differs from `../v3`'s only in the members it checks.

| Members | Event types | Why |
|---|---|---|
| `forked_from_run_id` (optional, `run_id` grammar) | `run_registered` | ADR-0061 decision 1. The run a fork's traffic-observed conversation fingerprint was linked from — distinct from `parent_run_id`, which names a spawning run tied to a tool call. |
| the type itself: `role` (**required**, `brief` \| `assistant`), `payload_digest` (**required, KEYED grammar** -- see below) | `agent_message` | ADR-0061 decision 2. A brief or an agent's own message, captured from the traffic a gateway observes. Neither names a tool, so neither belongs on `tool_call` (ADR-0021). |
| `workspace_tree_hash` (optional, git object id grammar) | `tool_call` | ADR-0061 decision 3. The workspace snapshot taken when the request carrying this tool call's result reached the gateway: evidence of tree state after the step, never a claim of authorship. Not a duplicate of `commit_intent.tree_hash` (a staged commit tree, not a per-step snapshot). |

**`agent_message.payload_digest` is not the envelope's plain `sha256:<64 hex>`
default.** It is `hmac-sha256:<key-id>:<64 lowercase hex>` — HMAC-SHA256 over the
stored body under a per-deployment secret, so a party with ledger or
read-only-API access alone cannot confirm a guessed brief by hashing it.
`tool_call.payload_digest` and every other type's keep the plain grammar,
unchanged; the two grammars cross-reject each other's values
(`TestADP008TheKeyedGrammarIsExclusiveToAgentMessage`).

`<key-id>` is not given a character-class grammar by ADR-0061 — it names the
placeholder throughout but never spells out what it may contain. This
implementation reuses doc 02 §5's identifier grammar (`[a-z0-9][a-z0-9-]{0,62}`,
the same shape `agent_type`, `task_id` and `run_id` already use) as the most
conservative available convention, pending a normative definition. See
`keyedDigestPattern` in `internal/event/validate.go`.

This package never computes or holds the HMAC key: the vectors below carry a
fixed key id (`core-2026-09`) naming no real secret, exactly as ADR-0061
requires this package to check the grammar only, never the computation (E16).

## Layout

The v3 vectors, re-versioned and re-chained with nothing else changed (minus
v3's own 2 -> 3 migration attestation, for the reason v3 excluded v2's), then:

| Vector | What it pins |
|---|---|
| `19-run_registered_fork` | the fork member, alongside a root run with no `parent_run_id` |
| `20-tool_call_workspace_tree_hash` | the workspace-tree member; `03-tool_call` stays the one without it |
| `21-agent_message_brief` | the new type, `role: brief` |
| `22-agent_message_assistant` | the new type, `role: assistant` |
| `23-schema_migrated` | the 3 -> 4 cutover attestation |

The generator is `TestGenerateV4Fixtures` in `internal/event/fixturegen4_test.go`.
Conventions are `../v1`'s, and load-bearing: see that README.

# TC-SER golden fixtures — `schema_version` 3

**These files are immutable**, on the same terms as [`../v1`](../v1/README.md)
and [`../v2`](../v2/README.md). Neither is superseded by this directory: doc 08
accepts a new version alongside all previous ones, without exception, and
`TestSER024EveryReleasedVersionHasAFixtureSetThatStillVerifies` asserts all
three sets on every run.

## What version 3 changed

One accepted ADR, and nothing else. The serializer is untouched, so `verify.py`
is `../v2`'s unchanged.

| Members | Event types | Why |
|---|---|---|
| the type itself: `adopted_run_id`, `adopted_run_state` (**required**), and the envelope's `payload_digest` (**required here**) | `run_adopted` | ADR-0051. A live run takes over the uncommitted work a dead run left. `payload_digest` is the claim: one line per path, the bytes' SHA-256 and the `tool_call` that produced them. It is stored as a body, not in the event (E4, and the 4 KB cap of LED-011). |
| `adoption_event_id` (optional) | `commit_intent` | ADR-0051. Present only on the intent that carries out an adoption, so the adoption and its commit cannot be separated. |

`adopted_run_state` is one of `retired`, `lapsed`, `abandoned`: the ledger's
word for how the run ended. Never `active`.

## Layout

The v2 vectors, re-versioned and re-chained with nothing else changed, then:

| Vector | What it pins |
|---|---|
| `17-run_adopted` | the new type |
| `18-commit_intent_adopted` | the one intent carrying `adoption_event_id`; `04-commit_intent` stays the one without it |
| `19-schema_migrated` | the 2 -> 3 cutover attestation |

The generator is `TestGenerateV3Fixtures` in `internal/event/fixturegen3_test.go`.
Conventions are `../v1`'s, and load-bearing: see that README.

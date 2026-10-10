# TC-SER golden fixtures — `schema_version` 5

**These files are immutable**, on the same terms as [`../v1`](../v1/README.md)
to [`../v4`](../v4/README.md). None is superseded by this directory: doc 08
accepts a new version alongside all previous ones, without exception, and
`TestSER024EveryReleasedVersionHasAFixtureSetThatStillVerifies` asserts all five
sets on every run.

## What version 5 changed

One accepted ADR (ADR-0080, #483), and nothing else. No member or event type is
added; the serializer is untouched.

| Members | Event types | Why |
|---|---|---|
| `repo` | `run_registered`, `commit_intent`, `commit_recorded` | May be the literal `host/org/name` or the keyed pseudonym `pn:<key-id>:<32 lowercase hex>`. |
| `branch` | `run_registered` | May be the literal reference name or `pn:<key-id>:<32 lowercase hex>`, keyed by its repository. `detached` stays literal. |

At schema 1 to 4 only the literal form is valid (`TestSER028…`).

The `pn:` values below were made with a published FIXTURE key, so `verify.py`
and `TestSER027…` can re-derive them. It names no deployment's key.

## Layout

The v4 vectors, re-versioned and re-chained with nothing else changed (minus
v4's own 3 -> 4 attestation) — so every repository among them stays literal,
which is the literal-mode vector at schema 5 — then:

| Vector | What it pins |
|---|---|
| `24-run_registered_pseudonymous` | `repo` and `branch` both pseudonymous, one key id |
| `25-commit_intent_pseudonymous` | a pseudonymous `repo` on a commit intent |
| `26-commit_recorded_pseudonymous` | the same repository under a second key id, 63 characters long (the longest allowed) |
| `27-run_registered_detached` | `branch: "detached"` beside a pseudonymous `repo` |
| `28-schema_migrated` | the 4 -> 5 cutover attestation |

The generator is `TestGenerateV5Fixtures` in `internal/event/fixturegen5_test.go`.
Conventions are `../v1`'s, and load-bearing: see that README.

# TC-SER golden fixtures — `schema_version` 2

**These files are immutable**, on the same terms as
[`../v1`](../v1/README.md): they are the normative, byte-level definition of a
protected surface, and `VERSIONING.md` gives them the last word — *"Where a
document and a fixture disagree, the fixture wins, because the fixture is what
verifiers actually re-derive."*

`../v1` is not superseded by this directory and never will be. doc 08 accepts a
new version **alongside** all previous ones without exception, the ledger still
holds every version-1 event ever appended, and I4 forbids rewriting them. Both
sets are asserted on every run —
`TestSER024EveryReleasedVersionHasAFixtureSetThatStillVerifies`, in
`internal/event/everyversion_test.go`, is the gate that would go red if either
stopped verifying.

## What version 2 changed

Two accepted ADRs, and nothing else. The serializer is untouched: RFC 8785 JCS,
the same member ordering, the same escaping, the same hash — which is why
`verify.py` here is `../v1`'s argument unchanged.

| Members | Event types | Why |
|---|---|---|
| `repo`, `branch` (**required**) | `run_registered` | ADR-0045. A repository used to reach the ledger only as a side effect of signing, so a run that signed nothing recorded nowhere it had been. Measured on 2026-09-08: 26 subagent runs, 1979 tool calls, not one saying which repository. |
| `parent_run_id` (optional) | `run_registered` | ADR-0045. A subagent's parent is a run. Optional because a root run has none — requiring it would make every root run invalid. |
| `patch_id` (**required**) | `commit_intent`, `commit_recorded` | ADR-0047. A gitsign signature covers the commit *object*, and GitHub's rebase rewrites it. `git patch-id --verbatim` names the *change*, which survives. |

`branch` is stored **verbatim** and held to git's ref grammar, not to the
SPIFFE identifier grammar: folding `dev/rm115-caller-split` into
`dev-rm115-caller-split` names a different branch, and one that may also exist.

`patch_id` is `--verbatim` and never `--stable`. The default normalises
whitespace, so `hello world` and `hello   world` hash the same; in Python, YAML
and a Makefile those are two different programs.

## Layout

Identical to `../v1`, and the conventions are load-bearing rather than
cosmetic — see that README for the full argument.

| File | Contents |
|---|---|
| `<name>.input.json` | The event object **without** `event_hash`, pretty-printed with its members in deliberately reverse-sorted order (so every fixture doubles as an ordering-independence vector, SER-002). |
| `<name>.canonical.json` | The exact RFC 8785 JCS bytes of that object. No trailing newline: the file *is* the preimage. |
| `<name>.hash` | `sha256:` + lowercase hex of SHA-256 over `<name>.canonical.json`. No trailing newline. |
| `format-probe.*` | The serializer format fingerprint under serializer version 2 (SER-005). |
| `verify.py` | Re-derives every file here with a non-Go oracle. `python3 verify.py` |

Two files in `../v1` have no counterpart here, deliberately:

- **`genesis.hash`** — the genesis constant is not a property of a schema
  version. doc 02 §4.4 ties it to `chain_position` 1, the seed is
  `innsegl-genesis-v1` under both versions, and every event ever appended hangs
  off it; a second copy here would be a value that could drift. `verify.py`
  computes it rather than reading it, and the chain below is walked from it.
- **`00-doc02-example`** — it reproduces doc 02 §6's example "member for member
  and byte for byte", and §6's example is a version 1 event. Adding version 2's
  members would make it reproduce nothing. doc 02 is normative and is not
  edited to match this package.

## The fixtures

`01`–`15` are **one valid hash chain**: position 1 carries the genesis constant
as `prev_event_hash`, and every later position carries the preceding fixture's
`event_hash`. `01`–`14` are `../v1`'s vectors carrying exactly what the two
ADRs add, so a diff between the two directories *is* the schema change.

| # | Fixture | What version 2 added |
|---|---|---|
| 01 | `run_registered` | `repo`, `branch` — and `branch` carries a `/`, which is the case a normalising grammar would silently corrupt |
| 04 | `commit_intent` | `patch_id` |
| 05 | `commit_recorded` | `patch_id`, the same value as 04's — one change, recorded twice, joinable |
| 15 | `run_registered` (subagent) | `parent_run_id`, naming 01's run |
| 02, 03, 06–14 | unchanged but for `schema_version` and the chain | the types the ADRs do not touch |

Fixture 15 exists because `parent_run_id` is version 2's only optional member,
and an optional member no fixture carries is an untested member — the same
reason `../v1` committed both 11 and 12 for `segment_sealed`'s anchor fields.

## Regenerating

Don't. A failing fixture test means the serializer changed, and the serializer
is what must be reverted.

The generator that produced this directory is
`TestGenerateV2Fixtures` in `internal/event/fixturegen_test.go`, and it is a
generator rather than a gate: it skips unless `INNSEGL_WRITE_V2_FIXTURES=1` is
set. It exists so that a *future* version's set can be derived from this one the
way this one was derived from `../v1`, not so that this one can be refreshed.

# ADR-0045: Record which repository, which branch, and which agent started it

- Status: proposed
- Date: 2026-09-08
- Deciders: the operator, on evidence from the running deployment

## Context

The deployment cannot answer three questions an operator asks first.

**Which repository was this run in?** A run's repository is recorded only as a
side effect of signing: `commit_intent` and `commit_recorded` carry `repo`, and
nothing else does. A run that registers, does work and retires without signing
has no repository anywhere in the ledger. Measured 2026-09-08:

```
task_ref          agent_type        runs  last seen
<repo-a>-main     general-purpose      1  2026-09-08 07:28:27
<repo-b>-main     general-purpose      1  2026-09-08 07:28:27
main              general-purpose     14  2026-09-08 07:27:58
```

Fourteen runs called `main`, from more than one project, indistinguishable from
each other. Two more that name a repository at all only because the harness hook
squeezes it into `task_ref` as a hyphenated prefix — and the operator's reaction
to those two was that one of them named a project they had not been working in,
which the label cannot confirm or deny.

**Which branch?** Nowhere, except inside that same squeezed string. `task_ref`
is one field with an invented grammar — `<repo>-<branch>` — which is ambiguous
the moment a branch name contains a hyphen, which is most of them.

**Which agent started this one?** Nowhere. Subagents are registered by the
harness hook and nested subagents work (measured: one parent, two children,
runs 39 through 42), but the ledger records four peers. Reconstructing the tree
means guessing from timestamps. The operator wants what git gives: who started
what, and how it went.

## The precedent that argues against changing the schema

This project has twice reached this exact fork and twice gone the other way.

- **#118** wanted a marker event for pruning. The stated blocker was which
  `event_type` it should carry; the binding one turned out to be the
  append-only trigger. The prunable index went into a separate, unprotected
  table and `innsegl.events` was left untouched.
- **#167 / ADR-0044** wanted alert resolutions. A twelfth `event_type` would
  have needed a new major `schema_version` (doc 02 §7, IP §2), so resolutions
  became a row in a separate table keyed by the alert's `event_id`, and "open"
  became a derived property.

Both are the same shape: the protected event is the record, and the new thing
is index-like metadata *about* the record. Applied here, that gives option B
below at a fraction of the cost.

## Options

### A. New fields on `run_registered` (a major release)

`run_registered` gains `repo`, `branch` and `parent_run_id`. `repo` is not a
new protected string — doc 02 §3 already defines it on `commit_intent` and
`commit_recorded`, and §5 fixes its format as `host/org/name`. `branch` and
`parent_run_id` are new ones.

doc 08 then requires all four of these in the same release:

- a new `schema_version` (`"1"` → `"2"`) accepted **alongside** `"1"` by every
  verifier, forever;
- updated golden fixtures for the new version, with the old ones kept;
- a signed migration attestation event marking the exact chain position of the
  cutover;
- this ADR, superseding nothing but binding the change.

Old events are never rewritten (I4 applies to the schema's own history), so the
dashboard must render both shapes: runs before the cutover have no repository,
and must say so rather than showing a blank that reads as "none".

**What it buys:** the claim "this agent worked in this repository, on this
branch, started by that agent" is inside the hash chain, covered by the segment
Merkle root, and anchored in Rekor. It is evidence, not annotation. For a
product whose whole argument is that attribution is tamper-evident, the
provenance of a run is arguably the part that most needs to be.

**What it costs:** a major release, a migration attestation, permanent
dual-version support in every verifier, and a fixture set that doubles.

### B. A `run_context` table (the precedent's answer)

A separate, unprotected table keyed by `run_id`, written by the MCP at
registration, holding repository, branch and parent. The dashboard joins it.
`innsegl.events` is untouched, `schema_version` stays `"1"`, no attestation, no
release ceremony.

**What it costs:** the three values are not in the chain. Anyone who can write
the database can change which repository a run claims to have touched, and no
verification anywhere would notice — the events still hash correctly, because
the values were never in them. `innsegl verify` would keep passing on a run
whose recorded provenance had been rewritten.

That is the whole of the difference, and it is not a small one. #118 and #167
put *metadata about records* outside the chain. This is a *property of the run
itself, at the moment it is created* — the same category as `agent_type` and
`task_ref`, which are already in the event.

## Decision

Not yet taken. The operator chose A when asked. This ADR exists because the
precedent runs the other way twice, and a major release is not a thing to enter
without the trade above stated in one place.

Recommendation: **A**, on the argument that provenance a verifier cannot check
is not provenance. If the release ceremony is the blocker rather than the
design, B is a defensible interim that does not preclude A later — but a run
recorded under B and later re-recorded under A will have two answers, and the
unchained one will be the older.

## Consequences if A is taken

- `register_agent` takes `repo`, `branch` and `parent_run_id`. Tool *names* and
  error classes are protected; arguments are additive, so this is not itself a
  protected-surface change.
- Whether `repo` and `branch` are **required** is the second decision, and it
  is the one that decides whether the hole can reappear. Required means a
  caller with no git context cannot register at all — which is IP §6.1's own
  argument applied one level out: work should be impossible to attribute
  without saying where it happened, not merely awkward.
- `parent_run_id` is optional by nature: a root run has no parent.
- The harness hook supplies all three. It already derives repository and branch
  from the main worktree; it would stop squeezing them into `task_ref`, and
  `task_ref` would go back to naming the task.
- The dashboard gains a repository column, a branch column, and a tree.

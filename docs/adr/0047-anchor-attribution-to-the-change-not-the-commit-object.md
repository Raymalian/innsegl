# ADR-0047: Anchor attribution to the change, not the commit object

- Status: accepted
- Date: 2026-09-09
- Deciders: the operator, on measurements taken against a real repository and GitHub itself
- Supersedes the merge-strategy half of ADR-0046

## Context

This project's central claim is that an agent's work carries a signature anyone
can check. That claim did not survive contact with a normal pull request.

A gitsign signature covers the commit **object**: tree, parent, author,
committer, timestamps, message. Any rewrite produces a different object, so the
signature no longer describes anything that exists. Git drops it rather than
carry one that cannot verify.

Every merge button on GitHub except "create a merge commit" rewrites. And a
repository that requires linear history cannot use that one — measured on this
repository:

```
required_linear_history: True
```

which is why the merge dialog reads "Create a merge commit — Not enabled for
this repository" while the repository setting says `allow_merge_commit: true`.
Branch protection overrides it. The remaining button is rebase.

So the shipped design left an adopter with a choice between linear history and
attribution, and no way to have both. That is not a configuration mistake. It is
the wrong question being asked at verification time.

## What was measured

All of it, because the first two attempts at this were wrong and the operator
was right to refuse anything unmeasured. `git patch-id --verbatim` throughout;
the `--stable` finding is below.

**GitHub's own rebase button**, on a throwaway branch pair, base moved first so
the rebase was real:

| | before | after |
|---|---|---|
| probe one | `1ac8345` `BEGIN SIGNED MESSAGE` | `36de5a9` **no gpgsig at all** |
| probe two | `7d55b0c` `BEGIN SIGNED MESSAGE` | `c377c7c` **no gpgsig at all** |
| patch-id one | `05d508d997e3` | `05d508d997e3` |
| patch-id two | `fbd79b2579ec` | `fbd79b2579ec` |

The signature is **deleted**, not replaced. Squash behaves differently: it
substitutes GitHub's own PGP key, which is why a squashed commit renders as
"Verified" while the shipped verifier answers `failed` on all three checks.

**Everything else**, in a controlled repository:

| operation | SHA | signature | patch-id |
|---|---|---|---|
| rebase onto a moved base | new | gone | **survives** |
| rebase with a conflict | new | gone | **changes** |
| commits reordered | new | gone | survives |
| message-only amend | new | gone | survives |
| squash | new | replaced | **matches none of the originals** |
| merge commit / fast-forward | unchanged | survives | survives |

**Where patch-id fails**, and these bound the decision:

| case | result |
|---|---|
| the same change made twice | **identical id** — it collides |
| an empty commit | **empty string** — no id exists |
| `--stable` and whitespace | `hello world` = `hello   world` |
| `--verbatim` and whitespace | 4-space and 8-space indentation differ |

## Decision

**Verification asks whether the CONTENT was signed, not whether this commit
object was signed.**

`git patch-id` identifies the change and nothing else — not the parent, not the
committer, not the timestamp. It is the only identity measured here that
survives what GitHub actually does.

Four parts, each forced by a measurement above.

### 1. `--verbatim`, never `--stable`

The default ignores whitespace. In Python, YAML and Makefiles whitespace is
meaning, so a tamper that only moved indentation would verify as untouched.
`--verbatim` distinguishes them and is equally stable under rebase — measured
both ways.

### 2. The ledger records the patch-id when it signs

A new `patch_id` member on `commit_intent` and `commit_recorded`. This is a
protected surface, and it rides the major release ADR-0045 already opened
(`schema_version` `"2"`); it does not justify one on its own.

### 3. The mapping is patch-id AND the run, never patch-id alone

Patch-id collides. The `Agent-Run` trailer names a run; the ledger says what
that run signed; the patch-id confirms the content matches. The trailer is
forgeable and the patch-id is not unique, and neither weakness is reachable
through the other.

An empty commit has no patch-id and is therefore outside this scheme entirely.
It also changes nothing, so there is nothing to attribute.

### 4. The new SHA is recorded, not merely derivable

After a merge, the reconciler walks the branch, computes each commit's
patch-id, and on a match appends a **superseding** `commit_recorded` carrying
the new SHA. doc 02 §2's `supersedes` exists for exactly this and
`segment_sealed` already uses it for anchoring; the original event is never
modified (I4).

This makes lookup by SHA work again, and turns the rewrite into a recorded fact
rather than an inference: the ledger can answer *this content was signed as
commit A and now lives as commit B*. The reconciler asserts nothing anyone has
to take on trust — it records a match that any reader can recompute from the
repository, which is the difference between a claim and a receipt.

## What this gives up, stated plainly

We prove an agent produced the **content**. We no longer prove the agent wrote
this exact commit: the message, the parent and the author belong to whoever
merged it.

That is honest, and it is what actually happened. The alternative was a claim
that only holds while nobody uses a pull request.

## Consequences

- **GH-003 is wrong as written** and must be rebuilt on this. It requires the
  signature to be on the object, so it fails every legitimately rebased commit.
  It also checks for the wrong failure shape: after a rebase there is no
  `gpgsig` at all, where after a squash there is one of the wrong type.
- **Squash merging stays disabled.** It is the only operation that severs the
  link completely, and nothing recovers it. ADR-0046's reasoning stands; only
  its "use a merge commit" instruction is superseded, because linear history can
  forbid that and rebase is now supported.
- The reconciler needs read access to the repositories, which it already has.
- A conflicted rebase will not match, and must be reported as *the content
  changed*, not as a fault. That is the correct answer and the message must say
  which of the two it means.

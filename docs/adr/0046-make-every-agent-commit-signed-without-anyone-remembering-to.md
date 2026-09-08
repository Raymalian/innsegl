# ADR-0046: Make every agent commit signed, without anyone remembering to

- Status: accepted
- Date: 2026-09-08
- Deciders: the operator, on measurements from the running deployment

## Context

The deployment records that agents work and does not record what they produce.
Measured 2026-09-08 across the whole ledger:

| agent_type | runs | recorded tool calls | signed commits |
|---|---|---|---|
| `general-purpose` (subagents) | 26 | 1979 | **0** |
| `orchestrator` | 27 | 2 | 19 |
| `session` | 1 | 0 | 0 |

All nineteen signed commits are in one repository. Subagents have made nearly
two thousand observed tool calls and have never signed anything. Every signature
that exists came from an orchestrator typing `scripts/innsegl-commit.sh` by
hand.

This is the same failure the project was created to answer, one level out. On
2026-09-07 a branch held twelve commits and three were signed; the other nine
were made with plain `git commit` by an orchestrator that had every tool it
needed and did not reach for them. IP §6.1: the MCP must make it impossible to
do attributed work anonymously, **not merely inconvenient**. An instruction in a
prompt is the definition of merely inconvenient.

Three mechanical causes, none of them the model's judgement:

1. Nothing makes an agent commit through the signing path. `sign_commit` is
   available and unused.
2. `innsegl-commit.sh` needs the repository linked into the MCP's workspace.
   Repositories other than this one are not linked, so an agent that *wanted*
   to sign could not.
3. GitHub's squash merge rewrote the signed commit on `main`: it dropped the
   gitsign signature and inserted `Co-authored-by:`, which ADR-0028 §5 forbids
   outright. The I6 gate caught it. So even a correctly signed commit did not
   survive being merged.

## Decision

Four mechanisms, each one deterministic and none of them relying on a model
remembering anything.

### 1. The repository links itself

`SessionStart` already derives the repository and branch from the main
worktree. It now also links that repository into the MCP workspace. Signing
becomes possible in any repository the operator opens, with no setup step, and
cause 2 disappears.

### 2. Plain `git commit` is refused, and the refusal is the instruction

A `PreToolUse` hook matches `git commit` and exits 2. In Claude Code that blocks
the call and returns the hook's stderr to the model as the reason, so the
instruction arrives at the only moment it matters and cannot be forgotten,
because it is not remembered — it is enforced.

Asymmetric, exactly as identity is (ADR-0045's precedent and the SessionStart
rule): **blocking for subagents, warning for the operator's own session.**
Refusing a subagent costs nothing; refusing the human stops them working on
their own machine.

It degrades safely. If the deployment is unreachable, or the repository cannot
be linked, the hook warns and allows — a wedged agent that can neither commit
nor sign is worse than an unsigned commit, and the branch gate still refuses to
merge unsigned work.

### 3. Only a merge commit preserves a signature

Measured on `4ab53d0`: squash produced a new commit object, so `git log
--format=%G?` answers `E` and the shipped verifier fails all three checks on a
commit whose trailers still claim an agent identity. That is worse than
unsigned — it is an unverifiable claim of attribution.

Squash merging is disabled on the repository. GitHub requires that squash or
rebase remain enabled, so rebase stays available and must not be used: it also
rewrites the commit and drops the signature, though it inserts no trailer.
**Create a merge commit is the only correct choice**, and it has a second
benefit — the I6 gate counts non-merge commits, so a real merge commit is
skipped and the agent's own commit underneath it is the one scanned, which is
the commit that satisfies the policy.

A rule that depends on which button a human clicks is not enough on its own.
The gate for it is in Consequences below.

### 4. Nothing is retrofitted

`4ab53d0` keeps its trailer. `main` is protected and rewriting it was declined
by the branch policy; more importantly, rewriting shared history to make a gate
green teaches the wrong lesson. The violation is real, it is recorded, and the
door it came through is now shut.

## Consequences

- The I6 gate stays red on `main` until it is given an explicit, dated baseline
  naming `4ab53d0` and the reason. That is a separate decision and must be
  written down rather than quietly widened — a gate with an unexplained
  exception is a gate nobody trusts.
- A CI check is still missing and is the real guarantee behind mechanism 3: a
  commit reachable from `main` that carries `Agent-Identity` and does not verify
  should fail the build. Without it, "click the right button" is advice. With
  it, a bad merge cannot stay merged.
- Auto-linking gives the MCP write access to every repository the operator opens
  under `INNSEGL_PROJECTS`, not only ones chosen deliberately. That is a real
  widening of what `innsegl.workrepo.yml` already warns about, and an operator
  who does not want it points `INNSEGL_PROJECTS` at a narrower directory.

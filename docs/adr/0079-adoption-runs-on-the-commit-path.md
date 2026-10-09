# ADR-0079: Adoption runs on the commit path

- Status: accepted
- Date: 2026-10-09
- Deciders: the operator
- Supersedes in part: ADR-0051 decision 1 (the trigger) and the `sign_commit`
  binding of decision 3. Every other part of ADR-0051 stands.

## Context

ADR-0051 lets a live run commit the work a dead run left, with the commit
naming both runs and a `run_adopted` event holding the proof. It bound the
whole mechanism to the `sign_commit` MCP tool: the caller names the dead run
in `adopt_run`, and the tool checks the index against the dead run's bodies.

Two things have changed since.

- Agents no longer commit through `sign_commit`. They run `git commit`, and the
  commit path signs it: `prepare-commit-msg` asks the core for the trailers,
  and git's signing program asks the core to sign the payload (ADR-0059).
  Adoption is not reachable from that path at all.
- The MCP wire surface is deprecated and leaves at the next major release
  (ADR-0077). Adoption bound only to `sign_commit` leaves with it.

So, today, the ordinary way a dead run's work reaches a commit is the one way
that cannot say whose work it is. The commit names the live run, which did not
write it. That is the wrong attribution ADR-0051 was written to stop (#269).

The commit path also differs from `sign_commit` in what it can be told. There
is no argument to put `adopt_run` in: the agent types `git commit`, and the
hook adds the trailers. A new argument would need a new flag on `git commit`,
which git does not have, or an environment variable the agent has to remember,
which is the "merely inconvenient" path ADR-0059 measured nobody using.

Two facts were measured while designing this:

- The bodies the gateway records (ADR-0058) are not shaped like the bodies
  ADR-0051 was written against. A gateway body carries the tool's `input`
  (`file_path`, `content` for `Write`; `file_path`, `old_string`,
  `new_string`, `replace_all` for `Edit`) and the tool's text `result`. It does
  not carry the file as it was before an `Edit`. ADR-0051's rebuild read
  `originalFile` out of a hook-shaped body, so against gateway bodies it could
  prove no `Edit` at all.
- On a hosted core (ADR-0063, ADR-0065) the agent's checkout is on another
  machine. The core sees the commit's objects only after the client pushes
  them to its mirror, which it does before signing.

## Decision

**The core proposes the adoption at `prepare-commit-msg`, and proves it again
at signing. Nobody names the dead run. Only a proof can.**

### 1. The trigger is the change itself

On every agent commit through the commit path, the core asks one question: is
this whole change exactly what one dead run left? If it is, the commit adopts
that run. If it is not, the commit is the live run's own work, as it is today.
No argument, flag or variable asks for it, and nothing a caller says changes
the answer.

### 2. What `prepare-commit-msg` sends, and when it sends nothing

The hook sends the core the tree `git write-tree` gives for the index git is
committing, and `HEAD` as its parent. A hosted client first pushes those
objects to the core's mirror, on the tool call's staging ref, exactly as the
signing program already does.

The hook sends no tree, and so no adoption is looked for, when git says the
message comes from an existing commit or a merge (`commit`, `merge` or
`squash` source), and the core looks for none when the relayed command is not
a plain `git commit`, or carries `--amend`. In each of those cases the commit's
real parent is not `HEAD`, and a proposal checked against the wrong parent
would make the signature refuse a commit that should have been made.

### 3. Who can be adopted: the search

The candidates are the runs registered for the committing run's own
repository that the ledger does not call `active`, whose last activity is
within the search window (seven days), most recent first, at most 32 of them.

A candidate is a match when ADR-0051 decision 2 holds for it against the
change from `HEAD` to the tree, unchanged:

- every changed path has a `Write` or `Edit` from the candidate, in one
  checkout;
- each path's bytes equal what the candidate's calls left there, rebuilt from
  bodies whose digests match the chain;
- no path is a deletion or a rename;
- the same bytes of the same path were not already adopted from it and
  committed (decision 6).

The core proposes an adoption only when **exactly one** candidate matches, and
the committing run itself recorded no `Write` or `Edit` to any changed path.
Two matches, or a change the live run also touched, is the live run's own
work. A run that cannot be read is not a match. A ledger that cannot be read
refuses the trailers, as it refuses any commit.

### 4. Rebuilding an `Edit` from a gateway body

A path's bytes are rebuilt by replaying the candidate's own calls on it in
chain order. `Write` sets the bytes to its `content`. `Edit` replaces
`old_string` with `new_string` in the bytes so far, once (it must occur
exactly once) or everywhere with `replace_all`. The bytes before the first
call are the path's blob in the parent commit. A path whose first call is an
`Edit` and that the parent does not hold cannot be rebuilt.

A call whose result says it failed changed nothing and is skipped. A call
whose result the gateway never observed may or may not have run, so the path
it touched cannot be proved. A hook-shaped body still carries `originalFile`
and is read as ADR-0051 read it.

The proof is still entirely the chain's: a third party with the parent
commit, the bodies and their digests can replay it.

### 5. Signing proves the named run again

The trailers step renders `Agent-Adopted-Run` with the three existing
trailers. At signing, the core reads it back from the payload's own message,
and gate 2 (ADR-0059 decision 4) requires the four trailers exactly. Then,
before Phase A, it proves the named run against the **payload's** tree and
first parent, with ADR-0051's refusals, plus one: the dead run was registered
for the committing run's repository. Any refusal means git makes no commit
(ADR-0059 decision 7).

The proof at signing is what the record rests on, not the proposal. A payload
that carries the trailer without the hook, or after the change moved, is held
to the same proof, and refused when it fails.

### 6. The record

What is appended is ADR-0051 decision 3's, unchanged: `run_adopted` under the
signing run, before `commit_intent`, its `payload_digest` naming the claim
stored on the body volume, and the intent's `adoption_event_id` naming it.
Its idempotency key is derived from the tool call id and the payload, as the
commit path's other two keys are.

### 7. `sign_commit`'s `adopt_run` stays until the major

It keeps working, with the rebuild of decision 4, until ADR-0077's phase 3
removes the wire surface.

## Alternatives considered

- **An environment variable or a commit-message line naming the dead run.**
  The agent has to know the run id and remember to say it. ADR-0059 measured
  what an explicit step costs: nobody does it. A line in the message is also a
  caller-spelled `Agent-*` key, which ADR-0028 refuses.
- **Decide only at signing.** The trailer is part of the signed bytes, and git
  builds the payload before it asks for a signature. A trailer decided after
  the payload exists cannot be in it.
- **Record the adoption without the trailer.** The content check reads a
  ledger adoption that the commit does not state as a stripped trailer and
  fails it (ADR-0051 decision 5). Both have to say the same thing.
- **Search every dead run of the repository.** Each candidate costs a ledger
  read and its bodies. Unbounded, a busy repository pays that on every commit.
  The window and the cap bound it. Work left longer ago is still committable,
  as the live run's own.
- **Adopt the best of several matches.** Any rule that picks one of two proofs
  is the inference ADR-0051 refused. Two matches is a question the record
  cannot answer, so it does not claim one.
- **Rebuild an `Edit` from the gateway's text result.** The harness's result
  is a display, a snippet with line numbers, not the file. It proves nothing
  byte for byte.

## Consequences

- **No protected surface changes.** No event type, member, enum value or
  trailer key is added or renamed; `Agent-Adopted-Run`, `run_adopted` and
  `adoption_event_id` are ADR-0051's. No MCP tool or error class changes. The
  trailers request gains two optional members, `tree` and `parents`, on the
  core's own commit-path route, which is not a protected surface. An older
  hook sends neither, and its commits are made exactly as before, with no
  adoption.
- **A commit that hands over a dead run's work now says so without anyone
  asking.** That includes the common case of a parent agent committing the
  work of a subagent that has ended: the subagent is retired on hand-back
  (ADR-0058 decision 7), and its own edits are what is staged.
- **One commit adopts one run.** A change mixing two dead runs' work, or a
  dead run's and the live run's, is the live run's own. Splitting it into one
  commit per run adopts each.
- **Cost.** One more push per commit on a hosted core, and at most 32 runs'
  bodies read at `prepare-commit-msg`. Signing reads one run's.
- **Retirement stays final** (IP §6.2). The dead run's identity is never
  issued a credential, never signs, and is named in the commit only by the
  signing run's own certificate-bound signature over the trailer.
- **Tests:** the search (one match, two, none, a partial change, a spent
  change, the live run's own edit, amend); the rebuild from gateway bodies
  (`Write`, `Edit` on the parent's blob, a failed and an unobserved call); the
  trailers step rendering the fourth trailer; signing proving the named run
  and refusing each failure with nothing recorded; and the whole path on a
  real stack, verified.

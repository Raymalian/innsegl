# ADR-0051: Let a live run adopt a dead run's work, and record the handover as an event

- Status: proposed
- Date: 2026-09-24
- Deciders: the operator

## Context

A run can die with work uncommitted in the tree: a crash, an out-of-memory
kill, a usage limit, or its whole session ending. #288 made that death visible:
the next session's start records the run and the paths it left. It did not make
the work committable.

A run that is no longer active cannot sign. `sign_commit` answers
`RUN_ALREADY_RETIRED`, and IP §6.2 makes that immediate and final. That is
correct and this ADR does not weaken it. A retired identity that could sign
again would turn every leaked credential of a dead run back into a live one.

So the only way to keep the work today is for another run to sign it. The
signature then names a run that did not write the change. The commit message
can say otherwise, but a message is prose, and nothing checks it. This is the
class #269 records: attribution that verifies and is wrong.

What already exists, and makes a checkable answer possible:

- Every tool call a run makes is appended to the chain as a `tool_call` event
  whose `payload_digest` is the SHA-256 of the call's body, and the body is kept
  under that digest (#211).
- A `Write` body carries the full content it wrote. An `Edit` body carries the
  file as it was before the edit and the replacement it made. Either way the
  exact bytes the run left in a path can be rebuilt from bodies the chain
  already vouches for.
- The chain already says how a run ended: `run_retired`, or a withdrawal that
  reads `lapsed` or `abandoned` (internal/ledger/runstate.go).

A path written through a shell command has no such body. Its bytes cannot be
tied to the run by anything the chain holds.

## Decision

A live run may **adopt** a dead run's work. The commit names both runs, and the
handover is its own event on the chain, with proof of which bytes were handed
over.

1. **`sign_commit` takes an optional `adopt_run`.** The signing run is the
   caller's own, as today. The adopted run is named, never inferred.

2. **The server refuses unless every one of these holds**, and names the first
   that does not:
   - the adopted run is registered, is not the signing run, and its state is
     not `active`. A run that may still be working is not dead, and silence is
     the reaper's question (ADR-0014), not this tool's;
   - every path in the staged change has a `Write` or `Edit` call from the
     adopted run on the chain;
   - for each path, the staged bytes equal the bytes rebuilt from the adopted
     run's **last** such call on that path, from a body whose digest matches
     the chain.

   A path the adopted run wrote through a shell, or one it never touched, is
   refused. It is the adopting run's own work and goes in a commit of its own.

3. **A new event, `run_adopted`**, is appended by the MCP before
   `commit_intent`, under the signing run. Its members:
   - `adopted_run_id`: the dead run.
   - `adopted_run_state`: the ledger's own word for how it ended at that
     moment (`retired`, `lapsed` or `abandoned`). Nothing the caller says. A
     reason the ledger cannot know, such as a usage limit, belongs in the
     commit message, as prose.
   - `claim`: one line per path, sorted by path, `<sha256 of the bytes>
     <event_hash of the tool_call that produced them> <path>`. It is what was
     handed over and where each part of it was proved.

   `commit_intent` for the same commit carries the `run_adopted` event's hash,
   so the two cannot be separated.

4. **A new trailer, `Agent-Adopted-Run: <run_id>`**, written by the server only,
   beside the three existing ones. A caller that supplies it is refused, as a
   caller-supplied `Agent-*` trailer already is.

5. **What each verifier can say.** `innsegl verify` stays ledger-free and does
   not change its three checks: the signature proves the adopting run signed
   the commit, and the report shows the adopted run as a claim it cannot check
   by itself. The content check, which does read the ledger, finds the
   `run_adopted` event and reports the change as adopted from that run, with
   the proof lines. A commit that carries `Agent-Adopted-Run` with no matching
   event is refused.

6. **An adoption is spent by its commit.** Once `commit_recorded` exists for a
   `run_adopted`, the same paths and bytes cannot be adopted again.

## Alternatives considered

- **Wake the retired identity and let it sign.** Retirement stops being final,
  and IP §6.2 exists to make it final. Every credential ever issued to a dead
  run would become something to revoke again.
- **Sign under a new run and say so in the message.** What was done on
  2026-09-23. The signature, the only checked part, names the wrong author, and
  the note is prose nothing verifies. That is #269 happening on purpose.
- **Trust the orphan sweep's record** (#288). It lives in a file on the
  operator's machine, not on the chain, and anyone who can write that file can
  write a claim.
- **Let the caller supply the digests.** A digest the caller computes proves
  the caller can hash. The proof has to come from bodies the chain already
  vouches for, so the server computes it.
- **Allow shell-written paths as unproven.** A handover that is partly proved
  reads as proved. It would make "adopted" mean "someone said so" for exactly
  the paths nothing checks.

## Consequences

- **Protected surfaces change.** A new event type and its member names, a new
  trailer key, and a new `sign_commit` argument (additive; no tool is renamed
  and no error class is added: refusals use `INVARIANT_VIOLATION`). Doc 08
  allows protected changes only with a new `schema_version` (3), golden
  fixtures for it, a `schema_migrated` attestation at the cutover, and this ADR.
  Doc 08 ties that to a major release. Whether a pre-1.0 release may carry it
  is the operator's call, not this ADR's.
- **Doc 02 is not edited here.** Whether it gains an errata line pointing at
  this ADR, or this ADR alone carries the new event, is the same question #270
  asks, and it is the operator's.
- **Adoption has a window.** Bodies are kept 90 days and capped at 1 MiB. Past
  either, the bytes cannot be rebuilt and adoption is refused. The work can
  still be committed as the adopting run's own.
- **The orphan sweep points at this.** Its report now says a dead run may not
  sign; it will name `adopt_run` instead.
- **Exit cost.** Events are append-only, so `run_adopted` records stay valid
  under schema 3 forever even if adoption is later removed. Removing it means
  refusing new ones, not rewriting old ones.
- **Tests to write:** the refusals in 2 one by one, each with a positive
  control; an `Edit` rebuilt byte for byte; a shell-written path refused; the
  trailer refused from a caller; the content check reporting an adoption and
  refusing a trailer with no event; an adoption spent by its commit.

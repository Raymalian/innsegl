# ADR-0052: A withdrawn credential is a lapse, not a death

- Status: accepted
- Date: 2026-09-26
- Deciders: the operator

## Context

Three specs describe the reaper's `run_expired` as the end of a run:

| where | says |
|---|---|
| doc 02 §3 | `run_expired` is "TTL expiry of an unretired run" |
| doc 01 §6.7 | an agent that crashes is expired by its entry's TTL |
| doc 06 §3.2 | an expired run "means an agent died unretired" |

The code has not worked that way since #255 and #258. The reaper withdraws a
run's credential when the run has been silent past policy. The run is not
ended: it may resume, and when it speaks again `get_credential` restores its
identity and the run reads active again.

Silence is not death at any threshold. An agent waiting on a provider's usage
limit, running a long build, or on a machine that went to sleep is silent and
alive. #180 measured a live agent with 313 tool calls reaped mid-task, and the
word "expired" read that as a death.

doc 02 is protected, and the event name `run_expired` cannot change outside a
major release. What can be fixed is what the event is taken to mean.

## Decision

`run_expired` records the **withdrawal of a credential**, not the end of a run.
A run's state is read from its newest recorded fact, in this order
(internal/ledger/runstate.go is the one implementation):

1. **retired**: a `run_retired` is on the chain. Someone said stop: a harness
   that owned the process, or a human. The only terminal state.
2. **lapsed**: the newest fact is a withdrawal, inside the restore horizon. The
   run resumes if it speaks again, and its identity is restored.
3. **abandoned**: the newest fact is a withdrawal, and the horizon has passed.
   This deployment will no longer mint for the run. That says what the
   deployment will not do, not what happened to the agent (E7).
4. **active**: otherwise.

A withdrawal stands only while nothing newer contradicts it: an event the
reaper did not write, after the withdrawal, puts the run back to active. The
horizon is `INNSEGL_ABANDON_AFTER`, 30 days by default.

No state is stored. Every answer is computed from recorded facts at read time,
because a stored state would be a fact nobody appended (I4).

doc 02 keeps its row and gains an errata line pointing here. doc 01 §6.7 and
doc 06 §3.2 are amended to match.

## Alternatives considered

- **Rename the event to say what it records.** `run_expired` is a protected
  string. Renaming it is a major release and a migration attestation, to fix a
  word whose meaning can be fixed in one line pointing here.
- **Leave the specs as they are and let this ADR carry the meaning alone.**
  The specs would keep telling a reader that an expired run died, beside code
  that says otherwise, in documents nobody may edit. The disagreement would
  outlive everyone who knew it was there.
- **Keep "expired" as a state beside the four.** Three words could not tell a
  run that is quiet from a run that is over, and the one they collapsed into
  read as death. That confusion is what #180 and #270 record.

## Consequences

- A dashboard or API that shows `expired` as a state is wrong. The four states
  above are the vocabulary; `expired` survives only as the name of the event.
- The reaper stays a question about silence, and silence stays ambiguous:
  nothing here lets it end a run. A run that is known to be over is retired
  (#290 does that on an observed kill), and work a dead run left is adopted
  (ADR-0051), which accepts `lapsed` and `abandoned` as well as `retired`.
- No event type, member or enum value changes, so no schema version.
- Exit cost: a later decision to treat withdrawal as terminal would be a new
  ADR superseding this one, and would have to say what happens to runs that
  resumed after a withdrawal under this rule.

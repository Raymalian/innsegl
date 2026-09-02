# ADR-0041: Pseudonymise `agent_type` and `task_ref` in the SPIFFE ID, and resolve them through the ledger row rather than a key

- Status: accepted
- Date: 2026-09-02
- Deciders: Mike

## Context

doc 02 §5 fixes the SPIFFE ID grammar:

```
spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}
```

with each of the three components matching `[a-z0-9][a-z0-9-]{0,62}`. The
project's own example is `spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42`.

That string is not internal. It is:

1. the **URI SAN of the Fulcio certificate** every commit is signed under, and
   therefore of the certificate embedded in the Rekor entry. Under public
   Sigstore (ADR-0002, demoted by ADR-0010 but still a supported configuration)
   a transparency-log entry is a permanent, world-readable, append-only record;
2. the **`Agent-Identity` commit trailer**, which is public in any public
   repository whatever the trust root is.

So `jira-118` — a ticket number, and with it the shape of an organisation's
tracker and its issue volume — and `fix-ci` — what kind of work an agent was
doing — leave the organisation forever, on every signed commit. `run_id` is not
the problem: `register_agent` derives it as 128 bits of a digest
(`registerAgentRunID`), and a real one reads `run-850d52ce86c191a3be92ab66c9a05a87`.

Invariants touched: **I5** (verification must not need this system — so
whatever is done here must leave a stranger with the same three verdicts),
**I2** (a credential is bound to one run — so whatever the identity says, it
must still name exactly one run), **I3/I4** (the record is never lost or
mutated — so the real values must still reach the ledger, unchanged, forever).

Two constraints shaped the answer before any design work.

**Nothing here may move a protected surface** (doc 08 "Protected surfaces").
Changing the grammar, the trailer keys, an event field name or the canonical
serialization would be a MAJOR release with a new `schema_version`, updated
golden fixtures, verifiers accepting both versions, and a signed migration
attestation. That is not proportionate to a privacy fix.

**The grammar does not have to move.** It constrains the two segments to
`[a-z0-9][a-z0-9-]{0,62}`, and eight hex characters satisfy that regex exactly
as well as a ticket number does. The fix is therefore a change to *what goes
into* the fields and to nothing else.

## Decision

**`register_agent` fills `{agent_type}` and `{task_id}` with keyed pseudonyms
of the caller's values, by default.**

```
pseudonym(field, value) = hex(HMAC-SHA256(deployment_secret, field ‖ ":" ‖ value))[:8]

before:  spiffe://innsegl.dev/agent/fix-ci/jira-118/run-850d52ce…
after:   spiffe://innsegl.dev/agent/a7f3c91b/e2d5f004/run-850d52ce…
```

`field` is the event schema's own member name — `agent_type` or `task_ref` —
used as an HMAC domain separator and written nowhere. Neither name contains a
colon and the separator is a colon, so an agent type and a task reference that
read the same cannot pseudonymise to the same eight characters.

HMAC and not a bare digest: the inputs are low-entropy and frequently
guessable, and an unkeyed hash of `jira-118` is reversible by anyone with a
ticket-number generator.

The eight decisions that follow from it:

1. **`internal/identity` owns the mapping.** One package, two modes, and every
   consumer is handed one instance. It checks doc 02 §5's grammar on the input
   in *both* modes, so `pseudonymous` and `literal` are one tool contract: a
   4 KB task reference is refused in both, even though eight hex characters
   would have carried it.

2. **`pseudonymous` is the default; `literal` reproduces the old behaviour
   exactly.** There are no tags, so there is no history to migrate, and the
   safe default for a privacy control is the one that protects. `literal` is
   the escape hatch — for a private repository where the commit was never
   public, and where an operator judges a human-legible `Agent-Task: JIRA-118`
   in `git log` worth the Rekor entry.

3. **An empty secret in `pseudonymous` mode REFUSES TO START.** See
   "Alternatives" — this is the decision with the sharpest teeth.

4. **The secret has a floor of 16 bytes.** The pseudonym publishes 32 bits of
   HMAC output; an adversary holding one (value, pseudonym) pair — and task
   references are guessable — tests candidate keys offline against it, so the
   key's own entropy is what protects every other pseudonym.

5. **The real `agent_type` and `task_ref` still reach `run_registered`
   unchanged**, verbatim and with the caller's own casing, beside the
   pseudonymous `spiffe_id`. That one row IS the mapping. There is no second
   table, and there is no new event field.

6. **The secret is needed to CREATE a pseudonym and never to RESOLVE one.**
   Resolution is a ledger read. Consequently: losing or rotating the secret
   does not orphan history, and — because no read path holds it — it does not
   strand a live run either. This is the property the whole shape was chosen
   for, and it is easy to lose by accident; see decision 8.

7. **`Agent-Task` carries the pseudonym under `pseudonymous`.** ADR-0018 §6
   requires the trailer to lowercase to the identity's `{task_id}`, and that
   redundancy is precisely what lets check 3 — a comparison of `Agent-Identity`
   against the certificate, with no access to our database — settle all three
   trailers at once. A literal trailer against a pseudonymous certificate is
   the mismatch that check exists to refuse. Under `literal` the trailer keeps
   the caller's own casing, exactly as before.

8. **Anything needing the identity's SEGMENTS reads them off the identity.**
   `spire.RunRefOf` parses them from the recorded `spiffe_id`;
   `mcp.CredentialRun.Ref` uses it. `internal/rundir` is unchanged and still
   reads `agent_type` and `task_ref` from the event rather than from the ID.

## Alternatives considered

**Pseudonymise the certificate and leave the trailer literal.** Better for a
private repository: the ticket stays readable in `git log`, and only the Rekor
entry is public. It was rejected because it breaks check 3 as written — that
check exists to compare the trailer against the certificate, and the two would
no longer be comparable. Repairing it means changing the verification the
product's credibility rests on, which is a decision for a human and a much
larger intervention than this one. It remains available as a future ADR.

**Pseudonymise both, and let the ticket live in the commit message.** This is
what a deployment can do today with no code at all, and it is stated in
`deploy/compose/README.md` rather than built: the message is unattested, and in
a public repository it leaks anyway, which makes putting it there a deliberate
choice rather than a loophole.

**Fall back to literal values when no secret is set.** Rejected as the worst
available option: the configuration would say the deployment is pseudonymous
while every ticket number went into Rekor, and the failure would be silent and
permanent. This project has shipped a default that meant "no protection" and
looked like a considered choice twice; this is not the third.

**Generate a random secret per process when none is set.** Rejected for a
correctness reason and not only a privacy one. The pseudonym would change on
every restart and differ between replicas, so ADR-0017's take-over of an
expired claim — which re-executes `register_agent` with the same derived
`run_id` — would ask SPIRE to create a SECOND SPIFFE ID for a run that already
has one. IP §1 allows one entry per run; a privacy feature would have broken
it.

**A mapping table from pseudonym to real values.** Rejected because
`run_registered` already carries both, so the table would be a second copy of
an append-only fact, with its own retention, its own backup and its own way of
disagreeing with the chain (I4).

**Encrypt the values into the segment instead of hashing them.** Rejected: it
would make the deployment key necessary to READ history, which turns key loss
into permanent data loss and inverts decision 6.

**More than eight hex characters.** Rejected. Eight is 32 bits; collisions
appear around 2^16 distinct references and cost nothing — the run id still
separates the identities, the entries and the rows, and the real values are in
the event. Ambiguity in the public record is the point.

## Consequences

**The attested link from a commit to a tracker is gone from the repository.**
This is the real cost and it is paid by people every day. `git log` no longer
shows `Agent-Task: JIRA-118`; tooling that maps commit → ticket from the
trailer stops working; resolving a commit to a ticket now needs the dashboard
or the ledger. It is paid on private repositories too, where only the Rekor
entry ever leaked. An operator who judges that trade wrong sets
`INNSEGL_IDENTITY_MODE=literal` and accepts the public record.

**One invariant check is narrower.** `mcp.credentialRunIdentity` previously
required `spiffe_id` to end in `/agent/{agent_type}/{task_id}/{run_id}` built
from the run directory's own values. Those segments are now keyed pseudonyms of
the recorded values, so reproducing them would mean holding the deployment
secret on a READ path — and then a rotated or lost secret would stop every live
run getting a credential and stop it being retired, which is exactly what
decision 6 exists to prevent. The check now requires a well-formed SPIFFE ID in
the `/agent/` subtree whose `{run_id}` is this run's, which is the half that
stopped a directory being a second route to AB-10. The residue is asserted as a
test (`TestADirectoryNamingAnotherTaskIsNoLongerDetectable`) rather than left as
a comment, so re-tightening it has to explain how.

**Two settings can be set inconsistently across replicas.** Two replicas with
different secrets mint two identities for one run. The deployment
documentation says so; nothing in the code can detect it, because a replica
cannot see another replica's secret.

**SPIRE selectors carry pseudonyms.** `DefaultRegisterAgentSelectors` builds
`dev.innsegl.agent-type` and `dev.innsegl.task-id` labels from the run
reference, so a workload container must be labelled with the segments of the
`spiffe_id` `register_agent` returned. Those labels are node-local and not a
public record; the change is that an orchestrator derives them from the reply
rather than from what it passed in.

**What still leaks, and is not addressed here.** The trust domain — it is the
root of trust and cannot be hidden. The timing and volume of anchoring. And the
fact that a commit was signed at all.

**Test IDs.** PRI-001 (the pseudonym is a pseudonym; the trailer lowercases to
the segment), PRI-002 (the modes, the absent secret, the grammar), PRI-003 (no
ticket reference reaches the SPIFFE ID, the SPIRE entry, the trailers or the
commit message, and the ledger holds both), PRI-004 (the same, scanned on the
reference stack against a real Fulcio certificate and a real Rekor entry). They
are not in doc 07 yet; adding them is a spec edit for a human.

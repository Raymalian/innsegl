# ADR-0049: Decide whether ownership belongs in the SPIFFE ID or in a record beside it

- Status: **proposed** — this ADR is the material for the decision, not the decision
- Date: 2026-09-16
- Deciders: the operator

## Context

### What the identity says, measured 2026-09-16

doc 02 §5 fixes the grammar:

```
spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}
```

Three segments, all about the work. Counted over doc 02 in full, the words
`user`, `human`, `owner` and `operator` appear **zero** times each. The event
package's envelope and type definitions carry no `principal` or `owner` member
either.

So the system answers *what kind of agent did this, on what task, in which
run*. It cannot answer *whose agent this was*. That question has no segment, no
field and no event.

What stands in for it today is the repository. ADR-0045 put `repo` and `branch`
on `run_registered` so that a run says where it worked from the moment it
exists. Ownership is then read off that: whoever owns the repository owned the
agent. The inference is correct here, and it is **circumstance rather than
authority** — nothing in the ledger or the certificate asserts it, and nothing
refuses a run registered against a repository its caller does not own.

Correct for one operator running their own agents. It does not survive a second
person on one deployment, and it does not survive customers.

### Why deciding late costs more than deciding now

The SPIFFE ID grammar is protected surface 3 in doc 08 §3, beside the event
schema (1), the trailer keys (2), the MCP tool names (4) and the namespace (5).
Doc 08's rules: a MINOR or PATCH release must not alter one, and a MAJOR may
only with, in the same release, verifiers that accept every previous
`schema_version` forever, updated golden fixtures, a signed migration
attestation marking the cutover position, and a superseding ADR.

Two facts fix the timing, both checked today:

- `internal/event/canonical.go` holds `SchemaVersion = "2"`, and the repository
  carries no release tag. The major that ADR-0045 opened and ADR-0047 rode is
  **open and uncut**. Anything taken before the cutover rides it; anything
  taken after opens a second major.
- Doc 08 forbids migrating records in place, and I4 says the same. Old events
  stay valid under their own version forever.

The second point is what actually makes lateness expensive, and it is not the
release mechanics. **Nothing retrofits a principal into an identity already
issued.** Every run recorded under the present grammar is a run whose ownership
can only ever be answered outside the certificate. A grammar change taken later
does not make the history self-contained — it splits the history into an era
that is and an era that is not, and the second era never shrinks. Under
ADR-0041 those identities are also in a transparency log, where they are
permanent and world-readable.

### The question that decides this

> **Does a third party need to verify WHO OWNED the agent, or only that a
> specific agent produced a specific change?**

If the first: ownership has to be in the certificate, and a principal in the
path is the only honest answer. Anything else asks the verifier to consult this
system, which is what I5 forbids.

If the second: the grammar is already right, and the binding can live beside it.

The two answers suit different products. Where the **customer** is the subject
of the claim — *this organisation's agent made this change* — the customer's
name has to travel with the claim. Where the **agent** is the subject and the
customer operates it — *this agent made this change, and the signature proves
it* — the customer's name is context, not evidence.

**This project has been the second throughout and has never written it down.**
Every invariant is about the agent: I1 attests the workload, I2 binds a
credential to a run, I3 records what the agent did, I5 makes the agent's
attribution checkable by a stranger, and I6 exists specifically to keep the
human *out* of the attribution. Making that implicit commitment explicit is
most of what this ADR is for. The two options are what follows from it.

## Decision

**Proposed, not taken: option B — leave the SPIFFE grammar alone, and bind a
run to a principal in a separate append-only record.** Held lightly. The
measurement above does not decide the question; the operator does.

Two things are part of the recommendation rather than caveats on it:

1. **The binding is its own event type**, so it is append-only like everything
   else: a correction supersedes rather than edits (I4), and the ownership
   history is as auditable as the signing history. A mutable owner column
   beside an immutable chain is a record that can disagree with itself, which
   ADR-0041 already rejected for the pseudonym mapping.
2. **doc 08 gains an explicit line stating that the ownership half is not
   covered by I5.** I5 requires every attribution claim to be checkable by a
   third party with no access to our database. Under B the *ownership* claim is
   not such a claim — it is checkable only through this system. Naming that
   limit in the governance document is worth more than quietly having it: an
   adopter who reads "anyone can verify" and later discovers the ownership half
   was never in scope has been misled by omission, and ADR-0042 already had to
   do the work of saying exactly what that phrase covers.

B is not free of the protected surfaces either. A new `event_type` is a new
enum value in doc 02 §3, which is surface 1. It rides the open
`schema_version` "2" major the way `patch_id` did under ADR-0047 and does not
justify a major of its own. What B avoids is moving surface 3 — the identity
grammar — and the disclosure that comes with moving it.

## Alternatives considered

**A. A principal in the path**, `spiffe://{td}/{org}/{user}/agent/{type}/{task}/{run}`
or the same with one segment.

The case for it is strong, and it is the case for the product itself.
Attribution becomes **self-contained**: a verifier holding the certificate
reads the organisation off it with no lookup, no API and no trust in this
deployment. That is the strongest form the claim can take and the form I5 asks
for everywhere else. If the answer to the deciding question is *yes, ownership
must be verifiable*, then A is not the better option — it is the only honest
one, and B should be refused outright rather than adopted with a disclaimer.

A loses here on the answer, not on the merits. Two costs remain to weigh even
if the answer changes.

It moves protected surface 3. Before the `schema_version` "2" cutover that is
small; after it, a second major release with its own migration attestation.
And it is retroactive for nobody — identities already issued keep their shape
forever.

It puts a customer's identity inside every certificate that reaches a
transparency log. ADR-0041 is directly on point: it pseudonymised `agent_type`
and `task_ref` because a ticket number in a permanent, world-readable,
append-only record discloses the shape of an organisation's tracker and its
issue volume. A principal is a stronger version of the same disclosure — not
the shape of a tracker but the identity of the customer, their agent count and
their working hours, published irrevocably. An argument accepted for a task
name is harder to refuse for a person.

**A′. A pseudonymised principal segment**, minted the way ADR-0041 mints the
other two. This is the obvious reconciliation and it does not work. A pseudonym
gives a verifier *distinguishability* — two runs came from the same principal,
or did not — and never *attribution*: which principal is a question only this
deployment's ledger answers, by ADR-0041 decision 6's design. So A′ pays A's
full protected-surface cost, buys none of the property A exists for, and lands
where B already is without the grammar change. If the pseudonym is acceptable,
B is strictly cheaper.

**A″. A second SAN or a custom certificate extension** carrying the principal,
leaving the grammar untouched. It dodges surface 3 and not the disclosure — the
certificate is what reaches the log — and it needs Fulcio to issue a field it
does not issue today, which IP §7 puts out of reach: SPIRE and Sigstore are
used as released upstream components, configuration and orchestration only.

**Leave it implicit and decide when a second user appears.** Rejected as the
option that looks like B and is not. B's value is the written commitment about
what the product claims; deferring keeps the same code and leaves the
commitment unmade, so the next person to ask *does this prove who owned the
agent?* gets an answer assembled on the spot. It also spends the cheap window:
the open `schema_version` "2" major is the last moment at which either option
is a small change.

**A mapping table outside the ledger.** Rejected for ADR-0041's reason,
unchanged in substance: a second copy of an append-only fact acquires its own
retention, its own backup, and its own way of disagreeing with the chain (I4).

## Consequences

**If B is taken.**

- The claim is bounded in writing: *this agent produced this change, and the
  signature proves it*, no longer implying *and we can prove to a stranger
  whose agent it was*. ADR-0047 already narrowed the claim once, from the
  commit object to the change, and said so plainly; this is the same kind of
  narrowing and deserves the same treatment.
- doc 02 §3 gains an event type and doc 08 §3 gains a sentence. Both are spec
  edits, which are a human's to make.
- doc 07 needs IDs, and what is honestly testable is the binding's append-only
  behaviour, not an ownership proof — there is nothing external to prove it
  against.
- The dashboard may show an owner. The public paste-a-SHA page must not, or
  must label it as coming from this system, because that page exists to answer
  without trusting us (IP §6.11).
- Reversal is not cheap. Adopting A later means the split history above,
  permanently.

**If A is taken.**

- ADR-0041's privacy position has to be revisited in the same release. A
  deployment that pseudonymises a ticket number while publishing the customer's
  name is not coherent.
- The cutover must happen before `schema_version` "2" is tagged, or it costs a
  second major.
- Runs recorded before the cutover still need B's mechanism to answer ownership
  at all. A does not remove B; it dates it.

**Either way.** Whoever answers the deciding question writes the answer into
doc 08, not only into this ADR's status line. The failure being guarded against
is not choosing wrongly — it is having chosen without noticing, which is the
state the project is in today.

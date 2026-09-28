# ADR-0059: A commit is attributed through the tool call that made it

- Status: accepted
- Date: 2026-09-28
- Deciders: the operator

## Context

ADR-0031 and ADR-0033 built `sign_commit` on one premise: the MCP runs `git
commit` itself, inside a repository linked into its own workspace (ADR-0031
decision 1; ADR-0033 decision 3). That premise is what makes IP §6.5's three
phases possible from inside one tool — the component that signs is the
component that creates the commit object, so it can `write-tree` and compare
before Phase A (ADR-0033 decision 2) and read the certificate back after
(ADR-0031 decision 1). It has one consequence nothing in those ADRs states
plainly: attribution exists only for commits made **by calling the tool**. A
harness's own `git commit` — the thing a coding agent naturally runs on every
turn — is invisible to this path entirely.

ADR-0046 built the enforcement this gap requires: a `PreToolUse` hook refuses
a plain `git commit` outright, so an agent has no unattributed way to commit.
Measured on 2026-09-08, before that hook existed, the cost of leaving the
natural path open was total: subagents had made nearly two thousand recorded
tool calls and signed nothing; every signed commit came from an operator
typing the signing script by hand. IP §6.1 calls this out directly — the MCP
"must make it impossible to do attributed work anonymously, not merely
inconvenient" — and a tool an agent has to remember to call instead of the one
it already reaches for is exactly "merely inconvenient."

**Four things were measured about the alternative — attributing the harness's
own `git commit` instead of replacing it:**

1. **Nothing in the harness's own process environment distinguishes which
   agent is committing.** The session identifier is the same for the main
   agent and every one of its subagents. No agent identifier reaches a tool
   process at all.
2. **Matching by command or message text is a heuristic that is sometimes
   wrong.** It fails outright for a message given as a file, for `--amend`,
   for an editor-composed message, and — the case that matters most — for two
   agents committing with the identical message or the identical command,
   which is common (parallel subagents given the same instruction). One trial
   produced a false match from an unrelated process's argv containing another
   agent's command as substring. A join used for attribution cannot be a
   heuristic that is sometimes wrong.
3. **A `PreToolUse` hook can inject the specific tool call's own identifier
   into the exact `git commit` invocation the model asked for**, as an
   environment variable on that one child process, and the party that signs
   can be made to cross-check that identifier against traffic it independently
   relayed — not merely trust what the hook claims. Measured against three
   subagents issuing the byte-identical `git commit` command at the same
   moment: three of three attributed correctly. A forged identifier and a
   missing one were both refused before anything was signed.
4. **Git serializes commits in one repository by itself, and it does so after
   signing, not before.** Of several parallel `git commit`s sharing a
   repository, only one updates the branch; the others fail to lock the ref.
   All of them were signed first, because gitsign runs before git moves the
   ref. A commit that is signed and never becomes reachable from any branch is
   therefore not a malfunction of this system — it is git's own concurrency
   control, operating on commits this system does not serialize and should
   not try to.

Invariants in play: I2 throughout (signing still requires a valid,
audience-correct credential for the current run, however the signing
invocation reaches the process that holds one); E8 in the signing step itself
(the ephemeral key and the child environment it runs in); I3 in Phase A/B/C;
I5 not at all — nothing here changes what a third party checks, or that they
never need this system's database to check it; I6 in the author-identity gate,
which this decision must keep enforcing even though it no longer builds the
committing process's environment itself.

## Decision

**The harness runs `git commit`. The MCP does not run it for the harness, and
does not refuse it. Attribution is built into the invocation instead.**

### 1. One hook injects the tool call's own identifier

The same `PreToolUse` match ADR-0046 uses (`git commit`) no longer exits 2.
It rewrites the command's environment to carry the tool call's own
identifier and the run's identity, on the one child process the model's
request is actually about to become — the mechanism measured above to
distinguish parallel, byte-identical commands exactly.

### 2. `prepare-commit-msg` asks the core for the run's trailers

The hook calls the core with the tool call identifier and the in-progress
commit message; the core answers with the message plus the three trailers,
rendered by the same code ADR-0028 built — placement decided in-process, never
by shelling to `git interpret-trailers` at signing time, for the reason
ADR-0028 gave: the render is a pure function of `(message, claim)`, and a
subprocess reading ambient configuration is not. Only the render moves; the
caller of it does. A request naming a tool call the core never relayed, or a
run that cannot claim the trailers it is asking for, is refused here, before a
signing attempt exists to refuse.

### 3. `gpg.x509.program` is an innsegl client, not gitsign directly

Git already speaks a contract for this configuration point (ADR-0031 decision
1, from the signer's side): the program is invoked with the object to sign on
stdin and returns a CMS signature on stdout. The program git is configured to
invoke is a thin client that reads that payload, attaches the same tool call
identifier the environment now carries, and asks the core to sign it. The
client never sees a credential and never runs gitsign itself.

### 4. The core is the checkpoint: gates, then Phase A, Phase B, Phase C — one call, IP §6.5's order

When the signing client (decision 3) hands the payload to the core, that
single call is where everything happens: gated exactly as `sign_commit`
already gates it (ADR-0033), then phased exactly as IP §6.5 requires.

**Gates, before anything is appended:**

- the tool call identifier is resolved against the traffic the core already
  relayed for this session — bound to the session, to the agent, and to a
  bounded time window, so a stale or replayed identifier from a different
  call or a different run is refused. This is the authorisation precondition
  decision 1's injection exists to satisfy: the `git commit` tool call the
  core observed earlier is checked here. It is not a phase of its own, and
  nothing is appended on the strength of having merely observed it;
- the trailers are read back out of the payload's own message and required
  to be the ones step 2 rendered for this same tool call — ADR-0028
  decision 4's agreement rule, checked against a payload instead of built by
  hand;
- the author and committer lines are read out of the payload itself and run
  through ADR-0028's `CheckAuthor` gate, unchanged in what it checks and
  changed only in where the checked bytes come from: a payload the core
  received, not an environment the core built. I6 is enforced exactly as
  before; the harness's own `user.name`/`user.email` never reaches a signed
  commit unadmitted;
- the run's credential is fetched the one way it always has —
  `get_credential` (ADR-0019, ADR-0033 decision 4) — keyed by the identity
  the tool call identifier resolved to.

**Phase A.** `commit_intent` is appended, with its tree hash read directly
out of the payload's own `tree` line. The payload is the unsigned commit
object the harness's own git already built; its tree is not a claim to be
checked against a second source, it is the exact bytes about to be signed, so
there is nothing to derive independently and nothing for it to disagree with.

**Phase B.** gitsign runs **inside the core process**, with the same
discipline ADR-0031 built: trust anchors fetched fresh for this call
(decision 2), a child environment built from nothing with no credential
cache reachable (decision 3, E8), the generated-and-discarded CT-log key
(decision 5), the Rekor entry found by searching for the artifact hash
rather than parsed from output (decision 6), skew widening a certificate's
window and never a credential's (decision 7).

**Phase C.** The core now holds the payload and the CMS signature it just
produced. Git's construction of a signed commit object from those two pieces
is fixed and public, so the core computes the resulting commit SHA itself and
appends `commit_recorded` — referencing the intent, carrying the Rekor
entry — in the same call, without a callback from the harness's local git.
It is signed, not landed; section 6 states what that leaves open.

A caller of the client is never handed a credential, a cache, or a private
key at any point in this chain — signing custody stays exactly where E8 puts
it, inside the core's own gitsign invocation, one process removed further
from the harness than before, not one process closer to it.

### 5. The observed tool call is a precondition, never a phase, and never a tree source

Section 1's hook fires when the model asks for a `git commit` — commonly as
one half of a single Bash call that also stages the change
(`git add … && git commit …`), so at the moment the core's traffic relay sees
that request, nothing may be staged yet, and any snapshot taken then would be
of the working tree, not of the index `git commit` is about to write.
Treating that moment as Phase A, or a snapshot taken then as
`commit_intent`'s tree hash, is wrong on the ordinary path, not only the
adversarial one.

So the tool call the hook injects an identifier for is exactly what decision
4's first gate checks and nothing more: proof that a specific, observed
request authorises whatever payload later arrives claiming it. Phase A does
not happen until decision 4's call does, and its tree hash is never anything
but the payload's own. The flight recorder's wider per-step working-tree
snapshots — taken for the run's timeline, independent of this decision —
remain a witness an operator or a later audit can read; they are not
consulted by, and do not gate, anything in this section.

### 6. Signed is recorded; landed is observed; the two are never conflated

Git writes an object before it moves a ref, and its own single-writer
serialization can refuse the ref update after signing has already happened
(measured above): of several parallel `git commit`s sharing a repository,
only one updates the branch, and the others fail to lock the ref **after**
every one of them was signed. `commit_recorded` (Phase C, decision 4) is
appended for what decision 4's call actually signed — it states that this
content was signed, under this run's identity, with this Rekor entry. It
states nothing about whether the resulting SHA is reachable from any branch,
and this ADR does not make it start to: doc 02's schema is not extended here
to carry a landing flag, and inventing one is not this ADR's to do — any
future need to persist landing as its own ledger fact goes through doc 08's
protected-surface process (a major release, a migration attestation), the
same as any other schema change.

Until and unless that happens, whether a signed commit landed is **derived,
never assumed**: from the tool result of the `git commit` invocation
itself — which the core's traffic relay already has, including a ref-lock
failure's own text — and from asking the repository whether the SHA
`commit_recorded` names is reachable. Both are read-only checks against
evidence that already exists; neither writes a new ledger event, and a
caller that wants to know "did this land" asks the question rather than
reading it off `commit_recorded`'s presence.

REC-003's log-side sweep is unaffected by any of this: its subject is a
Rekor entry with **no** corresponding intent, and a lost ref race still
leaves `commit_recorded` on the chain regardless of whether the object is
reachable, so it is still not that case. A run that lost the ref race is
free to retry; its retry is a new tool call, a new intent, and a new
signature, and none of that requires the reconciler to notice or repair
anything.

### 7. Any refusal means git creates no commit

An unresolved tool call identifier, a trailer mismatch, an author the policy
does not admit, a Sigstore outage, or a core that cannot be reached at all
each make `gpg.x509.program` exit non-zero. Git aborts the commit before
writing a ref on every one of those paths — the same guarantee IP §6.3 already
requires of `sign_commit`, held here by the same mechanism (no local key, no
unsigned fallback, no queue), one call site further from where it was proven
before.

### 8. This is additive, not a change to the protected tool surface

`sign_commit` is unchanged and stays bound as one of IP §4's five tools; a
caller that wants the core to run `git commit` on its behalf — a
non-interactive automation, or a harness with no hooks of its own — still has
it. The interface this decision adds is git's own `gpg.x509.program` contract,
answered by the core; it is not a new or renamed MCP tool, and it defines no
new error-class vocabulary. Doc 08's protected surface 4 — MCP tool names and
their error-class vocabulary — is untouched, and this addition is exactly the
shape a minor release is allowed to carry: nothing existing is altered.

## Alternatives considered

- **Keep `sign_commit` running `git commit` in a mounted repository, as the
  only path.** This is what forced ADR-0046's refuse-and-redirect hook to
  exist in the first place, and the 2026-09-08 measurement is what that hook
  costs left unenforced: a tool an agent must remember to call instead of the
  `git commit` it already reaches for is attributed work nobody does. It also
  does not fit a harness that gives each subagent its own working tree — each
  one would need linking into the single workspace root the core's own git
  process is confined to (ADR-0033 decision 3), one at a time, rather than
  being wherever the harness actually runs it. Keeping this as the *only*
  path was rejected; keeping it as *a* path (decision 8) was not.

- **Run gitsign on the client, with no per-signature checkpoint in the
  core.** Removes the core from the critical path entirely and is the
  simplest change to the harness. Rejected because it moves E8's discipline
  to a process the core cannot audit at the moment that matters: the
  guarantee ADR-0031 decision 3 gives today — no variable of the signing
  process reaches gitsign except a whitelist built from nothing, checked by a
  test that reflects over every struct in the path for a field that could
  hold a key — becomes a claim about a process outside this system, made by
  whoever built the client. It also widens IP §6.5's A → B window rather than
  keeping it bounded: with the core not a party to Phase B at all, the honest
  boundary of "in flight" becomes the whole client-side gitsign run, and a
  compromised client is under no obligation to contact the core for a check
  it is never forced to satisfy.

- **Match a commit to its agent by message or command text.** Measured above
  to misattribute: it fails for `-F`, for `--amend`, for editor-composed
  messages, and for any two agents committing with the identical text — which
  is common — and one trial produced a false match from unrelated process
  argv. Rejected as the join for a claim this system signs.

- **Use the harness's session identifier alone.** Measured to be shared by
  the main agent and every one of its subagents, so it cannot tell apart the
  identities most likely to commit at the same moment — exactly the ambiguity
  IP §6.9's trailer-spoofing concern already treats as unacceptable, arriving
  here from the attribution side instead of the verification side.

## Consequences

- **New tests are implied**, all failure-injection or property-shaped in IP
  §2's sense: the tool call cross-check refuses a forged identifier and a
  missing one before any signing attempt; N parallel, byte-identical
  `git commit` invocations in one repository each attribute to their own run
  even though at most one becomes reachable from a branch, and the ledger
  holds a `commit_recorded` for each one that was actually signed, with
  reachability derived per section 6 rather than assumed; a payload whose
  trailers do not match what step 2 rendered for the same tool call is
  refused before Phase A; a payload whose author does not satisfy the
  configured policy is refused (I6, unchanged in substance); killing the
  core, the signing client, or Sigstore at each point in decision 4's call
  leaves no signed object bearing this run's trailers, asserted the same way
  ADR-0031/0033 already assert it — by enumerating repository objects, not by
  reading HEAD; and a `commit_intent` whose tool call never reaches
  decision 4's call at all still expires through the existing reconciler
  window (ADR-0035) exactly as it does today, so the two paths do not need
  to agree about anything new.

- **What the core no longer independently derives, and does not need to.**
  ADR-0033 decision 2's inline `write-tree`-and-compare existed to check a
  caller's CLAIM about which tree it intended to commit against the index's
  reality — a check that made sense because the core built the commit from a
  `repo`/`staged_ref` argument pair. Here there is no such claim to check:
  the payload IS the commit the harness's own git already built, so Phase A's
  tree hash is read, not verified against a second source. What the core
  still does not do is watch the harness stage anything, or form any opinion
  on whether the staged content is what the agent meant to commit — the same
  scope `sign_commit` always had; signing has never vouched for intent, only
  for identity and integrity. `repo` is not re-derived at commit time either:
  it is the one fact ADR-0046 mechanism 1 already establishes once per
  session, from the main worktree's own git remote, not from a
  caller-supplied string — reused here rather than asked again.

- **`sign_commit` and the workspace-linking it depends on (ADR-0046
  mechanism 1) are unaffected and keep working.** Doc 02's schema is
  unchanged — no `schema_version` bump, no migration attestation — because
  this path writes the same `commit_intent` and `commit_recorded` events,
  with the same fields, from a different call site.

- **ADR-0046's refuse-and-redirect hook (mechanism 2) is superseded for a
  harness that supports this path.** A plain `git commit` is no longer
  refused, because it is now the attributed path rather than an escape from
  one. ADR-0046's branch gate (mechanism 3, requiring a merge commit to keep
  a signature reachable) and ADR-0028's author gate are unaffected and keep
  doing exactly what they did.

- **The core now has to be reachable synchronously from inside every
  `git commit` a harness makes this way, not only from inside `sign_commit`
  calls.** That is the same dependency ADR-0031 already created for
  `sign_commit`'s own gitsign subprocess, extended to a second call site
  rather than a new kind of dependency; an unreachable core means the commit
  fails to be created (decision 7), which is IP §6.3 held, seen from a place
  an operator has not had to watch before.

- **Exit cost.** Moderate to high, and asymmetric. Reversing this decision
  means reinstating the refuse-and-redirect hook and going back to requiring
  an explicit tool call for every attributed commit — not merely a code
  revert, but a return to the exact adoption failure this ADR exists to fix,
  since that failure was measured, not hypothesized. What is cheap to reverse
  is the call site: the event schema is untouched, `sign_commit` never
  stopped working, and nothing already signed depends on which process
  invoked gitsign. What would be more expensive to reverse is decision 4's
  ordering itself: once Phase A's tree hash is read from the payload rather
  than derived by the core's own `write-tree`, a later design that went back
  to requiring a `repo`/`staged_ref` argument pair would need every
  `commit_intent` written this way treated as a historical exception. Section
  6's rule stays true either way: landing was never read off
  `commit_recorded`, so there is nothing about reversing this decision that
  would let a later reader start doing so retroactively.

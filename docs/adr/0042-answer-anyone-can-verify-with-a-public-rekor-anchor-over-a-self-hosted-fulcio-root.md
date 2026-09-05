# ADR-0042: Answer "anyone can verify" with a public Rekor anchor over a self-hosted Fulcio root, and record that a public Fulcio root cannot issue this project's identities

- Status: accepted
- Date: 2026-09-03
- Accepted: 2026-09-05
- Deciders: Mike

## Context

RM-080 (#117) gives `innsegl init` two questions to put to an adopter. The
first is *who must be able to verify?*, and it offered two answers:

| answer | trust root | what leaves the deployment |
|---|---|---|
| only us | self-hosted Fulcio and Rekor (ADR-0010's default) | nothing |
| anyone | public Sigstore | certificate, timestamp, log index |

Implementing that command established that the second answer, as worded, is not
reachable. This ADR records why, what is reachable instead, and what an outside
party must take on faith under each arrangement.

### What a public Fulcio root will not issue

ADR-0010 surveyed public Fulcio's issuer allowlist on 2026-08-28: no entry has
issuer type `spiffe`, and every entry's `spiffeTrustDomain` field is empty. The
one `spiffe`-typed entry ever added, `allow.pub`, serves an unrelated OCI
registry. Sigstore's code still supports the type — `IssuerTypeSpiffe` at
`pkg/config/config.go:438`, validated at `:471–478` — so this is policy, not
capability, and it is policy this project does not control.

A public root therefore cannot issue a certificate bearing
`spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}`, the identity
grammar of IP §1 and doc 02 §5.

### What the verifier requires — narrower than it first appears

It would be convenient to stop there, but the verifier's actual requirement is
looser and the difference changes the options.

`internal/verify`'s `checkIdentity` requires the `Agent-Identity` trailer to be
byte-identical to the certificate's URI SAN. `DiffIdentity` returns early on
string equality, before parsing anything. The SPIFFE grammar is used to produce
a readable segment-by-segment diff when the two differ, and to cross-check
`Agent-Run` and `Agent-Task` against the identity — not as a condition of
admission.

Public Fulcio does issue certificates carrying URI SANs; a GitHub Actions or
GitLab CI workload certificate names the workflow and the ref. Such a
certificate satisfies `checkIdentity`.

It satisfies it **vacuously**, which is the reason this is not the answer.
Measured against `internal/verify`: with a non-SPIFFE URI SAN, bogus
`Agent-Run` and `Agent-Task` trailers are not caught, because
`Claim.disagreesWith` returns "no disagreement" for any identity it cannot
parse into named segments. Two of the three trailers go unchecked and the
commit is reported VERIFIED. That defect is RM-091 (#137); it is unreachable
under the shipped configuration, because every identity self-hosted Fulcio
issues is SPIFFE-shaped, and it becomes reachable the moment a non-SPIFFE URI
SAN is admitted.

### What the public transparency log will accept

The remaining possibility is to keep the self-hosted Fulcio root and anchor in
the *public* Rekor log. That depends on whether public Rekor validates who
issued a submitted certificate. It does not, established by reading
`sigstore/rekor` at `main` on 2026-09-03:

- **`pkg/types/hashedrekord/v0.0.1/entry.go`, `validate()`** ends at
  `sigObj.Verify(nil, keyObj, options.WithDigest(decoded),
  options.WithCryptoSignerOpts(alg))`. There is no `x509.Verify` call, no
  certificate pool, and no issuer check anywhere in the function.
- **`pkg/pki/x509/x509.go`, `Signature.Verify`** takes the public key directly
  off a submission carrying a single certificate (`case key.cert != nil: p =
  key.cert.c.PublicKey`), so `verifyCertChain` is not reached at all in that
  case.
- **`verifyCertChain`** returns `nil` immediately for a chain of length one,
  and otherwise builds its root pool from `certChain[len(certChain)-1]` — the
  last certificate *of the submission itself*. It establishes that what was
  submitted is internally consistent, never that it descends from a known root.
- The production manifest for `rekor.sigstore.dev` configures Trillian, Redis,
  KMS and sharding. No CA or issuer restriction exists to configure.

Adjacent and high-volume: since Cosign 2.0, `cosign sign --key` uploads to the
public log by default — bare user keys, no CA anywhere — so material Fulcio
never touched enters that log routinely. Client-side policy is not a blocker
either: cosign uploads bring-your-own-PKI signatures by default, gated by a
skippable prompt rather than a refusal.

**Not established.** No already-published entry in the public log bearing a
foreign CA's certificate was located and cited. The source finding above does
not rest on one, and this is recorded rather than papered over.

## What the three arrangements actually differ in

The question "who must be able to verify?" conflates two things that separate
cleanly once the measurements are in: whether an outside party must trust this
deployment about **when something happened and whether it exists**, and whether
they must trust it about **whose identity signed**.

| | existence and time | identity | SPIFFE identity issuable |
|---|---|---|---|
| self-hosted Fulcio and Rekor | the deployment's own log | the deployment's own root | yes |
| **self-hosted Fulcio, public Rekor** | **independent** | the deployment's own root | yes |
| public Fulcio and Rekor | independent | independent | no |

The middle row removes the operator's ability to backdate an entry, delete one,
or present a history the log does not corroborate. Under doc 04's model that is
the substantial threat: an operator of an append-only ledger who also operates
the log that witnesses it is attesting to their own history. The public log had
roughly 2.58 billion entries when it was read on 2026-09-03, and is monitored
by parties with no relationship to this project.

It does not make identity independent. That still rests on the deployment's own
Fulcio root.

## Accepted, and one thing the decision was not

Accepted on 2026-09-05. One proposal was raised and declined during that
discussion, recorded here so it is not raised again: encrypting what reaches
the public log, with a local record acting as the key.

There is nothing there to encrypt. A segment anchor uploads a `hashedrekord` —
a SHA-256 and a signature over it, not content. A hash is already opaque: it
can be checked against, and nothing can be read out of it.

The arrangement that proposal describes — opaque in public, readable only
locally — is what **ADR-0041** already does, one layer up. The certificate
carries `spiffe://…/agent/4799d6f0/01a32f1e/run-…`; the ledger row carries
`agent_type` and `task_ref` in clear. Adding encryption below that would cost a
key that must outlive the log, and would make the entry uncheckable by an
outsider — which is the whole reason for putting it there.

## Decision

**"Anyone" means a public Rekor anchor over a self-hosted Fulcio root.** The
deployment keeps ADR-0010's self-hosted Fulcio and its SPIFFE identities,
signs as it does today, and submits the log entry to `rekor.sigstore.dev`
instead of to its own Rekor. The deployment publishes its Fulcio root
certificate so a stranger can check the chain.

**A public Fulcio root is not offered.** `innsegl init` refuses
`-trust-root public` and cites this ADR. The two answers #117 puts to an
adopter become *only us* (both self-hosted) and *anyone* (public anchor,
published root); neither answer is public Fulcio.

**A public-Fulcio email identity is rejected**, not deferred. It would publish
an operator's email address in an immutable public log, which runs directly
against RM-079 (#116) and ADR-0041, and against the direction taken in RM-081
(#118). If it is ever revisited it needs its own ADR arguing that reversal.

## Consequences

**What an outside party can do that they could not before.** Fetch the entry
from a log this project does not run, check its inclusion proof against a
witness this project does not operate, and establish that the commit existed at
that time. Independently of the deployment, and of its operator's good faith.

**What they still need from us.** The Fulcio root certificate, published and
reachable; the entry's UUID or log index; and a verifier pointed at that root
rather than the public Sigstore trust bundle — `cosign verify-blob
--certificate-chain <root>`, or a bundle built with `cosign trusted-root
create`. Sigstore documents this as bring-your-own-PKI, so it is a supported
path and not a workaround.

**What is published, and it is permanent.** The certificate, its timestamp, and
the log index. The certificate carries the SPIFFE ID — and under ADR-0041 that
ID's `{agent_type}` and `{task_id}` are already pseudonymised, so what reaches
the public log is an opaque identity resolvable only through the deployment's
own ledger. The two decisions interlock, and this one is materially worse
without that one. Rekor is append-only: nothing submitted can be withdrawn, and
a deployment that turns this on should understand it as irreversible for every
entry it makes.

**Distributing the root becomes an operational obligation.** A verification
story that depends on a certificate nobody can fetch is not a verification
story. Where the root is published, how its rotation is handled, and what a
verifier does across a rotation are not settled by this ADR.

**RM-091 (#137) stays latent under this decision** — no non-SPIFFE URI SAN
becomes admissible — and should still be fixed. A check that cannot fail on
input it does not understand is reporting a verdict it has not established, and
this project treats that as a defect wherever it appears.

**doc 05's topology gains a case it does not describe:** a deployment whose
Rekor is not its own. The twelve rows of §1 assume the local instance.

## What #117 and the specifications must be given

Recommendations, not amendments. The eight numbered documents are normative and
this ADR does not edit them.

- **#117**'s first question is reworded to the two answers this ADR names, and
  its table's "anyone → public Sigstore" row is struck. The consequence column
  for the new *anyone* answer reads: certificate, timestamp and pseudonymous
  identity enter a permanent public log; the deployment must publish its root.
- **doc 05** should describe the public-anchor topology, or say that it is out
  of scope for the reference deployment.
- **doc 07** has no test IDs for any of this. An anchor that reaches a log this
  project does not control cannot be exercised in CI the way SEG-*'s local
  Rekor is, and what can honestly be tested — that the client is configured
  against the public endpoint, that the published root verifies a locally
  produced certificate — is a smaller claim than the arrangement makes. Naming
  those IDs is a human's call.
- **ADR-0010** is not superseded. Self-hosted Fulcio remains the shipped
  default and its reasoning is untouched; this ADR decides only what the
  *anchor* is when an adopter answers "anyone".

## References

- ADR-0010 — self-hosted Sigstore is the shipped default.
- ADR-0041 — pseudonymised `{agent_type}` and `{task_id}` in the SPIFFE ID.
- RM-080 (#117), and the implementation in #135.
- RM-088 (#133) — the measurements this ADR is built on.
- RM-091 (#137) — `Agent-Run` and `Agent-Task` unchecked on a non-SPIFFE SAN.
- IP §1 check 3; doc 02 §5's SPIFFE grammar; doc 04 §2; doc 05 §1.

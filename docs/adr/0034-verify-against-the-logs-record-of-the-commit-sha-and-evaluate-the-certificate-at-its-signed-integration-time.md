# ADR-0034: Verify against the log's record of the commit SHA, and evaluate the certificate at the log's signed integration time

- Status: accepted
- Date: 2026-08-30
- Deciders: Mike
- Implements: IP §1 (the three checks), IP §6.8, IP §6.9, invariants I5 and I6,
  RM-037 (#45); test IDs VER-001..VER-006
- Builds on: [ADR-0009](0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md),
  [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md),
  [ADR-0028](0028-place-commit-trailers-in-process-and-refuse-the-messages-git-places-ambiguously.md),
  [ADR-0029](0029-compose-self-hosted-sigstore-as-its-own-project-joined-to-spires-oidc-network.md),
  [ADR-0031](0031-orchestrate-released-gitsign-through-git-commit-and-configure-around-the-absent-ct-log.md)

## Context

I5 is the reason this project exists:

> Verification never trusts this system. Every attribution claim must be
> checkable against Fulcio/Rekor by a third party with no access to our
> database.

Everything before this issue built machinery. This is the thing a stranger runs
to check our work without trusting us, and doc 06 §4.1 fixes what it must
report: three named checks, each with its own tri-state result, never collapsed
— Fulcio certificate chain valid; Rekor inclusion proven, with the log index
shown; trailer matches certificate identity, both values shown side by side and
the differing segment identified on a mismatch.

Six facts constrain how that can be built, and four of them are properties of
software this project does not own.

**1. Fulcio certificates live for ten minutes.** A verifier that evaluated the
validity window against its own clock would report every commit older than ten
minutes as failed. VER-004 is the case that makes the whole system work a year
later, and it is only satisfiable if the window is evaluated at some moment in
the past that the verifier has a reason to believe.

**2. There is no CT log, so there is no SCT** (ADR-0029 decision 5). ADR-0031
measured the consequence for anything built on cosign: `gitsign verify`
constructs a certificate verifier *before* it consults `--insecure-ignore-sct`,
that constructor calls `cosign.GetCTLogPubs`, and `GetCTLogPubs` errors on an
empty key set and otherwise fetches keys from the public-good TUF mirror.
RM-032 worked around it with `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` and a key
generated and discarded. Its Consequences section then said, in terms:

> `Signer.Verify` is not the verifier that proves I5. It shares this wrapper's
> configuration, including its trust root, so it trusts things RM-037's
> `innsegl verify` must not. RM-037 must build its own trust material from the
> endpoints an outsider can reach, and should treat decision 5 as the thing to
> copy and decision 2 as the thing to redo.

**3. IP §7 forbids reimplementing Sigstore's crypto**, and threat model §5.4
warns about hand-written ASN.1. The commit's signature is a CMS SignedData in
a `gpgsig` header. Reading the certificate out of it is a structure walk this
repository already has one of (`internal/signing.certificatesFromSignature`);
*verifying* it would be a second CMS implementation.

**4. gitsign's online mode logs a hashedrekord whose artifact is the COMMIT
SHA** (ADR-0031 decision 6). That is a much stronger fact than it looks. An
entry exists for the exact object that was signed and for no other, because
altering one byte of a commit — a trailer, the tree, the parent — changes its
SHA.

**5. RM-031 deliberately exported no trailer parser**, and said why: its
classifier is a *writer's*, narrower than git's on purpose, because a writer
that mistakes prose for a trailer merges its claim into a paragraph git will
not read. Every one of its asymmetries points at "refuse, and place the claim
somewhere unambiguous". A verifier's point the other way.

**6. VER-001 asks for something stronger than "does not query the database".**
It asks for the three checks to pass with the database *unreachable*.

## Decision

**Eight decisions, all in `internal/verify/` and `cmd/innsegl/verify.go`.**

### 1. The verifier's whole input is a repository, a revision and two URLs

`verify.Config` carries a Fulcio URL, a Rekor URL, an optional expected OIDC
issuer, a git binary and a skew bound. There is no ledger, no DSN, and
`innsegl verify` has no flag with which to be given one — `--help` says so, and
a test asserts the absence.

I5 is then a property of the import graph rather than of the current code path:
`internal/verify` transitively imports no `internal/ledger`, no `internal/mcp`,
no `database/sql` and no `pgx`. VER-001 asserts that from `go list -deps` and
names the one allowance it found — `database/sql/driver` is present because
`github.com/google/uuid` implements `driver.Valuer`, and it is a package of
interface types that cannot open a socket.

The empirical half runs the shipped binary inside a container attached only to
the Sigstore stack's published network, with a real Postgres running on a
network of its own. The same container invocation first shows there is no route
to that Postgres by address and no name to resolve, and then verifies. A
control probe from the Postgres network shows the database IS reachable from
there, so "unreachable" is not satisfied by a database that is merely down.

### 2. The certificate's validity window is evaluated at the log's SIGNED integration time

Check 1 has two halves and they fail differently, so they are reported as
separate evidence:

- **the path** — does the leaf chain to the root this deployment's Fulcio
  publishes? Time-independent, and evaluated at the leaf's own `NotBefore` so
  that an expired certificate is not reported as a chain problem;
- **the window** — was the certificate live at the moment the transparency log
  integrated the entry?

If the log did not sign an integration time, there is no honest answer to the
second question, and check 1 is **unavailable**. It is never evaluated against
the wall clock. That single rule is what makes VER-004 pass and it is the
reason there is no fallback: a fallback to `now` would fail every historical
commit, which is the failure mode IP §6.8 exists to prevent.

### 3. The skew bound is 60 seconds, it is the verifier's alone, and it is not a flag

`verify.DefaultSkew` is `signing.DefaultSkew`, and a test holds the two
together. ADR-0031 decision 7 established the asymmetry and it is unchanged
here: a verifier reading somebody else's certificate must forgive clock
disagreement; a *signer* has no such licence, because widening a credential's
window by a minute is extending its TTL by a minute, which IP §6.2 forbids.

It is deliberately not exposed on the command line. A verifier whose tolerance
can be widened by its caller has no bound at all. VER-005 tests both sides at
the bound and at the bound plus one second.

### 4. The CMS signature is not re-verified; the log's record of the commit SHA stands in its place

This verifier reads the certificate out of the `gpgsig` header and never checks
the CMS signature over the commit object. What it does instead, as check 2, is
require the transparency log to hold an entry whose

- artifact is `sha256` of **this** commit's SHA,
- public key is byte-identical to **this** commit's certificate, and
- signature over that artifact verifies under that certificate's public key,
  checked with `crypto/ecdsa` and `crypto/rsa` rather than taken from Rekor's
  own acceptance,

and whose inclusion path reaches a root under a checkpoint signed by the log's
key — reusing `segment.InclusionProof.Verify` rather than writing a second
Merkle implementation (threat model §5.4).

That is not a weaker assertion. It is a third party's record that the holder of
that certificate's private key signed **this object and no other**, and it is
made of standard-library primitives instead of a second CMS reader. It is also
what makes VER-003 bite: a squashed or rebased commit is a new object with a
new SHA, so the log holds nothing for it and check 2 fails — "the signature does
not cover the new object", observed through the log rather than asserted.

The log answering "no entry" is FAILED. The log not answering is UNAVAILABLE.

### 5. X.509 path validation is `crypto/x509`'s, which is how the absent CT log costs nothing

Because cosign is never constructed, `cosign.GetCTLogPubs` is never reached, no
TUF mirror is contacted, and no placeholder CT key is needed. The verifier
fetches Fulcio's root over HTTP and validates the chain with
`x509.Certificate.Verify` and a code-signing EKU.

The absence of an SCT is then reported as an explicit evidence line on check 1
rather than passed over: *"none — this deployment operates no certificate
transparency log (ADR-0029 decision 5); the transparency this system offers is
the Rekor entry in check 2"*. Silence there would read as "checked and fine".

### 6. The signed entry timestamp is verified, and its canonicalization is written out

Decision 2 rests on `integratedTime`, and a timestamp taken from a response
body is a number an attacker who controls the response can choose. Rekor signs
`{body, integratedTime, logID, logIndex}` as the *signed entry timestamp*, and
this verifier checks that signature under the log's key before it will use the
value.

The canonicalization is RFC 8785's. For an object of four members of these
types it is one `fmt.Sprintf` — the members sorted (`body`, `integratedTime`,
`logID`, `logIndex`), no whitespace — so a canonicalizer dependency is not
taken for one object shape. An entry with no signed timestamp is not a failure:
check 2 still passes on the inclusion proof, and check 1 becomes *unavailable*,
which is the honest tri-state.

### 7. The verifier has its own trailer reader, permissive where the writer is strict

`ReadClaim` scans every line of the message, accepts any case, any whitespace
before the separator, and a trailer anywhere in the message — including past a
`---` divider, where git itself would not look. If a claim is present in a form
any reader could take as a claim, the verifier must SEE it and judge it; a
verifier that reported `Agent-Identity : spiffe://…` as "no claim" would be a
forger's best outcome.

It is strict in exactly one place, and that strictness is also a verifier's:
two `Agent-Identity` trailers are refused rather than resolved, because picking
one is choosing which claim to check (IP §6.9).

On a mismatch, `DiffIdentity` names the segment of the SPIFFE grammar that
differs — `trust-domain`, `agent-type`, `task-id`, `run-id` — with both values.
"Mismatch" is not a finding a reader can act on.

### 8. Four states, and four exit statuses

Doc 06 §4.1's rollup is implemented as written: any check failing makes the
verdict `failed`; any check erroring makes it `unavailable`, never `verified`.
There is no cache anywhere in the package, so doc 06 anti-pattern 1 — a
"verified" rendered from cache while the live check errored — is unreachable by
construction rather than by discipline.

A fourth verdict, `unattributed`, describes the COMMIT and not a check: a
commit with neither a signature nor an `Agent-*` trailer makes no attribution
claim, so **no checks are run and none are reported**. VER-006 requires that
state to be distinct from failed-verification and doc 06 anti-pattern 2 is the
collapse it refuses; E7 is the reason it is not a failure, since every commit
from before adoption is one. A commit that CLAIMS an identity and carries no
signature is not unattributed — it is a claim nothing proves, and it fails.

`innsegl verify` maps the four onto four exit statuses (0, 3, 4, 5) plus a
fifth for a request it could not act on (6), so a script can distinguish them
without parsing prose. An unrecognised verdict exits 6 rather than 0.

## Alternatives considered

**Shell out to the released `gitsign verify`.** The obvious reading of IP §7,
and it is what `Signer.Verify` does on the signing side. Rejected on ADR-0031's
own advice: it inherits the CT-log problem in full — a verifier that reaches
`tuf-repo-cdn.sigstore.dev` for keys it will not use is the opposite of a
verifier that trusts nothing — and it would make `innsegl verify` carry the
signer's configuration, including its trust root, which is the thing RM-037 was
told to redo. It would also make gitsign a runtime dependency of the artifact
we hand to strangers.

**Verify the CMS signature in process.** The most direct reading of "the
signature covers the object". Rejected under IP §7 ("do not reimplement their
crypto") and threat model §5.4. Decision 4's substitute is checkable with
`crypto/ecdsa` and is a stronger statement — it is a third party's record
rather than our own arithmetic — and the one thing it does not cover, a commit
whose `gpgsig` was replaced with a certificate that never signed it, is caught
by the byte-identity comparison between the entry's certificate and the
commit's.

**Evaluate the certificate at `now`, and accept that historical commits need a
timestamp source later.** One line shorter and wrong on the day it ships: every
commit older than ten minutes reports FAILED, which trains the reader to ignore
the verdict.

**Trust `integratedTime` without checking the signed entry timestamp.** Rekor
returns it and it is almost always right. Rejected because decision 2 makes the
whole certificate check rest on that number: an unverified timestamp is a
verifier that can be talked into accepting an expired certificate by anyone who
can answer for the log, which is exactly the party I5 says not to trust.

**Pin Fulcio's root and Rekor's key from files this project ships.** Stronger
against a compromised endpoint, and wrong for the artifact this is: a stranger
handed a binary with our trust root baked in is trusting us, not the log. The
endpoints are fetched, and the boundary is stated in Consequences.

**Reuse `internal/signing.findRekorEntry`.** It does most of the search. It is
unexported, it lives in a file this issue does not own, and exporting it would
tie the verifier's reader to the signer's — the coupling ADR-0031's
Consequences warned about. The verifier's reader additionally needs the entry's
timestamp, its signed entry timestamp and its inclusion proof, none of which
that function returns.

**Reuse `internal/segment.RekorClient` wholesale.** It is an anchor *writer*
(ADR-0009) with no search method and no SET reader. What IS reused is the half
that matters and that threat model §5.4 names: `InclusionProof.Verify` and
`ParseLogPublicKey`. There is exactly one Merkle verifier in this repository
and this package does not add a second.

**Expose `--skew`.** Convenient for a deployment with bad clocks. Rejected: see
decision 3.

**Report `unattributed` as a fourth check state rather than as a verdict.**
Would keep the verdict enumeration at three. Rejected because doc 06 §4.1's
three states are the outcomes of a check that RAN, and a commit that makes no
claim has nothing to check — three checks reported as "not applicable" is a
panel that has to be read twice.

## Consequences

**The verifier trusts the two endpoints it is given, on first use, and this is
the boundary worth naming.** Fulcio's root and Rekor's log key are fetched over
HTTP from the URLs the caller supplies. That is what a third party actually
has, and a pinned key has to come from somewhere the first time — but it means
`innsegl verify` against a URL an attacker controls proves nothing. **The next
serious step for this package is `--rekor-key` and `--fulcio-root` accepting
pinned files, with the fetch as the fallback and the report saying which was
used.** Not v0.1's, and not this issue's to invent quietly.

**A second CMS certificate reader now exists in this repository.** It is the
same structure walk as `internal/signing`'s, in a package that may not import
it. Threat model §5.4's concern stands and is now doubled; the mitigation is
that both stop at `SignedData.certificates` and hand the DER to `crypto/x509`,
and that this one is exercised against real gitsign output in VER-001 as well
as against seven hand-built malformations. Consolidating them means one of the
two packages importing the other, which is a coupling neither should have.

**`git` is a runtime dependency of the verifier; `gitsign` is not.** A third
party needs git, which they have if they have the repository, and two URLs.
Nothing else.

**`register.sh` is now reimplemented four times.** ADR-0031 recorded the third
and asked for `deploy/compose/spire/register.sh` to be parameterised by project
and container name. It has not been, so `internal/verify`'s harness derives the
same five selectors again. `deploy/` is not this issue's to change. The request
is repeated here, and it is the same one: without that entry the OIDC provider
holds no SVID, `GET /keys` answers HTTP 500, and Fulcio refuses every JWT-SVID
with "There was an error processing the identity token" — a message that names
neither the provider nor the missing entry.

**`sigstore-testscope.yml` is now used by a second suite and is still under
`internal/signing/testdata/`.** ADR-0031 said moving it to `deploy/compose/`
"should happen the moment a second suite needs it". This is that moment;
`deploy/` is not this issue's to change, so `internal/verify`'s harness
references it where it lives. The move is a rename and a two-line edit in two
harnesses.

**doc 07 has no test ID for the signed entry timestamp.** VER-004 and VER-005
both depend on it — they are about a window evaluated at a moment, and decision
6 is what makes the moment trustworthy — but "the log's signature over the
integration time is checked, and an entry without one leaves the window
unproven" is unnumbered. Proposed: **VER-007** (U) the integration time is used
only when the log has signed it.

**`scripts/coverage-floors.sh` has no line floor for `internal/verify`.** The
branch floor applies — `scripts/branch-coverage.sh` already lists the package
and stops reporting PENDING with this change — but the statement floor does
not, so a later refactor could delete tests without tripping the line gate.
`scripts/` is not this issue's to change; the entry to add is
`"internal/verify 95"`.

**The three checks are computed but not yet rendered by the dashboard.** Doc 06
§4.1's panel consumes exactly this `Report`, and `RenderJSON` is its wire
format. Nothing in Phase 4 has to recompute a verdict, and nothing in Phase 4
may: a dashboard that reached its own conclusion from the ledger would be doc
06 anti-pattern 1 with extra steps.

**Exit cost.** Low. The package produces a report and consumes two public HTTP
APIs; nothing persists, nothing is written, and no artifact already signed
depends on this verifier existing. The one decision that would be expensive to
reverse is 4, and only because it inherits ADR-0031 decision 6's choice of
online mode: a verifier written against `hashedrekord`-keyed-on-commit-SHA is
the verifier this project ships, and switching gitsign to offline mode would
change what every future entry is keyed on.

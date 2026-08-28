# ADR-0010: Ship self-hosted Fulcio/Rekor as the default, and demote public Sigstore to "where an accepted issuer already exists"

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike
- Supersedes in part: [ADR-0002](0002-public-sigstore-default.md) (its *Decision* only; its
  *Context* and its statement of the metadata tradeoff stand unchanged)

## Context

ADR-0002 made public Sigstore the default and the reference deployment, and
carried one explicit blocker: *"the public-good Fulcio instance accepts OIDC
tokens only from issuers on its configured allowlist. Whether a project-operated
SPIRE OIDC discovery provider (`oidc.innsegl.dev`) can be added, and by what
process, must be verified against current Sigstore federation documentation
before Phase 3 — measured, not assumed."* Doc 05 §3 carries the same instruction
as an operational one: do not stand up `oidc.` before the answer is known.

RM-016 (#24) is that measurement. The question has two halves — *will public
Fulcio accept a token from `oidc.innsegl.dev`* and *by what process* — and the
architecture that depends on the answer is doc 01 §1 component 3: JWT-SVID
(audience-bound to Sigstore) → `SIGSTORE_ID_TOKEN` → Fulcio short-lived cert →
signed commit → Rekor. The SPIFFE ID in that certificate is what makes a commit
attributable to one agent run; that is the whole of I1 and half of I5.

Doc 01 §7 is the boundary on any answer: Sigstore is used "as released upstream
… do not fork, do not reimplement their crypto. Configuration and orchestration
only." Nothing below proposes changing Fulcio. §7 also already requires that
*both* deployments be supported by configuration — so what is in question here
is only which one is the shipped default, never whether the other exists.

### What was measured

All figures below were taken on **2026-08-28** against `sigstore/fulcio` at
`main` = `ae51cd5b978de4389588cbb20cb08845e4e8b98c` (committed 2026-08-26) and
against the live production instance. Sources are cited so the measurement can
be repeated.

**1 — The live allowlist contains no SPIFFE issuer at all.**
`GET https://fulcio.sigstore.dev/api/v2/configuration` (fetched
`2026-08-28T18:41:34Z`, per the response `Date` header) returns 27 issuers:
13 `ci-provider`, 7 `kubernetes`, 6 `email`, 1 `chainguard-identity`. **Zero of
type `spiffe`.** Every entry's `spiffeTrustDomain` field is the empty string.
Every accepted issuer belongs to a large multi-tenant platform — Google,
GitHub Actions, GitLab (3 instances), CircleCI, Buildkite, Buddy (4), Codefresh,
Chainguard, Eclipse Foundation, IBM, Kaggle, hello.coop, and the AWS/Azure/GCP
managed-Kubernetes meta-issuers. There is no single-project, self-operated
issuer on the list.

**2 — That endpoint is driven by a file in the public repo, so a PR is
genuinely the mechanism.** `config/identity/config.yaml` at that commit declares
31 issuer keys. The live list is *exactly* those 31 minus the 4 carrying
`environment: staging` (`dev-oidc`, `psd-oidc` and `stage-oidc.buddyusercontent.com`,
and `oauth2.sigstage.dev/auth`). Set difference in the other direction is empty.
The repo file is therefore authoritative for the production allowlist, and the
allowlist is a public, reviewable artifact — which is the good news in this ADR.

**3 — The SPIFFE federation enrollment process was formally abandoned five
months ago.** `sigstore/fulcio#122`, "SPIFFE ID Federation Planning" — the issue
that proposed precisely what ADR-0002's first fallback assumes exists — was
**closed as `not_planned` on 2026-03-09** by Sigstore maintainer `Hayden-IO`. Its
body had proposed: *"Let's start manual. We can use a pull-request based,
'gitops-style' enrollment process… Users can open a pull request (or maybe issue
first?) requesting that we add their domain to our production config."* Four
comments over four years, then closed unimplemented.

**4 — The machinery that implemented it was deleted in 2024.** Commit
`6db2b36cc52c2322bd6f258876576fb5a03db043` (2024-07-17, PR #1736, *"Removes
identity providers federation"*) deleted the entire `federation/` directory —
15 per-issuer config files and a README whose text was: *"We'll happily accept
new entries here in the form of a pull request! Open one up with your endpoint,
filling in a directory and a `config.yaml` with the following structure: `url`,
`contact`, `description`, `type: <spiffe|email>`."* That open invitation, and
the only place `spiffe` was ever named as an enrollable type, no longer exists
anywhere in the repository.

**5 — The only SPIFFE issuer the public instance ever had was removed.**
`allow.pub` (issuer `https://allow.pub`, `type: spiffe`,
`spiffe-trust-domain: allow.pub`, for the vcr.pub OCI registry) was added in
2021 via issue #228 and removed in commit
`ccd120a04de893034ce63e4ce11019304df61599` (2024-08-08, PR #1757) with the
message: *"Currently offline and inactive. Spoke offline with maintainer, may
add back at a later point."* One SPIFFE issuer, in five years, now gone.

**6 — The written acceptance policy does not have a category for us.**
`docs/new-idp-requirements.md` (last substantively changed 2024-07-29,
`03a4d86c5d8f`) recognises exactly two kinds of provider: *"`Email` — …the
user's email or the machine identity for service accounts"* and *"`Workflow` —
…systems such as CI/CD pipelines, such as GitHub Actions or GitLab CI."* SPIFFE
is not one of them. The operative bar is: *"New identity providers must
demonstrate that there is either a gap that will be filled by including this
identity provider (e.g. support for a new CI platform) or there is significant
community interest. For any newer IDP, we would like to see additional demand
for it beyond the IDP maintainer. We recognize that this adds a barrier for
smaller IDPs, but we want to make sure that Sigstore's Public Good Instance is
associated with high-quality, trusted providers."* It further requires *"MUST
maintain good uptime… SHOULD maintain an uptime requirement of `99.9%+`"* and
reserves removal for inactivity: *"If the IDP is found to be infrequently used
(e.g. a certificate issued once every few months), Sigstore reserves the right
to remove the IDP."* Innsegl at v0.1, with one operator and no adopters, is
the exact case the "beyond the IDP maintainer" sentence is written to exclude.

**7 — The process, as actually practised, is slow and platform-shaped.** The
most recent onboarding is Buddy: issue #2327 filed 2026-04-13; maintainer reply
2026-04-21 setting terms — *"To be added, you'll need to provide a mapping
between Buddy token claims and the certificate extensions… We'll then update our
staging environment, ask that you verify certificates contain the expected
values, and then we'll push the configuration to the production environment. We
also ask that you review …new-idp-requirements.md…"*; PR #2371 opened
2026-06-10; merged 2026-07-08; confirmed in production 2026-07-17. Three months
end to end, for a commercial CI platform with a customer base.

**8 — The code still supports `spiffe`; this is a policy gap, not a capability
gap.** `IssuerTypeSpiffe = "spiffe"` is live at `pkg/config/config.go:438`,
validated at `:471–478`, and `pkg/identity/spiffe/principal.go` still builds the
URI SAN from the token `sub`. Two constraints matter if this is ever revisited:
`docs/oidc.md:256` — *"The trust domain of the configuration and hostname of
`sub` must match exactly"* — and `pkg/config/config.go:555`, which refuses
wildcard SPIFFE issuers outright: *"SPIFFE meta issuers not supported"*. Note
also that #122 recorded a shape rule — *"we require that the OIDC endpoint be at
or above the same (sub)domain of the SVID. An OIDC endpoint of `foo.com` can
grant SVIDs for `bar.foo.com`, but not the other way"* — under which our planned
pairing (issuer `https://oidc.innsegl.dev`, trust domain `innsegl.dev`) is the
*disallowed* direction. Current code does not enforce that for `spiffe`, but a
future request should propose `https://innsegl.dev` as the issuer, or
`oidc.innsegl.dev` as the trust domain, rather than the pairing doc 05 §3
currently sketches.

**9 — The official documentation site would have given the wrong answer.**
`https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/` still lists,
today, under its SPIFFE heading: *"vcr.pub OCI registry (`allow.pub`)"* — an
issuer removed from the instance two years ago. Anyone answering this question
from the docs site, or from a model's training data, would have concluded that
public Fulcio accepts SPIFFE issuers. It does not. This is the clearest possible
vindication of doc 01 §2's "measure artifacts, never assert from memory," and it
is why the live `/api/v2/configuration` endpoint, not any prose, is cited above
as the primary evidence.

### The answer

**No.** Public-good Fulcio will not accept a token from `oidc.innsegl.dev` as
things stand, and ADR-0002's first fallback — "pursue issuer federation with the
Sigstore project" — is not available, because the federation process it names
was closed `not_planned` and its implementation deleted. The residual path is
the generic new-IDP process (file an issue on `sigstore/fulcio`, then a PR to
`config/identity/config.yaml`), whose written criteria we do not currently meet
and were not written with a project-operated SPIRE trust domain in mind.

Confidence is **high** on the factual half — no SPIFFE issuer is accepted today,
no SPIFFE-specific onboarding path is advertised — because that is a direct read
of the production endpoint plus the repository provably driving it. Confidence
is **medium-high**, and explicitly an inference, on "a request from us would be
declined today": nobody has asked on Innsegl's behalf. See
[the remaining unknown](#the-remaining-unknown--for-the-human) below.

## Decision

**Self-hosted Fulcio and Rekor are the shipped default and the reference
deployment.** Public Sigstore is demoted from "the default" to "a supported
configuration, available where the deployment already holds a token from an
issuer on Fulcio's published allowlist" — that is, ADR-0002's second fallback,
taken because the first does not exist.

Three things follow directly and are part of this decision:

- **`oidc.innsegl.dev` is not stood up.** Doc 05 §3's row for it is not built in
  v0.1. The SPIRE OIDC discovery provider stays internal to the deployment,
  reachable by the self-hosted Fulcio only. Nothing about the trust domain name
  `spiffe://innsegl.dev` changes; a trust domain is a name, not an endpoint.
- **The public-Sigstore path is not deleted, and its tests are not deleted.**
  Doc 01 §7 requires both be supported by configuration; the config switch stays
  a protected, tested surface exactly as ADR-0002's Consequences required. What
  changes is which value ships as the default and what the docs promise.
- **Public Sigstore is not reachable by substituting a CI token.** A deployment
  running inside GitHub Actions *could* obtain a token from
  `token.actions.githubusercontent.com`, which is allowlisted — but the Fulcio
  certificate would then attest the *workflow*, not the *run*. Identity would no
  longer equal one run equals one purpose, and the trailer-to-certificate match
  that doc 01 §6.7 requires would have nothing to match against. That is a
  different product. It is recorded here only so that nobody later mistakes it
  for the escape hatch.

## Alternatives considered

**Keep public Sigstore as the default and file the onboarding request now.**
Lost on evidence, not on preference. The federation issue is closed
`not_planned`; the generic policy asks for demand "beyond the IDP maintainer"
and a 99.9% uptime commitment, neither of which a v0.1 project with no adopters
can honestly make; and the one comparable onboarding on record took three months
for a commercial platform. Shipping a default whose viability depends on an
unfiled request to a third party, against written criteria we do not meet, is
the failure mode doc 01 §2 exists to prevent.

**Ship no default and force a choice at install.** Rejected in ADR-0002 for a
reason that still holds — OPS-004 requires a working out-of-the-box path — and
the reason is now *stronger*, not weaker: RM-012 (#20) has already demonstrated
the five-container Rekor/Trillian stack end to end, with real inclusion proofs
and tamper mutations refused, so there is a default available that is known to
work. Forcing a choice would be forcing it between one path that runs and one
that cannot be reached.

**Fork or patch Fulcio to accept our issuer.** Refused outright by doc 01 §7:
"do not fork, do not reimplement their crypto." A forked Fulcio also destroys
the only thing public Sigstore was buying — a trust root outside our control.

**Wait for Phase 3 and decide then.** Rejected because doc 05 §3 forbids
standing up `oidc.` until this is answered, E5 is blocked on it, and deferring
would leave the SPIRE and signing work built against a default that the evidence
says will not hold. Late reversal is more expensive than none.

## Consequences

**The I5 argument changes shape and must be restated honestly.** ADR-0002's
strongest claim was "a transparency log outside the operator's control." A
self-hosted Rekor is operated by the same party as the ledger, and threat model
§5 already names this: it "weakens the third-party-trust story to 'trust our two
systems instead of one.'" That sentence moves from the *Alternatives considered*
section of ADR-0002 to the description of the shipped default, and every place
the project claims non-repudiation must say which log it means. What survives
intact is the *mechanism*: a Merkle-backed append-only log with verifiable
inclusion proofs, cryptographically detecting tampering, checkable by anyone
holding the log's public key — which RM-012 proved by mutating entries and
watching verification refuse them. Detection does not depend on who runs the
log; only the "even we can't" claim does.

**Threat model §5 residual risk 2 inverts and should be re-read at the next
review trigger.** As written it says organisations for whom public metadata
exposure is a leak "must run self-hosted Fulcio/Rekor — supported, documented,
second-class only in defaults." Under this ADR self-hosted *is* the default, so
the exposure risk stops being the default posture and becomes opt-in. The risk
does not disappear — it applies to whoever turns public Sigstore on — but it is
no longer a tradeoff the project makes on a user's behalf at install time. That
is a net privacy improvement and the one clear upside here.

**A new risk arrives to replace it: log-operator concentration.** Whoever
deploys Innsegl now runs the log that attests their own agents. Documentation
must state this in the same breath as the non-repudiation claim, the way
ADR-0002 required the metadata tradeoff be stated "prominently at install time
(not buried)". The verification page and dashboard requirement from ADR-0002 —
render the log endpoint in use, so a verifier knows which trust root they are
checking — becomes more important, not less, and is now load-bearing.

**Deployment gets heavier; adoption cost rises.** The fresh-clone experience
(OPS-004) now brings up Fulcio, Rekor, Trillian and their datastore rather than
reaching for a hosted endpoint. RM-012 has already paid most of this cost — the
compose stack exists and runs in CI — so the work is packaging and documenting
it as the supported production path, not building it. Doc 05 loses the
`oidc.innsegl.dev` row's urgency and gains a self-hosted-Sigstore topology it
must describe; that is an edit for the human, not for an implementing agent.

**Nothing in the code changes shape.** Because doc 01 §7 already required both
paths behind configuration, this ADR changes a default value and a set of
promises, not an architecture. The JWT-SVID → `SIGSTORE_ID_TOKEN` → Fulcio →
Rekor chain of doc 01 §1 component 3 is unchanged; only the address of the
Fulcio and Rekor at the end of it differs, and it was always a config value.

**Exit cost, if this is ever reversed.** Low, and deliberately so. Reversal
means flipping a default and standing up `oidc.innsegl.dev` — no data migration,
because segments anchored in a self-hosted Rekor stay valid under that log's key
and a later switch only changes where *new* anchors go. Verifiers need the log
endpoint and key that were in use at the time, which the ADR-0002 consequence
about rendering the endpoint already guarantees is recorded. This is the reason
to take the reversible option now rather than block on a third party.

## What the project should do next

1. **E5 is unblocked and its default flips.** Build the signing path against the
   self-hosted pair as the primary target. The public-Sigstore configuration
   remains a tested switch; it stops being what the reference deployment uses.
2. **Do not build `oidc.innsegl.dev`.** Doc 05 §3's condition for building it —
   "only for the public-Sigstore path — Fulcio must fetch this issuer" — is not
   met by any Fulcio we can reach.
3. **Re-measure on a schedule, not on memory.** The whole of the evidence above
   is a single unauthenticated `GET` against
   `https://fulcio.sigstore.dev/api/v2/configuration`. Add it to the standing
   review triggers in threat model §6 alongside GH-001: if an issuer of type
   `spiffe` ever reappears on that list, this ADR is worth revisiting. The check
   costs one HTTP request and needs no credentials.
4. **Re-read threat model §5 risk 2 and doc 05 §3 against this ADR.** Both are
   spec documents; neither may be edited by an implementing agent. They are
   listed here as human edits, not as work.

## The remaining unknown — for the human

One thing genuinely cannot be settled from public sources: **whether Sigstore's
maintainers would entertain a SPIFFE issuer request from a project like this if
asked directly.** Everything above establishes that no such issuer is accepted
today, that the SPIFFE-specific process was abandoned, and that the generic
written criteria exclude a single-maintainer v0.1 project. It does not establish
a refusal, because no one has asked.

Settling it costs one issue on `https://github.com/sigstore/fulcio/issues`, per
the process in `docs/new-idp-requirements.md` ("Identity providers should file an
issue before creating a PR"). The people who answer are the Fulcio and Public
Good Instance maintainers — `Hayden-IO` (Hayden Blauzvern) closed #122 and ran
the Buddy onboarding, and the Sigstore TAC (`tac@sigstore.dev`, the contact on
the `accounts.google.com` entry) is the escalation. A question worth asking in
that issue, beyond our own case: *is `type: spiffe` still supported for new
issuers on the public good instance at all, or is it de facto retired?* The
answer would be useful to more than this project.

That question is not on the critical path. This ADR does not wait for it, and
the recommendation above does not change if the answer is a friendly one — an
issuer added on Sigstore's timetable is a future upgrade, not a v0.1 default.

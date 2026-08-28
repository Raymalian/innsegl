# ADR-0002: Default to public Sigstore; self-hosted as first-class configuration

- Status: accepted; **superseded in part by [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md)** (its *Decision* only)
- Date: 2026-08-28
- Deciders: Mike

> **RESOLVED 2026-08-28.** The blocker stated below was measured under RM-016
> (#24) and the answer is **no**: public-good Fulcio accepts no SPIFFE issuer,
> and the federation process this ADR's first fallback assumes was closed
> `not_planned`. The second fallback therefore triggered — the shipped default
> flips to self-hosted Fulcio/Rekor. The blocker text is preserved unaltered
> below as written; the evidence and the new decision are in
> [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md), summarised in
> the [addendum](#addendum--2026-08-28-resolution-of-the-open-verification-item)
> at the foot of this file.

> **BLOCKER — this ADR carries an unresolved verification item.** Whether the
> public-good Fulcio instance will accept a project-operated OIDC issuer
> (`oidc.innsegl.dev`) is **unverified**. It must be settled — measured, not
> assumed — **before Phase 3**. A negative answer supersedes this ADR in part
> and flips the shipped default to self-hosted Fulcio/Rekor. See
> [Open verification item](#open-verification-item--blocking-for-the-public-default-path)
> below.

## Context
Non-repudiation (I5) requires a transparency log outside the operator's control. Public Sigstore (Fulcio + Rekor) provides free, permanent, globally verifiable transparency with zero infrastructure — the strongest possible "even we can't tamper" claim, and the lowest barrier for open-source adoption (OPS-004's fresh-clone experience). The cost: SPIFFE IDs, repo names, and signing timing become public record forever (threat model §5.2). Some organizations cannot accept that.

## Decision
The **default configuration and the reference deployment use public Sigstore**. Self-hosted Fulcio/Rekor is a supported, documented, CI-tested configuration switch — the integration test suite runs against local containers anyway, so the self-hosted path is exercised on every commit by construction.

## Alternatives considered
- **Self-hosted default**: privacy-safe, but a self-hosted log operated by the same party as the ledger weakens the third-party-trust story to "trust our two systems instead of one," and the infrastructure burden would gut adoptability.
- **No default / force a choice at install**: maximizes consent, but OPS-004 requires a working out-of-the-box path, and an attribution tool that doesn't demonstrate public verifiability by default undersells its own point.

## Consequences
Docs must state the metadata-exposure tradeoff prominently at install time (not buried); the config switch is a protected, tested surface; dashboards must render the log endpoint in use so a verifier knows which trust root they are checking. Public-instance rate limits and retention policies become an external dependency — monitored, with the self-hosted path as the documented escape hatch.

## Open verification item — blocking for the public-default path

**Open verification item (blocking for the public-default path):** the public-good Fulcio instance accepts OIDC tokens only from issuers on its configured allowlist. Whether a project-operated SPIRE OIDC discovery provider (`oidc.innsegl.dev`) can be added, and by what process, must be verified against current Sigstore federation documentation before Phase 3 — measured, not assumed. If public Fulcio cannot accept our issuer, the fallbacks in order are: pursue issuer federation with the Sigstore project, or flip the shipped default to the self-hosted pair and demote public Sigstore to "where supported." This ADR is superseded-in-part if the fallback triggers; record the outcome as an addendum with the evidence.

## Addendum — 2026-08-28: resolution of the open verification item

Recorded under RM-016 (#24), which this ADR's closing paragraph called for:
"record the outcome as an addendum with the evidence." The full evidence,
alternatives and consequences are in
[ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md); this addendum
is the summary a reader of ADR-0002 needs in order to know that its *Decision*
no longer holds.

**The question.** Will the public-good Fulcio instance accept OIDC tokens from a
project-operated SPIRE OIDC discovery provider at `oidc.innsegl.dev`, and if so
by what process?

**The answer: no, and the first fallback is unavailable.** Measured 2026-08-28
against `sigstore/fulcio` at `main` = `ae51cd5b978de4389588cbb20cb08845e4e8b98c`
and against the live instance:

- `GET https://fulcio.sigstore.dev/api/v2/configuration` returns 27 accepted
  issuers — 13 `ci-provider`, 7 `kubernetes`, 6 `email`, 1 `chainguard-identity`
  — and **none of type `spiffe`**. Every `spiffeTrustDomain` is empty.
- That list is exactly `config/identity/config.yaml` in the public repo minus its
  four `environment: staging` entries, so a PR to that file is the real
  mechanism and the allowlist is publicly auditable.
- `sigstore/fulcio#122` "SPIFFE ID Federation Planning" — the issue proposing the
  pull-request enrollment process this ADR's first fallback depends on — was
  **closed `not_planned` on 2026-03-09**. The `federation/` directory that
  implemented it was deleted in 2024 (commit `6db2b36`, PR #1736), and with it
  the only text that ever invited `type: spiffe` submissions.
- The one SPIFFE issuer the public instance ever carried, `allow.pub`, was
  removed in 2024 (commit `ccd120a`, PR #1757): "Currently offline and inactive."
- `docs/new-idp-requirements.md` recognises only `Email` and `Workflow`
  providers, and requires demand "beyond the IDP maintainer" plus a 99.9% uptime
  posture — criteria a v0.1 single-maintainer project cannot honestly meet.
- `https://docs.sigstore.dev` still advertises `allow.pub` under its SPIFFE
  heading. The documentation site is two years stale; only the live endpoint is
  authoritative. Doc 01 §2's "measure, never assert from memory" is what caught
  this.

**What the project does now.** The second fallback named in the paragraph above
triggers: the shipped default becomes self-hosted Fulcio/Rekor, and public
Sigstore is demoted to a supported configuration for deployments that already
hold a token from an allowlisted issuer. `oidc.innsegl.dev` is not stood up
(doc 05 §3's condition for building it is not met). Everything else in this ADR
stands — the metadata tradeoff, the requirement that the config switch be a
protected tested surface, and the requirement that dashboards render the log
endpoint in use, which becomes more load-bearing rather than less.

This is a reordering, not a crisis: RM-012 (#20) had already proved the
self-hosted path end to end — a five-container Rekor/Trillian stack, real
inclusion proofs, tamper mutations refused — so the default flips onto a path
that is already demonstrated and already exercised in CI.

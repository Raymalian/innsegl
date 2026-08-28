# ADR-0002: Default to public Sigstore; self-hosted as first-class configuration

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

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

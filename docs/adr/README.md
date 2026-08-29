# Architecture decision records

This directory is the project's decision record. It is the one part of `docs/`
that ships in the public repository — everything else under `docs/` is local
only.

An ADR is written for every significant decision. The test is: would a new
maintainer ask "why is it like this?"

## Rules

- ADRs live at `docs/adr/NNNN-title.md`, numbered sequentially.
- **ADRs are immutable once accepted.** A reversal is a *new* ADR that
  supersedes the old one; the superseded ADR keeps its text and gains a
  `Status: superseded by ADR-MMMM` line. Never rewrite history here.
- Start from [`0000-template.md`](0000-template.md). Every ADR carries all five
  sections: Status, Context, Decision, Alternatives considered, Consequences.
- "We preferred X" is not a reason. Each rejected alternative states the
  concrete reason it lost.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0000](0000-template.md) | Template | — | — |
| [0001](0001-language-and-module-path.md) | Implement the backend in Go; the dashboard in TypeScript | accepted | 2026-08-28 |
| [0002](0002-public-sigstore-default.md) | Default to public Sigstore; self-hosted as first-class configuration | accepted; superseded in part by [0010](0010-self-hosted-sigstore-is-the-shipped-default.md) | 2026-08-28 |
| [0003](0003-apache-2-0-license.md) | License Innsegl under Apache-2.0 | accepted | 2026-08-28 |
| [0004](0004-idempotency-key-scope.md) | Scope `idempotency_key` to the MCP tools that accept one | accepted | 2026-08-28 |
| [0005](0005-one-chain-per-database.md) | Scope a ledger chain to a database | accepted | 2026-08-28 |
| [0006](0006-segment-object-format-and-content-addressed-segment-id.md) | Address a sealed segment by the digest of its object, and make that digest its `segment_id` | accepted | 2026-08-28 |
| [0007](0007-protected-surfaces-gate-semantics.md) | Enforce the protected surfaces with a self-verifying gate, and define what it does before the first tag exists | accepted | 2026-08-28 |
| [0008](0008-worm-canary-proves-refusal-by-attempting-deletion.md) | Prove the WORM configuration by attempting a real deletion, and fail closed on anything short of a refusal | accepted | 2026-08-28 |
| [0009](0009-anchor-a-segment-as-a-signed-hashedrekord-entry.md) | Anchor a sealed segment as a signed `hashedrekord` entry, verify it from first principles, and accept at-least-once anchoring | accepted | 2026-08-28 |
| [0010](0010-self-hosted-sigstore-is-the-shipped-default.md) | Ship self-hosted Fulcio/Rekor as the default, and demote public Sigstore to "where an accepted issuer already exists" | accepted | 2026-08-28 |
| [0011](0011-compose-spire-admin-api-segmentation.md) | Segment the SPIRE admin API by mount and by network, and state the part SPIRE will not segment | accepted | 2026-08-28 |
| [0012](0012-scope-the-mcp-admin-credential-with-an-opa-authorization-policy.md) | Scope the MCP admin credential with an OPA authorization policy | accepted | 2026-08-28 |
| [0013](0013-record-spire-entry-drift-as-ledger-drift-detected.md) | Record SPIRE entry drift as `ledger_drift_detected` where a subject event exists, and refuse to record the unattributed case at all | accepted | 2026-08-29 |
| [0014](0014-reaper-orphan-test-and-expiry-idempotency-key.md) | Bound a run identity by its entry's TTL plus a configured grace, and key `run_expired` by run id | accepted | 2026-08-29 |
| [0015](0015-failure-injection-stack-per-test-process.md) | Give SPIRE failure injection a stack per test process, and record the half of SPI-007 that `sign_commit` must finish | accepted | 2026-08-29 |

## Open items

- **ADR-0007** flags a gap it does not close: `VERSIONING.md` protects "the
  `error_class` values they return" without enumerating them, and the only
  enumeration is IP §4, which is local-only. `scripts/protected-surfaces.sh`
  therefore carries the sole shipped copy of that vocabulary. Publishing the
  list belongs with the MCP tool work (RM-022..025).
- **ADR-0009** leaves one question for the human: doc 02 §3 gives
  `ledger_drift_detected` as emitted by `reconciler`, but the component that
  discovers an anchoring failure is the sealer, whose other output
  (`segment_sealed`) doc 02 marks `system`. The alert defaults to `system` and
  the caller may override; which value doc 02 intends needs deciding.
- **ADR-0004** requires one edit outside `docs/adr/`: doc 02 §2's
  `idempotency_key` description must be narrowed to "MCP tool calls that accept
  an `idempotency_key`", and its "≤128" made explicit as bytes. Implementing
  agents do not edit `docs/` outside this directory, so the ADR is the operative
  reading until a human makes that edit.
- **ADR-0005** leaves one question for the human: doc 02 §2 says
  `chain_position` is consecutive "per chain" and never defines a chain, and
  the envelope has no `chain_id`. The ADR defines a chain as a database, which
  is sufficient for the single-chain deployment doc 05 describes. A deployment
  needing several chains in one ledger requires doc 02 to say what names a
  chain and how a verifier reading a sealed segment learns which one it holds.
- ~~**ADR-0002** carries a blocking open verification item: whether public-good
  Fulcio will accept a project-operated OIDC issuer (`oidc.innsegl.dev`).~~
  **Closed 2026-08-28 by [ADR-0010](0010-self-hosted-sigstore-is-the-shipped-default.md).**
  Measured against the live instance: public-good Fulcio accepts no issuer of
  type `spiffe`, and the SPIFFE federation enrollment process ADR-0002's first
  fallback assumed was closed `not_planned` upstream. The second fallback
  triggered — self-hosted Fulcio/Rekor is now the shipped default and
  `oidc.innsegl.dev` is not stood up.
- **ADR-0010** leaves one question that cannot be settled from public sources:
  whether Sigstore's maintainers would entertain a SPIFFE issuer request from a
  project of this size if asked directly. Nobody has asked. Settling it costs
  one issue on `sigstore/fulcio` per that project's own new-IDP process; it is
  not on the critical path and the decision does not change if the answer is
  friendly. ADR-0010 also names a standing re-measurement: one unauthenticated
  `GET https://fulcio.sigstore.dev/api/v2/configuration` tells you whether a
  `spiffe` issuer has reappeared, and belongs with the threat model §6 review
  triggers — a human edit, outside this directory.

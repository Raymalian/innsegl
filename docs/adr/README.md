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
| [0002](0002-public-sigstore-default.md) | Default to public Sigstore; self-hosted as first-class configuration | accepted | 2026-08-28 |
| [0003](0003-apache-2-0-license.md) | License Innsegl under Apache-2.0 | accepted | 2026-08-28 |
| [0004](0004-idempotency-key-scope.md) | Scope `idempotency_key` to the MCP tools that accept one | accepted | 2026-08-28 |
| [0005](0005-one-chain-per-database.md) | Scope a ledger chain to a database | accepted | 2026-08-28 |
| [0006](0006-segment-object-format-and-content-addressed-segment-id.md) | Address a sealed segment by the digest of its object, and make that digest its `segment_id` | accepted | 2026-08-28 |

## Open items

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
- **ADR-0002** carries a blocking open verification item: whether public-good
  Fulcio will accept a project-operated OIDC issuer (`oidc.innsegl.dev`). It
  must be settled before Phase 3. A negative answer supersedes ADR-0002 in part
  and flips the shipped default to self-hosted Fulcio/Rekor.

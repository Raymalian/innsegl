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

## Open items

- **ADR-0002** carries a blocking open verification item: whether public-good
  Fulcio will accept a project-operated OIDC issuer (`oidc.innsegl.dev`). It
  must be settled before Phase 3. A negative answer supersedes ADR-0002 in part
  and flips the shipped default to self-hosted Fulcio/Rekor.

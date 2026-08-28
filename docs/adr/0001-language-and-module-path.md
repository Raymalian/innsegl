# ADR-0001: Implement the backend in Go; the dashboard in TypeScript

- Status: accepted
- Date: 2026-08-28
- Deciders: Mike

## Context
The backend's entire dependency surface is the SPIFFE/Sigstore ecosystem: SPIRE, gitsign, Fulcio, and Rekor are Go projects, and the first-party client libraries for the Workload API and Sigstore verification are Go-native. The MCP server must ship as an easily deployed service, the verify CLI must run anywhere with no runtime (VER-001 assumes a standalone binary), and the reconciler is a long-running concurrent worker. TDD demands a mature test toolchain including failure injection and property testing.

## Decision
Backend (MCP server, ledger, sealer, reconciler, reaper, `innsegl verify` CLI): **Go**, one module, static binaries. Dashboard: **TypeScript**, per the frontend design document's ADR on its foundation (that choice remains a separate FD-scoped ADR).

## Alternatives considered
- **Rust**: excellent correctness story, but the SPIFFE/Sigstore client ecosystem is thinner; we would wrap or reimplement verification paths that Go gets first-party — reimplementing crypto adjacency violates IP §7.
- **Python**: fastest MCP prototyping, but poor fit for a static verify binary, weaker concurrency for the reconciler, and heavier deployment for adopters.
- **TypeScript end-to-end**: one language is attractive, but Node runtime dependency for the CLI and secondhand Sigstore/SPIFFE support outweigh it.

## Consequences
First-party `go-spiffe` and Sigstore libraries; single-binary adopter experience; team must hold Go discipline for the property tests (use a mature Go property-testing library rather than hand-rolled generators). JCS canonicalization: adopt a tested Go RFC 8785 implementation and validate against TC-SER fixtures regardless (threat model §5.4). Module path is the **vanity import `innsegl.dev/innsegl`** (a `go-import` meta tag on innsegl.dev points at `github.com/Raymalian/innsegl`), decoupling consumer imports from the hosting org forever; the GitHub path is never the module identity. Reversal cost after Phase 0 is effectively a rewrite — hence founding ADR.

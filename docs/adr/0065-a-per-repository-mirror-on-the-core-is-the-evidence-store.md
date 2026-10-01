# ADR-0065: A per-repository mirror on the core is the evidence store

- Status: accepted
- Date: 2026-10-01
- Deciders: the operator

## Context

Landing, proof, step diffs and the reconciler read repository objects. With
the core on its own host, those objects are not on its disk.

## Decision

1. The core keeps one bare mirror per repository. Landing, proof, step diffs
   and the reconciler read it.
2. It is fed by an authenticated git push from the client (ADR-0063), after a
   signed commit and at session end.
3. Workspace snapshots arrive as snapshot refs. The core records a snapshot
   only for a tree it holds: a witness, never a gate.
4. Client-side stores are caches.
5. Bodies and snapshots live on the core. E4 is unchanged: the ledger holds
   references and digests only.

## Alternatives considered

- **The core fetches from the client.** Needs the client reachable from the
  core.
- **The core reads the forge.** Misses work not yet pushed there, which is
  the work most worth recording.
- **Keep evidence on the client.** A client could withdraw what the core
  needs to prove.

## Consequences

- The core's disk holds repository content and must be sized and backed up
  as evidence.
- A snapshot whose tree never arrived is not recorded.
- A failed push does not block the developer; the next push carries it.

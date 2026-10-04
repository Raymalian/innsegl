# ADR-0065: A per-repository mirror on the core is the evidence store

- Status: accepted; amended 2026-10-03 (see the Amendment)
- Date: 2026-10-01
- Deciders: the operator

## Context

Landing, proof, step diffs and the reconciler read repository objects. With
the core on its own host, those objects are not on its disk.

## Decision

1. The core keeps one bare mirror per repository. Landing, proof, step diffs
   and the reconciler read it.
2. It is fed by an authenticated git push from the client, after a signed
   commit and at session end. The push endpoint is checked by client
   certificate and repository scope (ADR-0063).
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

## Amendment (2026-10-03): the core reads only the mirror

**What changed.** Decision 1 is now built for the query API and the
reconciler. Both open the mirror read-only and read no other copy of a
repository. The query API lists repositories from the mirror itself, not from
a list set at deploy time. No service on the core mounts a folder of the
host's projects. The overlay that mounted one is gone.

**Why.** On a core host that folder is the core's own disk, not any client's.
A proof read there answered only for repositories that happened to be checked
out on the core, and said nothing about anyone else's.

**What still holds.**

- A repository or a commit the mirror lacks is answered "not held yet"
  (consequence 3). It is never a verdict about the commit.
- The mirror's absence of a signed commit is not evidence that none was
  made. The reconciler leaves such an intent open; it never expires it.
- Whether a commit landed is a question about the developer's branch, which
  the mirror does not hold. The landing pass reports it as not checked.
- The objects of a commit reach the mirror before it is signed (decision 2).
  The signed commit itself does not need a second push: the core builds the
  exact signed commit object while signing, writes it into the mirror under
  `refs/innsegl/signed/<sha>`, and checks its id is the signed commit's.
  That happens before the ledger records the commit; if it fails, signing
  fails, with nothing recorded and no signature handed back.

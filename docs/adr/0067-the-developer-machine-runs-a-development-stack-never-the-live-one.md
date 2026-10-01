# ADR-0067: The developer machine runs a development stack, never the live one

- Status: accepted
- Date: 2026-10-01
- Deciders: the operator

## Context

Two test packages tear the running deployment down: one re-points the
transparency log and one ends in `docker compose down -v`. They are correct on
a clean host and destructive on a working one. With a core host, building and
testing no longer need to share a machine with the deployment.

## Decision

1. Building and testing happen on the development machine.
2. The working deployment runs on the core host (ADR-0063).
3. The development stack has its own project name and trust prefix, listens
   on loopback, and never writes the harness's managed settings.

## Alternatives considered

- **One stack for both.** Keeps the hazard above.
- **A separate development host.** Extra machine without benefit: loopback
  plus a distinct project name already isolates the stacks.

## Consequences

- Destructive test packages can run without touching the live deployment.
- The development stack does not capture the developer's own harness
  traffic, by design.

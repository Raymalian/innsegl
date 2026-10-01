# ADR-0064: The client derives the workspace; the core binds it to the installation's scope

- Status: accepted
- Date: 2026-10-01
- Deciders: the operator

## Context

On one machine the gateway reads a bare directory and resolves it with
`describe_workspace`. A core on another host cannot read a client's files, and
should not.

## Decision

1. The client works out repository, worktree, branch, task and head from its
   own working tree and states them through `innsegl hook session`.
2. The core never reads a client's files.
3. A stated repository outside the installation's scope (ADR-0063) is
   refused.
4. A stated workspace is a claim of the same class as the agent-id header
   (ADR-0058 decision 2): it names where work happened, and proves nothing
   about it.
5. The single-host shape still resolves a bare directory through
   `describe_workspace`.

## Alternatives considered

- **The core reads the client's directory over a network mount.** Gives the
  core read access to client files.
- **The core runs a helper on the client.** Moves a trusted component onto the
  machine the scope is meant to bound.

## Consequences

- An installation's repository scope is the only workspace check the core
  enforces.
- A client that misstates its branch or task misleads the record, as a
  misstated agent id already can, and can reach no repository its
  installation does not cover.

# ADR-0056: A single-machine deployment runs the loops in the MCP

- Status: accepted
- Date: 2026-09-27
- Deciders: the operator

## Context

The reconciler's SPIRE pass compares SPIRE's entries with the ledger: an entry
missing for a live run, left behind by a retired one, or duplicated. It needs
the SPIRE admin API. SPIRE admits exactly one admin identity,
`spiffe://innsegl.dev/innsegl/mcp`, and authz-policy.rego scopes it to the
methods the MCP and its loops need, the reconciler's included.

The reconciler container holds no admin identity, so on the deployed stack the
pass has never run. Every cycle has logged `spire: OFF`.

`deploy/compose/innsegl.oneprocess.yml` already runs the sealer and the
reconciler inside the MCP (`serve -also seal,reconcile,reap`), where they read
the MCP's environment and use its identity. It says what that costs: one log
stream, one restart, no independent scaling. It also lagged the reconciler:
the rebase and writes passes' settings and mount never reached it (#333).

## Decision

A single-machine deployment runs with the one-process overlay: `make
innsegl-up-here ONEPROCESS=1`. The reconciler's SPIRE pass runs there, under
the MCP's existing admin identity. No new admin identity is created, and the
policy is unchanged.

The overlay must carry every setting and mount the services it folds were
given. `TestRM207OneProcessKeepsWhatTheFoldedServicesHad` holds it to that.

The separate-container topology stays the compose default, for doc 05 §2's
replicated MCP, where one-process mode would run N sealers. There the SPIRE
pass stays off until the reconciler has an identity of its own, which would
need its own ADR and a test that it cannot write.

## Alternatives considered

- **A second, read-only admin identity for the reconciler container.** Keeps
  doc 05 §1's layout, but adds a second identity that can reach SPIRE's admin
  API, which is threat-model asset A2's blast radius.
- **Leave the pass off.** Drift between SPIRE and the ledger would go on being
  something nothing checks.

## Consequences

- Two containers fewer on a single machine (19 to 17). This is phase 1 of the
  fewer-parts plan, taken for a reason of its own.
- `docker logs innsegl-mcp` carries the sealer's and the reconciler's lines,
  tagged by subcommand.
- A sealer or reconciler fault restarts the MCP (serve.go stops the process
  when a companion returns), and live runs see the MCP restart.

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

An overlay file, `innsegl.oneprocess.yml`, already ran the sealer and the
reconciler inside the MCP (`serve -also seal,reconcile,reap`), where they read
the MCP's environment and use its identity. It lagged the reconciler: the
rebase and writes passes' settings and mount never reached it (#333). And it
was a flag to remember: a redeploy without it brought the separate containers
back and turned the pass off without a word (#339).

## Decision

`deploy/compose/innsegl.yml` runs the loops in the MCP by default.
`INNSEGL_MCP_ALSO` defaults to `seal,reconcile,reap`, and `innsegl-mcp` carries
the sealer's and the reconciler's settings, networks and mounts. A plain
`docker compose up` is one process. The overlay and the Makefile flag are gone.
The reconciler's SPIRE pass runs under the MCP's existing admin identity. No
new admin identity is created, and the policy is unchanged.

`innsegl-sealer` and `innsegl-reconciler` stay defined, under the `separate`
profile. doc 05 §2's replicated MCP brings them up with `--profile separate`
and sets `INNSEGL_MCP_ALSO=reap`, or N replicas would run N sealers. There the
SPIRE pass stays off until the reconciler has an identity of its own, which
would need its own ADR and a test that it cannot write.

`TestRM207OneProcessKeepsWhatTheFoldedServicesHad` holds the MCP to every
setting, value, network and mount the two services have.
`TestRM211OneProcessIsBuiltIn` holds a plain `up` to one process.

## Alternatives considered

- **A second, read-only admin identity for the reconciler container.** Keeps
  doc 05 §1's layout, but adds a second identity that can reach SPIRE's admin
  API, which is threat-model asset A2's blast radius.
- **Leave the pass off.** Drift between SPIRE and the ledger would go on being
  something nothing checks.

## Consequences

- Two containers fewer by default (19 to 17). This is phase 1 of the
  fewer-parts plan, taken for a reason of its own.
- The readiness report reads a profiled service as not declared, so it no
  longer waits for the two containers a default bring-up does not start.
- `docker logs innsegl-mcp` carries the sealer's and the reconciler's lines,
  tagged by subcommand.
- A sealer or reconciler fault restarts the MCP (serve.go stops the process
  when a companion returns), and live runs see the MCP restart.

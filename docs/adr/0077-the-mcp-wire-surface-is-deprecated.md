# ADR-0077: The MCP wire surface is deprecated

- Status: accepted
- Date: 2026-10-08
- Deciders: the operator

## Context

innsegl's core serves eight MCP tools on one listener, and the six identity
lifecycle and recording tools on a second, admin, listener when one is
configured (#170, #264). They were how an agent harness was meant to reach the
core.

That is no longer how anything reaches it:

- The gateway registers, retires and records each run from its own traffic,
  and calls the engine behind `register_agent`, `retire_agent` and
  `observe_tool_call` in process (ADR-0058).
- The commit hook signs through the core's commit path, which calls the
  signing engine in process. It does not call `sign_commit`.
- The installer removes innsegl's MCP server entry from a harness's settings
  as legacy. No shipped client configures one.
- `describe_workspace` and `observe_session` already refuse every call
  (ADR-0071).
- The only shipped callers of the wire were `innsegl retire`, through the admin
  listener, which is off by default, and the demo profile's scripted agent.

The tool names and their error classes are a protected surface (VERSIONING.md
surface 4). Removing one is a major-release change, announced one minor
release ahead in `CHANGELOG.md` and in the tool descriptions.

## Decision

1. **The MCP wire surface is deprecated.** Every one of the eight tools'
   descriptions in `tools/list` begins with the same sentence:
   "Deprecated (ADR-0077): innsegl's gateway and commit hook replace the MCP
   wire surface, and this tool is removed from it at the next major release."
2. **Nothing is removed in this release.** All eight names stay bound, with
   their argument and result shapes and their error classes unchanged. The six
   working tools keep working. `describe_workspace` and `observe_session` keep
   refusing as ADR-0071 decided. Both listeners keep their flags and defaults.
3. **The engine stays.** Registration, retirement, signing and recording are
   kept, and so is the one process that holds SPIRE admin (ADR-0053). What is
   deprecated is the MCP binding in front of them.
4. **`innsegl retire` runs on the core.** It no longer calls `retire_agent`
   over the admin listener. It runs inside the core's container
   (`docker exec innsegl-mcp innsegl retire <run_id>`, or
   `make innsegl-retire RUN=<run_id>`), and calls the same retirement engine
   the gateway calls, under the core's own SPIRE admin identity and ledger
   credential. It adds no credential. Its five exit statuses keep their
   numbers. Status 21 now means this process holds no SPIRE admin identity,
   which is what running it anywhere but the core produces. Its `-url` and
   `-repo` flags are removed, and with them the admin credential it minted.
5. **Phase 3, at the next major release**, is a superseding ADR with a
   migration attestation (VERSIONING.md). It removes the eight tools' wire
   binding, both MCP listeners and the admin credential that guards the second
   one, the demo profile, and ADR-0071's stubs.

## Alternatives considered

- **Remove the surface in this minor release.** Rejected: the tool names are a
  protected surface, and VERSIONING.md allows their removal only in a major
  release announced one minor ahead.
- **Keep the surface and stop calling it deprecated.** Rejected: a surface no
  shipped component calls still has to be defended. The admin listener and its
  credential are an authentication boundary that protects only the wire.
- **Keep `innsegl retire` as an MCP client until the major.** Rejected: on a
  default deployment the admin listener is off, so the command could not
  retire anything. Running it on the core works on every deployment and uses
  the engine the gateway already uses.
- **Deprecate only the six working tools.** Rejected: ADR-0071's two are
  removed at the same major, and one identical sentence on all eight is what a
  client can match.

## Consequences

- A client that lists the tools sees the deprecation on each one. A client
  that calls them gets the same answers as before.
- An operator retires a run from the core host. Running `innsegl retire` on
  another machine is refused with status 21, and the message gives the
  command to run on the core.
- A script that passed `-url` or `-repo` to `innsegl retire` gets a usage
  error.
- Hookless automation that would sign through `sign_commit`, and ingestion
  tools for other harnesses, would have to be rebuilt as authenticated HTTP
  routes on the core if a harness ever needs them.

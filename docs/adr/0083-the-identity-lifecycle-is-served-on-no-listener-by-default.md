# ADR-0083: The identity lifecycle is served on no listener by default

- Status: accepted
- Date: 2026-10-12
- Deciders: the operator (approved 2026-10-12)
- Supersedes: ADR-0077 decision 2, only its sentence "Both listeners keep their flags and defaults"

## Decision

The MCP's main listener always serves only `get_credential` and `sign_commit`,
whether an admin listener is set or not. The identity lifecycle
(`register_agent`, `retire_agent`, `record_event`, `observe_tool_call`,
`describe_workspace`, `observe_session`) is served on `-admin-listen`, behind
its credential, when an operator sets one, and on no listener when none is set.
`make start`, `make update` and every other make path now leave it unset, and
the compose file publishes no host port for it. Nothing shipped needed it: the
gateway registers and records in process, and `innsegl retire` runs on the core
(ADR-0077 decisions 3 and 4). Before this, an empty `-admin-listen` put all six
back on the main listener with no credential, so anything that could reach it
could mint or retire a run (doc 04 AB-13, AB-15). That behaviour is kept only
behind `-lifecycle-on-agent-listener` (`INNSEGL_MCP_LIFECYCLE_ON_AGENT_LISTENER`),
which logs a warning at every start, is refused beside `-admin-listen`, and is
used only by test harnesses and the dev-only `make innsegl-demo`. The tool
names, their shapes and error classes are unchanged; the removal of the wire
binding is still ADR-0077 decision 5.

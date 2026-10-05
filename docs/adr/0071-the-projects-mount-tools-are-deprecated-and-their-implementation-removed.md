# ADR-0071: The projects-mount tools are deprecated and their implementation removed

- Status: accepted
- Date: 2026-10-05
- Deciders: the operator

## Context

`describe_workspace` and `observe_session` (RM-126, RM-128) were built for a
single-host deployment that mounted the operator's projects folder into the
core. `describe_workspace` translated a harness's host path onto that mount and
read git there. `observe_session` registered and retired a run per harness
session, resolving the workspace through `describe_workspace` and keeping a
session-to-run marker on its own volume.

That shape is gone:

- The core reads repositories only from its mirror (ADR-0065). It mounts no
  projects folder, and `innsegl serve` was never configured with a host root,
  so `describe_workspace` refused every call by name.
- The client derives its own workspace and states it (ADR-0064). The session
  hook posts that statement to the gateway, and the gateway drives each run's
  identity from the traffic (ADR-0058). Nothing calls `observe_session`, and
  its marker volume, `innsegl-sessions`, was mounted by nothing.
- `observe_tool_call`'s `session_id` path registered a session through
  `observe_session`'s start, so it refused whenever `observe_session` did.

Both names are a protected surface (VERSIONING.md surface 4). Removing one is
a major-release change, announced one minor release ahead in `CHANGELOG.md`
and in the tool descriptions.

## Decision

1. **The names stay until the next major release.** `describe_workspace` and
   `observe_session` remain bound and advertised, with their argument and
   result shapes unchanged. Every call is refused with `INVARIANT_VIOLATION`,
   the class the hosted core already answered them with, and a message that
   says the tool is deprecated and names this ADR. Their descriptions begin
   "Deprecated". No error class is added.
2. **`observe_tool_call` refuses `session_id`** with the same class, before any
   dependency is consulted or anything is written. `session_id`, `cwd`,
   `agent_type` and `parent_session_id` stay in its schema until the next
   major release. A run is named by `run_id`.
3. **The implementation is removed:** the workspace derivation behind
   `describe_workspace`, the session markers, resume and cascade behind
   `observe_session`, and the gateway's in-process resolver that called
   `describe_workspace`. A session statement that names only a directory is
   refused by name: the core reads no client tree.
4. **What configured them is removed:**
   - `innsegl serve`: `-host-projects`, `-projects-mount` and `-session-dir`,
     and the variables `INNSEGL_PROJECTS_MOUNT` and `INNSEGL_MCP_SESSION_DIR`.
   - `innsegl reconcile`: `-host-projects` and `-writes-projects`, and the
     variable `INNSEGL_WRITES_PROJECTS`. The writes check's path rule
     translated a harness's host path onto the same mount, so it now reports
     itself unscoped on every deployment, as it already did on the shipped one.
   - `innsegl retire`: the `INNSEGL_REPO_ID` fallback, which only the retired
     signer and the old hook read. `-repo` or the working tree names the
     repository.
   - The `innsegl-sessions` volume and the image's `/sessions` directory.
5. **`INNSEGL_HOST_PROJECTS` is not removed yet.** It is still one of the two
   roots git's ownership check trusts (`ProjectMountRoots`), which
   `sign_commit` and the gateway's workspace snapshot use. Neither tool nor
   the reconciler reads it any more.
6. **The names go at the next major release**, with a superseding ADR, as
   VERSIONING.md requires.

## Removed with it: `innsegl resolve-alert`

ADR-0044 gave alert resolution to an operator CLI, `innsegl resolve-alert`,
run on the core host under the append-only role. Its 2026-10-03 amendment moved
resolution into the dashboard behind a fresh passkey, written by the API's own
resolver role, and the shipped compose file always sets
`INNSEGL_API_RESOLVER_DSN`. The CLI is removed; it is not a protected surface.
Without a resolver DSN the API answers 503, and the dashboard says that
resolving an alert needs the resolver role configured on the API. The
append-only role keeps its grant on `innsegl.alert_resolutions`, because the
sealer closes drift alerts under it (ADR-0055).

Two other unused CLI surfaces go at the same time: `innsegl serve -also api`,
which nothing set and which would run the query API inside the process that
holds SPIRE admin, and the standalone `innsegl gateway` command, since the
gateway runs as a companion of `innsegl serve` (ADR-0060).

## Consequences

- A harness or script that still calls either tool gets a refusal that says
  why and where to read about it, instead of one about a missing setting.
- An operator who still sets one of the removed variables configures nothing.
  An operator who passes one of the removed flags gets a usage error.
- An existing `innsegl-sessions` volume is no longer declared. Compose leaves
  it in place; it holds nothing the core reads and can be deleted by hand.
- The contract matrix keeps all eleven cells for each deprecated tool:
  `INVARIANT_VIOLATION` is reachable and the other ten are unreachable, for one
  stated reason.

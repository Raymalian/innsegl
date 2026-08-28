# Versioning policy

Innsegl uses semantic versioning with one project-specific hardening:
a class of PROTECTED SURFACES that only ever change in a major release,
and only with a migration attestation.

## Protected surfaces

1. **The event schema and canonical serialization**, at `schema_version 1`:
   the genesis constant, the hash constructions, the enum values, and every
   field name — `event_id`, `run_id`, `spiffe_id`, `event_type`, `ts`,
   `payload_digest`, `prev_event_hash`, `event_hash`, `supersedes`, and the
   type-specific reference fields.
2. **The commit trailer keys**: `Agent-Identity`, `Agent-Run`, `Agent-Task`.
3. **The SPIFFE ID grammar**:
   `spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}`.
4. **The MCP tool names and their error-class vocabulary** — `register_agent`,
   `get_credential`, `record_event`, `sign_commit`, `retire_agent`, and the
   `error_class` values they return.
5. **The project namespace**: the `innsegl` MCP server name, the package
   names, and the CLI binary name.

The normative, byte-level definition of surface 1 is not prose — it is the
**golden serialization fixtures** (test-catalog `TC-SER`) and the **MCP
contract schemas** checked into this repository. Where a document and a
fixture disagree, the fixture wins, because the fixture is what verifiers
actually re-derive. Read the fixtures to learn the exact bytes.

## Rules

- MINOR/PATCH releases MUST NOT alter any protected surface. CI enforces
  this: the golden fixtures (`TC-SER`) and the contract schemas are diffed
  against the previous tag; any drift fails the release.
- A MAJOR release MAY change protected surfaces only with, in the same
  release: (a) a new `schema_version` accepted alongside all previous ones
  by verifiers — verification of old records is supported forever, without
  exception; (b) updated golden fixtures for the new version, with the old
  version's fixtures retained and still asserted; (c) a signed migration
  attestation event appended to the ledger, marking the exact chain position
  of the cutover; (d) a superseding ADR under `docs/adr/`.
- Records are never migrated in place. Old events remain valid under their
  own `schema_version` eternally; "upgrade" means new events use the new
  version, never that old bytes change (invariant I4 applies to the schema's
  own history).
- Deprecations are announced one minor release ahead in `CHANGELOG.md` and in
  the MCP tool descriptions; removal only at the next major.
- The compose reference stack and the documented smoke command are part of
  the compatibility surface: if `make smoke` from the previous minor's README
  fails on the new minor, that is a breaking change misfiled as minor —
  release is blocked.

## Pre-1.0

Until `v1.0.0`, the protected surfaces are still protected — they are the
whole point of the system — but the version number carries no compatibility
promise for anything outside them. A `0.x` minor bump may break an
unprotected API. A `0.x` minor bump may never break a protected surface;
that requires the major-release procedure above, taken early.

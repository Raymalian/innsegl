# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as constrained by [VERSIONING.md](VERSIONING.md) — a change to a protected
surface is a major release and nothing less, regardless of how small it looks.

Deprecations are announced here one minor release ahead of removal.

## [Unreleased]

### Added

- **A development stack that is never the live one** (#469, ADR-0072).
  `make dev-stack` marks a repository's stack as a development stack: every
  compose project, container and network is `innsegl-dev-*`, its trust
  volumes are `innsegl-dev-trust-*` (its own CA, log and ledger), its host
  folders are under `$HOME/.innsegl/dev`, and it is loopback only. With no
  marker a stack is live and nothing about it changes. An enrolled client
  without the marker is told about `make dev-stack` and is never switched.
- **Pseudonymous agent identity, on by default** (#116). `register_agent` now
  fills the SPIFFE ID's `{agent_type}` and `{task_id}` with
  `HMAC-SHA256(deployment_secret, "<field>:" ‖ value)` truncated to eight hex
  characters, so a ticket reference no longer reaches the Fulcio certificate,
  the Rekor entry or the `Agent-Identity` / `Agent-Task` trailers. Configured
  with `INNSEGL_IDENTITY_MODE` (`pseudonymous` by default, `literal` for the
  previous behaviour) and `INNSEGL_IDENTITY_SECRET`; **a deployment in
  `pseudonymous` mode with no secret refuses to start** rather than falling
  back to literal values. The real `agent_type` and `task_ref` still reach the
  `run_registered` event unchanged and are the only mapping back — the secret
  is needed to create a pseudonym and never to resolve one, so losing or
  rotating it orphans nothing. No protected surface moves: the grammar, the
  trailer keys, the event schema and the canonical serialization are untouched,
  and a third party's three verification checks are unchanged. See ADR-0041 for
  what it costs — the attested link from a commit to a tracker now lives in the
  ledger rather than in `git log`.
- Apache-2.0 licence, `NOTICE`, security policy, versioning policy,
  contribution guide, code of conduct, and issue templates.
- `internal/event`: the common event envelope, RFC 8785 (JCS) canonical
  serialization, the `event_hash` construction, and the genesis constant for
  `chain_position` 1 (#14). `event_hash` is excluded from its own preimage;
  optional members are omitted rather than nulled or emptied; timestamps are
  RFC 3339 UTC at exactly millisecond precision.
- **Golden serialization fixtures** at `internal/event/testdata/fixtures/v1`,
  covering every `event_type` in the schema plus escaping, unicode and integer
  bounds. Per VERSIONING.md these are the normative, byte-level definition of a
  protected surface: where a document and a fixture disagree, the fixture wins.
  They are immutable once tagged. `verify.py` alongside them re-derives every
  byte with a non-Go oracle and walks the hash chain from the genesis constant.
- A serializer version gate (#14): a divergence between `SerializerVersion` and
  `SchemaVersion` fails `go build`, and a frozen format fingerprint fails the
  tests if the serializer's output moves under an unchanged version tag. A
  silent change to the canonical format is not possible.
- ADR-0004, resolving a conflict between doc 02 §2 and IP §4 over when an event
  carries `idempotency_key`.

### Changed

- `idempotency_key` is now required only on events whose originating MCP tool
  accepts one (`run_registered`, `tool_call`, `commit_intent`,
  `commit_recorded`), and is forbidden on `credential_issued` and `run_retired`
  because `get_credential` and `retire_agent` take no such argument (ADR-0004).
  Its "≤128" limit is counted in bytes. This changed the canonical bytes of the
  affected events, so the golden fixtures from `chain_position` 2 onward were
  regenerated before the first tag. Operators: nothing has shipped yet, so
  there is no migration; after `v0.1.0` the same change would be a major
  release with a migration attestation.

### Deprecated

- **`describe_workspace` and `observe_session`** (ADR-0071). Both read a
  projects folder mounted into the core, and the core mounts none: it reads
  repositories only from its mirror (ADR-0065). Their names are a protected
  surface, so both stay advertised, with their argument and result shapes
  unchanged, and refuse every call with `INVARIANT_VIOLATION` and a message
  naming the ADR. **They are removed at the next major release.**
  `observe_tool_call`'s `session_id`, `cwd`, `agent_type` and
  `parent_session_id` arguments went through `observe_session`; a call that
  sends `session_id` is refused the same way, and the four are removed with
  it. Name the run with `run_id`.

### Removed

- The implementation behind `describe_workspace` and `observe_session`, and
  what configured it (ADR-0071): `innsegl serve`'s `-host-projects`,
  `-projects-mount` and `-session-dir`; `innsegl reconcile`'s `-host-projects`
  and `-writes-projects`; the variables `INNSEGL_PROJECTS_MOUNT`,
  `INNSEGL_MCP_SESSION_DIR` and `INNSEGL_WRITES_PROJECTS`; the
  `innsegl-sessions` volume and the image's `/sessions` directory.
  `INNSEGL_HOST_PROJECTS` is no longer read by either tool or by the
  reconciler; it remains one of the two roots git's ownership check trusts.
- `innsegl retire` no longer reads `INNSEGL_REPO_ID`; the repository comes
  from `-repo` or the working tree (ADR-0071).
- `innsegl resolve-alert` (ADR-0071). Resolve an alert from the dashboard,
  which needs the API's resolver role (`INNSEGL_API_RESOLVER_DSN`).
- `innsegl serve -also api`. Nothing set it, and it would have run the query
  API inside the process that holds SPIRE admin.
- The standalone `innsegl gateway` command. The gateway runs as a companion of
  `innsegl serve` (`-also gateway`, ADR-0060).

### Fixed

### Security

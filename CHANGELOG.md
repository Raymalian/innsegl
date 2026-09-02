# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as constrained by [VERSIONING.md](VERSIONING.md) — a change to a protected
surface is a major release and nothing less, regardless of how small it looks.

Deprecations are announced here one minor release ahead of removal.

## [Unreleased]

### Added

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

### Removed

### Fixed

### Security

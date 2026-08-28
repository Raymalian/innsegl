# TC-SER golden fixtures — `schema_version` 1

**These files are immutable.** They are the normative, byte-level definition of
a protected surface. `VERSIONING.md`: *"Where a document and a fixture disagree,
the fixture wins, because the fixture is what verifiers actually re-derive."*

Changing any byte below is a **major** schema version, and only with everything
doc 02 §7 requires in the same release: a new `schema_version` that verifiers
accept alongside version 1, a new fixture set with this one retained and still
asserted, a signed migration attestation event marking the cutover position,
and a superseding ADR. There is no other path. Do not regenerate these files
to make a test pass — a failing fixture test means the serializer changed, and
the serializer is what must be reverted.

## Layout

Each fixture is three files:

| File | Contents |
|---|---|
| `<name>.input.json` | The event object **without** `event_hash`, pretty-printed with its members in deliberately reverse-sorted order. Nothing reads this ordering; it is scrambled so every fixture doubles as an ordering-independence vector (SER-002). |
| `<name>.canonical.json` | The exact RFC 8785 JCS bytes of that object. No trailing newline: the file *is* the preimage. |
| `<name>.hash` | `sha256:` + lowercase hex of SHA-256 over `<name>.canonical.json`. No trailing newline. This is the event's `event_hash`. |

Plus:

| File | Contents |
|---|---|
| `genesis.hash` | `"sha256:" + hex(SHA-256(UTF-8("innsegl-genesis-v1")))` — the `prev_event_hash` of `chain_position` 1 (doc 02 §4.4). |
| `format-probe.*` | The serializer format fingerprint (SER-005); see below. |
| `verify.py` | Re-derives every file here with a non-Go oracle. See below. |

## The fixtures

`00-doc02-example` reproduces the `run_registered` example in **doc 02 §6**
member for member and byte for byte. The spec elides `prev_event_hash` as
`"sha256:…"`; the fixture substitutes the genesis constant so the vector is
complete and re-derivable. That substitution is inside a string value and does
not affect member ordering, which is what this vector pins against §6. It is
the only fixture that is not part of the chain below, and it keeps the spec's
`chain_position` of 412.

`01`–`14` are **one valid hash chain**: position 1 carries the genesis constant
as `prev_event_hash`, and every later position carries the preceding fixture's
`event_hash`. They cover all eleven `event_type` values in doc 02 §3.

| # | Fixture | Covers |
|---|---|---|
| 01 | `run_registered` | `source: mcp`, `idempotency_key`, genesis `prev_event_hash` |
| 02 | `credential_issued` | `audience`, `credential_expiry`; `idempotency_key` **absent** (ADR-0004) |
| 03 | `tool_call` | `payload_digest` present |
| 04 | `commit_intent` | 40-hex `tree_hash`, `repo` as `host/org/name` |
| 05 | `commit_recorded` | `rekor_log_index` as an integer, `intent_event_id` back-reference |
| 06 | `commit_intent_expired` | `source: reconciler`, `idempotency_key` absent |
| 07 | `run_retired` | no type-specific fields; `idempotency_key` **absent** (ADR-0004) |
| 08 | `run_expired` | `source: reaper` |
| 09 | `unattributed_signature_detected` | system-scope alert: `run_id` **and** `spiffe_id` omitted |
| 10 | `ledger_drift_detected` | free-text `reason` |
| 11 | `segment_sealed` | `source: system`, no run, anchor fields **absent** |
| 12 | `segment_sealed` (anchored) | the superseding update: `supersedes` + both anchor fields present |
| 13 | unicode and escapes | every JSON short escape, `\u`-escaped control characters, DEL, U+2028/U+2029, Latin-1, a combining sequence, BMP CJK, a non-BMP character, RTL text |
| 14 | integer and length bounds | `rekor_log_index` at 2^53−1, a 128-byte `idempotency_key`, 64-hex `commit_sha`/`tree_hash` from a SHA-256 repository |

Fixtures 11 and 12 are the two sides of doc 02 §3's rule that anchoring fields
arrive in a *superseding* `segment_sealed`, never by mutating the original.
Together with 09 they are the ones that pin "optional means **omitted**": there
is no `"anchor_rekor_log_index": null` and no `"run_id": ""` anywhere in this
directory, and there never can be.

### `idempotency_key` placement (ADR-0004)

`idempotency_key` appears on exactly the events whose originating MCP tool takes
one — `run_registered`, `tool_call`, `commit_intent`, `commit_recorded` — and on
none of the others. Fixtures 02 (`credential_issued`) and 07 (`run_retired`) do
not carry it, because `get_credential` and `retire_agent` accept no such
argument (IP §4). doc 02 §2's wider wording is narrowed by ADR-0004, and
`verify.py` re-checks the placement from the committed bytes.

### Synthetic values

Every synthetic digest, commit SHA, tree hash and Rekor UUID is
`SHA-256(UTF-8(seed))`, truncated to the width the field requires, so an
auditor can re-derive it rather than trusting it:

| Value | Seed |
|---|---|
| `payload_digest` (03) | `innsegl-fixture/payload/03-tool_call` |
| `tree_hash` (04, 05) | `innsegl-fixture/tree/04-commit_intent`, first 40 hex |
| `commit_sha` (05) | `innsegl-fixture/commit/05-commit_recorded`, first 40 hex |
| `rekor_entry_uuid` (05, 09, 12, 14) | `innsegl-fixture/rekor-uuid/<nn>` |
| `segment_merkle_root` (11, 12) | `innsegl-fixture/merkle-root/11` |
| `commit_sha`, `tree_hash` (14) | `innsegl-fixture/commit/14`, `innsegl-fixture/tree/14` |

`event_id` values are real UUIDv7s built deterministically: the 48-bit
big-endian millisecond timestamp of the fixture's own `ts`, then ten bytes of
`SHA-256(UTF-8("innsegl-fixture/event-id/<fixture name>"))`, with the version
nibble forced to 7 and the variant bits to `10`.

## The format probe (SER-005)

`format-probe.input.json` is not an event. It is a fixed object that exercises
every rule doc 02 §4.2 freezes — member sorting across the ASCII range, every
escape form, both booleans, and the JCS-safe integer ceiling and floor. Its
`event_hash`-shaped digest is the serializer's **format fingerprint**, frozen a
second time as a constant in `canonical.go`. Any behavioural change to the
serializer moves it, and `VerifyFormat` then fails, so the format cannot change
quietly under an unchanged version tag.

## Independent re-derivation

The canonical bytes and digests here were produced *before* the Go serializer
existed, by an oracle that is not Go, and can be re-checked at any time:

```
python3 verify.py
```

It re-derives every canonical byte and digest, recomputes the genesis constant,
walks the 01–14 chain from that constant checking each `prev_event_hash`
against its predecessor's committed `.hash`, and checks the ADR-0004
`idempotency_key` placement — all from the committed files, with no Go
involved.

Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` is byte-identical to RFC 8785 over the value domain doc 02
admits; `verify.py` documents exactly why, and where the equivalence would stop
holding. The Go test suite asserts the same bytes from the other side, so a
fixture is only green when two unrelated implementations agree on it.

`00-doc02-example.canonical.json` was additionally checked against doc 02 §6 by
extracting the example straight out of the spec, substituting the elided
`prev_event_hash`, and running `cmp`; its digest was checked with `shasum -a
256` and `openssl dgst -sha256`. The genesis constant was derived with
`shasum`, GNU `sha256sum`, `openssl` and Python `hashlib`, which all agree.

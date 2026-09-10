#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-derive every schema-2 golden fixture with an oracle that is not Go.

Same job as ../v1/verify.py and, deliberately, the same method: these fixtures
are the normative, byte-level definition of a protected surface, and a fixture
only ever checked by the implementation it came from proves nothing.  See that
file for why `json.dumps` is a valid RFC 8785 oracle for this schema; the
argument is unchanged, because the SERIALIZATION is unchanged.  Schema 2 adds
members; it does not touch how members are ordered, escaped or hashed.

    python3 verify.py            # from this directory

What this checks that v1's does not:

  * ADR-0045 - `run_registered` carries `repo` and `branch`, and `parent_run_id`
    where a run has a parent.
  * ADR-0047 - `commit_intent` and `commit_recorded` carry `patch_id`, a
    40-hex object id from `git patch-id --verbatim`.
  * every fixture declares `schema_version` "2".

What it does NOT check, and where that lives instead:

  * the genesis constant, which is not a property of a schema version - the
    seed is `innsegl-genesis-v1` under both, doc 02 §4.4 ties it to
    chain_position 1, and ../v1/genesis.hash is where it is committed.  The
    chain below is still walked FROM it, computed here rather than trusted.

This script only ever READS the fixtures.  Fixtures are immutable once merged
(doc 02 §7); regenerating one is a major schema version with a migration
attestation, never a convenience.
"""
import hashlib
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
GENESIS_SEED = "innsegl-genesis-v1"
SCHEMA_VERSION = "2"
OBJECT_ID = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def main() -> int:
    failures = []

    def check(label, got, want):
        if got != want:
            failures.append(f"{label}\n      got  {got!r}\n      want {want!r}")

    inputs = sorted(HERE.glob("*.input.json"))
    if not inputs:
        print("no fixtures found", file=sys.stderr)
        return 2

    for src in inputs:
        name = src.name[: -len(".input.json")]
        obj = json.loads(src.read_text(encoding="utf-8"))
        if "event_hash" in obj:
            failures.append(f"{name}: event_hash is in its own preimage")
            continue
        got = canonical(obj)
        check(f"{name}.canonical.json",
              got, (HERE / f"{name}.canonical.json").read_bytes())
        check(f"{name}.hash",
              digest(got), (HERE / f"{name}.hash").read_bytes().decode("ascii"))
        if obj.get("schema_version") != SCHEMA_VERSION:
            failures.append(
                f"{name}: schema_version {obj.get('schema_version')!r}, "
                f"want {SCHEMA_VERSION!r}")

    # --- the chain, walked from the genesis constant (doc 02 §4.4, §4.5).
    # Computed here, not read from a file: this directory holds no genesis.hash
    # because the seed is not a property of a schema version.
    chain = sorted(n for n in (s.name[: -len(".input.json")] for s in inputs)
                   if n[:2].isdigit())
    prev = digest(GENESIS_SEED.encode("utf-8"))
    for i, name in enumerate(chain, start=1):
        obj = json.loads((HERE / f"{name}.input.json").read_text(encoding="utf-8"))
        if obj.get("chain_position") != i:
            failures.append(f"{name}: chain_position {obj.get('chain_position')}, want {i}")
        check(f"{name}: prev_event_hash", obj.get("prev_event_hash"), prev)
        prev = (HERE / f"{name}.hash").read_bytes().decode("ascii")

    # --- ADR-0004, unchanged by schema 2: idempotency_key is carried by exactly
    # the events whose originating MCP tool accepts one.
    ACCEPTS = {"run_registered", "tool_call", "commit_intent", "commit_recorded"}
    FORBIDS = {"credential_issued", "run_retired"}

    # --- ADR-0045 and ADR-0047: what schema 2 adds, and where.
    REQUIRED_BY_TYPE = {
        "run_registered": ("repo", "branch"),
        "commit_intent": ("patch_id",),
        "commit_recorded": ("patch_id",),
    }
    subagents = 0

    for src in inputs:
        name = src.name[: -len(".input.json")]
        obj = json.loads(src.read_text(encoding="utf-8"))
        etype, source = obj.get("event_type"), obj.get("source")
        if etype is None:
            continue                      # the serializer probe is not an event
        has = "idempotency_key" in obj
        if etype in FORBIDS and has:
            failures.append(f"{name}: {etype} carries an idempotency_key (ADR-0004)")
        if etype in ACCEPTS and source == "mcp" and not has:
            failures.append(f"{name}: {etype} from mcp has no idempotency_key (ADR-0004)")
        if has and len(obj["idempotency_key"].encode("utf-8")) > 128:
            failures.append(f"{name}: idempotency_key exceeds 128 bytes")

        for member in REQUIRED_BY_TYPE.get(etype, ()):
            if member not in obj:
                failures.append(f"{name}: {etype} has no {member} (schema 2)")
        if "patch_id" in obj and not OBJECT_ID.match(obj["patch_id"]):
            failures.append(f"{name}: patch_id {obj['patch_id']!r} is not an object id")
        if "parent_run_id" in obj:
            subagents += 1
            if obj["parent_run_id"] == obj.get("run_id"):
                failures.append(f"{name}: parent_run_id is the run's own id")

    # parent_run_id is schema 2's one OPTIONAL member, and an optional member no
    # fixture carries is an untested member.
    if subagents == 0:
        failures.append("no fixture carries parent_run_id, so nothing pins it")

    if failures:
        print(f"FAIL: {len(failures)} fixture mismatch(es)")
        for f in failures:
            print("  - " + f)
        return 1

    print(f"OK: {len(inputs)} fixtures re-derived independently; "
          f"{len(chain)}-event chain walked from the genesis constant; "
          f"ADR-0004 placement, ADR-0045 and ADR-0047 membership hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

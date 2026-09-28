#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-derive every schema-4 golden fixture with an oracle that is not Go.

Same job as ../v1/verify.py and, deliberately, the same method: these fixtures
are the normative, byte-level definition of a protected surface, and a fixture
only ever checked by the implementation it came from proves nothing.  See that
file for why `json.dumps` is a valid RFC 8785 oracle for this schema; the
argument is unchanged, because the SERIALIZATION is unchanged.  Schema 4 adds
members and one type; it does not touch how members are ordered, escaped or
hashed.

    python3 verify.py            # from this directory

What this checks that v3's does not:

  * ADR-0061 decision 1 - `run_registered` may carry `forked_from_run_id`, the
    run_id grammar.
  * ADR-0061 decision 2 - `agent_message` carries `role` (brief | assistant)
    and a KEYED `payload_digest`: hmac-sha256:<key-id>:<64 lowercase hex>, not
    the plain sha256:<64 hex> every other type's payload_digest uses.
  * ADR-0061 decision 3 - `tool_call` may carry `workspace_tree_hash`, a git
    object id.
  * every fixture declares `schema_version` "4".

What it does NOT check, and where that lives instead:

  * the genesis constant, which is not a property of a schema version - the
    seed is `innsegl-genesis-v1` under every version, doc 02 §4.4 ties it to
    chain_position 1, and ../v1/genesis.hash is where it is committed. The
    chain below is still walked FROM it, computed here rather than trusted.
  * the HMAC computation or the per-deployment secret behind a keyed digest --
    this package (and this oracle) check the GRAMMAR only, never the
    computation, which is the recorder's job (E16, ADR-0061 decision 2).

This script only ever READS the fixtures. Fixtures are immutable once merged
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
SCHEMA_VERSION = "4"
OBJECT_ID = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
KEYED_DIGEST = re.compile(r"^hmac-sha256:[a-z0-9][a-z0-9-]{0,62}:[0-9a-f]{64}$")
PLAIN_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
AGENT_MESSAGE_ROLES = {"brief", "assistant"}


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

    # --- ADR-0004, unchanged by schema 4: idempotency_key is carried by
    # exactly the events whose originating MCP tool accepts one.
    ACCEPTS = {"run_registered", "tool_call", "commit_intent", "commit_recorded"}
    FORBIDS = {"credential_issued", "run_retired"}

    # --- ADR-0061: what schema 4 adds, and where.
    forks = 0
    workspace_trees = 0
    roles_seen = set()

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

        if "forked_from_run_id" in obj:
            forks += 1
            if not RUN_ID.match(obj["forked_from_run_id"]):
                failures.append(f"{name}: forked_from_run_id {obj['forked_from_run_id']!r} "
                                 f"is not a run id")
            if obj["forked_from_run_id"] == obj.get("run_id"):
                failures.append(f"{name}: forked_from_run_id is the run's own id")

        if "workspace_tree_hash" in obj:
            workspace_trees += 1
            if not OBJECT_ID.match(obj["workspace_tree_hash"]):
                failures.append(f"{name}: workspace_tree_hash {obj['workspace_tree_hash']!r} "
                                 f"is not an object id")

        if etype == "agent_message":
            role = obj.get("role")
            if role not in AGENT_MESSAGE_ROLES:
                failures.append(f"{name}: agent_message role {role!r} not in {AGENT_MESSAGE_ROLES}")
            roles_seen.add(role)
            pd = obj.get("payload_digest")
            if pd is None:
                failures.append(f"{name}: agent_message has no payload_digest")
            else:
                if not KEYED_DIGEST.match(pd):
                    failures.append(f"{name}: agent_message payload_digest {pd!r} is not "
                                     f"the keyed grammar hmac-sha256:<key-id>:<64 hex>")
                if PLAIN_DIGEST.match(pd):
                    failures.append(f"{name}: agent_message payload_digest {pd!r} matches "
                                     f"the PLAIN grammar too, which the keyed one must exclude")
        elif "payload_digest" in obj:
            # Every other type keeps the plain envelope grammar, unchanged.
            pd = obj["payload_digest"]
            if not PLAIN_DIGEST.match(pd):
                failures.append(f"{name}: {etype} payload_digest {pd!r} is not the plain "
                                 f"envelope grammar sha256:<64 hex>")
            if KEYED_DIGEST.match(pd):
                failures.append(f"{name}: {etype} payload_digest {pd!r} matches the KEYED "
                                 f"grammar, which is exclusive to agent_message")

    # forked_from_run_id and workspace_tree_hash are both OPTIONAL, and an
    # optional member no fixture carries is an untested member.
    if forks == 0:
        failures.append("no fixture carries forked_from_run_id, so nothing pins it")
    if workspace_trees == 0:
        failures.append("no fixture carries workspace_tree_hash, so nothing pins it")
    if roles_seen != AGENT_MESSAGE_ROLES:
        failures.append(f"agent_message roles seen = {roles_seen}, want {AGENT_MESSAGE_ROLES}")

    if failures:
        print(f"FAIL: {len(failures)} fixture mismatch(es)")
        for f in failures:
            print("  - " + f)
        return 1

    print(f"OK: {len(inputs)} fixtures re-derived independently; "
          f"{len(chain)}-event chain walked from the genesis constant; "
          f"ADR-0004 placement and ADR-0061 membership hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

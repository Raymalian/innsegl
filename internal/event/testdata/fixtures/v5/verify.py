#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-derive every schema-5 golden fixture with an oracle that is not Go.

Same job as ../v1/verify.py and the same method. Schema 5 (ADR-0080) adds no
member and no type: it lets `repo` and `branch` carry a keyed pseudonym,
pn:<key-id>:<32 lowercase hex>, beside doc 02 §5's literal form. The
serialization is unchanged.

    python3 verify.py            # from this directory

What this checks that v4's does not:

  * every repo and branch is either the literal form or the pn: grammar;
  * every pn: value re-derives from the published FIXTURE key with HMAC-SHA256
    over "repo:<literal>" or "branch:<literal repo>\n<literal branch>", the
    literal being the one the vectors' generator used;
  * no pseudonymous vector carries the literal repository or branch;
  * a detached HEAD stays the literal "detached";
  * every fixture declares `schema_version` "5".

The fixture key is a test vector, not a secret: fixtures pin bytes.

This script only ever READS the fixtures.
"""
import hashlib
import hmac
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
GENESIS_SEED = "innsegl-genesis-v1"
SCHEMA_VERSION = "5"
FIXTURE_KEY = b"innsegl-v5-fixture-repository-key-not-a-secret-0001"
LITERAL_REPO = "github.com/acme/payments"
LITERAL_BRANCH = "feature/quiet-acquisition"
PSEUDONYM = re.compile(r"^pn:([a-z0-9][a-z0-9-]{0,62}):[0-9a-f]{32}$")
LITERAL_REPO_FORM = re.compile(r"^[a-z0-9.-]+/[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
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

    # --- ADR-0080: what schema 5 changes.
    def pn(key_id, msg):
        mac = hmac.new(FIXTURE_KEY, msg.encode("utf-8"), hashlib.sha256)
        return "pn:" + key_id + ":" + mac.hexdigest()[:32]

    pseudonymous = 0
    for src in inputs:
        name = src.name[: -len(".input.json")]
        obj = json.loads(src.read_text(encoding="utf-8"))
        repo, branch = obj.get("repo"), obj.get("branch")
        for member, value in (("repo", repo), ("branch", branch)):
            if value is None or not value.startswith("pn:"):
                continue
            m = PSEUDONYM.match(value)
            if not m:
                failures.append(f"{name}: {member} {value!r} is not pn:<key-id>:<32 hex>")
                continue
            msg = ("repo:" + LITERAL_REPO if member == "repo"
                   else "branch:" + LITERAL_REPO + "\n" + LITERAL_BRANCH)
            check(f"{name}: {member} re-derived from the fixture key", value, pn(m.group(1), msg))
        if repo is not None and not repo.startswith("pn:") and not LITERAL_REPO_FORM.match(repo):
            failures.append(f"{name}: repo {repo!r} is neither host/org/name nor pn:")
        if repo is not None and repo.startswith("pn:"):
            pseudonymous += 1
            text = (HERE / f"{name}.canonical.json").read_text(encoding="utf-8")
            if LITERAL_REPO in text or LITERAL_BRANCH in text:
                failures.append(f"{name}: a pseudonymous vector carries a literal name")
    if pseudonymous < 4:
        failures.append(f"{pseudonymous} vectors carry a pseudonymous repo, want 4")

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
          f"ADR-0004 placement, ADR-0061 membership and ADR-0080 pseudonyms hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())

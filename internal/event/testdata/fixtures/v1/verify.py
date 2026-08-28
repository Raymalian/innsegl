#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Re-derive every innsegl golden fixture with an oracle that is not Go.

These fixtures are the normative, byte-level definition of a protected surface
(VERSIONING.md: "Where a document and a fixture disagree, the fixture wins").
A fixture that is only ever checked by the implementation it came from proves
nothing, so this script re-derives the canonical bytes and the event_hash of
every fixture from its `.input.json` using nothing but the Python standard
library, and fails if any committed byte differs.

    python3 verify.py            # from this directory

Why json.dumps is a valid RFC 8785 oracle *for this schema*:

  * member sorting   - JCS sorts member names by UTF-16 code unit, Python by
                       code point.  The two orders agree for every name in the
                       Basic Multilingual Plane and diverge only above U+FFFF.
                       Every member name in doc 02 is ASCII, and member names
                       are a protected surface, so the orders cannot diverge.
  * string escaping  - both escape only `"`, `\\` and U+0000..U+001F, both use
                       the short forms \\b \\f \\n \\r \\t where they exist and
                       lower-case \\u00xx otherwise, and both emit every other
                       character, U+2028 and U+2029 included, as raw UTF-8.
  * numbers          - doc 02 admits only integers inside the JCS-safe range,
                       where the ES6 number format JCS mandates and Python's
                       integer repr are the same digits.
  * whitespace       - separators=(",", ":") is JCS's "no insignificant
                       whitespace".

This script only ever READS the fixtures.  Fixtures are immutable once merged
(doc 02 §7); regenerating one is a major schema version with a migration
attestation, never a convenience.
"""
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
GENESIS_SEED = "innsegl-genesis-v1"


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

    # doc 02 §4.4 - the genesis constant, computed rather than trusted.
    check("genesis.hash",
          digest(GENESIS_SEED.encode("utf-8")),
          (HERE / "genesis.hash").read_bytes().decode("ascii"))

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

    if failures:
        print(f"FAIL: {len(failures)} fixture mismatch(es)")
        for f in failures:
            print("  - " + f)
        return 1

    print(f"OK: {len(inputs)} fixtures re-derived independently, plus the "
          f"genesis constant")
    return 0


if __name__ == "__main__":
    sys.exit(main())

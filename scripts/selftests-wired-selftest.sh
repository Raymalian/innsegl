#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/selftests-wired.sh, driven against scratch repositories (#279).
#
# Each case builds a root holding one self-test and one workflow, and changes
# one thing. A gate that passed everything or refused everything fails here.
set -uo pipefail

GATE="${INNSEGL_SELFTESTS_WIRED:-$(cd "$(dirname "$0")" && pwd)/selftests-wired.sh}"
pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# root <name> — a scratch repository with scripts/a-selftest.sh and an empty
# workflow directory.
root() {
  local r="$WORK/$1"
  mkdir -p "$r/scripts" "$r/.github/workflows"
  printf '#!/bin/sh\nexit 0\n' > "$r/scripts/a-selftest.sh"
  printf 'jobs: {}\n' > "$r/.github/workflows/ci.yml"
  printf '%s' "$r"
}

gate() { INNSEGL_NOT_IN_CI="${2-}" "$GATE" "$1" >/dev/null 2>&1; }

r="$(root wired)"; printf '      run: ./scripts/a-selftest.sh\n' >> "$r/.github/workflows/ci.yml"
if gate "$r"; then ok "a self-test a workflow runs passes"; else bad "a wired self-test was refused"; fi

r="$(root unwired)"
if ! gate "$r"; then ok "a self-test no workflow runs is refused"; else bad "an unwired self-test passed"; fi

r="$(root excused)"
if gate "$r" "scripts/a-selftest.sh|needs something CI cannot have"; then
  ok "an unwired self-test with a recorded reason passes"
else
  bad "a recorded reason was not honoured"
fi

r="$(root stale)"; printf '      run: ./scripts/a-selftest.sh\n' >> "$r/.github/workflows/ci.yml"
if ! gate "$r" "scripts/gone-selftest.sh|a reason for a file that is not there"; then
  ok "a recorded reason for a file that does not exist is refused"
else
  bad "a stale reason passed"
fi

r="$WORK/empty"; mkdir -p "$r/scripts" "$r/.github/workflows"
if ! gate "$r"; then ok "a tree with no self-tests at all is refused, not passed on nothing"; else bad "an empty tree passed"; fi

echo
echo "selftests-wired-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

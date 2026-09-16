#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The gate, watched failing — scripts/no-operator-paths.sh's own test.
#
# IP §2: no production code exists without a test observed failing first. A
# content gate is the case where that matters most, because its failure mode is
# silent: a grep that matches nothing passes every file, reports success, and is
# indistinguishable from a working gate until the day something slips past.
#
# RM-133 (#212) exists because two files reached main naming the operator's
# home directory — once in a compose comment, four times in captured gate
# output — and nothing checked. Both were measured evidence, which is CLAUDE.md's
# stated trap: "a comment that says 'measured on this machine' is exactly where
# a real project name gets written down."
#
# Seven cases, and the last two are the ones usually left out:
#
#   1. GREEN on the repository as it stands.
#   2. RED on a planted /Users/<name>/... path.
#   3. RED on a planted /home/<name>/... path.
#   4. GREEN on /home/innsegl/... — the container image's OWN user, which
#      appears in both Dockerfiles and is not an operator path. A gate that
#      fires on it would be turned off within a week.
#   5. RED on a user whose name merely BEGINS with the container's user —
#      the allowlist must match a whole name, not a prefix.
#   6. GREEN on a path inside docs/, which is local-only and never pushed.
#   7. RED on a path inside docs/adr/, which SHIPS. Both directions, because
#      one without the other is how the exclusion got too wide in the first
#      place: `docs/` was local-only when that line was written, and stopped
#      being local-only when ADRs started shipping.
#
# Case 4 carries a TRAILING SEGMENT deliberately. It was first written as
# `HOME=/home/innsegl`, which the gate's pattern — a home directory followed by
# a name and a further segment — never matches at all, so the case passed
# without ever reaching the allowlist it exists to test. Mutation-testing the
# gate is what exposed it: deleting the allowlist entirely left the selftest
# reporting five passes. A case that cannot fail is worse than no case.
#
# USAGE
#   scripts/no-operator-paths-selftest.sh

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GATE="$ROOT/scripts/no-operator-paths.sh"

# The plant literals are ASSEMBLED rather than written out, so this file does
# not itself contain the thing it plants. Exempting the selftest from the gate
# would have been the easy way and is a hole: a gate with an exemption is a gate
# with a place to hide.
HOMES="/Users"
HOMEL="/home"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

if [ ! -x "$GATE" ]; then
  echo "no-operator-paths-selftest: $GATE is missing or not executable" >&2
  exit 4
fi

# run_gate FILE... -> returns the gate's exit status, output suppressed.
#
# The gate reads git-tracked files, so a planted file must be `git add`ed. The
# working tree is left exactly as it was found: every case removes its own
# plant, including on failure.
run_gate() { ( cd "$ROOT" && "$GATE" >/dev/null 2>&1 ); }

plant() {  # plant PATH CONTENT
  printf '%s\n' "$2" > "$ROOT/$1"
  ( cd "$ROOT" && git add -- "$1" >/dev/null 2>&1 )
}
# plantf forces the file into the index, for a path .gitignore covers. The
# gate reads `git ls-files`, so an ignored plant is no plant at all.
plantf() {  # plantf PATH CONTENT
  printf '%s\n' "$2" > "$ROOT/$1"
  ( cd "$ROOT" && git add -f -- "$1" >/dev/null 2>&1 )
}
unplant() {
  ( cd "$ROOT" && git rm -q --cached --force -- "$1" >/dev/null 2>&1 || true )
  rm -f "$ROOT/$1"
}

# --- case 1: green on the repository as it stands ---------------------------
if run_gate; then
  ok "green on the repository as it stands (exit 0)"
else
  bad "THE REPOSITORY ALREADY CARRIES AN OPERATOR PATH — run the gate to see it"
fi

# --- case 2: red on a /Users path -------------------------------------------
plant "selftest-plant-users.txt" "measured at $HOMES/someone/Applications/thing/.git"
if run_gate; then
  bad "THE GATE ACCEPTED A /Users PATH (exit 0)"
else
  ok "red on a planted /Users path"
fi
unplant "selftest-plant-users.txt"

# --- case 3: red on a /home path --------------------------------------------
plant "selftest-plant-home.txt" "measured at $HOMEL/someone/src/thing/.git"
if run_gate; then
  bad "THE GATE ACCEPTED A /home PATH (exit 0)"
else
  ok "red on a planted /home path"
fi
unplant "selftest-plant-home.txt"

# --- case 4: green on the image's own user ----------------------------------
#
# This is the case that decides whether the gate survives contact. Both
# Dockerfiles set HOME=/home/innsegl and WORKDIR /home/innsegl; a gate that
# calls those violations is a gate someone disables.
plant "selftest-plant-container.txt" "COPY --chown=innsegl $HOMEL/innsegl/work/ledger ."
if run_gate; then
  ok "green on $HOMEL/innsegl/..., the image's own user"
else
  bad "THE GATE FIRED ON THE CONTAINER'S OWN USER — it will be turned off"
fi
unplant "selftest-plant-container.txt"

# --- case 5: the allowlist matches a user, not a prefix ---------------------
# The name is assembled, like every other plant in this file: writing it out
# would put a violation in a tracked file and fail the gate this very script
# tests. See the note beside HOMES/HOMEL above.
PREFIXUSER="innsegl""user"
plant "selftest-plant-prefix.txt" "measured at $HOMEL/$PREFIXUSER/src/thing"
if run_gate; then
  bad "THE ALLOWLIST OVER-MATCHES — a name merely beginning with the image's user was accepted"
else
  ok "red on a user name that merely starts with the image's user"
fi
unplant "selftest-plant-prefix.txt"

# --- case 6: green on the rest of docs/, which never ships -------------------
#
# `git add -f`, and it is not a detail. `docs/*` is gitignored, so a plain
# `git add` here adds NOTHING, the gate never sees the file, and the case
# passes on a green that says nothing about the skip it exists to test. Forced
# into the index the file is genuinely tracked, and only the gate's own
# exclusion can keep it from being read.
if [ -d "$ROOT/docs" ]; then
  plantf "docs/selftest-plant-doc.txt" "measured at $HOMES/someone/Applications/thing"
  if run_gate; then
    ok "green on a path inside docs/, which is local-only and never pushed"
  else
    bad "THE GATE FIRED ON docs/, which does not ship"
  fi
  unplant "docs/selftest-plant-doc.txt"
fi

# --- case 7: red on docs/adr/, which SHIPS ----------------------------------
#
# The one docs directory that reaches the public repository was the one
# directory the gate skipped. `docs/adr/` is tracked, is in every clone, and
# CLAUDE.md names it out loud: "That includes `docs/adr/`, which is the one
# docs directory that does ship."
#
# Measured before the fix: a file carrying an operator home path at
# docs/adr/0099-probe.md produced "784 shipped files, none names an operator
# path". A false pass, in the gate whose entire job is to prevent one.
if [ -d "$ROOT/docs/adr" ]; then
  plant "docs/adr/9999-selftest-plant.md" "measured at $HOMES/someone/Applications/thing"
  if run_gate; then
    bad "THE GATE SKIPPED docs/adr/, WHICH SHIPS — the one docs directory in every clone"
  else
    ok "red on a path inside docs/adr/, which ships"
  fi
  unplant "docs/adr/9999-selftest-plant.md"
fi

echo "no-operator-paths-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1

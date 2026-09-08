#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The gate, watched failing — scripts/verify-branch.sh's own test.
#
# IP §2: no production code exists without a test observed failing first. A
# merge gate is the case where that matters most, because the failure mode is
# silent: a gate that cannot fail passes everything, reports success, and is
# indistinguishable from a working one until the day it was supposed to catch
# something. `verify-branch.sh` returns 0 on a branch of ordinary commits, and
# this file is what establishes that it does so on merit.
#
# Three cases, and the third is the one usually left out:
#
#   1. GREEN on a branch whose commits make no attribution claim.
#   2. RED (exit 3) when a commit carries an Agent-Identity trailer its
#      signature does not support — a forged claim.
#   3. INCONCLUSIVE (exit 4), NOT red and NOT green, when Rekor cannot be
#      reached. doc 06 P2 and AB-08: "could not check" is never "checked".
#
# Case 2 forges a claim the only way that produces a real one: it takes a
# genuinely signed commit and rewrites its Agent-Identity trailer, leaving the
# gpgsig header untouched. The signature is real, the certificate is real, and
# the trailer now names an identity the certificate does not carry — which is
# exactly what `innsegl verify`'s third check exists to catch, and exactly what
# a developer pasting a trailer to blame an agent would produce (AB-05).
#
# USAGE
#   scripts/verify-branch-selftest.sh
#
# It needs the deployment up for cases 1 and 2 — the commits under test were
# signed against a local Fulcio and Rekor and are meaningless without them.
#   export INNSEGL_FULCIO_URL=http://127.0.0.1:5555
#   export INNSEGL_REKOR_URL=http://127.0.0.1:3010

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
GATE="$ROOT/scripts/verify-branch.sh"

# SIGNED_FIXTURE is a commit in this repository's history that carries a real
# Agent-Identity trailer and a real signature. Pinned rather than discovered:
# a selftest that went looking for "any signed commit" would quietly test
# nothing on the day there are none, which is the failure this file exists to
# prevent in the gate itself.
SIGNED_FIXTURE="${SIGNED_FIXTURE:-e58bd5cd5aeec4e349309cdd9b5b4b3d6185d982}"

pass=0
fail=0

ok()   { pass=$((pass + 1)); echo "  ok    $1"; }
bad()  { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

# run_gate BASE -> prints nothing, returns the gate's exit status.
run_gate() {
  set +e
  GATE_OUT="$("$GATE" "$1" 2>&1)"
  GATE_STATUS=$?
  set -e
}

echo "verify-branch-selftest: three cases"

# ---------------------------------------------------------------------------
# 0. The fixture has to be what this file claims it is, or cases 2 and 3 are
#    testing something else. Checked rather than assumed.
# ---------------------------------------------------------------------------
if ! git -C "$ROOT" cat-file -e "$SIGNED_FIXTURE^{commit}" 2>/dev/null; then
  echo "verify-branch-selftest: the pinned fixture $SIGNED_FIXTURE is not in this repository." >&2
  echo "  It is the signed commit cases 2 and 3 rewrite. Set SIGNED_FIXTURE to another" >&2
  echo "  commit carrying a real Agent-Identity trailer, or fetch the branch that has it." >&2
  exit 4
fi
if ! git -C "$ROOT" cat-file commit "$SIGNED_FIXTURE" | grep -q '^gpgsig'; then
  echo "verify-branch-selftest: fixture $SIGNED_FIXTURE carries no signature; it cannot forge a claim." >&2
  exit 4
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The verifier is built once, here, and handed to every case through
# INNSEGL_BIN. The gate builds its own when that is unset — with `go build
# ./cmd/innsegl`, relative to the working directory — and case 1 runs inside a
# throwaway repository that has no go.mod. Measured: the first run of this file
# failed case 1 with "cannot find main module".
BIN="$WORK/innsegl"
(cd "$ROOT" && go build -o "$BIN" ./cmd/innsegl)
export INNSEGL_BIN="$BIN"

# ---------------------------------------------------------------------------
# 1. GREEN: a branch of ordinary, unattributed commits.
# ---------------------------------------------------------------------------
REPO1="$WORK/plain"
git init -q -b main "$REPO1"
(
  cd "$REPO1"
  git config user.email "selftest@innsegl.invalid"
  git config user.name "Selftest"
  echo one > a.txt && git add a.txt && git commit -qm "first"
  git branch -q base
  echo two > b.txt && git add b.txt && git commit -qm "second"
)
# NOT in a subshell, and that is load-bearing: `bad` increments a counter, and
# a counter incremented inside `( ... )` is discarded when the subshell exits.
# Measured: an earlier version of this file ran every case in a subshell,
# failed case 1, and reported "2 passed, 0 failed" with exit 0 — a selftest
# lying about itself, which is the one defect it exists to prevent.
CASE1_DIR="$PWD"
cd "$REPO1"
INNSEGL_REPO="$REPO1" run_gate base
cd "$CASE1_DIR"
if [ "$GATE_STATUS" -eq 0 ]; then
  ok "green on a branch that claims nothing (exit 0)"
else
  bad "a branch of unattributed commits returned $GATE_STATUS, want 0"
  printf '%s\n' "$GATE_OUT" | tail -5 >&2
fi

# ---------------------------------------------------------------------------
# 2. RED: a forged Agent-Identity trailer on a genuinely signed commit.
#
#    The commit object is rebuilt by hand. `git commit --amend` would re-sign
#    or drop the signature; hash-object writes the object as given, so the
#    gpgsig header survives a changed trailer — which is the whole point.
# ---------------------------------------------------------------------------
FORGED="$(
  cd "$ROOT"
  git cat-file commit "$SIGNED_FIXTURE" \
    | sed 's|^Agent-Identity: .*|Agent-Identity: spiffe://innsegl.dev/agent/00000000/00000000/run-forged|' \
    | git hash-object -t commit -w --stdin
)"
if [ "$FORGED" = "$SIGNED_FIXTURE" ]; then
  bad "rewriting the trailer produced the same object; the forgery did not happen"
else
  # THROUGH THE GATE, not around it. An earlier version of this file verified
  # the forged commit directly with the binary, which tests `innsegl verify`
  # and says nothing about verify-branch.sh — measured by mutating the gate to
  # exit 0 unconditionally and watching this case keep passing.
  #
  # A --shared clone so the forged object, which was written into this
  # repository's store, is visible without copying it, and so nothing moves
  # HEAD in the working repository.
  FORGEDREPO="$WORK/forged"
  git clone -q --shared "$ROOT" "$FORGEDREPO"
  git -C "$FORGEDREPO" reset -q --hard "$FORGED"

  CASE2_DIR="$PWD"
  cd "$FORGEDREPO"
  INNSEGL_REPO="$FORGEDREPO" run_gate "$SIGNED_FIXTURE^"
  cd "$CASE2_DIR"

  case "$GATE_STATUS" in
    3) ok "red on a forged Agent-Identity trailer (exit 3)" ;;
    4) bad "forged trailer returned 4 (inconclusive) — bring the deployment up and rerun" ;;
    0) bad "THE GATE ACCEPTED A FORGED Agent-Identity TRAILER (exit 0)" ;;
    *) bad "a forged Agent-Identity trailer returned $GATE_STATUS, want 3" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 3. INCONCLUSIVE: Rekor unreachable must be 4, never 0 and never 3.
#
#    Port 1 is nobody's Rekor, on 127.0.0.1 or anywhere else.
# ---------------------------------------------------------------------------
set +e
(
  cd "$ROOT"
  INNSEGL_REKOR_URL="http://127.0.0.1:1" \
  INNSEGL_REPO="$ROOT" "$GATE" "$SIGNED_FIXTURE^" >/dev/null 2>&1
)
UNAVAIL_STATUS=$?
set -e
case "$UNAVAIL_STATUS" in
  4) ok "inconclusive when Rekor is unreachable (exit 4, not 0 and not 3)" ;;
  0) bad "an unreachable Rekor returned 0 — the gate would pass every commit with the stack down" ;;
  3) bad "an unreachable Rekor returned 3 — 'could not check' reported as 'failed' (doc 06 P2)" ;;
  *) bad "an unreachable Rekor returned $UNAVAIL_STATUS, want 4" ;;
esac

echo
echo "verify-branch-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
echo "verify-branch-selftest: OK — the gate is green on merit, red on a forgery, and honest when it cannot check."

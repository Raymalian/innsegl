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
# FOUR CASES, AND WHAT EACH ONE PROVES
#
#   1. GREEN (exit 0) on a branch whose commits make no attribution claim.
#      Proves the gate can return zero at all, and that it returns zero for the
#      right reason — the verifier reported "unattributed" (its exit 5), not
#      "we could not look". A gate that cannot pass gets switched off.
#
#   2. RED (exit 3) on a commit carrying an Agent-Identity trailer its signature
#      does not support. Proves the gate refuses a forged attribution claim, and
#      refuses it in the words reserved for one. This is the case the gate
#      exists for; everything else is about not crying wolf.
#
#   3. INCONCLUSIVE (exit 4) when the transparency log is unreachable and
#      nothing else has changed. Proves the gate tells an outage from a forgery.
#      doc 06 P2 and AB-08: "could not check" is never "checked". The same
#      commit returns 0 in case 0c with the log up, so the ONLY variable this
#      case moves is whether Rekor answers — which is what makes exit 4 here
#      mean something.
#
#   4. UNCHECKABLE (exit 6), never 3, when the verifier is unconfigured.
#      Proves the gate does not accuse a commit it never looked at. Until #281
#      it did: `innsegl verify` exits 6 on a configuration it cannot verify
#      with, the gate swept every unrecognised status into its failure bucket,
#      and an ordinary commit came out as "claim(s) an agent identity that does
#      not hold" because two environment variables were missing. That is doc 06
#      P2's collapse, and it is the one that teaches people REFUSED means
#      `--no-verify`.
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
# It needs the deployment up and the verifier pointed at it. Both URLs, always:
# a verifier given one of them refuses to start, and every case would come out
# UNCHECKABLE — including the three that are not testing that.
#
#   export INNSEGL_FULCIO_URL=http://127.0.0.1:5555
#   export INNSEGL_REKOR_URL=http://127.0.0.1:23000
#
# Those are the ports deploy/compose publishes; `deploy/compose/sigstore/verify.sh`
# is where the defaults live if they ever move.

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
GATE="$ROOT/scripts/verify-branch.sh"

# SIGNED_FIXTURE is a commit in this repository's history that carries a real
# Agent-Identity trailer and a real signature. Pinned rather than discovered:
# a selftest that went looking for "any signed commit" would quietly test
# nothing on the day there are none, which is the failure this file exists to
# prevent in the gate itself.
#
# A pin rots. Re-key Fulcio or start a fresh transparency log and the old
# certificate stops chaining and the old entry stops existing — so case 0c
# below verifies the fixture BEFORE anything forges it, and says which of the
# two happened. Measured: the previous pin (e58bd5c, signed 2026-09-07) failed
# checks 1 and 2 unforged, which meant case 2 had been going red with no
# forgery in it at all.
# Re-pinned 2026-09-26: the previous pin was re-hashed when main's history was
# rewritten, and a rewritten commit carries no signature. This one was signed
# after the rewrite and passes all four cases against the running deployment.
SIGNED_FIXTURE="${SIGNED_FIXTURE:-3bd15bc9400754d997ac6c19e0ed01c4e3bb3ff0}"

# Port 1 is nobody's Rekor, on 127.0.0.1 or anywhere else.
DEAD_REKOR="http://127.0.0.1:1"

pass=0
fail=0

ok()   { pass=$((pass + 1)); echo "  ok    $1"; }
bad()  { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

# run_gate DIR BASE [env overrides…] — runs the gate inside DIR, against BASE,
# and records its exit status in GATE_STATUS and its output in GATE_OUT.
#
# The gate runs inside a command substitution, which is its own subshell: the
# `cd` cannot move this shell, and — unlike running a whole CASE in `( … )` —
# `pass` and `fail` are still incremented HERE, where they survive. That is
# load-bearing. Measured: an earlier version of this file ran every case in a
# subshell, failed case 1, and reported "2 passed, 0 failed" with exit 0 — a
# selftest lying about itself, which is the one defect it exists to prevent.
#
# No pipe anywhere near it, either: `cmd | head` reports head's status.
run_gate() {
  _dir="$1"
  _base="$2"
  shift 2
  set +e
  GATE_OUT="$(cd "$_dir" && env "$@" INNSEGL_REPO="$_dir" "$GATE" "$_base" 2>&1)"
  GATE_STATUS=$?
  set -e
}

# The preconditions come before the banner. A file that announces four cases
# and then refuses to run any of them reads as a crash; the refusals below are
# deliberate, and each says what to do about it.

# ---------------------------------------------------------------------------
# 0a. The verifier has to be configured, or every case below measures the same
#     thing — case 4 — and three of them report it as a failure of something
#     else. Refused here, loudly, rather than discovered in a truncated tail.
# ---------------------------------------------------------------------------
if [ -z "${INNSEGL_FULCIO_URL:-}" ] || [ -z "${INNSEGL_REKOR_URL:-}" ]; then
  echo "verify-branch-selftest: the verifier is unconfigured; cases 1-3 cannot run." >&2
  echo "  A verifier needs BOTH a Fulcio and a Rekor URL. Bring the deployment up and:" >&2
  echo "    export INNSEGL_FULCIO_URL=http://127.0.0.1:5555" >&2
  echo "    export INNSEGL_REKOR_URL=http://127.0.0.1:23000" >&2
  exit 4
fi

# ---------------------------------------------------------------------------
# 0b. The fixture has to be what this file claims it is, or cases 2, 3 and 4
#     are testing something else. Checked rather than assumed.
# ---------------------------------------------------------------------------
if ! git -C "$ROOT" cat-file -e "$SIGNED_FIXTURE^{commit}" 2>/dev/null; then
  echo "verify-branch-selftest: the pinned fixture $SIGNED_FIXTURE is not in this repository." >&2
  echo "  It is the signed commit cases 2, 3 and 4 are built on. Set SIGNED_FIXTURE to" >&2
  echo "  another commit carrying a real Agent-Identity trailer, or fetch the branch" >&2
  echo "  that has it." >&2
  exit 4
fi
if ! git -C "$ROOT" cat-file -p "$SIGNED_FIXTURE" | grep -q '^gpgsig'; then
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
# 0c. The fixture VERIFIES, unforged, right now.
#
#     Without this, case 2 goes red whether or not the trailer was forged and
#     case 3 can never reach 4, and both report success. The three outcomes are
#     told apart deliberately: a rotted pin and a deployment that is down need
#     completely different things done about them, which is the same
#     distinction the gate itself is being tested on.
# ---------------------------------------------------------------------------
set +e
FIXTURE_OUT="$("$BIN" verify "$SIGNED_FIXTURE" -repo "$ROOT" 2>&1)"
FIXTURE_STATUS=$?
set -e
# The verdict and the three results, not the tail of the report: the tail is
# check 3, which is the one that still passes on a rotted fixture and so says
# nothing about why this refused.
fixture_digest() {
  printf '%s\n' "$FIXTURE_OUT" | grep -E 'VERDICT|^  [0-9]\. |result:' >&2 || true
}
case "$FIXTURE_STATUS" in
  0) : ;;
  4)
    echo "verify-branch-selftest: the deployment is not reachable; the fixture cannot be verified." >&2
    echo "  Bring it up — \`make innsegl-up\` — and run this again." >&2
    fixture_digest
    exit 4
    ;;
  3)
    echo "verify-branch-selftest: the pinned fixture $SIGNED_FIXTURE no longer verifies." >&2
    echo "  Its certificate no longer chains, or the current log holds no entry for it —" >&2
    echo "  which happens when the deployment is re-keyed or the log is started fresh." >&2
    echo "  Cases 2, 3 and 4 are meaningless against it: case 2 would go red with no" >&2
    echo "  forgery in it. Re-pin SIGNED_FIXTURE to a commit on main that verifies today." >&2
    fixture_digest
    exit 4
    ;;
  *)
    echo "verify-branch-selftest: verifying the pinned fixture returned $FIXTURE_STATUS." >&2
    fixture_digest
    exit 4
    ;;
esac

echo "verify-branch-selftest: four cases"

# A --shared clone of this repository, with HEAD moved to the fixture, is how
# cases 3 and 4 gate exactly ONE commit. The gate reads `git rev-list
# BASE..HEAD` in its working directory, so the range is whatever HEAD happens
# to be — and pointing it at this repository's HEAD would gate every commit
# since the fixture. Measured: 164 of them, one of which genuinely failed, so
# case 3 returned 3 and reported the gate had collapsed P2 when it had not.
# A case that cannot tell its own defect from a correct answer proves nothing.
PINNEDREPO="$WORK/pinned"
git clone -q --shared "$ROOT" "$PINNEDREPO"
git -C "$PINNEDREPO" checkout -q --detach "$SIGNED_FIXTURE"

# ---------------------------------------------------------------------------
# 1. GREEN: a branch of ordinary, unattributed commits.
#
#    PROVES: the gate returns 0, and does so because the verifier said
#    "unattributed" (exit 5) — not because it failed to look.
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
run_gate "$REPO1" base
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
#
#    PROVES: the gate refuses a claim the signature does not support, with
#    exit 3, and case 0c has already established the same commit verifies
#    unforged — so the forgery is what moved it.
# ---------------------------------------------------------------------------
FORGED="$(
  cd "$ROOT"
  git cat-file -p "$SIGNED_FIXTURE" \
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
  git -C "$FORGEDREPO" checkout -q --detach "$FORGED"

  run_gate "$FORGEDREPO" "$SIGNED_FIXTURE^"
  case "$GATE_STATUS" in
    3) ok "red on a forged Agent-Identity trailer (exit 3)" ;;
    4) bad "forged trailer returned 4 (inconclusive) — bring the deployment up and rerun" ;;
    6) bad "forged trailer returned 6 (uncheckable) — the verifier could not act on it" ;;
    0) bad "THE GATE ACCEPTED A FORGED Agent-Identity TRAILER (exit 0)" ;;
    *) bad "a forged Agent-Identity trailer returned $GATE_STATUS, want 3" ;;
  esac
fi

# ---------------------------------------------------------------------------
# 3. INCONCLUSIVE: Rekor unreachable must be 4, never 0 and never 3.
#
#    One commit, unforged, already known to verify. The only thing this case
#    changes is the Rekor URL.
#
#    PROVES: an outage and a forgery leave by different doors. Exit 0 here
#    would mean the gate passes everything with the stack down; exit 3 would
#    mean it calls a bad network a forgery, which is doc 06 P2's collapse and
#    the reason people start bypassing gates.
# ---------------------------------------------------------------------------
run_gate "$PINNEDREPO" "$SIGNED_FIXTURE^" INNSEGL_REKOR_URL="$DEAD_REKOR"
case "$GATE_STATUS" in
  4) ok "inconclusive when Rekor is unreachable (exit 4, not 0 and not 3)" ;;
  0) bad "an unreachable Rekor returned 0 — the gate would pass every commit with the stack down" ;;
  3) bad "an unreachable Rekor returned 3 — 'could not check' reported as 'failed' (doc 06 P2)" ;;
  *) bad "an unreachable Rekor returned $GATE_STATUS, want 4" ;;
esac

# ---------------------------------------------------------------------------
# 4. UNCHECKABLE: an unconfigured verifier must be 6, and must not accuse
#    anybody.
#
#    Same commit, same everything, with both URLs taken away. `innsegl verify`
#    refuses to start and exits 6; the gate must carry that through as its own
#    outcome rather than reading it as a verdict.
#
#    PROVES: the status is 6, AND the prose does not borrow a forgery's words.
#    The exit status alone would not catch a regression that kept the number
#    and restored the accusation, and it is the accusation that does the
#    damage (#281).
# ---------------------------------------------------------------------------
run_gate "$PINNEDREPO" "$SIGNED_FIXTURE^" -u INNSEGL_FULCIO_URL -u INNSEGL_REKOR_URL
case "$GATE_STATUS" in
  6)
    if printf '%s' "$GATE_OUT" | grep -q 'claim an agent identity that does not hold'; then
      bad "an unconfigured verifier exited 6 but still accused the commit of a forged claim"
    else
      ok "uncheckable when the verifier is unconfigured (exit 6, and no accusation)"
    fi
    ;;
  0) bad "an unconfigured verifier returned 0 — the gate would pass every commit unconfigured" ;;
  3) bad "an unconfigured verifier returned 3 — a commit nothing looked at, called a forgery (doc 06 P2)" ;;
  *) bad "an unconfigured verifier returned $GATE_STATUS, want 6" ;;
esac

echo
echo "verify-branch-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
echo "verify-branch-selftest: OK — the gate is green on merit, red on a forgery, and honest when it cannot check."

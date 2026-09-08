#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The merge gate for agent-signed commits — #173 (RM-108).
#
# Until this existed, `innsegl verify` was a command nobody ran. Agents signed
# commits, Rekor logged them, and no merge path checked a single one. A
# signature nothing verifies is decoration.
#
# The maintainer's decision on #173 is what this implements: `main` does not
# have to carry signatures — squash-merge detaches them and that is accepted —
# because verification happens HERE, before the merge, where the deployment
# that issued the identity is still reachable. The proof lives in Rekor and in
# the branch object; both survive the squash. What must not be lost is the
# CHECK, and a check is only real if something runs it.
#
# # Why this is a script the harness runs, and not a CI workflow
#
# Commits signed by a local deployment are logged in that deployment's Rekor.
# A GitHub Actions runner cannot reach `http://rekor:3000` on someone's laptop,
# so a CI gate would return exit 4 — inconclusive — on every commit, forever.
# An always-inconclusive gate is an absent gate that looks present, which is
# worse than none.
#
# So it runs where the deployment is. A project signing against public Sigstore
# can run the same script in CI unchanged: point INNSEGL_FULCIO_URL and
# INNSEGL_REKOR_URL at the public endpoints.
#
# # It re-implements nothing
#
# doc 05 §3.1: one verifier. This runs the shipped `innsegl verify` once per
# commit and reads its exit status. The three checks, the tri-state, and every
# judgement about what "verified" means stay in the Go binary.
#
#   0  verified
#   3  the checks ran and attribution does not hold      -> the gate fails
#   4  Fulcio or Rekor unreachable                       -> the gate fails, differently
#   5  the commit makes no attribution claim             -> skipped, not a failure
#   6  unusable: no such commit, unworkable configuration -> the gate fails
#
# Exit 5 is why this script does not grep for `Agent-Identity` itself. The
# verifier already decides what is attributed, and a second opinion here would
# be a second implementation of the question doc 05 §3.1 says has one.
#
# # Exit 4 fails the gate, deliberately
#
# doc 06 P2 and AB-08: "unavailable" is never "verified". A gate that let
# unreachable-Rekor through would pass every commit on a machine with the stack
# down — which is the state a laptop is in most of the time. Rerun it with the
# deployment up; that is the whole remedy.
#
# USAGE
#   scripts/verify-branch.sh [base]       default base: origin/main
#
#   INNSEGL_BIN       the verifier. Default: `go run ./cmd/innsegl`.
#   INNSEGL_REPO      the repository to verify in. Default: this one.
#   INNSEGL_FULCIO_URL / INNSEGL_REKOR_URL   read by the verifier itself.

set -euo pipefail

BASE="${1:-origin/main}"
REPO="${INNSEGL_REPO:-$(git rev-parse --show-toplevel)}"

# Exit statuses, matching cmd/innsegl/verify.go so a caller reading this
# script's status reads the same vocabulary the verifier uses.
readonly EXIT_FAILED=3
readonly EXIT_UNAVAILABLE=4

if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "verify-branch: no such base revision: $BASE" >&2
  echo "verify-branch:   pass one explicitly, or fetch the remote first." >&2
  exit 2
fi

# A read loop rather than mapfile: mapfile is bash 4+ and macOS ships 3.2.
COMMITS=""
while IFS= read -r line; do
  COMMITS="$COMMITS$line
"
done <<EOT
$(git rev-list --reverse "$BASE..HEAD")
EOT

if [ -z "$(printf '%s' "$COMMITS" | tr -d '[:space:]')" ]; then
  echo "verify-branch: no commits on HEAD that are not already on $BASE. Nothing to gate."
  exit 0
fi

# The verifier is a BUILT BINARY, never `go run`.
#
# `go run` reports its own exit status 1 when the program exits non-zero and
# prints "exit status 5" to stderr as text. This gate reads exit statuses to
# tell a failure (3) from an inconclusive result (4) from an unattributed
# commit (5) — through `go run` all three arrive as 1, and the tri-state doc 06
# P2 insists on collapses into "something went wrong". Measured the hard way:
# the first run of this script reported every unattributed commit as a failure.
BIN="${INNSEGL_BIN:-}"
if [ -z "$BIN" ]; then
  BIN="$(mktemp -d)/innsegl"
  trap 'rm -rf "$(dirname "$BIN")"' EXIT
  echo "verify-branch: building the verifier…"
  go build -o "$BIN" ./cmd/innsegl
fi

verifier() {
  # shellcheck disable=SC2086 # deliberate: INNSEGL_BIN may carry arguments.
  $BIN "$@"
}

checked=0
verified=0
unattributed=0
failures=""
nfail=0
unavailable=""
nunavail=0

for sha in $COMMITS; do
  [ -n "$sha" ] || continue
  checked=$((checked + 1))
  subject="$(git log -1 --format='%s' "$sha" | cut -c1-58)"
  short="$(git rev-parse --short "$sha")"

  set +e
  out="$(verifier verify "$sha" -repo "$REPO" 2>&1)"
  status=$?
  set -e

  case "$status" in
    0)
      verified=$((verified + 1))
      echo "  verified      $short  $subject"
      ;;
    5)
      unattributed=$((unattributed + 1))
      echo "  unattributed  $short  $subject"
      ;;
    "$EXIT_UNAVAILABLE")
      nunavail=$((nunavail + 1))
      unavailable="$unavailable  $short  $subject
$(printf '%s' "$out" | sed 's/^/      /' | tail -4)
"
      echo "  INCONCLUSIVE  $short  $subject"
      ;;
    *)
      nfail=$((nfail + 1))
      failures="$failures  $short  $subject  (exit $status)
$(printf '%s' "$out" | sed 's/^/      /' | tail -6)
"
      echo "  FAILED        $short  $subject  (exit $status)"
      ;;
  esac
done

echo
echo "verify-branch: $checked commit(s) on $BASE..HEAD — $verified verified, $unattributed unattributed, $nunavail inconclusive, $nfail failed"

if [ "$nfail" -gt 0 ]; then
  echo
  echo "REFUSED: $nfail commit(s) claim an agent identity that does not hold." >&2
  printf '%s' "$failures" >&2
  echo "A commit carrying an Agent-Identity trailer the signature does not support" >&2
  echo "must not reach main: it is an attribution claim with nothing behind it." >&2
  exit "$EXIT_FAILED"
fi

if [ "$nunavail" -gt 0 ]; then
  echo
  echo "INCONCLUSIVE: $nunavail commit(s) could not be checked." >&2
  printf '%s' "$unavailable" >&2
  echo "Fulcio or Rekor could not be reached, so nothing was proved either way." >&2
  echo "This is not a failure and must not be read as one (doc 06 P2, AB-08)." >&2
  echo "Bring the deployment up — \`make innsegl-up\` — and run this again." >&2
  exit "$EXIT_UNAVAILABLE"
fi

echo "verify-branch: OK — every attributed commit on this branch verifies."

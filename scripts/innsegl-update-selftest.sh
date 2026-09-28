#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/innsegl-update.sh, watched failing before it existed — RM-217.
#
# WHY THIS EXISTS. innsegl-update is the one command an operator runs on the
# deployment host to move `main` and redeploy. It only ever pulls, and its
# whole job is to refuse in every shape except the one PRs actually take:
# fetch, fast-forward, a first-parent chain of merge commits, every other new
# commit signature-verified. A gate that refuses nothing is indistinguishable
# from no gate at all until the day it should have refused, so every branch
# below is exercised here against a throwaway "remote" and "clone" — nothing
# real, no Docker, no network, no deployment.
#
# WHAT IS STUBBED, and why nothing here can touch a real deployment:
#   - INNSEGL_UPDATE_VERIFY_CMD points at a fake verifier that records the sha
#     it was asked about and answers VERDICT: VERIFIED unless told (by
#     $VERIFY_FAIL_SHA, threaded through the environment) to fail one sha.
#   - INNSEGL_UPDATE_DEPLOY_CMD points at a fake deploy that records that it
#     ran and exits 0. `make innsegl-up-here` is never invoked here.
#   - INNSEGL_UPDATE_REPO and INNSEGL_UPDATE_STATE_DIR always point inside
#     this file's own temp directory — never $HOME/.innsegl-update, never this
#     checkout.
#
# CASES, matching the issue's list one for one:
#   1. nothing new                                    -> exit 0, no deploy
#   2. a new merge with a verified child               -> updates, deploys
#      once, records the previous commit
#   3. a direct non-merge commit on main                -> refused, HEAD
#      unchanged
#   4. a rewritten remote (no fast-forward)             -> refused
#   5. a dirty tree, and separately local-only commits -> refused
#   6. verify failing for one commit                    -> refused, no deploy
#   7. --check                                          -> changes nothing
#   8. --rollback                                       -> deploys the
#      recorded previous commit
#   9. (bonus) no --yes with no terminal on stdin        -> refused, no change
#
# USAGE
#   scripts/innsegl-update-selftest.sh
#
# Needs bash and git. No Docker, no MCP, no network, no go: verify and deploy
# are both fakes, so nothing here builds or runs the real innsegl binary.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
UPDATE="$ROOT/scripts/innsegl-update.sh"

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2" >&2; return 0; }

if [ ! -x "$UPDATE" ]; then
  echo "innsegl-update-selftest: $UPDATE is missing or not executable" >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

new_repo() {  # new_repo <dir>
  git init -q -b main "$1" >/dev/null
  git -C "$1" config user.email "selftest@innsegl.invalid"
  git -C "$1" config user.name "selftest"
  git -C "$1" config commit.gpgsign false
}

commit_file() {  # commit_file <dir> <relpath> <content> <message>
  printf '%s\n' "$3" > "$1/$2"
  git -C "$1" add "$2"
  git -C "$1" commit -q --no-gpg-sign -m "$4"
}

clone_of() {  # clone_of <remote-dir> <clone-dir>
  git clone -q "$1" "$2" >/dev/null
  git -C "$2" config user.email "selftest@innsegl.invalid"
  git -C "$2" config user.name "selftest"
  git -C "$2" config commit.gpgsign false
}

# setup_pr_case <name> — a remote and a clone, both at one seed commit, then a
# feature commit on the remote merged into its main with --no-ff. Leaves
# PR_REMOTE, PR_CLONE, PR_BASE (the seed, what the clone starts at), PR_CHILD
# (the feature commit, not a merge) and PR_MERGE (the merge commit) set.
setup_pr_case() {
  local name="$1"
  PR_REMOTE="$TMP/$name-remote"
  PR_CLONE="$TMP/$name-clone"
  new_repo "$PR_REMOTE"
  commit_file "$PR_REMOTE" seed.txt one seed
  PR_BASE="$(git -C "$PR_REMOTE" rev-parse main)"
  clone_of "$PR_REMOTE" "$PR_CLONE"

  git -C "$PR_REMOTE" checkout -q -b feature
  commit_file "$PR_REMOTE" feature.txt content "add a feature"
  PR_CHILD="$(git -C "$PR_REMOTE" rev-parse feature)"
  git -C "$PR_REMOTE" checkout -q main
  git -C "$PR_REMOTE" merge -q --no-ff --no-edit -m "Merge feature into main" feature
  PR_MERGE="$(git -C "$PR_REMOTE" rev-parse main)"
}

DEPLOY_STUB="$TMP/deploy-stub.sh"
cat > "$DEPLOY_STUB" <<'EOT'
#!/bin/sh
echo "deploy" >> "$INNSEGL_TEST_DEPLOY_CALLS"
exit 0
EOT
chmod +x "$DEPLOY_STUB"

VERIFY_STUB="$TMP/verify-stub.sh"
cat > "$VERIFY_STUB" <<'EOT'
#!/bin/sh
sha="$1"
echo "verify $sha" >> "$INNSEGL_TEST_VERIFY_CALLS"
if [ -n "${INNSEGL_TEST_VERIFY_FAIL:-}" ] && [ "$sha" = "$INNSEGL_TEST_VERIFY_FAIL" ]; then
  echo "innsegl verify (fake)"
  echo
  echo "  VERDICT: FAILED"
  exit 3
fi
echo "innsegl verify (fake)"
echo
echo "  VERDICT: VERIFIED"
exit 0
EOT
chmod +x "$VERIFY_STUB"

DEPLOY_CALLS="$TMP/deploy-calls.log"
VERIFY_CALLS="$TMP/verify-calls.log"

# run_update <repo> <state-dir> [args…] — runs the real script against the
# fixtures above, with both externals faked. VERIFY_FAIL_SHA, when set in the
# caller's shell, names the one sha the fake verifier should fail.
run_update() {
  local repo="$1" state="$2"
  shift 2
  RUN_OUT="$(env \
    INNSEGL_UPDATE_REPO="$repo" \
    INNSEGL_UPDATE_STATE_DIR="$state" \
    INNSEGL_UPDATE_VERIFY_CMD="$VERIFY_STUB" \
    INNSEGL_UPDATE_DEPLOY_CMD="$DEPLOY_STUB" \
    INNSEGL_TEST_DEPLOY_CALLS="$DEPLOY_CALLS" \
    INNSEGL_TEST_VERIFY_CALLS="$VERIFY_CALLS" \
    INNSEGL_TEST_VERIFY_FAIL="${VERIFY_FAIL_SHA:-}" \
    "$UPDATE" "$@" 2>&1)"
  RUN_STATUS=$?
}

ncalls() {  # ncalls <file> — number of lines, 0 if empty or missing
  if [ -s "$1" ]; then
    wc -l < "$1" | tr -d '[:space:]'
  else
    printf '%s' 0
  fi
}

# ===========================================================================
echo "case 1 — nothing new"
# ===========================================================================
R1="$TMP/case1-remote"; C1="$TMP/case1-clone"
new_repo "$R1"; commit_file "$R1" seed.txt one seed
clone_of "$R1" "$C1"
HEAD1="$(git -C "$C1" rev-parse main)"
S1="$TMP/state1"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
run_update "$C1" "$S1" --yes
if [ "$RUN_STATUS" -eq 0 ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ] && [ "$(git -C "$C1" rev-parse main)" = "$HEAD1" ]; then
  ok "nothing new: exit 0, no deploy"
else
  bad "nothing new: exit 0, no deploy" "status=$RUN_STATUS deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 2 — a new merge with a verified child updates, deploys once, records the previous commit"
# ===========================================================================
setup_pr_case case2
C2_CLONE="$PR_CLONE"; C2_BASE="$PR_BASE"; C2_CHILD="$PR_CHILD"; C2_MERGE="$PR_MERGE"
S2="$TMP/state2"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
VERIFY_FAIL_SHA=""
run_update "$C2_CLONE" "$S2" --yes
HEAD_AFTER="$(git -C "$C2_CLONE" rev-parse main)"
PREV_RECORDED="$(cat "$S2/previous" 2>/dev/null || echo '<none>')"
if [ "$RUN_STATUS" -eq 0 ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 1 ] \
   && [ "$HEAD_AFTER" = "$C2_MERGE" ] && [ "$PREV_RECORDED" = "$C2_BASE" ]; then
  ok "updates, deploys exactly once, and records the previous commit"
else
  bad "updates, deploys exactly once, and records the previous commit" \
      "status=$RUN_STATUS deploys=$(ncalls "$DEPLOY_CALLS") head=$HEAD_AFTER want=$C2_MERGE prev=$PREV_RECORDED want_prev=$C2_BASE
$RUN_OUT"
fi
if grep -q "verify $C2_CHILD" "$VERIFY_CALLS" 2>/dev/null && ! grep -q "verify $C2_MERGE" "$VERIFY_CALLS" 2>/dev/null; then
  ok "signature verification runs on the child commit, not on the merge commit"
else
  bad "signature verification runs on the child commit, not on the merge commit" \
      "verify calls: $(cat "$VERIFY_CALLS" 2>/dev/null || echo '<none>')"
fi

# ===========================================================================
echo
echo "case 3 — a direct non-merge commit on main is refused, and HEAD is unchanged"
# ===========================================================================
R3="$TMP/case3-remote"; C3="$TMP/case3-clone"
new_repo "$R3"; commit_file "$R3" seed.txt one seed
BASE3="$(git -C "$R3" rev-parse main)"
clone_of "$R3" "$C3"
commit_file "$R3" direct.txt content "pushed straight to main"
S3="$TMP/state3"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
run_update "$C3" "$S3" --yes
HEAD_AFTER="$(git -C "$C3" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$BASE3" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ]; then
  ok "a direct non-merge commit on main is refused, and HEAD is unchanged"
else
  bad "a direct non-merge commit on main is refused, and HEAD is unchanged" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$BASE3 deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 4 — a rewritten remote (no fast-forward) is refused"
# ===========================================================================
R4="$TMP/case4-remote"; C4="$TMP/case4-clone"
new_repo "$R4"; commit_file "$R4" seed.txt one seed
clone_of "$R4" "$C4"
commit_file "$R4" a.txt one "advance"
git -C "$C4" pull -q --ff-only origin main
SYNCED4="$(git -C "$C4" rev-parse main)"
ROOT4="$(git -C "$R4" rev-list --max-parents=0 main | head -1)"
git -C "$R4" reset -q --hard "$ROOT4"
commit_file "$R4" b.txt two "history rewritten upstream"
S4="$TMP/state4"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
run_update "$C4" "$S4" --yes
HEAD_AFTER="$(git -C "$C4" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$SYNCED4" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ] \
   && printf '%s' "$RUN_OUT" | grep -qi "fast-forward"; then
  ok "a rewritten remote is refused"
else
  bad "a rewritten remote is refused" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$SYNCED4 deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 5 — a dirty tree, and separately local-only commits, are refused"
# ===========================================================================
# Uses setup_pr_case so the upstream change is a merge commit — an ordinary
# single-parent upstream commit would ALSO trip the first-parent gate, and a
# case that can be refused for two different reasons proves nothing about
# either one. Here only the dirty tree can be the reason.
setup_pr_case case5a
C5A="$PR_CLONE"; BASE5A="$PR_BASE"
echo "uncommitted change" >> "$C5A/seed.txt"
S5A="$TMP/state5a"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
run_update "$C5A" "$S5A" --yes
HEAD_AFTER="$(git -C "$C5A" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$BASE5A" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ] \
   && [ "$(ncalls "$VERIFY_CALLS")" -eq 0 ] && grep -q "uncommitted change" "$C5A/seed.txt" \
   && printf '%s' "$RUN_OUT" | grep -qi "dirty"; then
  ok "a dirty working tree is refused, and the dirt is left exactly as it was"
else
  bad "a dirty working tree is refused, and the dirt is left exactly as it was" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$BASE5A deploys=$(ncalls "$DEPLOY_CALLS") verifies=$(ncalls "$VERIFY_CALLS")
$RUN_OUT"
fi

R5B="$TMP/case5b-remote"; C5B="$TMP/case5b-clone"
new_repo "$R5B"; commit_file "$R5B" seed.txt one seed
clone_of "$R5B" "$C5B"
commit_file "$C5B" local.txt content "a local commit never pushed anywhere"
LOCAL_TIP5B="$(git -C "$C5B" rev-parse main)"
S5B="$TMP/state5b"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
run_update "$C5B" "$S5B" --yes
HEAD_AFTER="$(git -C "$C5B" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$LOCAL_TIP5B" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ] \
   && printf '%s' "$RUN_OUT" | grep -qi "local edits"; then
  ok "a local commit not on origin/main is refused"
else
  bad "a local commit not on origin/main is refused" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$LOCAL_TIP5B deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 6 — verify failing for one commit is refused, and nothing deploys"
# ===========================================================================
setup_pr_case case6
C6_CLONE="$PR_CLONE"; C6_BASE="$PR_BASE"; C6_CHILD="$PR_CHILD"
S6="$TMP/state6"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
VERIFY_FAIL_SHA="$C6_CHILD"
run_update "$C6_CLONE" "$S6" --yes
VERIFY_FAIL_SHA=""
HEAD_AFTER="$(git -C "$C6_CLONE" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$C6_BASE" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ] \
   && [ ! -s "$S6/previous" ]; then
  ok "verify failing for one commit refuses, deploys nothing, and records no previous"
else
  bad "verify failing for one commit refuses, deploys nothing, and records no previous" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$C6_BASE deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 6b — no environment variable skips verification"
# ===========================================================================
setup_pr_case case6b
C6B_CLONE="$PR_CLONE"; C6B_BASE="$PR_BASE"; C6B_CHILD="$PR_CHILD"
S6B="$TMP/state6b"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
VERIFY_FAIL_SHA="$C6B_CHILD"
INNSEGL_UPDATE_SKIP_VERIFY=1 run_update "$C6B_CLONE" "$S6B" --yes
VERIFY_FAIL_SHA=""
HEAD_AFTER="$(git -C "$C6B_CLONE" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$C6B_BASE" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ]; then
  ok "INNSEGL_UPDATE_SKIP_VERIFY=1 still verifies, refuses, and deploys nothing"
else
  bad "INNSEGL_UPDATE_SKIP_VERIFY=1 still verifies, refuses, and deploys nothing" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$C6B_BASE deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 7 — --check changes nothing"
# ===========================================================================
setup_pr_case case7
C7_CLONE="$PR_CLONE"; C7_BASE="$PR_BASE"; C7_MERGE="$PR_MERGE"; C7_CHILD="$PR_CHILD"
S7="$TMP/state7"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
run_update "$C7_CLONE" "$S7" --check
HEAD_AFTER="$(git -C "$C7_CLONE" rev-parse main)"
DIRTY_AFTER="$(git -C "$C7_CLONE" status --porcelain)"
if [ "$RUN_STATUS" -eq 0 ] && [ "$HEAD_AFTER" = "$C7_BASE" ] && [ -z "$DIRTY_AFTER" ] \
   && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ] && [ "$(ncalls "$VERIFY_CALLS")" -eq 0 ] \
   && [ ! -e "$S7/previous" ]; then
  ok "--check leaves the checkout, the deploy and the verifier untouched"
else
  bad "--check leaves the checkout, the deploy and the verifier untouched" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$C7_BASE deploys=$(ncalls "$DEPLOY_CALLS") verifies=$(ncalls "$VERIFY_CALLS")
$RUN_OUT"
fi
if printf '%s' "$RUN_OUT" | grep -qF "$(git -C "$C7_CLONE" rev-parse --short "$C7_CHILD")"; then
  ok "--check names the new commit"
else
  bad "--check names the new commit" "$RUN_OUT"
fi
if printf '%s' "$RUN_OUT" | grep -q "feature.txt"; then
  ok "--check names the file it touches"
else
  bad "--check names the file it touches" "$RUN_OUT"
fi
if [ -f "$S7/update.log" ] && grep -q "check" "$S7/update.log"; then
  ok "--check still logs the run"
else
  bad "--check still logs the run" "$(cat "$S7/update.log" 2>/dev/null || echo '<no log file>')"
fi

# ===========================================================================
echo
echo "case 8 — --rollback deploys the recorded previous commit"
# ===========================================================================
# Reuses case 2's clone and state dir: a completed update that fast-forwarded
# C2_CLONE to C2_MERGE and recorded C2_BASE as the previous commit.
: > "$DEPLOY_CALLS"
run_update "$C2_CLONE" "$S2" --rollback --yes
BRANCH_AFTER="$(git -C "$C2_CLONE" symbolic-ref --short -q HEAD || echo '<detached>')"
HEAD_AFTER="$(git -C "$C2_CLONE" rev-parse HEAD)"
WANT_BRANCH="rollback-$(git -C "$C2_CLONE" rev-parse --short "$C2_BASE")"
if [ "$RUN_STATUS" -eq 0 ] && [ "$BRANCH_AFTER" = "$WANT_BRANCH" ] && [ "$HEAD_AFTER" = "$C2_BASE" ] \
   && [ "$(ncalls "$DEPLOY_CALLS")" -eq 1 ]; then
  ok "--rollback checks out and redeploys the recorded previous commit"
else
  bad "--rollback checks out and redeploys the recorded previous commit" \
      "status=$RUN_STATUS branch=$BRANCH_AFTER want=$WANT_BRANCH head=$HEAD_AFTER want_head=$C2_BASE deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "case 9 (bonus) — no --yes, and no terminal on stdin, is refused with no change"
# ===========================================================================
setup_pr_case case9
C9_CLONE="$PR_CLONE"; C9_BASE="$PR_BASE"
S9="$TMP/state9"
: > "$DEPLOY_CALLS"; : > "$VERIFY_CALLS"
RUN_OUT="$(env \
  INNSEGL_UPDATE_REPO="$C9_CLONE" \
  INNSEGL_UPDATE_STATE_DIR="$S9" \
  INNSEGL_UPDATE_VERIFY_CMD="$VERIFY_STUB" \
  INNSEGL_UPDATE_DEPLOY_CMD="$DEPLOY_STUB" \
  INNSEGL_TEST_DEPLOY_CALLS="$DEPLOY_CALLS" \
  INNSEGL_TEST_VERIFY_CALLS="$VERIFY_CALLS" \
  "$UPDATE" </dev/null 2>&1)"
RUN_STATUS=$?
HEAD_AFTER="$(git -C "$C9_CLONE" rev-parse main)"
if [ "$RUN_STATUS" -eq 1 ] && [ "$HEAD_AFTER" = "$C9_BASE" ] && [ "$(ncalls "$DEPLOY_CALLS")" -eq 0 ]; then
  ok "no --yes and no terminal on stdin is refused, with no change"
else
  bad "no --yes and no terminal on stdin is refused, with no change" \
      "status=$RUN_STATUS head=$HEAD_AFTER want=$C9_BASE deploys=$(ncalls "$DEPLOY_CALLS")
$RUN_OUT"
fi

# ===========================================================================
echo
echo "usage — bad arguments exit 2 and touch nothing"
# ===========================================================================
SU="$TMP/state-usage"
: > "$DEPLOY_CALLS"
RUN_OUT="$(env INNSEGL_UPDATE_REPO="$C1" INNSEGL_UPDATE_STATE_DIR="$SU" \
  INNSEGL_UPDATE_VERIFY_CMD="$VERIFY_STUB" INNSEGL_UPDATE_DEPLOY_CMD="$DEPLOY_STUB" \
  "$UPDATE" --not-a-flag 2>&1)"
RUN_STATUS=$?
if [ "$RUN_STATUS" -eq 2 ]; then
  ok "an unrecognised flag exits 2"
else
  bad "an unrecognised flag exits 2" "status=$RUN_STATUS
$RUN_OUT"
fi

RUN_OUT="$(env INNSEGL_UPDATE_REPO="$C1" INNSEGL_UPDATE_STATE_DIR="$SU" \
  INNSEGL_UPDATE_VERIFY_CMD="$VERIFY_STUB" INNSEGL_UPDATE_DEPLOY_CMD="$DEPLOY_STUB" \
  "$UPDATE" --check --rollback 2>&1)"
RUN_STATUS=$?
if [ "$RUN_STATUS" -eq 2 ]; then
  ok "--check and --rollback together exit 2"
else
  bad "--check and --rollback together exit 2" "status=$RUN_STATUS
$RUN_OUT"
fi

# ---------------------------------------------------------------------------
echo
printf 'innsegl-update-selftest: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# innsegl-update — the one command a deployment host runs to move `main`
# forward and redeploy. RM-217.
#
# WHO RUNS THIS. An operator, on the deployment host, by hand or from a timer.
# Agents have no access to that host — this script never runs under one — and
# it only ever PULLS: nothing here pushes, force-pushes or rewrites anything.
#
# WHAT IT REFUSES, rather than working around:
#
#   * a dirty working tree, or local commits `origin/main` does not have —
#     this is not the tree to run `git reset --hard` on to make room;
#   * `origin/main` that is not a fast-forward of local `main` — a force-push
#     or a rewritten history, which this host has no business reconciling;
#   * a first-parent commit on `main` that is not a merge commit — this
#     project's `main` only ever moves by a PR's merge commit; a commit
#     pushed straight to `main` is refused, sight unseen;
#   * a commit whose signature `innsegl verify` cannot confirm.
#
# Every refusal changes nothing. The exit status says which kind of "no":
#
#   0  updated (or there was nothing to update)
#   1  refused — a gate above, or the operator's own "no" at the prompt
#   2  usage — the command line was not understood
#
# USAGE
#   innsegl-update [--check] [--rollback] [--yes]
#
#   --check     fetch and print what would change; changes nothing
#   --rollback  redeploy the commit recorded before the last update
#   --yes       skip the confirmation prompt
#
# TESTING HOOKS. None of these are for an operator to set day to day; every
# one exists so scripts/innsegl-update-selftest.sh can run this against a
# throwaway repository with nothing real behind it.
#
#   INNSEGL_UPDATE_REPO         the checkout to update. Default: derived from
#                               this script's own location (resolved through
#                               the symlink `deploy/compose/README.md` tells an
#                               operator to install), so a plain
#                               `sudo ln -s .../scripts/innsegl-update.sh
#                               /usr/local/bin/innsegl-update` finds the right
#                               repository with no configuration at all.
#   INNSEGL_UPDATE_STATE_DIR    where `previous`, `history` and `update.log`
#                               live. Default: $HOME/.innsegl-update
#   INNSEGL_UPDATE_VERIFY_CMD   the verifier, without the commit argument.
#                               Default: `go run ./cmd/innsegl verify`. Success
#                               means its OUTPUT contains `VERDICT: VERIFIED` —
#                               not its exit status, because `go run` collapses
#                               the verifier's own tri-state exit codes into a
#                               single "exit status 1" on stderr (see
#                               scripts/verify-branch.sh for the measurement).
#   INNSEGL_UPDATE_DEPLOY_CMD   the redeploy command. Default:
#                               `make innsegl-up-here`, which the Makefile
#                               requires INNSEGL_SPIRE_JWT_ISSUER for; this
#                               script sets it to http://spire-oidc:8080 when
#                               it is not already set.
#   INNSEGL_UPDATE_SKIP_VERIFY  1 skips step 3 with a loud warning. This is not
#                               a convenience flag: it exists ONLY because this
#                               host's own trust roots cannot verify commits
#                               signed by another deployment until the core
#                               moves. There is no environment variable that
#                               silences the warning.
#   INNSEGL_FULCIO_URL,
#   INNSEGL_REKOR_URL           read by the verifier itself, exactly as
#                               `innsegl verify` reads them everywhere else.
#
# WHY --check DOES NOT RUN THE GATES BELOW. It fetches and prints a diff; it
# is not a dry run of the gates, because a preview that can be wrong about
# whether the real run will refuse is worse than one that only ever answers
# the question it was asked: "what is on origin/main that is not here yet."

set -euo pipefail

readonly EXIT_OK=0
readonly EXIT_REFUSED=1
readonly EXIT_USAGE=2

# --- resolve the checkout this installs into --------------------------------
#
# The classic loop, because this script is meant to be reached through a
# symlink in /usr/local/bin and plain `dirname "$0"` would answer
# /usr/local/bin instead of the checkout that put it there. `readlink` with no
# flag reads one level, which is all POSIX guarantees and all BSD ships; the
# loop is what makes that enough for a chain of links.
resolve_self() {
  local src="$0" dir
  while [ -h "$src" ]; do
    dir="$(cd -- "$(dirname -- "$src")" && pwd)"
    src="$(readlink "$src")"
    case "$src" in
      /*) ;;
      *) src="$dir/$src" ;;
    esac
  done
  (cd -- "$(dirname -- "$src")/.." && pwd)
}

REPO="${INNSEGL_UPDATE_REPO:-$(resolve_self)}"
STATE_DIR="${INNSEGL_UPDATE_STATE_DIR:-$HOME/.innsegl-update}"
DEPLOY_CMD="${INNSEGL_UPDATE_DEPLOY_CMD:-make innsegl-up-here}"
VERIFY_CMD="${INNSEGL_UPDATE_VERIFY_CMD:-go run ./cmd/innsegl verify}"
SKIP_VERIFY="${INNSEGL_UPDATE_SKIP_VERIFY:-0}"
SPIRE_ISSUER="${INNSEGL_SPIRE_JWT_ISSUER:-http://spire-oidc:8080}"

# --- args --------------------------------------------------------------------
CHECK=0
ROLLBACK=0
YES=0

usage() {
  cat <<'EOT'
usage: innsegl-update [--check] [--rollback] [--yes]

  --check     fetch origin/main and print what would change; changes nothing
  --rollback  check out and redeploy the commit recorded before the last update
  --yes       skip the confirmation prompt

exit status: 0 updated (or nothing to do), 1 refused, 2 usage
EOT
}

for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    --rollback) ROLLBACK=1 ;;
    --yes) YES=1 ;;
    -h|--help) usage; exit "$EXIT_OK" ;;
    *)
      echo "innsegl-update: unrecognised argument: $arg" >&2
      usage >&2
      exit "$EXIT_USAGE"
      ;;
  esac
done

if [ "$CHECK" = 1 ] && [ "$ROLLBACK" = 1 ]; then
  echo "innsegl-update: --check and --rollback are mutually exclusive" >&2
  exit "$EXIT_USAGE"
fi

if [ ! -d "$REPO/.git" ]; then
  echo "innsegl-update: $REPO does not look like a git checkout (no .git)" >&2
  exit "$EXIT_USAGE"
fi

MODE_LABEL=update
[ "$CHECK" = 1 ] && MODE_LABEL=check
[ "$ROLLBACK" = 1 ] && MODE_LABEL=rollback

# --- small helpers -----------------------------------------------------------

log_run() {  # log_run <result words...>
  mkdir -p "$STATE_DIR"
  printf '%s  %-8s  %s\n' "$(date -u +%FT%TZ)" "$MODE_LABEL" "$*" >> "$STATE_DIR/update.log"
}

refuse() {  # refuse <message> — clear, and nothing has changed
  echo "innsegl-update: refused — $*" >&2
  log_run "refused: $*"
  exit "$EXIT_REFUSED"
}

is_merge() {  # is_merge <sha> — a real second parent, not just a message
  git -C "$REPO" rev-parse --verify -q "$1^2" >/dev/null 2>&1
}

# confirm_or_abort <plan text already printed> — the y/N gate, item 6. --yes
# skips it; a non-interactive stdin with no --yes refuses rather than hangs,
# because a timer invoking this without --yes must never be the thing that
# silently waits forever, or the thing that silently proceeds.
confirm_or_abort() {
  [ "$YES" = 1 ] && return 0
  if [ ! -t 0 ]; then
    refuse "no --yes, and no terminal to confirm on"
  fi
  printf 'Proceed? [y/N] '
  read -r ans || ans=""
  case "$ans" in
    y|Y|yes|YES) return 0 ;;
    *) refuse "not confirmed" ;;
  esac
}

# print_change <from> <to> — the commits and the files, in that order, both
# for --check's report and for the plan shown before the y/N prompt.
print_change() {
  local from="$1" to="$2"
  echo "  commits:"
  git -C "$REPO" log --reverse --pretty='    %h  %s' "$from..$to"
  echo "  files touched:"
  git -C "$REPO" diff --name-only "$from" "$to" | sed 's/^/    /'
}

# --- --rollback ---------------------------------------------------------------
#
# Item 5: check out the recorded previous commit on its own branch and
# redeploy. It does not touch `main`, and it does not require `main` to be
# what is currently checked out — the whole point is to move away from
# whatever state update just left behind.
if [ "$ROLLBACK" = 1 ]; then
  PREV_FILE="$STATE_DIR/previous"
  if [ ! -s "$PREV_FILE" ]; then
    refuse "no previous commit recorded in $PREV_FILE; nothing to roll back to"
  fi
  PREV="$(cat "$PREV_FILE")"
  if ! git -C "$REPO" cat-file -e "${PREV}^{commit}" 2>/dev/null; then
    refuse "the recorded previous commit $PREV is not in $REPO"
  fi
  SHORT="$(git -C "$REPO" rev-parse --short "$PREV")"
  BRANCH="rollback-$SHORT"

  echo "innsegl-update: plan (rollback)"
  echo "  checkout   $BRANCH -> $PREV"
  echo "  deploy     $DEPLOY_CMD"
  confirm_or_abort

  if ! git -C "$REPO" checkout -q -B "$BRANCH" "$PREV"; then
    refuse "could not check out $BRANCH at $PREV"
  fi
  if ! ( cd "$REPO" && INNSEGL_SPIRE_JWT_ISSUER="$SPIRE_ISSUER" sh -c "$DEPLOY_CMD" ); then
    refuse "deploy command failed: $DEPLOY_CMD"
  fi

  echo "innsegl-update: rolled back to $SHORT on branch $BRANCH, and redeployed."
  echo "innsegl-update: to return to main:"
  echo "  git -C $REPO checkout main"
  echo "  ( cd $REPO && INNSEGL_SPIRE_JWT_ISSUER=$SPIRE_ISSUER $DEPLOY_CMD )"
  log_run "rolled back to $SHORT on $BRANCH"
  exit "$EXIT_OK"
fi

# --- fetch (both --check and the real run) -----------------------------------
git -C "$REPO" fetch origin main >/dev/null 2>&1 || {
  refuse "git fetch origin main failed"
}

LOCAL="$(git -C "$REPO" rev-parse --verify -q main)" || {
  refuse "no local branch named main in $REPO"
}
REMOTE="$(git -C "$REPO" rev-parse --verify -q origin/main)" || {
  refuse "no origin/main after fetching"
}

# --- --check -------------------------------------------------------------------
#
# Item 1: report only. No gate below this line runs in --check mode — a
# preview that ran the gates would be answering a different, larger question
# than the one it advertises, and could disagree with the real run under it.
if [ "$CHECK" = 1 ]; then
  if [ "$LOCAL" = "$REMOTE" ]; then
    echo "innsegl-update --check: origin/main has no new commits."
    log_run "no new commits"
    exit "$EXIT_OK"
  fi
  echo "innsegl-update --check: origin/main is ahead of local main."
  print_change "$LOCAL" "$REMOTE"
  log_run "would update $(git -C "$REPO" rev-parse --short "$LOCAL") -> $(git -C "$REPO" rev-parse --short "$REMOTE")"
  exit "$EXIT_OK"
fi

# --- the real run --------------------------------------------------------------

CURRENT_BRANCH="$(git -C "$REPO" symbolic-ref --short -q HEAD || true)"
if [ "$CURRENT_BRANCH" != "main" ]; then
  refuse "HEAD is not on branch main (it is $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo detached)); this command updates main"
fi

if [ -n "$(git -C "$REPO" status --porcelain)" ]; then
  refuse "the working tree is dirty"
fi

# Gate 2a/2b: a fast-forward has exactly one of local ahead of origin, origin
# ahead of local, or neither — checked in that order so "local edits" and "a
# rewritten remote" are never confused with each other.
if git -C "$REPO" merge-base --is-ancestor "$LOCAL" "$REMOTE"; then
  : # origin/main is at or ahead of local main — the safe direction
elif git -C "$REPO" merge-base --is-ancestor "$REMOTE" "$LOCAL"; then
  refuse "local main has commits that are not on origin/main (local edits)"
else
  refuse "origin/main is not a fast-forward of local main (a force-push or rewrite)"
fi

if [ "$LOCAL" = "$REMOTE" ]; then
  echo "innsegl-update: origin/main has no new commits. Nothing to do."
  log_run "no new commits"
  exit "$EXIT_OK"
fi

# Gate 2c: every first-parent commit on the way to origin/main must be a merge
# commit. This project merges PRs with a merge commit; a first-parent commit
# with only one parent is a direct push and is refused, sight unseen.
FIRST_PARENT="$(git -C "$REPO" rev-list --first-parent "$LOCAL..$REMOTE")"
for sha in $FIRST_PARENT; do
  if ! is_merge "$sha"; then
    subject="$(git -C "$REPO" log -1 --format='%s' "$sha")"
    refuse "$(git -C "$REPO" rev-parse --short "$sha") ($subject) is a direct push to main, not a merge commit"
  fi
done

# Gate 2d / item 3: every new commit that is NOT a merge gets its signature
# verified. A merge commit carries no content of its own to attribute; the
# commits it merged in are what this checks.
ALL_NEW="$(git -C "$REPO" rev-list "$LOCAL..$REMOTE")"
if [ "$SKIP_VERIFY" = "1" ]; then
  echo "innsegl-update: WARNING — skipping signature verification (INNSEGL_UPDATE_SKIP_VERIFY=1)." >&2
  echo "innsegl-update:   This exists only because the host's own trust roots cannot verify" >&2
  echo "innsegl-update:   commits signed by another deployment until the core moves." >&2
else
  for sha in $ALL_NEW; do
    if is_merge "$sha"; then
      continue
    fi
    out="$( (cd "$REPO" && sh -c "$VERIFY_CMD $sha") 2>&1)" || true
    case "$out" in
      *"VERDICT: VERIFIED"*) : ;;
      *)
        subject="$(git -C "$REPO" log -1 --format='%s' "$sha")"
        {
          echo "innsegl-update: verification did not report VERDICT: VERIFIED for"
          echo "  $(git -C "$REPO" rev-parse --short "$sha") ($subject)"
          echo "  --- verifier output ---"
          printf '%s\n' "$out" | sed 's/^/  /'
        } >&2
        refuse "signature verification failed for $(git -C "$REPO" rev-parse --short "$sha")"
        ;;
    esac
  done
fi

echo "innsegl-update: plan"
print_change "$LOCAL" "$REMOTE"
echo "  fast-forward main  $(git -C "$REPO" rev-parse --short "$LOCAL") -> $(git -C "$REPO" rev-parse --short "$REMOTE")"
echo "  deploy              $DEPLOY_CMD"
confirm_or_abort

# --- item 4: record, fast-forward, deploy -------------------------------------
mkdir -p "$STATE_DIR"
printf '%s\n' "$LOCAL" > "$STATE_DIR/previous"
printf '%s  from=%s  to=%s\n' "$(date -u +%FT%TZ)" "$LOCAL" "$REMOTE" >> "$STATE_DIR/history"

if ! git -C "$REPO" merge -q --ff-only origin/main; then
  refuse "fast-forward merge failed unexpectedly"
fi

if ! ( cd "$REPO" && INNSEGL_SPIRE_JWT_ISSUER="$SPIRE_ISSUER" sh -c "$DEPLOY_CMD" ); then
  refuse "deploy command failed: $DEPLOY_CMD"
fi

echo "innsegl-update: updated $(git -C "$REPO" rev-parse --short "$LOCAL") -> $(git -C "$REPO" rev-parse --short "$REMOTE") and redeployed."
log_run "updated $(git -C "$REPO" rev-parse --short "$LOCAL") -> $(git -C "$REPO" rev-parse --short "$REMOTE")"
exit "$EXIT_OK"

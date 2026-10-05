#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/stack-mode.sh, and the host-side scripts that name a DEV stack's
# containers — OPS-129, RM-293 (#469), ADR-0072.
#
# test/deploy/devstack_test.go holds the compose files and the Makefile to
# the mode. This holds what only a real checkout shows: where the marker is
# read from (a linked worktree follows its repository), what refuses, and
# that every script that calls a container by name calls the dev one in dev.
#
# The cases:
#   OPS-129  no marker is live, and says nothing
#   OPS-129  a linked worktree reads its repository's marker; INNSEGL_STACK wins
#   OPS-129  make dev-stack writes the marker, says what it does, writes no HOME
#   OPS-129  a marker or INNSEGL_STACK that is neither dev nor live is refused
#   OPS-129  dev refuses a non-loopback bind from deploy/compose/.env
#   OPS-129  dev refuses a legacy trust prefix
#   OPS-129  dev refuses to start beside a running live-named stack
#   OPS-129  the dev prefix reaches every container a host script names
#
# Portability: the bash 3.2 that ships with macOS, and Linux CI.
set -u
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }

HERE="$(cd "$(dirname "$0")" && pwd -P)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# A repository holding the two scripts the mode is decided by, and a linked
# worktree of it.
REPO="$TMP/repo"
mkdir -p "$REPO/scripts" "$REPO/deploy/compose"
cp "$HERE/stack-mode.sh" "$HERE/repo-main-worktree.sh" "$REPO/scripts/"
git -C "$REPO" init -q
git -C "$REPO" -c user.name=t -c user.email=t@example.test add scripts
git -C "$REPO" -c user.name=t -c user.email=t@example.test commit -qm init
git -C "$REPO" worktree add -q "$TMP/wt" 2>/dev/null
WT="$TMP/wt"
HOMEDIR="$TMP/home"
mkdir -p "$HOMEDIR"

# No docker answers anything unless a case says so.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "${STUB_LOG:-/dev/null}"
case "$1" in
  ps) printf '%s\n' ${STUB_RUNNING:-} ;;
  port) printf '127.0.0.1:41234\n' ;;
  exec) printf 'ENROLCODE\n' ;;
esac
exit 0
SH
chmod +x "$TMP/bin/docker"

sm() { # sm <checkout> <args...>
  _c="$1"; shift
  env -u INNSEGL_STACK -u INNSEGL_BIND -u INNSEGL_TRUST_LEGACY_PREFIX \
    HOME="$HOMEDIR" INNSEGL_STACK_DOCKER="$TMP/bin/docker" "$@" 2>&1
}
run() { _c="$1"; shift; sm "$_c" "$_c/scripts/stack-mode.sh" "$@"; }

# --- no marker ------------------------------------------------------------
check "OPS-129 no marker is live" "$(run "$REPO" mode)" "live"
check "OPS-129 no marker, not enrolled: announce says nothing" "$(run "$REPO" announce)" ""
check "OPS-129 no marker: env sets nothing" "$(run "$REPO" env)" ""

# --- the marker -----------------------------------------------------------
before="$(cd "$HOMEDIR" && find . | sort)"
out="$(run "$WT" mark-dev)"
case "$out" in
  *"$REPO/.innsegl/stack-mode"*innsegl-dev*"no harness settings"*) ok "OPS-129 make dev-stack marks the repository and says what it does" ;;
  *) bad "OPS-129 make dev-stack marks the repository and says what it does" "$out" ;;
esac
check "OPS-129 make dev-stack writes nothing under HOME" "$(cd "$HOMEDIR" && find . | sort)" "$before"
check "OPS-129 the marker holds dev" "$(cat "$REPO/.innsegl/stack-mode" 2>/dev/null)" "dev"
check "OPS-129 a linked worktree follows its repository's marker" "$(run "$WT" mode)" "dev"
check "OPS-129 INNSEGL_STACK=live wins over the marker" "$(sm "$WT" INNSEGL_STACK=live "$WT/scripts/stack-mode.sh" mode)" "live"
case "$(run "$WT" env)" in
  *"INNSEGL_STACK_PREFIX=innsegl-dev"*"INNSEGL_TRUST_VOLUME_PREFIX=innsegl-dev-trust"*"INNSEGL_GATEWAY_CA_HOST_DIR=$HOMEDIR/.innsegl/dev/ca"*)
    ok "OPS-129 dev env: dev names, dev trust root, dev host folders" ;;
  *) bad "OPS-129 dev env: dev names, dev trust root, dev host folders" "$(run "$WT" env)" ;;
esac

# --- refused values -------------------------------------------------------
sm "$REPO" INNSEGL_STACK=staging "$REPO/scripts/stack-mode.sh" mode >/dev/null; rc=$?
check "OPS-129 INNSEGL_STACK=staging is refused" "$rc" "2"
printf 'maybe\n' > "$REPO/.innsegl/stack-mode"
run "$REPO" mode >/dev/null; rc=$?
check "OPS-129 a marker holding neither dev nor live is refused" "$rc" "2"
printf 'dev\n' > "$REPO/.innsegl/stack-mode"

# --- loopback -------------------------------------------------------------
printf 'INNSEGL_SPIRE_PARENT_ID=x\nINNSEGL_BIND=192.0.2.10\n' > "$REPO/deploy/compose/.env"
out="$(run "$REPO" check)"; rc=$?
if [ "$rc" = 4 ] && printf '%s' "$out" | grep -q 'loopback only, and INNSEGL_BIND is 192.0.2.10'; then
  ok "OPS-129 dev refuses a non-loopback bind from deploy/compose/.env"
else
  bad "OPS-129 dev refuses a non-loopback bind from deploy/compose/.env" "exit $rc: $out"
fi
sm "$REPO" INNSEGL_BIND=127.0.0.1 "$REPO/scripts/stack-mode.sh" check >/dev/null; rc=$?
check "OPS-129 an explicit loopback INNSEGL_BIND wins over .env" "$rc" "0"
sm "$REPO" INNSEGL_STACK=live "$REPO/scripts/stack-mode.sh" check >/dev/null; rc=$?
check "OPS-129 live keeps its bind: nothing refused" "$rc" "0"
rm -f "$REPO/deploy/compose/.env"

sm "$REPO" INNSEGL_TRUST_LEGACY_PREFIX=innsegl-trust "$REPO/scripts/stack-mode.sh" check >/dev/null; rc=$?
check "OPS-129 dev refuses a legacy trust prefix" "$rc" "4"

# --- beside a live-named stack ---------------------------------------------
out="$(sm "$REPO" STUB_RUNNING="innsegl-postgres innsegl-mcp" "$REPO/scripts/stack-mode.sh" announce)"; rc=$?
if [ "$rc" = 5 ] && printf '%s' "$out" | grep -q 'innsegl-mcp'; then
  ok "OPS-129 dev refuses to start beside a running live-named stack"
else
  bad "OPS-129 dev refuses to start beside a running live-named stack" "exit $rc: $out"
fi
out="$(sm "$REPO" STUB_RUNNING="innsegl-dev-mcp" "$REPO/scripts/stack-mode.sh" announce)"; rc=$?
case "$rc:$out" in
  "0:innsegl: starting a DEV stack ("*) ok "OPS-129 a running dev stack is not a live one" ;;
  *) bad "OPS-129 a running dev stack is not a live one" "exit $rc: $out" ;;
esac

# --- the prefix reaches every container a host script names ----------------
LOG="$TMP/docker.log"; : > "$LOG"
PATH="$TMP/bin:$PATH" STUB_LOG="$LOG" INNSEGL_STACK_PREFIX=innsegl-dev INNSEGL_REKOR_PORT= \
  "$HERE/rekor-port.sh" >/dev/null
grep -q '^port innsegl-dev-sigstore-rekor 3000' "$LOG" \
  && ok "OPS-129 rekor-port.sh asks the dev Rekor" || bad "OPS-129 rekor-port.sh asks the dev Rekor" "$(cat "$LOG")"

check "OPS-129 the dev log has its own pin" \
  "$(INNSEGL_STACK_PREFIX=innsegl-dev "$HERE/rekor-tlog-pin.sh" rel)" "deploy/compose/.rekor-tlog-id.innsegl-dev"
check "OPS-129 the live pin is where it was" \
  "$(env -u INNSEGL_STACK_PREFIX "$HERE/rekor-tlog-pin.sh" rel)" "deploy/compose/.rekor-tlog-id"

cat > "$TMP/bin/curl" <<'SH'
#!/bin/sh
printf '{"needed":true}'
SH
chmod +x "$TMP/bin/curl"
: > "$LOG"
STUB_LOG="$LOG" INNSEGL_STACK_PREFIX=innsegl-dev INNSEGL_SETUP_LINK_CURL="$TMP/bin/curl" \
  INNSEGL_SETUP_LINK_DOCKER="$TMP/bin/docker" INNSEGL_SETUP_LINK_URL=http://localhost:8082 \
  "$HERE/setup-link.sh" >/dev/null 2>&1
grep -q '^exec innsegl-dev-api ' "$LOG" \
  && ok "OPS-129 setup-link.sh mints the code in the dev dashboard" || bad "OPS-129 setup-link.sh mints the code in the dev dashboard" "$(cat "$LOG")"

for s in "$HERE/rekor-reindex.sh:INNSEGL_STACK_PREFIX:-innsegl}-sigstore-rekor-index" \
         "$HERE/rekor-reindex.sh:INNSEGL_STACK_PREFIX:-innsegl}-sigstore-trillian-db" \
         "$HERE/backup-freshness.sh:INNSEGL_STACK_PREFIX:-innsegl}-backup" \
         "$HERE/../deploy/compose/spire/register.sh:INNSEGL_STACK_PREFIX:-innsegl}-spire-oidc" \
         "$HERE/../deploy/compose/spire/register.sh:dev/spire.yml"; do
  f="${s%%:*}"; want="${s#*:}"
  grep -qF -- "$want" "$f" && ok "OPS-129 $(basename "$f") names the dev ${want##*\}}" \
    || bad "OPS-129 $(basename "$f") names the dev ${want##*\}}" "no '$want' in $f"
done

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

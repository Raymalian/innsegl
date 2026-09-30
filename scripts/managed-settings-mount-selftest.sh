#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The API mounts the harness's managed-settings directory (ADR-0062) so it can
# check the socket denial before a passkey enrolment. On a Mac that directory
# is under /Library, which Docker Desktop does not share by default. Measured
# on 2026-09-30: `make start` stopped halfway with "is not shared from the
# host and is not known to Docker", after the API and dashboard had already
# been removed for recreation, so the dashboard was down until someone
# noticed. scripts/managed-settings-mount.sh names the directory once and
# checks Docker can mount it before anything is torn down.
set -u
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/uname" <<'SH'
#!/bin/sh
printf '%s\n' "${STUB_OS:-Linux}"
SH
# The stub records the -v argument it was given and fails when told to, the
# way Docker Desktop fails on a directory it does not share.
cat > "$TMP/bin/docker" <<'SH'
#!/bin/sh
while [ $# -gt 0 ]; do
  [ "$1" = "-v" ] && printf '%s\n' "$2" > "$STUB_SEEN"
  shift
done
[ -z "${STUB_DOCKER_FAIL:-}" ] || { echo "mounts denied: the path is not shared from the host" >&2; exit 125; }
exit 0
SH
chmod +x "$TMP/bin/uname" "$TMP/bin/docker"
export STUB_SEEN="$TMP/seen"
run() { PATH="$TMP/bin:$PATH" "$HERE/managed-settings-mount.sh" "$@" 2>&1; }

got="$(STUB_OS=Darwin INNSEGL_MANAGED_SETTINGS_HOST_DIR='' run)"
[ "$got" = "/Library/Application Support/ClaudeCode" ] && ok "a Mac mounts the harness's own directory" || bad "a Mac mounts the harness's own directory" "got '$got'"

got="$(STUB_OS=Linux INNSEGL_MANAGED_SETTINGS_HOST_DIR='' run)"
[ "$got" = "/etc/claude-code" ] && ok "Linux mounts the harness's own directory" || bad "Linux mounts the harness's own directory" "got '$got'"

got="$(STUB_OS=Darwin INNSEGL_MANAGED_SETTINGS_HOST_DIR=/srv/managed run)"
[ "$got" = "/srv/managed" ] && ok "an explicit directory wins" || bad "an explicit directory wins" "got '$got'"

rm -f "$STUB_SEEN"
got="$(STUB_OS=Darwin INNSEGL_MANAGED_SETTINGS_HOST_DIR='' run --check)"; rc=$?
seen="$(cat "$STUB_SEEN" 2>/dev/null)"
[ "$rc" -eq 0 ] && ok "a directory Docker can mount passes" || bad "a directory Docker can mount passes" "exit $rc: $got"
case "$seen" in
  "/Library/Application Support/ClaudeCode:"*) ok "the check mounts the same directory, spaces intact" ;;
  *) bad "the check mounts the same directory, spaces intact" "docker saw -v '$seen'" ;;
esac

got="$(STUB_OS=Darwin STUB_DOCKER_FAIL=1 INNSEGL_MANAGED_SETTINGS_HOST_DIR='' run --check)"; rc=$?
[ "$rc" -eq 3 ] && ok "a directory Docker cannot mount stops the start (exit 3)" || bad "a directory Docker cannot mount stops the start (exit 3)" "exit $rc"
case "$got" in
  *"/Library/Application Support/ClaudeCode"*"File sharing"*) ok "the refusal names the directory and where to share it" ;;
  *) bad "the refusal names the directory and where to share it" "got '$got'" ;;
esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

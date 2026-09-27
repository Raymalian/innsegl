#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# RM-216 (#347): every tool finds the port Rekor actually listens on.
#
# `make start` publishes Rekor on a random free port, and every other tool
# assumed 23000. Measured on a fresh VM: `make rekor-tlog-id` failed with
# "rekor is not answering on port 23000" and the readiness report said the log
# was UNREACHABLE, while Rekor was up on another port. scripts/rekor-port.sh is
# the one answer: an explicit INNSEGL_REKOR_PORT, else the port Docker
# publishes, else 23000.
set -u
pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
cat > "$TMP/bin/docker" <<'SH'
#!/bin/sh
[ "$1 $2 $3" = "port innsegl-sigstore-rekor 3000" ] || exit 1
[ -n "${STUB_PORT:-}" ] || exit 1
printf '127.0.0.1:%s\n' "$STUB_PORT"
SH
chmod +x "$TMP/bin/docker"

got="$(PATH="$TMP/bin:$PATH" STUB_PORT=54321 INNSEGL_REKOR_PORT= "$HERE/rekor-port.sh" 2>&1)"
[ "$got" = "54321" ] && ok "RM-216 the port Docker publishes is found" || bad "RM-216 the port Docker publishes is found" "got '$got'"
got="$(PATH="$TMP/bin:$PATH" STUB_PORT=54321 INNSEGL_REKOR_PORT=40000 "$HERE/rekor-port.sh" 2>&1)"
[ "$got" = "40000" ] && ok "RM-216 an explicit port wins" || bad "RM-216 an explicit port wins" "got '$got'"
got="$(PATH="$TMP/bin:$PATH" STUB_PORT= INNSEGL_REKOR_PORT= "$HERE/rekor-port.sh" 2>&1)"
[ "$got" = "23000" ] && ok "RM-216 with no Rekor running, the default" || bad "RM-216 with no Rekor running, the default" "got '$got'"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]

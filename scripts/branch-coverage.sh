#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Branch coverage gate for the surfaces IP §2 names.
#
# IP §2 requires 100% BRANCH coverage on four surfaces, not four packages:
#
#   1. hash-chain append          internal/ledger/chain.go
#   2. segment sealing            internal/segment/seal.go, merkle.go
#   3. signature verification     internal/verify/       (RM-037)
#   4. every error-return path
#      of every MCP tool          internal/mcp/          (RM-022..025)
#
# Go has no branch coverage mode — `go tool cover` counts statements, and a
# function can reach 100% statements with an untaken `if`, which is exactly the
# case this floor exists to catch. gobco instruments conditions instead, and
# reports any that were only ever evaluated in one direction.
#
# ADR-0043 records why gobco was chosen and why this runs as its own CI job.
#
# A surface whose file does not exist yet is reported as PENDING, never passed
# silently — the mechanism that matters if a floored surface is ever removed,
# not only while RM-037 and RM-022..025 were still landing.

set -eu

fail=0
pending=0
checked=0

# "package|file-prefix|description" — bash 3.2 safe, no associative arrays.
SURFACES="
internal/ledger|internal/ledger/chain.go|hash-chain append
internal/segment|internal/segment/seal.go|segment sealing
internal/segment|internal/segment/merkle.go|merkle construction
internal/verify|internal/verify/|signature verification (RM-037)
internal/mcp|internal/mcp/|MCP tool error paths (RM-022..025)
"

GOBCO="${GOBCO:-gobco}"
if ! command -v "$GOBCO" >/dev/null 2>&1; then
  if [ -x "$(go env GOPATH)/bin/gobco" ]; then
    GOBCO="$(go env GOPATH)/bin/gobco"
  else
    echo "branch-coverage: gobco not found. Install with:" >&2
    echo "  go install github.com/rillig/gobco@latest" >&2
    exit 4
  fi
fi

printf '==> branch coverage — IP §2\n'

# Run gobco once per distinct package, then attribute findings to surfaces.
pkgs=$(printf '%s\n' "$SURFACES" | while IFS='|' read -r p f d; do
  [ -n "${p:-}" ] || continue
  [ -e "$p" ] || continue
  echo "$p"
done | sort -u)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# gobco exits non-zero for a failing test as well as for a crash, and a crash
# names no file: counting findings alone would read "gobco never ran" as 100%
# (measured 2026-10-09: a gobco built against a Go toolchain since upgraded
# panicked before any test, and every surface read ok). So a package's run
# counts only when gobco exited 0 and printed its own summary line.
for p in $pkgs; do
  f="$tmp/$(echo "$p" | tr / _).txt"
  rc=0
  "$GOBCO" -branch "./$p" > "$f" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || ! grep -q '^Branch coverage: ' "$f"; then
    echo "$p" >> "$tmp/norun"
    echo "gobco exited $rc on ./$p; its last lines:" >> "$tmp/norun.log"
    tail -n 15 "$f" >> "$tmp/norun.log"
  fi
done

printf '%s\n' "$SURFACES" | while IFS='|' read -r pkg file desc; do
  [ -n "${pkg:-}" ] || continue
  if [ ! -e "$pkg" ]; then
    printf '    PENDING  %-46s %s does not exist yet\n' "$desc" "$pkg"
    continue
  fi
  out="$tmp/$(echo "$pkg" | tr / _).txt"
  if grep -qx "$pkg" "$tmp/norun" 2>/dev/null; then
    printf '    FAIL     %-46s gobco did not run on %s\n' "$desc" "$pkg"
    continue
  fi
  hits=$(grep -c "^$file" "$out" 2>/dev/null || true)
  hits=${hits:-0}
  if [ "$hits" -gt 0 ]; then
    printf '    FAIL     %-46s %s one-directional condition(s)\n' "$desc" "$hits"
    grep "^$file" "$out" | sed 's/^/               /'
  else
    printf '    ok       %-46s 100%% branch\n' "$desc"
  fi
done | tee "$tmp/report"

# The subshell above cannot set our counters, so derive them from the report.
fail=$(grep -c '^    FAIL' "$tmp/report" || true);       fail=${fail:-0}
pending=$(grep -c '^    PENDING' "$tmp/report" || true); pending=${pending:-0}
checked=$(grep -c '^    ok' "$tmp/report" || true);      checked=${checked:-0}

printf '\n'
[ -s "$tmp/norun.log" ] && cat "$tmp/norun.log" && printf '\n'
if [ "$fail" -gt 0 ]; then
  printf 'branch coverage: BREACHED (%s surface(s) below 100%%)\n' "$fail"
  exit 1
fi
printf 'branch coverage: OK (%s surface(s) at 100%%, %s pending)\n' "$checked" "$pending"
[ "$pending" -gt 0 ] && printf '  pending surfaces are not yet implemented; they are reported, never skipped silently\n'
exit 0

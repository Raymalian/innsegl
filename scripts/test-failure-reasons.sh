#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Say WHY each failed test failed, from a go test -json transcript.
#
#   scripts/test-failure-reasons.sh <go test -json output>
#
# go test -json carries every line a test printed as an "output" action, and a
# "fail" action with no output at all. RM-070 (#100) is the report of a CI
# failure that carried no evidence, which is why this prints the transcript.
#
# NOT THE FIRST N LINES. Measured on 2026-09-26: OPS-029 failed in CI, and the
# report showed its first 40 lines, which were a Docker image download. The line
# that said what failed came after them and was cut off. So this prints every
# line the testing package wrote (`name_test.go:N: ...`: the logs and the
# assertions) and then the last lines of everything else, which is where a
# panic or a fatal message lands. Noise, however long, can push out neither.
#
# Prints nothing when nothing failed.
set -uo pipefail

json="${1:?usage: test-failure-reasons.sh <go test -json output>}"
[ -s "$json" ] || exit 0

# A PACKAGE THAT TIMED OUT. Measured in CI on 2026-10-11 (PR #620): test/deploy
# hit go test's ten-minute -timeout. The panic names every test still running,
# but go test -json files it as output of whichever test was running and gives
# NO test a "fail" action — only the package. Read as a list of failed tests,
# that run had none, and the report said "fail test/deploy" and nothing else.
# So for each failed package this prints the panic line, the "running tests:"
# list, and the slowest top-level tests that finished before it, which is
# where the package's time went. The goroutine dump is left out.
fpkgs="$(grep -F '"Action":"fail"' "$json" | grep -vF '"Test":' \
  | sed -n -e 's/.*"Package":"\([^"]*\)".*/\1/p' | sort -u)"
while IFS= read -r p; do
  [ -n "$p" ] || continue
  panic="$(grep -F '"Action":"output"' "$json" | grep -F "\"Package\":\"${p}\"" \
    | sed -e 's/.*"Output":"//' -e 's/\\n"}$//' -e 's/\\n",.*$//' \
    | awk '/^panic: test timed out/ { on = 1; print; next }
           on && /^\\trunning tests:/ { print "  running tests:"; next }
           on && /^\\t\\t/ { sub(/^\\t\\t/, "    "); print; next }
           on { exit }')"
  [ -n "$panic" ] || continue
  printf '\n--- %s timed out ---\n%s\n' "$p" "$panic"
  printf '  slowest tests that finished first (seconds):\n'
  grep -E '"Action":"(pass|fail|skip)"' "$json" | grep -F "\"Package\":\"${p}\"" \
    | grep -F '"Test":' | grep -F '"Elapsed":' \
    | sed -n -e 's/.*"Test":"\([^"/]*\)".*"Elapsed":\([0-9.]*\).*/\2 \1/p' \
    | sort -rn | awk 'NR <= 15 { printf "    %8.1f  %s\n", $1, $2 }'
done <<EOF_PKGS
${fpkgs}
EOF_PKGS

failed="$(grep -F '"Action":"fail"' "$json" | grep -F '"Test":' \
  | sed -e 's/.*"Test":"//' -e 's/".*//' | sort -u)"
[ -n "$failed" ] || exit 0

printf '\n--- why ---\n'
while IFS= read -r t; do
  [ -n "$t" ] || continue
  printf '\n%s\n' "$t"
  lines="$(grep -F '"Action":"output"' "$json" | grep -F "\"Test\":\"${t}\"" \
    | sed -e 's/.*"Output":"//' -e 's/\\n"}$//' -e 's/\\t/  /g' -e 's/^/  /')"
  asserted="$(printf '%s\n' "$lines" | grep -E '_test\.go:[0-9]+:' || true)"
  if [ -n "$asserted" ]; then
    printf '%s\n' "$asserted" | awk 'NR <= 80'
  fi
  printf '  ... the last lines it printed:\n'
  printf '%s\n' "$lines" | awk '{ last[NR % 20] = $0 } END { s = NR > 20 ? NR - 19 : 1; for (i = s; i <= NR; i++) print last[i % 20] }'
done <<EOF_FAILED
${failed}
EOF_FAILED

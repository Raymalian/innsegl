#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Say how long each package ran, against the -timeout it runs under.
#
#   scripts/test-package-times.sh <go test -json output> <limit in seconds>
#
# go test's -timeout is per package, and a package that crosses it dies with a
# panic instead of a test result. Measured in CI on 2026-10-11 (PR #620):
# test/deploy reached the ten-minute limit for the second time in two days,
# and no earlier run had said it was getting close. Its runtime was in the
# JSON stream every time; nothing printed it.
#
# So this prints every package that ran, slowest first, with its share of the
# limit, and raises a GitHub warning for any package past 60% of it: the
# headroom a CI runner under load needs (test/deploy measured 372s alone on a
# workstation and over 600s in CI). A warning is the cue to split the package
# the way test/deploy was split, before it fails. It never fails the run.
set -uo pipefail

json="${1:?usage: test-package-times.sh <go test -json output> <limit seconds>}"
limit="${2:?usage: test-package-times.sh <go test -json output> <limit seconds>}"
[ -s "$json" ] || exit 0

rows="$(grep -E '"Action":"(pass|fail)"' "$json" | grep -vF '"Test":' \
  | sed -n -e 's/.*"Package":"\([^"]*\)".*"Elapsed":\([0-9.]*\).*/\2 \1/p' \
  | sort -rn)"
[ -n "$rows" ] || exit 0

printf '\n--- package runtimes (each package'"'"'s -timeout is %ss) ---\n' "$limit"
printf '%s\n' "$rows" | awk -v limit="$limit" '{
  printf "%8.1fs %4d%%  %s\n", $1, int($1 * 100 / limit + 0.5), $2
}'
printf '%s\n' "$rows" | awk -v limit="$limit" '$1 * 100 > limit * 60 {
  printf "::warning title=package near its timeout::%s ran %.1fs, %d%% of its %ds -timeout. Split it before it reaches the limit, as test/deploy was.\n", $2, $1, int($1 * 100 / limit + 0.5), limit
}'
exit 0

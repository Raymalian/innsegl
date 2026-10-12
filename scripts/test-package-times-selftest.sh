#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/test-package-times.sh, driven against go test -json fixtures.
#
# MEASURED in CI on 2026-10-11 (PR #620): test/deploy ran into go test's
# ten-minute -timeout for the second time in two days, and nothing had said it
# was getting close. The runtime of each package is in the JSON stream; this
# holds the report that prints it, and the warning that fires before a package
# reaches its limit rather than after.
set -uo pipefail

TIMES="${INNSEGL_PACKAGE_TIMES:-$(cd "$(dirname "$0")" && pwd)/test-package-times.sh}"
pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

J="$WORK/run.json"
{
  printf '{"Action":"pass","Package":"m/fast","Elapsed":3.2}\n'
  printf '{"Action":"pass","Package":"m/slow","Test":"TestBig","Elapsed":500}\n'
  printf '{"Action":"pass","Package":"m/slow","Elapsed":420.5}\n'
  printf '{"Action":"fail","Package":"m/mid","Elapsed":300}\n'
  printf '{"Action":"skip","Package":"m/none","Elapsed":0}\n'
} > "$J"

got="$("$TIMES" "$J" 600 2>&1)"
order="$(printf '%s\n' "$got" | grep -E '^ +[0-9.]+s +[0-9]+%' | grep -oE 'm/(fast|slow|mid)' | tr '\n' ' ')"
if [ "$order" = "m/slow m/mid m/fast " ]; then
  ok "packages are listed slowest first"
else
  bad "the order was '$order':\n$got"
fi
if printf '%s\n' "$got" | grep -qE '420\.5s +70% +m/slow'; then
  ok "each line gives the runtime and its share of the limit"
else
  bad "the slow package's line is wrong:\n$got"
fi
if printf '%s\n' "$got" | grep -q '^::warning.*m/slow ran 420.5s, 70% of its 600s'; then
  ok "a package past 60% of its limit raises a CI warning"
else
  bad "no warning for the package at 70%:\n$got"
fi
if printf '%s\n' "$got" | grep -q '^::warning.*m/mid'; then
  bad "a package at 50% was warned about"
else
  ok "and one at 50% is not"
fi
if printf '%s\n' "$got" | grep -q 'TestBig\|m/none'; then
  bad "a test, or a package with no tests, was listed as a package runtime"
else
  ok "and only packages that ran are listed"
fi
if "$TIMES" "$J" 600 >/dev/null 2>&1; then
  ok "the report never fails the run on its own"
else
  bad "the report exited non-zero"
fi

: > "$WORK/none.json"
if [ -z "$("$TIMES" "$WORK/none.json" 600 2>&1)" ]; then
  ok "an empty run prints nothing"
else
  bad "an empty run printed a report"
fi

echo
echo "package-times-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

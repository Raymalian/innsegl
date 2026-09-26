#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/test-failure-reasons.sh, driven against go test -json fixtures.
#
# MEASURED in CI on 2026-09-26: OPS-029 failed, and the report showed the first
# 40 lines the test printed. Those were a Docker image download, so the line
# that said WHAT failed was cut off and the failure could not be diagnosed.
# The case below buries an assertion under exactly that kind of noise.
set -uo pipefail

SUMMARY="${INNSEGL_FAILURE_REASONS:-$(cd "$(dirname "$0")" && pwd)/test-failure-reasons.sh}"
pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok    $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# out <test> <line> — one go test -json output action.
out() { printf '{"Action":"output","Package":"p","Test":"%s","Output":"%s\\n"}\n' "$1" "$2"; }

J="$WORK/buried.json"
{
  out TestBuried "=== RUN   TestBuried"
  out TestBuried "    x_test.go:10: phase A starting"
  for i in $(seq 1 60); do out TestBuried "          layer$i: Pulling fs layer"; done
  out TestBuried "    x_test.go:99: the gateway answered 403, want 200"
  out TestBuried "--- FAIL: TestBuried (1.00s)"
  printf '{"Action":"fail","Package":"p","Test":"TestBuried"}\n'
  out TestPassed "    y_test.go:5: fine"
  printf '{"Action":"pass","Package":"p","Test":"TestPassed"}\n'
} > "$J"

got="$("$SUMMARY" "$J" 2>&1)"
if printf '%s' "$got" | grep -q "x_test.go:99: the gateway answered 403"; then
  ok "an assertion buried under 60 lines of noise is shown"
else
  bad "the buried assertion was cut off:\n$got"
fi
if printf '%s' "$got" | grep -q "x_test.go:10: phase A starting"; then
  ok "and the test's own earlier log lines are shown too"
else
  bad "the earlier log line was dropped"
fi
if printf '%s' "$got" | grep -q "TestPassed\|y_test.go"; then
  bad "a passing test's output was reported as a failure's"
else
  ok "and a passing test says nothing"
fi
if printf '%s' "$got" | grep -qi "broken pipe"; then
  bad "the report printed a broken pipe"
else
  ok "and nothing in the report is a broken pipe"
fi

: > "$WORK/none.json"
if [ -z "$("$SUMMARY" "$WORK/none.json" 2>&1)" ]; then
  ok "no failure prints nothing"
else
  bad "a run with no failure printed a report"
fi

echo
echo "failure-reasons-selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

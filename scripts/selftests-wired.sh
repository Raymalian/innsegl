#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Every gate self-test runs in CI, or says in writing why it cannot — #279.
#
# A self-test only protects anyone if something runs it on what was pushed.
# Measured on 2026-09-17: five self-tests were named in no workflow, and one of
# them had been failing with nothing to report it. A local hook does not
# travel to a clone or another checkout, so "it runs on my machine" is not a
# control.
#
# This lists every scripts/**/*-selftest.sh and fails on any that no workflow
# under .github/workflows names, unless NOT_IN_CI below records why. An entry
# there is a reason, not a way to make this green: each one says what the test
# needs that CI cannot have.
#
# USAGE
#   scripts/selftests-wired.sh [<repository root>]
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

# <path relative to the root> | <why CI cannot run it>
# INNSEGL_NOT_IN_CI replaces the list, for this gate's own self-test only.
NOT_IN_CI_DEFAULT='scripts/no-personal-identity-selftest.sh|two of its cases check the operator'"'"'s own permitted-name list, which is untracked on purpose: publishing it would publish the names it exists to keep out
scripts/verify-branch-selftest.sh|it checks real signatures against the deployment'"'"'s own Fulcio and Rekor, which a CI runner cannot reach; the branch gate it tests runs where the deployment is, for the same reason'
NOT_IN_CI="${INNSEGL_NOT_IN_CI-$NOT_IN_CI_DEFAULT}"

missing=0
checked=0
while IFS= read -r test; do
  rel="${test#"$ROOT"/}"
  checked=$((checked + 1))
  if grep -rqF -- "$(basename "$rel")" "$ROOT/.github/workflows" 2>/dev/null; then
    continue
  fi
  if printf '%s\n' "$NOT_IN_CI" | grep -q "^${rel}|"; then
    continue
  fi
  echo "selftests-wired: $rel is run by no workflow and has no recorded reason" >&2
  missing=$((missing + 1))
done < <(find "$ROOT/scripts" -name '*-selftest.sh' -type f | sort)

# A recorded reason for a file that no longer exists is a reason for nothing.
while IFS='|' read -r rel _; do
  [ -n "$rel" ] || continue
  if [ ! -f "$ROOT/$rel" ]; then
    echo "selftests-wired: NOT_IN_CI names $rel, which does not exist" >&2
    missing=$((missing + 1))
  fi
done <<< "$NOT_IN_CI"

if [ "$checked" -eq 0 ]; then
  echo "selftests-wired: found no self-tests under $ROOT/scripts; refusing to pass on nothing" >&2
  exit 1
fi
if [ "$missing" -gt 0 ]; then
  exit 1
fi
echo "selftests-wired: all $checked self-tests run in CI or say why they cannot"

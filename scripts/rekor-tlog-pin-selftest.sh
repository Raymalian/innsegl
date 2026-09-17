#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-055 — the transparency log's pin survives a worktree (RM-150, #242).
#
# WHY THIS NEEDS A REAL WORKTREE. The bug is not in the pin's content, it is in
# WHERE the pin is looked for: the file is gitignored, so a git worktree is a
# checkout that does not carry it, and the fallback for "absent" is 0 — the
# value that means mint a new tree. A fixture that only wrote and read a file
# would pass against the broken code, because the broken code read a file too.
# It read the wrong one.
#
# The last case is the one that keeps the others honest: minting must still be
# ALLOWED on a machine that has no log yet, or the guard would be a gate that
# refuses every first boot.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
PIN="${ROOT}/scripts/rekor-tlog-pin.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'git -C "${TMP}/repo" worktree remove --force "${TMP}/wt" >/dev/null 2>&1; rm -rf "${TMP}"' EXIT

REPO="${TMP}/repo"
mkdir -p "${REPO}/deploy/compose" "${REPO}/scripts"
cp "${PIN}" "${ROOT}/scripts/repo-main-worktree.sh" "${REPO}/scripts/"
git -C "${REPO}" init -q
git -C "${REPO}" config user.email "selftest@example.invalid"
git -C "${REPO}" config user.name "selftest"
printf 'deploy/compose/.rekor-tlog-id\n' >"${REPO}/.gitignore"
git -C "${REPO}" add -A
git -C "${REPO}" commit -q -m seed --no-gpg-sign
git -C "${REPO}" worktree add -q "${TMP}/wt" -b wt
WT="${TMP}/wt"

# PHYSICAL paths for comparison. mktemp hands out /var/... on macOS and the
# resolver answers /private/var/..., which is the same directory spelled two
# ways — the exact class of bug this repository keeps meeting. Comparing the
# unresolved spellings failed here first.
REPO_P="$(cd -- "${REPO}" && pwd -P)"
WT_P="$(cd -- "${WT}" && pwd -P)"

# The deployment's real pin, in the repository and NOT in the worktree, which
# is exactly the arrangement that minted a second tree.
printf '2028999985815895099\n' >"${REPO}/deploy/compose/.rekor-tlog-id"

echo "the pin is found from a worktree"

got="$("${REPO}/scripts/rekor-tlog-pin.sh" read "${WT}")"
if [ "${got}" = "2028999985815895099" ]; then
  ok "read from a worktree answers the repository's pin"
else
  bad "read from a worktree answers the repository's pin" "got '${got}' — 0 means it would MINT"
fi

got="$("${REPO}/scripts/rekor-tlog-pin.sh" path "${WT}")"
case "${got}" in
  "${WT_P}"/*) bad "the path resolves to the repository, not the worktree" "got ${got}" ;;
  "${REPO_P}"/*) ok "the path resolves to the repository, not the worktree" ;;
  *) bad "the path resolves to the repository, not the worktree" "got ${got}" ;;
esac

# The old rule, asserted so the case cannot quietly stop being a case: if a
# worktree ever carried gitignored files, this file would be testing nothing.
if [ -e "${WT}/deploy/compose/.rekor-tlog-id" ]; then
  bad "a worktree really does lack the gitignored pin" "the worktree has the file; the bug shape is gone"
else
  ok "a worktree really does lack the gitignored pin"
fi

echo "an absent pin reads as 0, and 0 is what mints"

rm -f "${REPO}/deploy/compose/.rekor-tlog-id"
got="$("${REPO}/scripts/rekor-tlog-pin.sh" read "${WT}")"
[ "${got}" = "0" ] && ok "an absent pin reads as 0" || bad "an absent pin reads as 0" "got '${got}'"

printf 'not-a-tree-id\n' >"${REPO}/deploy/compose/.rekor-tlog-id"
got="$("${REPO}/scripts/rekor-tlog-pin.sh" read "${WT}")"
[ "${got}" = "0" ] && ok "a pin that is not digits reads as 0, not as itself" \
  || bad "a pin that is not digits reads as 0, not as itself" "got '${got}' — Rekor would take that as a tree id"

echo "the guard refuses a silent mint, and allows a first boot"

printf '2028999985815895099\n' >"${REPO}/deploy/compose/.rekor-tlog-id"
"${REPO}/scripts/rekor-tlog-pin.sh" guard "${WT}" >/dev/null 2>&1 \
  && ok "a pinned deployment passes the guard" \
  || bad "a pinned deployment passes the guard" "it refused a deployment that is already pinned"

rm -f "${REPO}/deploy/compose/.rekor-tlog-id"
if command -v docker >/dev/null 2>&1; then
  # A volume name that cannot exist stands in for "this machine has no log".
  out="$(INNSEGL_TRUST_TRILLIAN_DB_VOLUME=innsegl-selftest-no-such-log-$$ \
    "${REPO}/scripts/rekor-tlog-pin.sh" guard "${WT}" 2>&1)"; rc=$?
  [ "${rc}" -eq 0 ] && ok "a machine with no log may still mint (first boot)" \
    || bad "a machine with no log may still mint (first boot)" "exit ${rc}: ${out}"

  # And the dangerous case: no pin, but a log already exists.
  vol="innsegl-selftest-log-$$"
  docker volume create "${vol}" >/dev/null 2>&1
  out="$(INNSEGL_TRUST_TRILLIAN_DB_VOLUME="${vol}" \
    "${REPO}/scripts/rekor-tlog-pin.sh" guard "${WT}" 2>&1)"; rc=$?
  docker volume rm "${vol}" >/dev/null 2>&1
  if [ "${rc}" -eq 3 ] && printf '%s' "${out}" | grep -q "REFUSING to mint"; then
    ok "no pin + an existing log is REFUSED, and says how to recover"
  else
    bad "no pin + an existing log is REFUSED, and says how to recover" "exit ${rc}: $(printf '%s' "${out}" | head -2)"
  fi
else
  printf '  ....  guard cases need docker; skipped the two that do\n'
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]

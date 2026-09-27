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
# The guard reads the log database's pinned image from its own repository's
# sigstore.yml (#343), so the staged copy carries it.
mkdir -p "${REPO}/deploy/compose" && cp "${ROOT}/deploy/compose/sigstore.yml" "${REPO}/deploy/compose/"
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

  # A FRESH MACHINE: `make start` creates the trust volumes EMPTY before
  # sigstore-up runs (trust-volumes.sh ensure), so on first boot the log's
  # volume exists and holds nothing. Measured on a new VM on 2026-09-27: the
  # guard read the empty volume as an existing log and refused, so a fresh
  # install could not start (#343). An empty volume is no log.
  empty="innsegl-selftest-empty-log-$$"
  docker volume create "${empty}" >/dev/null 2>&1
  out="$(INNSEGL_TRUST_TRILLIAN_DB_VOLUME="${empty}" \
    "${REPO}/scripts/rekor-tlog-pin.sh" guard "${WT}" 2>&1)"; rc=$?
  docker volume rm "${empty}" >/dev/null 2>&1
  [ "${rc}" -eq 0 ] && ok "RM-213 an empty log volume (first boot) may still mint" \
    || bad "RM-213 an empty log volume (first boot) may still mint" "exit ${rc}: $(printf '%s' "${out}" | head -2)"

  # And the dangerous case: no pin, but a log already exists -- a volume
  # holding a database, which is what a log that has ever run leaves.
  vol="innsegl-selftest-log-$$"
  docker volume create "${vol}" >/dev/null 2>&1
  docker run --rm --entrypoint sh -v "${vol}:/v" "$("${REPO}/scripts/rekor-tlog-pin.sh" db-image "${WT}")" \
    -c 'mkdir -p /v/trillian && echo x > /v/trillian/db.opt' >/dev/null 2>&1
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

# RM-215 (#345). THE PIN IS RECORDED ONCE THE LOG ANSWERS, AND ONLY THEN.
#
# Bring-up recorded the pin right after starting Rekor, without waiting, and
# swallowed the failure. Measured on a new VM: Rekor was still starting, no pin
# was written, and the next `make start` there would have been refused by the
# guard above for a log that had simply never been pinned. `record` waits for
# the log to answer, and fails loudly -- writing nothing -- if it never does.
STUB="${TMP}/stubbin"; mkdir -p "${STUB}"
cat > "${STUB}/curl" <<'STUBSH'
#!/bin/sh
n=$(cat "${STUB_COUNT}" 2>/dev/null || echo 0); n=$((n + 1)); echo "${n}" > "${STUB_COUNT}"
[ "${n}" -gt "${STUB_FAILS}" ] || exit 7
printf '{"treeSize":1,"signedTreeHead":"rekor.test - 2028999985815895099\\n1\\n"}'
STUBSH
chmod +x "${STUB}/curl"
rm -f "${REPO}/deploy/compose/.rekor-tlog-id"
out="$(PATH="${STUB}:${PATH}" STUB_COUNT="${TMP}/n1" STUB_FAILS=2 INNSEGL_REKOR_PIN_WAIT=10 INNSEGL_REKOR_PIN_INTERVAL=0 \
  "${REPO}/scripts/rekor-tlog-pin.sh" record http://127.0.0.1:1 "${WT}" 2>&1)"; rc=$?
if [ "${rc}" -eq 0 ] && [ "$(cat "${REPO}/deploy/compose/.rekor-tlog-id" 2>/dev/null)" = "2028999985815895099" ]; then
  ok "RM-215 a log that answers after a slow start is pinned"
else
  bad "RM-215 a log that answers after a slow start is pinned" "exit ${rc}: ${out}"
fi
rm -f "${REPO}/deploy/compose/.rekor-tlog-id"
out="$(PATH="${STUB}:${PATH}" STUB_COUNT="${TMP}/n2" STUB_FAILS=999 INNSEGL_REKOR_PIN_WAIT=2 INNSEGL_REKOR_PIN_INTERVAL=1 \
  "${REPO}/scripts/rekor-tlog-pin.sh" record http://127.0.0.1:1 "${WT}" 2>&1)"; rc=$?
if [ "${rc}" -ne 0 ] && [ ! -e "${REPO}/deploy/compose/.rekor-tlog-id" ] && printf '%s' "${out}" | grep -qi "not answering"; then
  ok "RM-215 a log that never answers fails loudly and pins nothing"
else
  bad "RM-215 a log that never answers fails loudly and pins nothing" "exit ${rc}: ${out}"
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]

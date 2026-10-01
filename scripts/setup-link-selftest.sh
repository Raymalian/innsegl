#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# scripts/setup-link.sh's own cases (#445) — entirely against FAKE curl and
# docker commands this file writes, named by $INNSEGL_SETUP_LINK_CURL and
# $INNSEGL_SETUP_LINK_DOCKER: nothing here reaches a real deployment, a real
# API, or a real container, matching backup-ledger-selftest.sh's own
# "hermetic, start no container" discipline.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SCRIPT="${ROOT}/scripts/setup-link.sh"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

# fakecurl answers from a file this test writes: a line "<url> <body>" per
# known URL. A URL with no matching line answers nothing and exits 1, the
# same shape -f gives a real curl against an unreachable server.
write_fakecurl() {                # write_fakecurl <path> <responses-file>
  cat > "$1" <<'SHIM'
#!/bin/sh
# args: -fsS --max-time 10 <url> -- the url is always the LAST argument.
for a in "$@"; do url="$a"; done
line=$(grep -F "${url} " "${INNSEGL_FAKE_CURL_RESPONSES}" 2>/dev/null) || exit 1
printf '%s' "${line#* }"
SHIM
  chmod +x "$1"
}

# fakedocker answers `exec <container> sh -c '...'` with the contents of
# $INNSEGL_FAKE_DOCKER_CODE (or exits 1 if that file is absent/empty, the
# "minting failed" case), and records the container name and full argument
# list it was called with so a case can assert what was asked for.
write_fakedocker() {              # write_fakedocker <path>
  cat > "$1" <<'SHIM'
#!/bin/sh
printf '%s\n' "$*" >> "${INNSEGL_FAKE_DOCKER_CALLS}"
[ "$1" = "exec" ] || exit 0
if [ -n "${INNSEGL_FAKE_DOCKER_CODE:-}" ] && [ -s "${INNSEGL_FAKE_DOCKER_CODE}" ]; then
  cat "${INNSEGL_FAKE_DOCKER_CODE}"
  exit 0
fi
exit 1
SHIM
  chmod +x "$1"
}

run() {                           # run [extra args...]
  INNSEGL_SETUP_LINK_CURL="${FAKE_CURL}" \
  INNSEGL_SETUP_LINK_DOCKER="${FAKE_DOCKER}" \
  INNSEGL_FAKE_CURL_RESPONSES="${RESPONSES}" \
  INNSEGL_FAKE_DOCKER_CALLS="${DOCKER_CALLS}" \
  INNSEGL_FAKE_DOCKER_CODE="${DOCKER_CODE}" \
    "${SCRIPT}" "$@"
}

FAKE_CURL="${TMP}/fakecurl"
FAKE_DOCKER="${TMP}/fakedocker"
write_fakecurl "${FAKE_CURL}"
write_fakedocker "${FAKE_DOCKER}"

# ---------------------------------------------------------------------------
echo "an account that already exists prints nothing and mints nothing"

RESPONSES="${TMP}/responses-exists"
DOCKER_CALLS="${TMP}/calls-exists"
DOCKER_CODE="${TMP}/code-unused"
printf 'http://localhost:8082/api/v1/auth/setup {"needed":false}\n' > "${RESPONSES}"
: > "${DOCKER_CALLS}"

out="$(run)"; rc=$?
if [ "${rc}" = 0 ]; then
  ok "exits 0 when no account is needed"
else
  bad "exits 0 when no account is needed" "exit ${rc}"
fi
if [ -z "${out}" ]; then
  ok "prints nothing when no account is needed"
else
  bad "prints nothing when no account is needed" "got: ${out}"
fi
if [ -s "${DOCKER_CALLS}" ]; then
  bad "docker is never invoked when no account is needed" "calls: $(cat "${DOCKER_CALLS}")"
else
  ok "docker is never invoked when no account is needed"
fi

# ---------------------------------------------------------------------------
echo
echo "an account that is still needed mints a code and prints the link"

RESPONSES="${TMP}/responses-needed"
DOCKER_CALLS="${TMP}/calls-needed"
DOCKER_CODE="${TMP}/code-needed"
printf 'http://localhost:8082/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
: > "${DOCKER_CALLS}"
printf 'abcd-1234\n' > "${DOCKER_CODE}"

out="$(run)"; rc=$?
if [ "${rc}" = 0 ]; then
  ok "exits 0 when the link is printed"
else
  bad "exits 0 when the link is printed" "exit ${rc}: ${out}"
fi
case "${out}" in
  *"http://localhost:8082/setup?code=abcd-1234"*) ok "the link carries the minted code, trimmed" ;;
  *) bad "the link carries the minted code, trimmed" "got: ${out}" ;;
esac
if grep -q '^exec innsegl-api sh -c' "${DOCKER_CALLS}"; then
  ok "docker exec names the default container (innsegl-api)"
else
  bad "docker exec names the default container (innsegl-api)" "calls: $(cat "${DOCKER_CALLS}")"
fi
if grep -q 'INNSEGL_API_AUTH_DSN' "${DOCKER_CALLS}"; then
  ok "the enrol-code command reads INNSEGL_API_AUTH_DSN inside the container"
else
  bad "the enrol-code command reads INNSEGL_API_AUTH_DSN inside the container" \
      "calls: $(cat "${DOCKER_CALLS}")"
fi

# ---------------------------------------------------------------------------
echo
echo "--url and --container are honoured"

RESPONSES="${TMP}/responses-custom"
DOCKER_CALLS="${TMP}/calls-custom"
DOCKER_CODE="${TMP}/code-custom"
printf 'https://example.invalid:9999/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
: > "${DOCKER_CALLS}"
printf 'wxyz-9999\n' > "${DOCKER_CODE}"

out="$(run --url https://example.invalid:9999/ --container my-api)"; rc=$?
case "${out}" in
  *"https://example.invalid:9999/setup?code=wxyz-9999"*)
    ok "a custom --url is used, with no doubled slash" ;;
  *) bad "a custom --url is used, with no doubled slash" "got: ${out}" ;;
esac
if grep -q '^exec my-api sh -c' "${DOCKER_CALLS}"; then
  ok "a custom --container is used"
else
  bad "a custom --container is used" "calls: $(cat "${DOCKER_CALLS}")"
fi

# ---------------------------------------------------------------------------
echo
echo "the API being unreachable is reported, not silently swallowed"

RESPONSES="${TMP}/responses-empty"
DOCKER_CALLS="${TMP}/calls-unreachable"
DOCKER_CODE="${TMP}/code-unused2"
: > "${RESPONSES}"
: > "${DOCKER_CALLS}"

out="$(run 2>"${TMP}/stderr-unreachable")"; rc=$?
if [ "${rc}" = 4 ]; then
  ok "an unreachable API exits 4"
else
  bad "an unreachable API exits 4" "exit ${rc}"
fi
if grep -q 'could not reach' "${TMP}/stderr-unreachable"; then
  ok "an unreachable API says so on stderr"
else
  bad "an unreachable API says so on stderr" "$(cat "${TMP}/stderr-unreachable")"
fi
if [ -s "${DOCKER_CALLS}" ]; then
  bad "docker is never invoked when the API is unreachable" "calls: $(cat "${DOCKER_CALLS}")"
else
  ok "docker is never invoked when the API is unreachable"
fi

# ---------------------------------------------------------------------------
echo
echo "a failed mint is reported, not a link with an empty code"

RESPONSES="${TMP}/responses-mintfail"
DOCKER_CALLS="${TMP}/calls-mintfail"
DOCKER_CODE="${TMP}/code-empty"
printf 'http://localhost:8082/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
: > "${DOCKER_CALLS}"
: > "${DOCKER_CODE}"

out="$(run 2>"${TMP}/stderr-mintfail")"; rc=$?
if [ "${rc}" = 6 ]; then
  ok "a failed mint exits 6"
else
  bad "a failed mint exits 6" "exit ${rc}: ${out}"
fi
if printf '%s' "${out}" | grep -q 'setup?code='; then
  bad "a failed mint prints no link at all" "got: ${out}"
else
  ok "a failed mint prints no link at all"
fi
if grep -q 'minting the one-time code failed' "${TMP}/stderr-mintfail"; then
  ok "a failed mint says so on stderr"
else
  bad "a failed mint says so on stderr" "$(cat "${TMP}/stderr-mintfail")"
fi

# ---------------------------------------------------------------------------
echo
echo "an unknown flag is refused"

out="$("${SCRIPT}" --nonsense 2>&1)"; rc=$?
if [ "${rc}" = 2 ]; then
  ok "an unknown flag exits 2"
else
  bad "an unknown flag exits 2" "exit ${rc}: ${out}"
fi

# ---------------------------------------------------------------------------
echo
printf 'setup-link-selftest: %s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" = 0 ] || exit 1

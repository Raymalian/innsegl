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
if [ -n "${INNSEGL_FAKE_CURL_FAIL_FIRST:-}" ]; then
  n=$(cat "${INNSEGL_FAKE_CURL_COUNT}" 2>/dev/null || echo 0)
  n=$((n + 1)); echo "${n}" > "${INNSEGL_FAKE_CURL_COUNT}"
  [ "${n}" -le "${INNSEGL_FAKE_CURL_FAIL_FIRST}" ] && exit 1
fi
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

# run [extra args...]. Hermetic by default: no .env file is read, the real
# environment's INNSEGL_BIND / INNSEGL_DASHBOARD_PORT never leak in, and the
# wait for the API is zero (one attempt), so a case that wants to wait says so.
run() {
  env -u INNSEGL_DASHBOARD_PORT -u INNSEGL_SETUP_LINK_URL INNSEGL_BIND="${BIND:-}" \
  INNSEGL_SETUP_LINK_ENV="${ENVFILE:-${TMP}/no-such-env}" \
  INNSEGL_SETUP_LINK_WAIT="${WAIT:-0}" \
  INNSEGL_SETUP_LINK_INTERVAL="${INTERVAL:-1}" \
  INNSEGL_SETUP_LINK_CURL="${FAKE_CURL}" \
  INNSEGL_SETUP_LINK_DOCKER="${FAKE_DOCKER}" \
  INNSEGL_FAKE_CURL_RESPONSES="${RESPONSES}" \
  INNSEGL_FAKE_DOCKER_CALLS="${DOCKER_CALLS}" \
  INNSEGL_FAKE_DOCKER_CODE="${DOCKER_CODE}" \
  INNSEGL_FAKE_CURL_FAIL_FIRST="${FAIL_FIRST:-}" \
  INNSEGL_FAKE_CURL_COUNT="${TMP}/curl-count" \
    "${SCRIPT}" "$@"
}

FAKE_CURL="${TMP}/fakecurl"
FAKE_DOCKER="${TMP}/fakedocker"
write_fakecurl "${FAKE_CURL}"
write_fakedocker "${FAKE_DOCKER}"

# ---------------------------------------------------------------------------
echo "an account that already exists prints one line and mints nothing"

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
if [ "$(printf '%s\n' "${out}" | wc -l | tr -d ' ')" = 1 ] && printf '%s' "${out}" | grep -q 'account already exists'; then
  ok "prints exactly one line, saying an account already exists"
else
  bad "prints exactly one line, saying an account already exists" "got: ${out}"
fi
if printf '%s' "${out}" | grep -q 'setup?code='; then
  bad "prints no link when no account is needed" "got: ${out}"
else
  ok "prints no link when no account is needed"
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
if grep -q 'could not reach http://localhost:8082/api/v1/auth/setup' "${TMP}/stderr-unreachable"; then
  ok "an unreachable API says so on stderr, naming the URL it tried"
else
  bad "an unreachable API says so on stderr, naming the URL it tried" "$(cat "${TMP}/stderr-unreachable")"
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
echo "the dashboard's published address is read from the environment file (RM-325)"

RESPONSES="${TMP}/responses-bind"
DOCKER_CALLS="${TMP}/calls-bind"
DOCKER_CODE="${TMP}/code-bind"
printf 'http://192.0.2.10:9090/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
: > "${DOCKER_CALLS}"
printf 'bind-1111\n' > "${DOCKER_CODE}"
ENVFILE="${TMP}/env-bind"
printf '# comment\nINNSEGL_BIND=192.0.2.10\nINNSEGL_DASHBOARD_PORT="9090"\nOTHER=x\n' > "${ENVFILE}"

out="$(run)"; rc=$?
case "${out}" in
  *"http://192.0.2.10:9090/setup?code=bind-1111"*) ok "INNSEGL_BIND and INNSEGL_DASHBOARD_PORT from the env file build the URL" ;;
  *) bad "INNSEGL_BIND and INNSEGL_DASHBOARD_PORT from the env file build the URL" "exit ${rc}: ${out}" ;;
esac

# The real environment wins over the file.
printf 'http://192.0.2.77:9090/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
out="$(BIND=192.0.2.77 run)"; rc=$?
case "${out}" in
  *"http://192.0.2.77:9090/setup?code=bind-1111"*) ok "the environment overrides the env file" ;;
  *) bad "the environment overrides the env file" "exit ${rc}: ${out}" ;;
esac

# A wildcard bind is where the stack listens, not an address to dial.
printf 'http://localhost:8082/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
printf 'INNSEGL_BIND=0.0.0.0\n' > "${ENVFILE}"
out="$(run)"; rc=$?
case "${out}" in
  *"http://localhost:8082/setup?code=bind-1111"*) ok "INNSEGL_BIND=0.0.0.0 is reached as localhost" ;;
  *) bad "INNSEGL_BIND=0.0.0.0 is reached as localhost" "exit ${rc}: ${out}" ;;
esac
ENVFILE=""

# ---------------------------------------------------------------------------
echo
echo "an API that is slow to come up is waited for, boundedly (RM-325)"

RESPONSES="${TMP}/responses-slow"
DOCKER_CALLS="${TMP}/calls-slow"
DOCKER_CODE="${TMP}/code-slow"
printf 'http://localhost:8082/api/v1/auth/setup {"needed":true}\n' > "${RESPONSES}"
: > "${DOCKER_CALLS}"
printf 'slow-2222\n' > "${DOCKER_CODE}"
rm -f "${TMP}/curl-count"

out="$(WAIT=20 INTERVAL=1 FAIL_FIRST=2 run)"; rc=$?
case "${out}" in
  *"setup?code=slow-2222"*) ok "an API that answers on the third try yields the link" ;;
  *) bad "an API that answers on the third try yields the link" "exit ${rc}: ${out}" ;;
esac

RESPONSES="${TMP}/responses-never"
: > "${RESPONSES}"
: > "${DOCKER_CALLS}"
ENVFILE="${TMP}/env-never"
printf 'INNSEGL_BIND=192.0.2.10\n' > "${ENVFILE}"
start=$(date +%s)
out="$(WAIT=3 INTERVAL=1 run 2>"${TMP}/stderr-never")"; rc=$?
elapsed=$(( $(date +%s) - start ))
ENVFILE=""
if [ "${rc}" = 4 ]; then ok "an API that never answers exits 4 after the wait"; else bad "an API that never answers exits 4 after the wait" "exit ${rc}"; fi
if [ "${elapsed}" -ge 2 ] && [ "${elapsed}" -le 12 ]; then
  ok "it gave up in ${elapsed}s, not forever"
else
  bad "it gave up in about 3s, not forever" "took ${elapsed}s"
fi
if grep -q 'http://192.0.2.10:8082/api/v1/auth/setup' "${TMP}/stderr-never" \
   && grep -q 'scripts/setup-link.sh' "${TMP}/stderr-never"; then
  ok "one message names the URL tried and how to get the link later"
else
  bad "one message names the URL tried and how to get the link later" "$(cat "${TMP}/stderr-never")"
fi
if [ "$(wc -l < "${TMP}/stderr-never" | tr -d ' ')" -le 2 ]; then
  ok "no endless 'could not reach' lines"
else
  bad "no endless 'could not reach' lines" "$(cat "${TMP}/stderr-never")"
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

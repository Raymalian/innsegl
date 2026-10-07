#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-131 — the Sigstore bootstrap gives each host its own CA password, and
# moves an existing host onto one with no manual step (#533).
#
# It runs the SHIPPED deploy/compose/sigstore/bootstrap.sh, with the CA
# library it sources, in the pinned openssl image sigstore.yml runs it in,
# against throwaway directories. No compose project, no named volume, no
# network: nothing here can reach a real stack.
#
#   OPS-131a  a fresh host: a 32-byte password is generated into ca.pass, the
#             key opens with it and not with the old public default, and
#             Fulcio's serve.yaml carries it. Never printed.
#   OPS-131b  a second run changes nothing; two hosts get different passwords.
#   OPS-131c  an existing host with INNSEGL_FULCIO_CA_PASSWORD set: the file is
#             written from it once, the key is untouched.
#   OPS-131d  that variable set, and wrong for the key: refused, nothing written.
#   OPS-131e  an existing host whose key opens with the old public default:
#             re-locked with a new password, same key material, and the old
#             password no longer opens it.
#   OPS-131f  the variable set TO the old public default: not adopted; re-locked.
#   OPS-131g  neither a file nor the variable, and a key the old default does
#             not open: refused, nothing changed.
#   OPS-131h  a re-lock interrupted between its two renames is finished; one
#             interrupted before them is undone.
#   OPS-131i  a file already there wins over the variable, and says so.
#
# Needs docker. Files are owned by uid 65532 inside the volumes, so every read
# runs through the same image as root.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
SIG="${ROOT}/deploy/compose/sigstore"
COMPOSE="${ROOT}/deploy/compose/sigstore.yml"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

command -v docker >/dev/null 2>&1 || { echo 'sigstore-bootstrap-selftest: docker is required' >&2; exit 1; }

# The pin is read from sigstore.yml, so the test cannot run a different
# openssl from the one the stack runs.
IMAGE="$(sed -n 's/^  \(alpine\/openssl:[^ ]*\)$/\1/p' "${COMPOSE}" | head -n 1)"
[ -n "${IMAGE}" ] || { echo 'sigstore-bootstrap-selftest: no openssl image pin in sigstore.yml' >&2; exit 1; }
# The old public default, read from the library rather than written here again.
LEGACY="$(sed -n "s/^CA_LEGACY_PUBLIC_PASSWORD='\(.*\)'$/\1/p" "${SIG}/ca-lib.sh" 2>/dev/null)"
[ -n "${LEGACY}" ] || { echo 'sigstore-bootstrap-selftest: ca-lib.sh names no CA_LEGACY_PUBLIC_PASSWORD' >&2; exit 1; }

# A host is a pair of named volumes, the shape compose gives the bootstrap.
# Named volumes rather than bind mounts: a bind mount on a desktop Docker
# does not keep the uid a chown sets, and the owner is one of the checks.
# The names are this run's own and are removed on exit.
HOSTS=()
SEQ=0
cleanup() {
  local h
  for h in "${HOSTS[@]+"${HOSTS[@]}"}"; do
    docker volume rm -f "${h}-fulcio" "${h}-rekor" >/dev/null 2>&1
  done
}
trap cleanup EXIT

# new_host sets HOST to a new host's name. Not a $(...) call: a subshell
# would lose the count and the cleanup list.
new_host() {
  SEQ=$((SEQ + 1))
  HOST="innsegl-selftest-bootstrap-$$-${SEQ}"
  docker volume create "${HOST}-fulcio" >/dev/null && docker volume create "${HOST}-rekor" >/dev/null \
    || { echo "sigstore-bootstrap-selftest: could not create volumes for ${HOST}" >&2; exit 1; }
  HOSTS+=("${HOST}")
}

# boot HOST [ENV=VALUE...] runs the shipped bootstrap the way compose does.
boot() {
  local h="$1"; shift
  local envs=() e
  for e in "$@"; do envs+=(-e "${e}"); done
  docker run --rm --network none --read-only --tmpfs /tmp \
    --security-opt no-new-privileges:true \
    -e INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080 "${envs[@]+"${envs[@]}"}" \
    -v "${SIG}/bootstrap.sh:/bootstrap.sh:ro" \
    -v "${SIG}/ca-lib.sh:/ca-lib.sh:ro" \
    -v "${SIG}/fulcio-config.yaml:/in/fulcio-config.yaml:ro" \
    -v "${h}-fulcio:/out/fulcio" -v "${h}-rekor:/out/rekor" \
    --entrypoint /bin/sh "${IMAGE}" /bootstrap.sh 2>&1
}

# box HOST SCRIPT [ENV=VALUE] runs a shell in the image as root with the
# host's Fulcio volume at /f, and LEGACY in the environment.
box() {
  docker run --rm --network none -e LEGACY="${LEGACY}" ${3:+-e "$3"} -v "${1}-fulcio:/f" \
    --entrypoint /bin/sh "${IMAGE}" -c "$2" 2>&1
}

opens()        { box "$1" "openssl pkey -in /f/ca.key -passin file:/f/ca.pass -noout" >/dev/null; }
opens_legacy() { box "$1" "openssl pkey -in /f/ca.key -passin env:LEGACY -noout" >/dev/null; }
pass_of()      { box "$1" 'cat /f/ca.pass'; }
key_sum()      { box "$1" 'sha256sum /f/ca.key | cut -d" " -f1'; }
pub_of()       { box "$1" "openssl pkey -in /f/ca.key -passin file:/f/ca.pass -pubout"; }

# lock HOST PASSWORD re-encrypts the host's key under PASSWORD and removes the
# password file and serve.yaml: the shape of a host from before this change.
lock() {
  box "$1" 'set -e; openssl pkcs8 -in /f/ca.key -passin file:/f/ca.pass -out /tmp/p.key
    openssl pkcs8 -topk8 -v2 aes-256-cbc -in /tmp/p.key -out /f/ca.key.tmp -passout env:P
    mv /f/ca.key.tmp /f/ca.key; rm -f /f/ca.pass /f/serve.yaml' "P=$2" >/dev/null \
    || { echo "sigstore-bootstrap-selftest: could not lock ${1}'s key" >&2; exit 1; }
}

echo "OPS-131a — a fresh host gets its own password"
new_host; A="${HOST}"
out="$(boot "${A}")" || bad "the bootstrap succeeds on a fresh host" "${out}"
pa="$(pass_of "${A}")"
if printf '%s' "${pa}" | grep -qE '^[0-9a-f]{64}$'; then ok "ca.pass holds 32 random bytes, hex"; else bad "ca.pass holds 32 random bytes, hex" "got: ${pa:-nothing}"; fi
if opens "${A}"; then ok "the key opens with ca.pass"; else bad "the key opens with ca.pass"; fi
if opens_legacy "${A}"; then bad "the old public default does not open the key"; else ok "the old public default does not open the key"; fi
serve="$(box "${A}" 'cat /f/serve.yaml')"
if [ "${serve}" = "fileca-key-passwd: '${pa}'" ]; then ok "serve.yaml hands Fulcio the password"; else bad "serve.yaml hands Fulcio the password" "got: ${serve}"; fi
modes="$(box "${A}" 'stat -c "%a %u %n" /f/ca.key /f/ca.pass /f/serve.yaml')"
if [ "$(printf '%s\n' "${modes}" | grep -c '^400 65532 ')" = 3 ]; then ok "key, password and serve.yaml are 0400, owned by Fulcio's uid"; else bad "key, password and serve.yaml are 0400, owned by Fulcio's uid" "${modes}"; fi
if printf '%s' "${out}" | grep -qF "${pa}"; then bad "the password is never printed" "it is in the bootstrap's output"; else ok "the password is never printed"; fi

echo "OPS-131b — a re-run changes nothing; two hosts differ"
sum="$(key_sum "${A}")"
boot "${A}" >/dev/null || bad "a second run succeeds"
if [ "$(pass_of "${A}")" = "${pa}" ] && [ "$(key_sum "${A}")" = "${sum}" ]; then ok "a second run leaves the key and password alone"; else bad "a second run leaves the key and password alone"; fi
new_host; B="${HOST}"
boot "${B}" >/dev/null || bad "a second host bootstraps"
if [ "$(pass_of "${B}")" != "${pa}" ]; then ok "two hosts get different passwords"; else bad "two hosts get different passwords"; fi

echo "OPS-131c — an existing host with the variable set moves it into the file"
new_host; C="${HOST}"; boot "${C}" >/dev/null
lock "${C}" "it's an operator pw"
sum="$(key_sum "${C}")"
out="$(boot "${C}" "INNSEGL_FULCIO_CA_PASSWORD=it's an operator pw")" || bad "the bootstrap migrates the variable" "${out}"
if [ "$(pass_of "${C}")" = "it's an operator pw" ]; then ok "ca.pass is the variable's value"; else bad "ca.pass is the variable's value" "got: $(pass_of "${C}")"; fi
if [ "$(key_sum "${C}")" = "${sum}" ]; then ok "the key is not touched"; else bad "the key is not touched"; fi
if [ "$(box "${C}" 'cat /f/serve.yaml')" = "fileca-key-passwd: 'it''s an operator pw'" ]; then ok "serve.yaml quotes it for YAML"; else bad "serve.yaml quotes it for YAML" "$(box "${C}" 'cat /f/serve.yaml')"; fi
if printf '%s' "${out}" | grep -q 'no longer read'; then ok "it says the variable is no longer read"; else bad "it says the variable is no longer read" "${out}"; fi

echo "OPS-131d — the variable set, and wrong for the key"
new_host; D="${HOST}"; boot "${D}" >/dev/null
lock "${D}" "the real one"
sum="$(key_sum "${D}")"
if out="$(boot "${D}" "INNSEGL_FULCIO_CA_PASSWORD=not the real one")"; then bad "a wrong variable is refused" "${out}"; else ok "a wrong variable is refused"; fi
if box "${D}" 'test -e /f/ca.pass || test -e /f/ca.pass.new' >/dev/null; then bad "nothing is written"; else ok "nothing is written"; fi
if [ "$(key_sum "${D}")" = "${sum}" ]; then ok "the key is not touched"; else bad "the key is not touched"; fi

if out="$(boot "${D}" "INNSEGL_FULCIO_CA_PASSWORD=the real one
and a second line")"; then bad "a variable with a line break is refused" "${out}"; else ok "a variable with a line break is refused"; fi

echo "OPS-131e — a key on the old public default is re-locked"
new_host; E="${HOST}"; boot "${E}" >/dev/null
pub="$(pub_of "${E}")"
lock "${E}" "${LEGACY}"
sum="$(key_sum "${E}")"
out="$(boot "${E}")" || bad "the bootstrap re-locks" "${out}"
pe="$(pass_of "${E}")"
if printf '%s' "${pe}" | grep -qE '^[0-9a-f]{64}$'; then ok "a new password was generated"; else bad "a new password was generated" "${pe}"; fi
if opens "${E}" && ! opens_legacy "${E}"; then ok "the key opens with it, and no longer with the old default"; else bad "the key opens with it, and no longer with the old default"; fi
if [ "$(pub_of "${E}")" = "${pub}" ]; then ok "it is the same key"; else bad "it is the same key" "the public key changed"; fi
if [ "$(key_sum "${E}")" != "${sum}" ]; then ok "the file on disk was replaced"; else bad "the file on disk was replaced"; fi
if box "${E}" 'test -e /f/ca.key.new || test -e /f/ca.pass.new' >/dev/null; then bad "no temporary file is left"; else ok "no temporary file is left"; fi

echo "OPS-131f — the variable set to the old public default is not adopted"
new_host; F="${HOST}"; boot "${F}" >/dev/null
lock "${F}" "${LEGACY}"
boot "${F}" "INNSEGL_FULCIO_CA_PASSWORD=${LEGACY}" >/dev/null || bad "the bootstrap succeeds"
if [ "$(pass_of "${F}")" != "${LEGACY}" ] && opens "${F}" && ! opens_legacy "${F}"; then ok "re-locked instead"; else bad "re-locked instead"; fi

echo "OPS-131g — no file, no variable, a key the old default does not open"
new_host; G="${HOST}"; boot "${G}" >/dev/null
lock "${G}" "something private"
sum="$(key_sum "${G}")"
if out="$(boot "${G}")"; then bad "refused" "${out}"; else ok "refused"; fi
if printf '%s' "${out}" | grep -q 'INNSEGL_FULCIO_CA_PASSWORD'; then ok "the refusal names the variable to set"; else bad "the refusal names the variable to set" "${out}"; fi
if [ "$(key_sum "${G}")" = "${sum}" ] && ! box "${G}" 'test -e /f/ca.pass' >/dev/null; then ok "nothing changed"; else bad "nothing changed"; fi

# A password file that does not open the key: refused, both left as they are.
box "${G}" "echo wrong > /f/ca.pass" >/dev/null
if out="$(boot "${G}")"; then bad "a ca.pass that does not open the key is refused" "${out}"; else ok "a ca.pass that does not open the key is refused"; fi
if [ "$(key_sum "${G}")" = "${sum}" ] && [ "$(pass_of "${G}")" = wrong ]; then ok "and both are left as they are"; else bad "and both are left as they are"; fi

echo "OPS-131h — an interrupted re-lock is finished or undone"
new_host; H="${HOST}"; boot "${H}" >/dev/null
# Between the renames: the key is new, the new password is still beside it.
box "${H}" 'mv /f/ca.pass /f/ca.pass.new' >/dev/null
ph="$(box "${H}" 'cat /f/ca.pass.new')"
boot "${H}" >/dev/null || bad "the bootstrap finishes it"
if [ "$(pass_of "${H}")" = "${ph}" ] && opens "${H}"; then ok "finished: ca.pass is the new password"; else bad "finished: ca.pass is the new password"; fi
new_host; I="${HOST}"; boot "${I}" >/dev/null
lock "${I}" "${LEGACY}"
# Before the renames: a new password and key were written beside the old key.
box "${I}" "openssl rand -hex 32 > /f/ca.pass.new; cp /f/ca.key /f/ca.key.new" >/dev/null
boot "${I}" >/dev/null || bad "the bootstrap undoes it and re-locks"
if opens "${I}" && ! opens_legacy "${I}" && ! box "${I}" 'test -e /f/ca.key.new || test -e /f/ca.pass.new' >/dev/null; then ok "undone, then re-locked"; else bad "undone, then re-locked"; fi

echo "OPS-131i — a file already there wins over the variable"
out="$(boot "${A}" "INNSEGL_FULCIO_CA_PASSWORD=something else")" || bad "the bootstrap succeeds"
if [ "$(pass_of "${A}")" = "${pa}" ]; then ok "the file is kept"; else bad "the file is kept"; fi
if printf '%s' "${out}" | grep -q 'differs'; then ok "it says the variable differs and is ignored"; else bad "it says the variable differs and is ignored" "${out}"; fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]

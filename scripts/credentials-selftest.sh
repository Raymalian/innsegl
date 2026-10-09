#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-164 — every service credential is generated per host, kept, and
# rendered for its readers (ADR-0078).
#
# It runs the SHIPPED generators in the pinned openssl image, the way compose
# runs them, against throwaway named volumes: innsegl/credentials-init.sh for
# the core, and sigstore/bootstrap.sh for the log database. No compose
# project, no network: nothing here can reach a real stack.
#
#   OPS-164a  a fresh host: every credential is 64 hex characters, 0400, in
#             the trust volume; every reader's file holds the same value in
#             the form that reader takes. No value is printed.
#   OPS-164b  a second run changes nothing; two hosts get different values.
#   OPS-164c  a malformed credential in the trust volume is refused, and
#             nothing is rewritten.
#   OPS-164d  the log database: the init file, Trillian's flag file and
#             Rekor's config carry this host's values, and the template's
#             placeholder is gone.
#
# Needs docker. The ledger's move is OPS-163 (test/deploy), against a real
# Postgres; the log database's is OPS-163f, against the pinned MySQL.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
COMPOSE_DIR="${ROOT}/deploy/compose"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

command -v docker >/dev/null 2>&1 || { echo 'credentials-selftest: docker is required' >&2; exit 1; }

IMAGE="$(sed -n 's/^  \(alpine\/openssl:[^ ]*\)$/\1/p' "${COMPOSE_DIR}/innsegl.yml" | head -n 1)"
[ -n "${IMAGE}" ] || { echo 'credentials-selftest: no openssl image pin in innsegl.yml' >&2; exit 1; }

CORE_RENDER='ledger-owner appender reader authwriter resolver backup objects-root objects-sealer'
CORE_STORE='ledger-owner ledger-appender ledger-reader ledger-authwriter ledger-resolver ledger-backup objects-root objects-sealer'
SIG_RENDER='logdb trillian rekor-index'
VOLS=()
SEQ=0
cleanup() {
  local v
  for v in "${VOLS[@]+"${VOLS[@]}"}"; do docker volume rm -f "${v}" >/dev/null 2>&1; done
}
trap cleanup EXIT

vol() { docker volume create "$1" >/dev/null || { echo "could not create $1" >&2; exit 1; }; VOLS+=("$1"); }

# new_host sets HOST and makes its volumes: a trust volume and one per
# rendered credential, for both projects.
new_host() {
  SEQ=$((SEQ + 1))
  HOST="innsegl-selftest-cred-$$-${SEQ}"
  local r
  vol "${HOST}-store"; vol "${HOST}-sigstore"; vol "${HOST}-fulcio"; vol "${HOST}-rekor"
  for r in ${CORE_RENDER} ${SIG_RENDER}; do vol "${HOST}-r-${r}"; done
}

core() {
  local h="$1" args=() r
  for r in ${CORE_RENDER}; do args+=(-v "${h}-r-${r}:/run/innsegl/render/${r}"); done
  docker run --rm --network none --read-only --tmpfs /tmp --security-opt no-new-privileges:true \
    -v "${COMPOSE_DIR}/credentials-lib.sh:/innsegl/credentials-lib.sh:ro" \
    -v "${COMPOSE_DIR}/innsegl/credentials-init.sh:/innsegl/credentials-init.sh:ro" \
    -v "${h}-store:/run/innsegl/credentials-store" "${args[@]}" \
    --entrypoint /bin/sh "${IMAGE}" /innsegl/credentials-init.sh 2>&1
}

sig() {
  local h="$1" args=() r
  for r in ${SIG_RENDER}; do args+=(-v "${h}-r-${r}:/run/innsegl/render/${r}"); done
  docker run --rm --network none --read-only --tmpfs /tmp --security-opt no-new-privileges:true \
    -e INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080 \
    -e INNSEGL_CREDENTIALS_STORE=/run/innsegl/credentials-store \
    -v "${COMPOSE_DIR}/sigstore/bootstrap.sh:/bootstrap.sh:ro" \
    -v "${COMPOSE_DIR}/sigstore/ca-lib.sh:/ca-lib.sh:ro" \
    -v "${COMPOSE_DIR}/credentials-lib.sh:/credentials-lib.sh:ro" \
    -v "${COMPOSE_DIR}/sigstore/fulcio-config.yaml:/in/fulcio-config.yaml:ro" \
    -v "${COMPOSE_DIR}/sigstore/rekor-index.sql:/in/rekor-index.sql:ro" \
    -v "${h}-fulcio:/out/fulcio" -v "${h}-rekor:/out/rekor" \
    -v "${h}-sigstore:/run/innsegl/credentials-store" "${args[@]}" \
    --entrypoint /bin/sh "${IMAGE}" /bootstrap.sh 2>&1
}

# look HOST SCRIPT runs a shell with every volume of the host under /v.
look() {
  local h="$1" args=() r
  for r in ${CORE_RENDER} ${SIG_RENDER}; do args+=(-v "${h}-r-${r}:/v/r/${r}:ro"); done
  docker run --rm --network none -v "${h}-store:/v/store:ro" -v "${h}-sigstore:/v/sigstore:ro" \
    "${args[@]}" --entrypoint /bin/sh "${IMAGE}" -c "$2" 2>&1
}

echo "OPS-164a — a fresh host gets its own credentials"
new_host; A="${HOST}"
out="$(core "${A}")" || bad "the core generator succeeds on a fresh host" "${out}"
listing="$(look "${A}" 'cd /v/store && for f in *; do printf "%s %s %s\n" "$f" "$(stat -c %a "$f")" "$(cat "$f")"; done')"
n=0
for name in ${CORE_STORE}; do
  if printf '%s\n' "${listing}" | grep -qE "^${name} 400 [0-9a-f]{64}$"; then n=$((n + 1)); else bad "${name} is 64 hex characters, 0400" "$(printf '%s\n' "${listing}" | grep "^${name} " | cut -d' ' -f1-2)"; fi
done
[ "${n}" = 8 ] && ok "all eight core credentials are 64 hex characters, 0400"
leaked=0
for v in $(printf '%s\n' "${listing}" | cut -d' ' -f3); do
  printf '%s' "${out}" | grep -qF "${v}" && leaked=1
done
if [ "${leaked}" = 0 ]; then ok "no value is printed"; else bad "no value is printed"; fi
check="$(look "${A}" '
  s=/v/store; r=/v/r
  [ "$(cat $r/ledger-owner/password)" = "$(cat $s/ledger-owner)" ] || echo "owner password"
  for role in appender reader authwriter resolver backup; do
    [ "$(cat $r/$role/password)" = "$(cat $s/ledger-$role)" ] || echo "$role password"
    [ "$(cat $r/$role/pgpass)" = "*:*:*:*:$(cat $s/ledger-$role)" ] || echo "$role pgpass"
  done
  for o in objects-root objects-sealer; do
    [ "$(cat $r/$o/secret)" = "$(cat $s/$o)" ] || echo "$o secret"
  done
  [ "$(cat $s/objects-root)" != "$(cat $s/objects-sealer)" ] || echo "sealer equals root"')"
if [ -z "${check}" ]; then ok "every reader's file holds its credential, in its reader's form"; else bad "every reader's file holds its credential" "${check}"; fi

echo "OPS-164b — a second run changes nothing; two hosts differ"
before="$(look "${A}" 'cat /v/store/*')"
core "${A}" >/dev/null || bad "a second run succeeds"
if [ "$(look "${A}" 'cat /v/store/*')" = "${before}" ]; then ok "a second run keeps every value"; else bad "a second run keeps every value"; fi
new_host; B="${HOST}"
core "${B}" >/dev/null || bad "the second host's run succeeds"
common="$(comm -12 <(printf '%s\n' "${before}" | sort) <(look "${B}" 'cat /v/store/*' | sort))"
if [ -z "${common}" ]; then ok "two hosts share no credential"; else bad "two hosts share no credential"; fi

echo "OPS-164c — a malformed credential is refused"
docker run --rm --network none -v "${B}-store:/s" --entrypoint /bin/sh "${IMAGE}" \
  -c 'chmod 600 /s/ledger-reader; printf "short\n" > /s/ledger-reader' >/dev/null
out="$(core "${B}")"; rc=$?
if [ "${rc}" != 0 ] && printf '%s' "${out}" | grep -q 'ledger-reader is not one line'; then ok "refused, naming the file"; else bad "refused, naming the file" "rc=${rc}: ${out}"; fi
if [ "$(look "${B}" 'cat /v/store/ledger-reader')" = short ]; then ok "nothing was rewritten"; else bad "nothing was rewritten"; fi

echo "OPS-164d — the log database's credentials are rendered for each reader"
out="$(sig "${A}")" || bad "the Sigstore bootstrap succeeds with credentials" "${out}"
check="$(look "${A}" '
  s=/v/sigstore; r=/v/r
  for f in logdb-root logdb-trillian logdb-rekor; do
    grep -qE "^[0-9a-f]{64}$" $s/$f || echo "$f is not 64 hex"
    [ "$(stat -c %a $s/$f)" = 400 ] || echo "$f is not 0400"
  done
  t=$(cat $s/logdb-trillian); k=$(cat $s/logdb-rekor); o=$(cat $s/logdb-root)
  grep -q "@REKOR_INDEX_PASSWORD@" $r/logdb/init.sql && echo "placeholder left in init.sql"
  grep -qF "CREATE USER '"'"'rekor'"'"'@'"'"'%'"'"' IDENTIFIED BY '"'"'$k'"'"';" $r/logdb/init.sql || echo "init.sql does not create rekor with its password"
  grep -qF "ALTER USER IF EXISTS '"'"'test'"'"'@'"'"'%'"'"' IDENTIFIED BY '"'"'$t'"'"';" $r/logdb/init.sql || echo "init.sql does not set the trillian user"
  grep -qF "DROP USER IF EXISTS '"'"'root'"'"'@'"'"'%'"'"';" $r/logdb/init.sql || echo "init.sql keeps root@%"
  grep -qF "$o" $r/logdb/init.sql || echo "init.sql does not set root@localhost"
  [ "$(cat $r/logdb/root)" = "$o" ] || echo "root file"
  [ "$(cat $r/logdb/trillian)" = "$t" ] || echo "trillian file"
  [ "$(cat $r/trillian/flags)" = "--mysql_uri=test:$t@tcp(trillian-db:3306)/test" ] || echo "trillian flags"
  grep -qF "dsn: rekor:$k@tcp(trillian-db:3306)/rekor_index" $r/rekor-index/rekor-server.yaml || echo "rekor config"
  grep -qx "password=$t" $r/logdb/healthcheck.cnf || echo "healthcheck.cnf"
  grep -qx "password=$k" $r/logdb/rekor.cnf || echo "rekor.cnf"
  awk "!/^--/ && NF && !/;\$/ {print \"init.sql line is not one statement: \" \$0}" $r/logdb/init.sql')"
if [ -z "${check}" ]; then ok "init file, flag file, config and option files carry this host's values"; else bad "the log database's files" "${check}"; fi
for v in $(look "${A}" 'cat /v/sigstore/*'); do
  printf '%s' "${out}" | grep -qF "${v}" && { bad "no log database value is printed"; break; }
done

echo
printf 'credentials-selftest: %s passed, %s failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]

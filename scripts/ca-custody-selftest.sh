#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPS-049 and OPS-051, the halves that are properties of the REPOSITORY — the
# CA's custody (RM-147, #238).
#
# WHAT IS HERE AND WHAT IS NOT. The live halves need a store, a CA and a
# certificate: those are OPS-049's filesystem read and OPS-050's issued
# certificate, and they run against a deployment. What is asserted here is
# everything a pull request can break without anyone noticing:
#
#   OPS-051  the DEFAULT is untouched — file CA, no store, no unseal step. A
#            deployment that needs a secret store unsealed before it starts is
#            not `docker compose up`, and that is the adopter's first experience.
#   OPS-049  under the overlay the CA is handed no key: no fileca flag survives,
#            and the volume it mounts is not the one holding ca.key.
#   #238     no dev-mode store and no unseal key anywhere in the repository.
#            "A dev-mode store that unseals with a known key is theatre and must
#            not be what ships."
#
# THE FIRST CASE KEEPS THE REST HONEST. An overlay that failed to apply at all
# would pass every "no key" check by accident, because nothing would have
# changed — so the suite first requires that the overlay CHANGES the CA, and
# only then that what it changed it to holds no key.

set -uo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
BASE="${ROOT}/deploy/compose/sigstore.yml"
OVER="${ROOT}/deploy/compose/sigstore.keycustody.yml"

pass=0; fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; return 0; }

command -v docker >/dev/null 2>&1 || { printf 'ca-custody-selftest: docker is required to resolve compose\n' >&2; exit 1; }

render() {
  INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080 \
  INNSEGL_CA_STORE_TOKEN=selftest-not-a-real-token \
    docker compose "$@" config 2>/dev/null
}

# fulcio_block prints just the CA service out of a rendered config.
fulcio_block() {
  awk '/^  fulcio:/{f=1;next} f&&/^  [a-z]/{exit} f{print}'
}

echo "OPS-051 — the default is untouched"

default="$(render -f "${BASE}")"
if [ -z "${default}" ]; then
  bad "the default stack renders" "compose config produced nothing"
else
  ok "the default stack renders"
fi

if printf '%s' "${default}" | fulcio_block | grep -q -- "--ca=fileca"; then
  ok "the default CA is still the file CA"
else
  bad "the default CA is still the file CA" "no --ca=fileca in the rendered default"
fi

if printf '%s' "${default}" | grep -qE "innsegl-ca-store|openbao"; then
  bad "the default needs no secret store" "a store appears in the default stack"
else
  ok "the default needs no secret store"
fi

echo "OPS-049 — under the overlay the CA is handed no key"

overlay="$(render -f "${BASE}" -f "${OVER}")"
if [ -z "${overlay}" ]; then
  bad "the overlay renders" "compose config produced nothing"
  printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
  exit 1
fi
ok "the overlay renders"

# THE CONTROL: the overlay must actually change the CA.
if printf '%s' "${overlay}" | fulcio_block | grep -q -- "--ca=kmsca"; then
  ok "the overlay changes the CA to a KMS-backed one"
else
  bad "the overlay changes the CA to a KMS-backed one" \
      "without this, every check below passes because nothing changed"
fi

if printf '%s' "${overlay}" | fulcio_block | grep -q "fileca"; then
  bad "no fileca flag survives the overlay" \
      "$(printf '%s' "${overlay}" | fulcio_block | grep fileca | head -1 | sed 's/^ *//')"
else
  ok "no fileca flag survives the overlay"
fi

# The volume holding ca.key must not be mounted into the CA.
if printf '%s' "${overlay}" | fulcio_block | grep -q "sigstore-fulcio-pki"; then
  bad "the CA does not mount the volume that holds ca.key" \
      "sigstore-fulcio-pki is mounted into the CA; a kmsca deployment with a private key beside it"
else
  ok "the CA does not mount the volume that holds ca.key"
fi

echo "#238 — no theatre: no dev mode, no unseal key in the repository"

# COMMENTS ARE NOT CONFIGURATION. The overlay's own header explains at length
# that there is no `server -dev` here, and a check that fired on the explanation
# would make the rule unmentionable — the first fix anyone reached for would be
# deleting the paragraph that says why. Same rule the exemptions gate lives by.
# BOTH SPELLINGS OF THE COMMAND. compose writes exec form — ["server", "-dev"] —
# and a pattern written for the shell form `server -dev` misses it entirely.
# Found by mutating this file: a real dev-mode service passed the check.
dev_hits="$(git -C "${ROOT}" grep -nE "server[\", ]+-dev([\"[:space:]]|$)|\"-dev\"|BAO_DEV_ROOT_TOKEN_ID|VAULT_DEV_ROOT_TOKEN_ID" \
  -- ':!:scripts/ca-custody-selftest.sh' 2>/dev/null |
  awk -F: '{ line=$0; sub(/^[^:]*:[0-9]*:/, "", line); sub(/^[ \t]*/, "", line);
             if (line !~ /^(#|\/\/|--)/) print }')"
if [ -n "${dev_hits}" ]; then
  bad "no dev-mode store is configured anywhere" "$(printf '%s' "${dev_hits}" | head -1)"
else
  ok "no dev-mode store is configured anywhere"
fi

if git -C "${ROOT}" grep -nE "unseal[_-]?key *[:=] *[\"'][^\"'$]" -- \
     ':!:scripts/ca-custody-selftest.sh' >/dev/null 2>&1; then
  bad "no unseal key is written down in the repository" \
      "$(git -C "${ROOT}" grep -nE "unseal[_-]?key *[:=] *[\"'][^\"'$]" -- ':!:scripts/ca-custody-selftest.sh' | head -1)"
else
  ok "no unseal key is written down in the repository"
fi

# The unseal key must never be an argument: an argument is in a process listing.
if grep -qE '^\s*stty -echo' "${ROOT}/scripts/ca-custody.sh"; then
  ok "the unseal key is read from the terminal, not an argument"
else
  bad "the unseal key is read from the terminal, not an argument" \
      "ca-custody.sh does not read it with echo off"
fi

printf '\n%d passed, %d failed\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]

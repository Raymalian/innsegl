#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The operator's side of rung 3 — RM-147 (#238).
#
# WHY THERE IS AN OPERATOR SIDE AT ALL, and why it cannot be automated away.
# #238: "A dev-mode store that unseals with a known key is theatre and must not
# be what ships." A store that unseals itself holds a key that something on this
# machine can read, which is the property rung 3 exists to remove. So the unseal
# key is minted once, shown once, and never written down by anything here — the
# operator holds it and supplies it per start.
#
# The cost is honest and is the whole trade: LOSING THE UNSEAL KEY LOSES THE CA
# exactly as losing the key file would. That is not a regression from rung 1 and
# 2; it is the same loss with a different custodian, and the custodian is now a
# person rather than a directory anything on the box can read.
#
# THIS IS OPT-IN AND CHANGES NOTHING BY DEFAULT. Without it the stack is the
# file CA it has always been, and OPS-051 asserts that: `docker compose up` stays
# the adopter's first experience.
#
# USAGE
#   scripts/ca-custody.sh init      once, on a machine that has never done it
#   scripts/ca-custody.sh unseal    per start; reads the key from the terminal
#   scripts/ca-custody.sh status    sealed or not, and whether the CA key is in
#   scripts/ca-custody.sh token     mint a short-lived token scoped to the CA key
#   scripts/ca-custody.sh revoke    revoke the CA's token; issuance stops (OPS-052)
#
# It prints secrets to a TERMINAL and never to a file. A shell that logs its own
# scrollback will capture them; that is the operator's to know, and saying so
# here is cheaper than a reader assuming otherwise.

set -uo pipefail

STORE="${INNSEGL_CA_STORE_CONTAINER:-innsegl-ca-store}"
ADDR="${INNSEGL_CA_STORE_ADDR:-http://127.0.0.1:8200}"
KEY="${INNSEGL_CA_STORE_KEY:-innsegl-ca}"
TTL="${INNSEGL_CA_TOKEN_TTL:-24h}"

die()  { printf 'ca-custody: %s\n' "$*" >&2; exit 1; }
note() { printf 'ca-custody: %s\n' "$*"; }

api() {
  _method="$1"; _path="$2"; _body="${3:-}"; _token="${4:-}"
  set -- -sS -X "${_method}" "${ADDR}${_path}"
  [ -n "${_token}" ] && set -- "$@" -H "X-Vault-Token: ${_token}"
  [ -n "${_body}" ] && set -- "$@" -d "${_body}"
  curl "$@" 2>/dev/null
}

reachable() {
  api GET /v1/sys/seal-status >/dev/null 2>&1
}

case "${1:-}" in

  init)
    reachable || die "the store at ${ADDR} is not answering. Bring it up first:
  docker compose -f deploy/compose/sigstore.yml -f deploy/compose/sigstore.keycustody.yml up -d innsegl-ca-store"
    if api GET /v1/sys/seal-status | grep -q '"initialized":true'; then
      die "this store is already initialised. Its unseal key was shown once, at
  init, and is not recoverable from here — that is the design. If it is lost, the
  CA key is lost with it, and the deployment needs a new root."
    fi
    # ONE SHARE, ONE THRESHOLD, and that is a deliberate simplification for a
    # single-operator deployment rather than a default nobody looked at. Splitting
    # the key across five holders protects against one holder; there is one
    # holder here, and five shares they keep in one place is theatre of a second
    # kind. A deployment with more than one operator raises both numbers.
    out="$(api POST /v1/sys/init '{"secret_shares":1,"secret_threshold":1}')"
    printf '%s' "${out}" | grep -q root_token || die "init failed: ${out}"
    printf '\n'
    printf '  ============================================================\n'
    printf '  SHOWN ONCE. Nothing here writes these down.\n'
    printf '  ============================================================\n'
    printf '  unseal key : %s\n' "$(printf '%s' "${out}" | sed -n 's/.*"keys_base64":\["\([^"]*\)".*/\1/p')"
    printf '  root token : %s\n' "$(printf '%s' "${out}" | sed -n 's/.*"root_token":"\([^"]*\)".*/\1/p')"
    printf '  ============================================================\n'
    printf '  Put both in a password manager now. Losing the unseal key loses\n'
    printf '  the CA, exactly as losing a key file would.\n\n'
    ;;

  unseal)
    reachable || die "the store at ${ADDR} is not answering"
    api GET /v1/sys/seal-status | grep -q '"sealed":false' && { note "already unsealed"; exit 0; }
    # Read from the terminal, never from an argument: an argument is visible in
    # a process listing to everything else on this machine.
    printf 'unseal key: '
    stty -echo 2>/dev/null; read -r k; stty echo 2>/dev/null; printf '\n'
    [ -n "${k}" ] || die "no key given"
    out="$(api POST /v1/sys/unseal "{\"key\":\"${k}\"}")"
    if printf '%s' "${out}" | grep -q '"sealed":false'; then
      note "unsealed"
    else
      die "still sealed: $(printf '%s' "${out}" | head -c 200)"
    fi
    ;;

  status)
    reachable || die "the store at ${ADDR} is not answering"
    s="$(api GET /v1/sys/seal-status)"
    printf '  store      %s\n' "$(printf '%s' "${s}" | grep -q '"sealed":true' && echo 'SEALED — the CA cannot sign' || echo 'unsealed')"
    printf '  initialised %s\n' "$(printf '%s' "${s}" | grep -q '"initialized":true' && echo yes || echo 'no — run: scripts/ca-custody.sh init')"
    if [ -n "${INNSEGL_CA_STORE_TOKEN:-}" ]; then
      if api GET "/v1/transit/keys/${KEY}" '' "${INNSEGL_CA_STORE_TOKEN}" | grep -q '"type"'; then
        printf '  CA key     present in the store as %s\n' "${KEY}"
      else
        printf '  CA key     NOT reachable with the token in $INNSEGL_CA_STORE_TOKEN\n'
      fi
    else
      printf '  CA key     unknown ($INNSEGL_CA_STORE_TOKEN is unset)\n'
    fi
    ;;

  token)
    [ -n "${INNSEGL_CA_STORE_ROOT_TOKEN:-}" ] || die "set INNSEGL_CA_STORE_ROOT_TOKEN to the root token from init.
  It is used here to mint a SHORT-LIVED token scoped to the CA key, and the CA
  is given that one — never the root. A CA holding the root token could change
  its own permissions, which is the opposite of a custody boundary."
    reachable || die "the store at ${ADDR} is not answering"
    api POST /v1/sys/policies/acl/innsegl-ca-signer \
      "{\"policy\":\"path \\\"transit/sign/${KEY}\\\" { capabilities = [\\\"update\\\"] }\npath \\\"transit/keys/${KEY}\\\" { capabilities = [\\\"read\\\"] }\"}" \
      "${INNSEGL_CA_STORE_ROOT_TOKEN}" >/dev/null
    out="$(api POST /v1/auth/token/create \
      "{\"policies\":[\"innsegl-ca-signer\"],\"ttl\":\"${TTL}\",\"renewable\":true}" \
      "${INNSEGL_CA_STORE_ROOT_TOKEN}")"
    tok="$(printf '%s' "${out}" | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')"
    [ -n "${tok}" ] || die "could not mint a token: $(printf '%s' "${out}" | head -c 200)"
    printf '%s\n' "${tok}"
    note "scoped to sign with ${KEY} and read its public half, ttl ${TTL}" >&2
    ;;

  revoke)
    [ -n "${INNSEGL_CA_STORE_ROOT_TOKEN:-}" ] || die "set INNSEGL_CA_STORE_ROOT_TOKEN"
    reachable || die "the store at ${ADDR} is not answering"
    api POST /v1/auth/token/revoke-accessor '{}' "${INNSEGL_CA_STORE_ROOT_TOKEN}" >/dev/null 2>&1
    api PUT "/v1/sys/policies/acl/innsegl-ca-signer" \
      '{"policy":"# revoked"}' "${INNSEGL_CA_STORE_ROOT_TOKEN}" >/dev/null
    note "the signer policy is emptied; the CA can no longer sign."
    note "issuance STOPS and says so — a custody boundary whose failure is silent"
    note "would read as a working CA that had quietly stopped attesting (OPS-052)."
    ;;

  *)
    sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac

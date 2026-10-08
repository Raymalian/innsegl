#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# make ca-custody-reset CONFIRM=reset — remove the CA key store, its sealed
# unlock material and the store's root, so `make update` provisions a fresh
# store (ADR-0076, OPS-159).
#
# WHY IT EXISTS. A store's policies are written once, by a root token that is
# revoked when provisioning ends (OPS-140): nothing can widen them later, and
# that is what keeps the key in. So a store provisioned with a wrong policy is
# fixed by provisioning a new one, never by repairing it.
#
# WHEN IT REFUSES. Only a store nothing depends on is removed:
#   - Fulcio runs on it (--ca=kmsca): its key is the CA in use;
#   - the trust history holds its root: that root may have signed, and its
#     key would be gone for good;
#   - the history cannot be asked: not known, so not removed.
# The trust-key backups keep any older copy of the store; this touches none.
#
# EXIT  0 removed · 2 usage · 3 refused
set -uo pipefail

DOCKER="${INNSEGL_RESET_DOCKER:-docker}"
PREFIX="${INNSEGL_STACK_PREFIX:-innsegl}"
CORE="${INNSEGL_RESET_CORE:-${PREFIX}-mcp}"
FULCIO="${PREFIX}-sigstore-fulcio"
KMS_VOLUME="${PREFIX}-sigstore_sigstore-fulcio-kms"
IMAGE="${INNSEGL_RESET_IMAGE:-alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce}"

die() { code="$1"; shift; printf 'ca-custody-reset: %s\n' "$*" >&2; exit "${code}"; }

[ "${CONFIRM:-}" = reset ] \
  || die 2 "set CONFIRM=reset to remove the CA key store and its unlock material (runbooks/ca-custody.md)"

cmd="$("${DOCKER}" inspect -f '{{json .Config.Cmd}}' "${FULCIO}" 2>/dev/null)"
case "${cmd}" in
  *--ca=kmsca*) die 3 "REFUSED: Fulcio runs on the store, so its key is the CA in use. Rotate off it first." ;;
esac

chain="$("${DOCKER}" run --rm -v "${KMS_VOLUME}:/k:ro" "${IMAGE}" cat /k/chain.pem 2>/dev/null)"
if [ -n "${chain}" ]; then
  printf '%s\n' "${chain}" | "${DOCKER}" exec -i "${CORE}" innsegl trust-history has --kind fulcio_root >/dev/null 2>&1
  rc=$?
  case "${rc}" in
    0) die 3 "REFUSED: the trust history holds the store's root, so it may have signed; its key would be lost for good." ;;
    4) : ;;
    *) die 3 "REFUSED: could not ask the trust history whether the store's root is in it (exit ${rc})." ;;
  esac
fi

"${DOCKER}" rm -f "${PREFIX}-ca-custodian" "${PREFIX}-ca-store" "${PREFIX}-ca-bootstrap" >/dev/null 2>&1
"${DOCKER}" volume rm innsegl-trust-ca-store innsegl-trust-ca-custody "${KMS_VOLUME}" >/dev/null \
  || die 3 "could not remove the store's volumes; see docker volume ls"
echo "ca-custody-reset: removed. \`make update\` provisions a new store; then a new backup and drill."

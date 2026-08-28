#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bootstrap registration entries for the reference SPIRE compose stack
# (RM-014, #22).
#
# WHAT THIS IS FOR, AND WHAT IT IS NOT FOR
# ----------------------------------------
# Doc 01 §1: "One SPIRE registration entry per run, short TTL, created at
# registration, deleted at retirement." Those entries are created by the MCP
# over the admin API and are RM-015's (#23) — this script must never grow a
# path that creates one.
#
# What it creates is the small fixed set of *infrastructure* entries the stack
# needs before it can serve anything: today, spire-oidc's own identity, without
# which the discovery provider cannot fetch the JWKS it exists to publish.
#
# WHY `docker compose exec` AND NOT A CONTAINER
# ---------------------------------------------
# The server's admin socket is unauthenticated: whatever can open it has full
# admin over the trust domain. Giving a second container that socket, even a
# short-lived registrar, would make "the admin API is reachable only from
# innsegl-mcp" (doc 05 §1) false the moment the stack boots. So bootstrap
# registration runs *inside* the server container, as an operator action, using
# access the operator already has. See ADR-0011.
#
# Idempotent: re-running is a no-op once the entries exist.

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_FILE="${SCRIPT_DIR}/../spire.yml"
readonly TRUST_DOMAIN="innsegl.dev"
readonly ADMIN_SOCKET="/run/spire/admin/api.sock"
readonly OIDC_CONTAINER="innsegl-spire-oidc"
readonly OIDC_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/innsegl/oidc-discovery-provider"

log()  { printf 'register: %s\n' "$*"; }
fail() { printf 'register: FAIL: %s\n' "$*" >&2; exit 1; }

compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }

# Scratch directory, cleaned on exit. Declared at file scope because the trap
# fires outside main()'s scope and `set -u` would trip on a local.
WORK=""
cleanup() { [ -n "${WORK}" ] && rm -rf "${WORK}"; return 0; }
trap cleanup EXIT

# spire() runs the SPIRE server CLI inside the server container against the
# local admin socket.
spire() { compose exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath "${ADMIN_SOCKET}"; }

# sha256_of prints the lowercase hex SHA-256 of a file, using whichever of the
# three usual tools this machine has.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  fi
}

# agent_spiffe_id returns the attested agent's SPIFFE ID. Every entry is
# parented to it: an entry with no reachable parent is an entry no workload can
# ever match.
agent_spiffe_id() {
  spire agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -n 1
}

entry_exists() {
  spire entry show -spiffeID "$1" 2>/dev/null | grep -q '^Entry ID'
}

main() {
  command -v docker >/dev/null 2>&1 || fail 'docker is not on PATH'

  local parent
  parent="$(agent_spiffe_id || true)"
  [ -n "${parent}" ] || fail 'no attested agent yet — is the stack up and healthy?'
  log "parent (node) SPIFFE ID: ${parent}"

  if entry_exists "${OIDC_SPIFFE_ID}"; then
    log "entry already present: ${OIDC_SPIFFE_ID}"
    spire entry show -spiffeID "${OIDC_SPIFFE_ID}"
    return 0
  fi

  # ------------------------------------------------------------------
  # Selector material for spire-oidc, derived from the running container and
  # the pinned image rather than typed in — a hand-copied digest is a digest
  # that goes stale and gets "fixed" by deleting the selector.
  # ------------------------------------------------------------------
  docker inspect "${OIDC_CONTAINER}" >/dev/null 2>&1 \
    || fail "${OIDC_CONTAINER} is not running; selectors are read from it"

  local image_config_digest
  image_config_digest="$(docker inspect --format '{{.Image}}' "${OIDC_CONTAINER}")"

  # The SHA-256 of the binary the provider actually runs. Copied out of the
  # container so it is the same bytes the agent hashes at attestation time.
  local binary_sha
  WORK="$(mktemp -d)"
  docker cp "${OIDC_CONTAINER}:/opt/spire/bin/oidc-discovery-provider" "${WORK}/oidc" >/dev/null
  binary_sha="$(sha256_of "${WORK}/oidc")"

  log "creating ${OIDC_SPIFFE_ID}"
  # Five selectors, all of which must match (SPIRE ANDs them).
  #
  #   unix:sha256      the exact binary. The strongest selector available:
  #                    unforgeable from inside the workload's own container.
  #   unix:uid:1000    the image's unprivileged user. Not uid 0 — see agent.conf
  #                    on why unix:uid:0 is the textbook weak selector.
  #   docker:image_config_digest
  #                    the exact image, content-addressed and registry-agnostic.
  #   docker:label:dev.innsegl.component
  #                    the role. Ours, not compose's own label scheme.
  #   docker:image_id  the pinned reference, so a retag cannot silently swap
  #                    what "the OIDC provider" means.
  #
  # No -admin and no -downstream: this workload is neither. Its SVID is good
  # for exactly one thing, calling FetchJWTBundles on the Workload API.
  spire entry create \
    -parentID "${parent}" \
    -spiffeID "${OIDC_SPIFFE_ID}" \
    -selector "unix:sha256:${binary_sha}" \
    -selector "unix:uid:1000" \
    -selector "docker:image_config_digest:${image_config_digest}" \
    -selector "docker:label:dev.innsegl.component:oidc-discovery-provider" \
    -selector "docker:image_id:$(docker inspect --format '{{.Config.Image}}' "${OIDC_CONTAINER}")" \
    -x509SVIDTTL 1800 \
    -jwtSVIDTTL 300

  log 'done'
}

main "$@"

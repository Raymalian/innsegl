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
# needs before it can serve anything:
#
#   spire-oidc   without which the discovery provider cannot fetch the JWKS it
#                exists to publish, and Fulcio refuses every token;
#   innsegl-mcp  doc 05 §1's "Only service holding SPIRE admin credential".
#                Added by RM-076 (#109) — see THE SECOND CASE below.
#
# THE SECOND CASE, and the circularity it does NOT have
# -----------------------------------------------------
# deploy/compose/README.md used to record this as the reason the MCP could not
# be attested: an entry needs the MCP container's own selectors, and reading
# them needs the container to exist, which needs the entry. That is true of the
# way spire-oidc's selectors are derived here — from the RUNNING container —
# and it is not true of the selectors themselves.
#
# All five of them are properties of the IMAGE:
#
#   docker:image_config_digest   `docker image inspect --format '{{.Id}}'`
#   unix:sha256                  the binary, copied out of a container that is
#                                created and removed without ever being started
#   unix:uid:1000                the image's USER
#   docker:label:...             set by the compose file, not by the container
#   docker:image_id              the tag the compose file names
#
# MEASURED: `docker image inspect innsegl:local --format '{{.Id}}'` and a
# container's `.Image` are the same digest, so the entry can be created before
# anything from that image has ever run. The MCP therefore gets an ATTESTED
# X509-SVID from the Workload API, with rotation, rather than three PEM files
# an operator minted by hand.
#
# The remaining order requirement is small and stated in the README: the
# innsegl image must be BUILT before this script can register it. If it is not,
# this script says so and creates the spire-oidc entry anyway rather than
# failing — the SPIRE stack is usable without the MCP, and a bootstrap script
# that refuses to bootstrap anything is worse than one that does what it can.
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

# The MCP. This SPIFFE ID is server.conf's single `admin_ids` entry — the one
# identity the admin API accepts — so it is spelled the same in both files and
# a change here is a change to a protected surface.
readonly MCP_IMAGE="${INNSEGL_MCP_IMAGE:-innsegl:local}"
readonly MCP_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/innsegl/mcp"
readonly MCP_BINARY="/usr/local/bin/innsegl"

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

  publish_parent_id "${parent}"
  register_oidc "${parent}"
  register_mcp "${parent}"

  log 'done'
}

# ---------------------------------------------------------------------------
# publish_parent_id writes the attested node's SPIFFE ID where compose can read
# it (RM-076, #109).
#
# `innsegl serve` REQUIRES a parent ID and refuses to start without one — an
# entry with no reachable parent is an entry no workload can ever match. It is
# not knowable in advance: the agent's ID is
# spiffe://innsegl.dev/spire/agent/x509pop/<sha1 of the agent certificate>, and
# spire/bootstrap.sh mints a fresh certificate on every `up` after a `down -v`.
#
# `.env` in the compose project directory is read automatically by every
# `docker compose -f deploy/compose/*.yml` invocation, so the value flows to
# innsegl.yml without the operator carrying it. It is gitignored (the
# repository ignores `.*`) and therefore never part of a fresh clone, which is
# correct: it describes ONE booted stack and would be a lie in any other.
# ---------------------------------------------------------------------------
publish_parent_id() {
  local parent="$1"
  local env_file="${SCRIPT_DIR}/../.env"

  local tmp
  tmp="$(mktemp "${env_file}.XXXXXX")"
  if [ -f "${env_file}" ]; then
    grep -v '^INNSEGL_SPIRE_PARENT_ID=' "${env_file}" > "${tmp}" || true
  fi
  printf 'INNSEGL_SPIRE_PARENT_ID=%s\n' "${parent}" >> "${tmp}"
  mv "${tmp}" "${env_file}"
  log "wrote INNSEGL_SPIRE_PARENT_ID to deploy/compose/.env"
}

register_oidc() {
  local parent="$1"

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
}

# ---------------------------------------------------------------------------
# innsegl-mcp (RM-076, #109). doc 05 §1: "Only service holding SPIRE admin
# credential", and server.conf's admin_ids names exactly this SPIFFE ID.
#
# Its selectors come from the IMAGE and not from a running container, which is
# what removes the circularity the README used to record. See the header.
#
# This entry carries -admin. That is the whole grant: the MCP's SVID is what
# the admin API accepts, and SPI-005 / threat-model AB-10's scoping of entry
# creation to the /agent/ subtree is authz-policy.rego's job, not this flag's.
# admin_ids says WHO is an admin, never WHAT an admin may do.
# ---------------------------------------------------------------------------
register_mcp() {
  local parent="$1"

  if entry_exists "${MCP_SPIFFE_ID}"; then
    log "entry already present: ${MCP_SPIFFE_ID}"
    spire entry show -spiffeID "${MCP_SPIFFE_ID}"
    return 0
  fi

  if ! docker image inspect "${MCP_IMAGE}" >/dev/null 2>&1; then
    log "SKIPPING ${MCP_SPIFFE_ID}: the image ${MCP_IMAGE} is not built yet."
    log '  build it and re-run this script, which is idempotent:'
    log '    docker compose -f deploy/compose/innsegl.yml build'
    log '    deploy/compose/spire/register.sh'
    return 0
  fi

  local image_config_digest
  image_config_digest="$(docker image inspect --format '{{.Id}}' "${MCP_IMAGE}")"

  # The SHA-256 of the binary the MCP actually runs, taken out of a container
  # that is created and removed WITHOUT EVER BEING STARTED. `docker cp` reads a
  # created container's filesystem, so this needs no MCP process to exist — and
  # the bytes are the same ones the agent hashes from /proc/<pid>/exe at
  # attestation time, because they are the same layer.
  local binary_sha scratch
  WORK="$(mktemp -d)"
  scratch="$(docker create "${MCP_IMAGE}" help)"
  docker cp "${scratch}:${MCP_BINARY}" "${WORK}/innsegl" >/dev/null
  docker rm --force "${scratch}" >/dev/null
  binary_sha="$(sha256_of "${WORK}/innsegl")"

  log "creating ${MCP_SPIFFE_ID} (admin)"
  spire entry create \
    -parentID "${parent}" \
    -spiffeID "${MCP_SPIFFE_ID}" \
    -selector "unix:sha256:${binary_sha}" \
    -selector "unix:uid:1000" \
    -selector "docker:image_config_digest:${image_config_digest}" \
    -selector "docker:label:dev.innsegl.component:mcp" \
    -selector "docker:image_id:${MCP_IMAGE}" \
    -admin \
    -x509SVIDTTL 1800 \
    -jwtSVIDTTL 300
}

main "$@"

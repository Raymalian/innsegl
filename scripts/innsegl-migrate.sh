#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Move a deployment's state and its trust roots to another host — RM-218
# (#352).
#
# WHY THIS EXISTS. A deployment's state lives in Docker volumes: the ledger,
# the transparency log and its signing key, the Fulcio CA, the SPIRE server,
# sealed segments, and the credential keys. Nothing moved that state to
# another host before this — `make innsegl-backup` covers only the ledger.
# A new host that starts fresh mints new trust roots, so it cannot verify a
# single commit signed before the move: the signature is intact, but the CA
# that issued the certificate and the log that recorded it both exist only on
# the old host.
#
# THE ONE PLACE THE VOLUMES ARE NAMED is volume_table() below. Every name in
# it was read from deploy/compose/*.yml and the Makefile, not guessed:
# trust-volumes.sh's five suffixes under its "innsegl-trust" prefix; the
# `name:` a compose project gives its own volumes (spire.yml -> innsegl-spire,
# innsegl.yml -> innsegl-core, sigstore.yml -> innsegl-sigstore).
#
# WHAT IS DELIBERATELY NOT ON THE LIST. `spire-agent-socket` is a live Unix
# socket directory, not state — nothing an archive of it could reproduce
# would mean anything on another host. Anything without a name in the compose
# files (an ad-hoc `docker run -v`) is out of scope by construction.
#
# EXPORT refuses while any container is using one of these volumes — copying
# a live Postgres or MySQL data directory out from under its server produces
# a copy nobody can restore. It packs every volume it finds into one archive,
# with a manifest naming each one's sha256, and carries the transparency-log
# pin (scripts/rekor-tlog-pin.sh) alongside them so the new host does not
# have to re-derive it. THE LEDGER EVENT COUNT NEEDS THE STACK UP TO READ,
# which export cannot have — see `check` below for how an operator gets it
# in first. The archive is written mode 0600: it holds CA private keys.
#
# IMPORT verifies every checksum in the manifest, that no container — running
# OR STOPPED — holds any target volume, and that no target already holds
# data without --replace, ALL BEFORE WRITING A SINGLE BYTE to any volume. A
# stopped container still references its volume just as a running one does —
# `docker volume rm` refuses either — so the check that matters here is
# `docker ps -a`, not `docker ps`, and it runs against every volume in the
# manifest before the write loop starts, not discovered by hitting
# `docker volume rm` partway through it. If a docker command still fails
# mid-way regardless (a race with something outside this script, a daemon
# hiccup), the error names every volume already replaced or loaded before
# that point and says plainly that the import must be re-run.
#
# EVERY HELPER CONTAINER THIS SCRIPT STARTS (the tar read/write helpers, and
# vol_empty's peek) carries HELPER_LABEL and runs with --rm, so a leftover
# one — Ctrl-C at the wrong moment can kill this script's docker CLI before
# the container it just asked for ever starts, leaving it stuck in "Created"
# forever — is refused by the preflight, by name, before any write, exactly
# like a stopped real container is. A trap on INT/TERM also force-removes
# any helper THIS run started, so an interrupted run does not routinely leave
# one behind in the first place. IMPORT prints one line per volume to STDERR
# as it starts that volume's work, so a large import never looks stuck.
#
# LABELS TRAVEL WITH THE VOLUME, and this is load-bearing rather than tidy:
# scripts/teardown-guard.sh reads dev.innsegl.trust-root to refuse deleting
# a trust volume, and Docker CANNOT add a label to a volume that already
# exists — only `docker volume create` can set one. So export records each
# volume's labels (base64 of `docker volume inspect -f '{{json .Labels}}'`,
# since a label's value can hold anything, including a tab or a newline the
# manifest's own format cannot carry raw) and import supplies them back on
# the SAME `docker volume create` call that makes the volume, on both the
# fresh-create path and the --replace path. A volume import merely loads
# into (already exists, already empty) is left exactly as it is: Docker
# offers no way to relabel it short of destroying it, and nothing asked for
# that here.
#
# THE HOST FOLDER THE BODIES LIVE IN MOVES TOO — RM-292 (#468), BAK-024.
# Every tool-call body, workspace snapshot and telemetry record the ledger
# references by digest lives in INNSEGL_LOG_DIR (default $HOME/.innsegl/log),
# a HOST bind mount (innsegl.yml: /agentlog read-write, /harness-log and the
# API's /agentlog read-only), not a volume. An archive of the volumes alone
# moved a ledger whose every body reference resolved to nothing. Export packs
# the folder into the same archive as hostdirs/log.tar, as root inside the
# helper so mode and numeric ownership are kept, and lists EVERY FILE in the
# manifest with its sha256 and size. Import checks the folder tar's checksum,
# re-hashes every file it holds against those lines, and refuses a non-empty
# target folder without --replace — all in the same pass that checks the
# volumes, before anything is written. It restores into the folder THIS host
# resolves, which is not necessarily the path the old host used.
#
# THE OTHER TWO HOST FOLDERS THE CORE BINDS ARE NOT CARRIED, on purpose.
# INNSEGL_GATEWAY_CA_HOST_DIR (~/.innsegl/ca) holds the gateway's PUBLIC
# certificate, rewritten on every start from innsegl-gateway-ca-key, which is
# carried; on the old host it is also what that machine's commit hook trusts,
# so it is left alone there. INNSEGL_BACKUP_HOST_DIR (~/innsegl-backups) is the
# backup service's off-volume copy of what innsegl-backups holds, and that
# volume is carried; the next backup on the new host writes a fresh copy.
# sigstore.yml and spire.yml bind only files from this repository.
#
# PREFIXES. The volume names, and the log folder, follow the stack this host
# resolves, exactly as the Makefile does: INNSEGL_STACK_PREFIX (default
# innsegl), INNSEGL_TRUST_VOLUME_PREFIX (default innsegl-trust) and
# INNSEGL_LOG_DIR, overridden by scripts/stack-mode.sh env on a DEV stack
# (ADR-0072). The archive records the prefixes it was written under, and
# import names each volume by this host's own — identical on an ordinary move.
# An archive without them (schema 1) is imported under the names it carries.
# IMPORT INTO A DEV STACK IS REFUSED: a dev stack mints its own trust root and
# never takes another deployment's (ADR-0072).
#
# THE MANIFEST is versioned. schema 1 carried volumes and the pin; schema 2
# adds `prefix`, `hostdir` and `file` lines. This script imports both. A
# schema-1 archive carries no log folder and leaves the target's alone. A
# script older than this one ignores lines it does not know, so it would
# import a schema-2 archive's volumes and silently skip the bodies: import
# with this version or later.
#
# CHECK has two modes. Run against a running stack with no archive, it
# prints the ledger's current event count and the transparency log's tree id
# — the number an operator notes down before taking the stack down, to pass
# to `export --event-count`. Run with an archive, it compares those same two
# numbers, LIVE, against what the archive's manifest recorded, and says
# MATCH or MISMATCH.
#
# USAGE
#   scripts/innsegl-migrate.sh export [--event-count N] <archive>
#   scripts/innsegl-migrate.sh import [--replace] <archive>
#   scripts/innsegl-migrate.sh check [<archive>]
#   scripts/innsegl-migrate.sh volumes      what this host would carry
#
# ENVIRONMENT
#   INNSEGL_STACK, INNSEGL_STACK_PREFIX, INNSEGL_TRUST_VOLUME_PREFIX,
#   INNSEGL_LOG_DIR                 resolved as the Makefile resolves them (see
#                                   PREFIXES above). In test mode (below)
#                                   INNSEGL_LOG_DIR must be set explicitly.
#   INNSEGL_MIGRATE_VOLUME_PREFIX   TEST ONLY. Set, volume_table() answers a
#                                   small synthetic table of throwaway
#                                   volumes under this prefix instead of the
#                                   real nineteen. scripts/innsegl-migrate-
#                                   selftest.sh is the only caller that sets
#                                   it, and refuses to run at all if it is
#                                   unset. NEVER set this against a real
#                                   deployment; there is nothing it protects
#                                   there, because the real names are simply
#                                   not consulted while it is set.
#   INNSEGL_MIGRATE_PIN_FILE        override the transparency-log pin file's
#                                   path instead of asking
#                                   scripts/rekor-tlog-pin.sh for it. Test use.
#   INNSEGL_MIGRATE_LEDGER_CONTAINER, _USER, _DB, _COUNT_SQL
#                                   how `check` reaches the ledger by default
#                                   (docker exec innsegl-postgres psql ...).
#                                   Defaults match deploy/compose/innsegl.yml.
#   INNSEGL_MIGRATE_LEDGER_COUNT_CMD
#                                   TEST ONLY. Replaces the whole retrieval
#                                   with this shell command's stdout, so
#                                   `check`'s comparison logic can be proven
#                                   without a real ledger.
#   INNSEGL_MIGRATE_HELPER_SLEEP    TEST ONLY. Every helper container sleeps
#                                   this many seconds before doing its real
#                                   work, so scripts/innsegl-migrate-
#                                   selftest.sh can interrupt a run mid-way
#                                   deterministically instead of racing real
#                                   disk I/O. NEVER set this against a real
#                                   deployment; it only slows things down.
#
# EXIT
#   0  done, or (check) the manifest and the running stack agree
#   1  refused, or failed, or (check) they disagree
#   2  the command line was not understood
#
# WHAT IT NEEDS: bash, docker, tar, jq, and sha256sum or shasum on PATH.
# Nothing here starts, stops, or otherwise touches `docker compose` — an
# operator brings the stack up and down themselves, per
# deploy/compose/README.md.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# The pinned base image scripts/innsegl-migrate.sh tars and untars volumes
# with. Same digest the Dockerfile's runtime/backup/ca-bootstrap stages
# already build on (Dockerfile), so this is not a second image to audit.
readonly TAR_IMAGE="alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

# HELPER_LABEL marks every throwaway container this script starts to read or
# write a volume — every `docker run` in this file goes through run_helper()
# below, and every one of them carries this label — so a leftover one is
# recognisable on sight: `docker ps -a --filter label=dev.innsegl.migrate-
# helper=1` finds it regardless of which run started it or what random name
# Docker gave it. --rm only removes a container once it exits; Ctrl-C at the
# wrong moment can kill this script's docker CLI before the container it
# just asked for ever starts, leaving it stuck in "Created" forever — the
# same "in use" refusal a stopped real container produces, for a container
# nothing is actually using any more.
readonly HELPER_LABEL="dev.innsegl.migrate-helper=1"

# Every helper THIS RUN starts also carries a name under this prefix (this
# process's own pid), so cleanup_helpers can remove exactly the ones it made
# — never a concurrent script instance's — without guessing.
HELPER_NAME_PREFIX="innsegl-migrate-helper-$$"
HELPER_SEQ=0
next_helper_name() {
  HELPER_SEQ=$((HELPER_SEQ + 1))
  printf '%s-%s' "${HELPER_NAME_PREFIX}" "${HELPER_SEQ}"
}

WORK=""
cleanup() { [ -n "${WORK}" ] && rm -rf "${WORK}"; }

# cleanup_helpers removes every helper container THIS RUN started, matched
# by HELPER_NAME_PREFIX, regardless of what state Ctrl-C left it in.
cleanup_helpers() {
  local c
  for c in $(docker ps -aq --filter "name=^${HELPER_NAME_PREFIX}" 2>/dev/null); do
    docker rm -f "${c}" >/dev/null 2>&1 || true
  done
}

# on_interrupt runs on INT or TERM: force-remove any helper this run
# started, then exit with the signal's conventional code. It does not rely
# on the interrupted docker command noticing the signal itself — an
# in-flight helper is removed explicitly, whether or not the docker CLI
# child also got the same signal.
on_interrupt() {
  local code="$1"
  printf 'innsegl-migrate: interrupted — removing any helper container this run started...\n' >&2
  cleanup_helpers
  cleanup
  trap - INT TERM EXIT
  exit "${code}"
}

trap cleanup EXIT
trap 'on_interrupt 130' INT
trap 'on_interrupt 143' TERM

die()  { printf 'innsegl-migrate: %s\n' "$*" >&2; exit 1; }
usage_die() { usage >&2; printf 'innsegl-migrate: %s\n' "$*" >&2; exit 2; }
note() { printf 'innsegl-migrate: %s\n' "$*"; }
# progress writes a line to STDERR immediately, so it shows up even while
# stdout is captured or piped — used for the one-line-per-volume progress
# import prints as it goes, so a large import never looks stuck.
progress() { printf 'innsegl-migrate: %s\n' "$*" >&2; }

# run_helper MOUNT_ARGS... -- SH_COMMAND — docker run --rm, labelled and
# named (see HELPER_LABEL and next_helper_name above) so a leftover from an
# interrupted run is always identifiable, executing SH_COMMAND inside the
# pinned tar image via `sh -c`. INNSEGL_MIGRATE_HELPER_SLEEP, TEST ONLY,
# prefixes a `sleep` before SH_COMMAND so the self-test can interrupt a run
# deterministically instead of racing real disk I/O.
run_helper() {
  local mounts=() cmd
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do
    mounts+=("$1"); shift
  done
  [ "${1:-}" = "--" ] && shift
  cmd="${1:-}"
  if [ -n "${INNSEGL_MIGRATE_HELPER_SLEEP:-}" ]; then
    cmd="sleep ${INNSEGL_MIGRATE_HELPER_SLEEP}; ${cmd}"
  fi
  docker run --rm --label "${HELPER_LABEL}" --name "$(next_helper_name)" \
    "${mounts[@]}" "${TAR_IMAGE}" sh -c "${cmd}"
}

# refuse_if_helper_leftover dies if a helper container from an earlier,
# interrupted run of this script is still here. Every helper this script
# ever starts carries HELPER_LABEL, so this is one query regardless of which
# run left it behind or what Docker named it.
refuse_if_helper_leftover() {
  local rows name
  rows="$(docker ps -a --filter "label=${HELPER_LABEL}" --format '{{.Names}}' 2>/dev/null)"
  [ -n "${rows}" ] || return 0
  printf 'innsegl-migrate: refusing: a helper container from an earlier, interrupted run is\n' >&2
  printf '  still here — remove it, then try again:\n' >&2
  while IFS= read -r name; do
    [ -n "${name}" ] || continue
    printf '    docker rm -f %s\n' "${name}" >&2
  done <<EOF
${rows}
EOF
  exit 1
}

usage() {
  cat <<'EOF'
usage:
  innsegl-migrate.sh export [--event-count N] <archive>
  innsegl-migrate.sh import [--replace] <archive>
  innsegl-migrate.sh check [<archive>]
  innsegl-migrate.sh volumes
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required and is not on PATH"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "need sha256sum or shasum on PATH"
  fi
}

# base64_enc/base64_dec — a single unbroken line either way, regardless of
# which base64 this host has: GNU wraps output at 76 columns by default and
# BSD/macOS does not, and a wrapped value would break manifest.txt's one-
# line-per-record format.
base64_enc() { base64 | tr -d '\n'; }
base64_dec() { base64 -d 2>/dev/null; }

# vol_labels_b64 NAME — base64 of `{"k":"v",...}` (or of the literal text
# "null" when the volume carries no labels), read straight from Docker.
vol_labels_b64() {
  docker volume inspect -f '{{json .Labels}}' "$1" 2>/dev/null | base64_enc
}

# labels_json_of_b64 B64 — the decoded JSON, or "null" if it will not decode
# at all. Whether it is valid JSON is for the caller to ask jq.
labels_json_of_b64() {
  local j
  j="$(printf '%s' "$1" | base64_dec)"
  [ -n "${j}" ] && printf '%s' "${j}" || printf 'null'
}

# create_volume_with_labels NAME LABELS_JSON — docker volume create NAME,
# with every key/value LABELS_JSON holds applied AT CREATION, which is the
# only time Docker will accept one. NUL-delimited throughout, so a label
# value holding a tab, a newline, or anything else survives intact.
create_volume_with_labels() {
  local name="$1" json="$2" args=()
  if [ -n "${json}" ] && [ "${json}" != "null" ]; then
    while IFS= read -r -d '' key && IFS= read -r -d '' val; do
      args+=(--label "${key}=${val}")
    done < <(printf '%s' "${json}" | jq -j 'to_entries[]? | (.key + "\u0000" + .value + "\u0000")' 2>/dev/null)
  fi
  # NOT `docker volume create "${args[@]}" "${name}"` unconditionally: an
  # empty array expanded under `set -u` is "unbound variable" on bash before
  # 4.4, which is what macOS ships as /bin/bash. `${#args[@]}` is always
  # safe to ask, even empty or unset.
  if [ "${#args[@]}" -eq 0 ]; then
    docker volume create "${name}" >/dev/null
  else
    docker volume create "${args[@]}" "${name}" >/dev/null
  fi
}

# ---------------------------------------------------------------------------
# resolve_stack — which stack this host runs, as the Makefile resolves it.
#
# Sets STACK_MODE (dev|live), STACK_PREFIX, TRUST_PREFIX and LOG_DIR. On a DEV
# stack scripts/stack-mode.sh env's values win over the environment, as they
# do in the Makefile (which exports them over whatever was there).
# ---------------------------------------------------------------------------
STACK_MODE="" STACK_PREFIX="" TRUST_PREFIX="" LOG_DIR=""
resolve_stack() {
  STACK_MODE="$("${SCRIPT_DIR}/stack-mode.sh" mode)" \
    || die "scripts/stack-mode.sh could not say whether this stack is dev or live"
  STACK_PREFIX="${INNSEGL_STACK_PREFIX:-}"
  TRUST_PREFIX="${INNSEGL_TRUST_VOLUME_PREFIX:-}"
  LOG_DIR="${INNSEGL_LOG_DIR:-}"
  if [ "${STACK_MODE}" = dev ]; then
    local line key val
    while IFS= read -r line; do
      key="${line%%=*}"; val="${line#*=}"
      case "${key}" in
        INNSEGL_STACK_PREFIX) STACK_PREFIX="${val}" ;;
        INNSEGL_TRUST_VOLUME_PREFIX) TRUST_PREFIX="${val}" ;;
        INNSEGL_LOG_DIR) LOG_DIR="${val}" ;;
      esac
    done <<EOF
$("${SCRIPT_DIR}/stack-mode.sh" env)
EOF
  fi
  STACK_PREFIX="${STACK_PREFIX:-innsegl}"
  TRUST_PREFIX="${TRUST_PREFIX:-innsegl-trust}"
  if [ -n "${INNSEGL_MIGRATE_VOLUME_PREFIX:-}" ] && [ -z "${INNSEGL_LOG_DIR:-}" ]; then
    # TEST ONLY: the default is this machine's real bodies, and an import
    # would write into them.
    die "test mode (INNSEGL_MIGRATE_VOLUME_PREFIX) needs INNSEGL_LOG_DIR set explicitly"
  fi
  LOG_DIR="${LOG_DIR:-${HOME}/.innsegl/log}"
}

# The string prefixes volume names start with, as the manifest records them
# and as import renames by. In test mode the synthetic table's one prefix.
name_prefix_stack() {
  if [ -n "${INNSEGL_MIGRATE_VOLUME_PREFIX:-}" ]; then
    printf '%s' "${INNSEGL_MIGRATE_VOLUME_PREFIX}"
  else
    printf '%s-' "${STACK_PREFIX}"
  fi
}
name_prefix_trust() {
  [ -n "${INNSEGL_MIGRATE_VOLUME_PREFIX:-}" ] || printf '%s-' "${TRUST_PREFIX}"
}

# ---------------------------------------------------------------------------
# volume_table — THE ONE PLACE the state volumes are named.
#
# "<name>|<what it holds>", one per line. Verified against
# deploy/compose/trust-volumes.sh (the five innsegl-trust-* suffixes),
# deploy/compose/spire.yml, innsegl.yml and sigstore.yml (each project's
# `name:`, which is the prefix compose gives its own volumes), on 2026-09-28,
# and against deploy/compose/dev/*.yml (ADR-0072), whose projects are the
# same names under the dev prefix, on 2026-10-06.
# innsegl-sessions is not listed: it held observe_session's markers, which
# nothing reads since ADR-0071, and an old host's copy is left behind.
# ---------------------------------------------------------------------------
volume_table() {
  local prefix="${INNSEGL_MIGRATE_VOLUME_PREFIX:-}"
  if [ -n "${prefix}" ]; then
    # TEST ONLY. Two throwaway volumes under the caller's own prefix — never
    # the real nineteen. scripts/innsegl-migrate-selftest.sh is the only
    # caller that sets INNSEGL_MIGRATE_VOLUME_PREFIX.
    printf '%sledger-data|throwaway ledger volume (self-test)\n' "${prefix}"
    printf '%strillian-db|throwaway trillian volume (self-test)\n' "${prefix}"
    return 0
  fi
  local t="${TRUST_PREFIX}" s="${STACK_PREFIX}"
  cat <<EOF
${t}-ledger-data|the ledger hot tier: postgres's data directory
${t}-trillian-db|the transparency log itself: trillian's mysql data directory
${t}-rekor-key|the transparency log's signing key
${t}-fulcio-pki|the Fulcio CA certificate and encrypted key
${t}-identity-secret|this deployment's pseudonymisation secret
${t}-history|the trust history: every root and log key this deployment has used (ADR-0073)
${t}-credentials|the ledger and object store passwords this host generated (ADR-0078)
${t}-sigstore-credentials|the log database passwords this host generated (ADR-0078)
${s}-spire_spire-server-data|the SPIRE server's datastore and keys
${s}-spire_spire-pki-server|the SPIRE server's upstream CA cert+key and node CA cert
${s}-spire_spire-pki-agent|the SPIRE agent's node identity and bootstrap trust bundle
${s}-spire_spire-agent-data|the SPIRE agent's own data
${s}-core_innsegl-object-data|sealed segments' bytes, under object lock
${s}-core_innsegl-object-filer-data|the object store's metadata
${s}-core_innsegl-s3-identities|the object gateway's S3 credentials
${s}-core_innsegl-message-key|RM-237's own derived agent-message key (check-only; the run page's query API verifies with it)
${s}-core_innsegl-admin-key|the admin-credential private signing key
${s}-core_innsegl-admin-jwks|the admin-credential public key set
${s}-core_innsegl-gateway-ca-key|the gateway's own CA private key (its certificate is republished on start)
${s}-core_innsegl-workspace|the working trees the sign_commit MCP tool resolves \`repo\` under
${s}-core_innsegl-backups|verified ledger backups and their reports
${s}-core_innsegl-trust-backups|the encrypted trust-key bundles (ADR-0074); only the operator's own key can read them
${s}-core_innsegl-mirror|the per-repository mirrors clients push commits to (ADR-0065)
${s}-core_innsegl-dashboard-tls|the dashboard's certificate and key (RM-311; rewritten on start)
${s}-sigstore_sigstore-rekor-search|Rekor's search index
EOF
}

known_volume() {
  local target="$1" table name
  table="$(volume_table)"
  while IFS='|' read -r name _; do
    [ -n "${name}" ] || continue
    [ "${name}" = "${target}" ] && return 0
  done <<EOF
${table}
EOF
  return 1
}

# ---------------------------------------------------------------------------
# The transparency-log pin (scripts/rekor-tlog-pin.sh).
# ---------------------------------------------------------------------------

pin_file_path() {
  if [ -n "${INNSEGL_MIGRATE_PIN_FILE:-}" ]; then
    printf '%s' "${INNSEGL_MIGRATE_PIN_FILE}"
    return 0
  fi
  "${SCRIPT_DIR}/rekor-tlog-pin.sh" path "${REPO_ROOT}"
}

pin_tree_id() {
  if [ -n "${INNSEGL_MIGRATE_PIN_FILE:-}" ]; then
    local p="${INNSEGL_MIGRATE_PIN_FILE}"
    if [ -s "${p}" ]; then
      local id
      id="$(tr -dc '0-9' <"${p}" | head -c 32)"
      [ -n "${id}" ] && printf '%s' "${id}" || printf '0'
    else
      printf '0'
    fi
    return 0
  fi
  "${SCRIPT_DIR}/rekor-tlog-pin.sh" read "${REPO_ROOT}"
}

# ---------------------------------------------------------------------------
# The ledger's live event count (`check`).
# ---------------------------------------------------------------------------

ledger_event_count() {
  if [ -n "${INNSEGL_MIGRATE_LEDGER_COUNT_CMD:-}" ]; then
    # TEST ONLY — see the ENVIRONMENT block above.
    sh -c "${INNSEGL_MIGRATE_LEDGER_COUNT_CMD}" 2>/dev/null | tr -dc '0-9'
    return 0
  fi
  local container user db sql
  container="${INNSEGL_MIGRATE_LEDGER_CONTAINER:-innsegl-postgres}"
  user="${INNSEGL_MIGRATE_LEDGER_USER:-innsegl}"
  db="${INNSEGL_MIGRATE_LEDGER_DB:-innsegl}"
  sql="${INNSEGL_MIGRATE_LEDGER_COUNT_SQL:-SELECT count(*) FROM innsegl.events;}"
  docker exec "${container}" psql -X -q -A -t -U "${user}" -d "${db}" -c "${sql}" 2>/dev/null \
    | tr -d ' \r\n'
}

# ---------------------------------------------------------------------------
# Volume helpers, the same shape deploy/compose/trust-volumes.sh already
# uses for its own four.
# ---------------------------------------------------------------------------

vol_exists() { docker volume inspect "$1" >/dev/null 2>&1; }

vol_empty() {
  local out
  out="$(run_helper -v "$1:/d:ro" -- 'ls -A /d 2>/dev/null | head -1' 2>/dev/null)"
  [ -z "${out}" ]
}

vol_holders() {
  docker ps -q --filter "volume=$1" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'
}

# vol_holders_all NAME — every container that references volume NAME,
# running OR STOPPED, as "<name> (<state>)" one per line. `docker volume rm`
# refuses while ANY container holds a volume, not only a running one — a
# stopped container still references it — so import's preflight has to see
# stopped containers too. vol_holders above (running only, plain `docker
# ps`) is what export's refuse_if_running uses: reading a volume out from
# under a STOPPED container is fine, only a running writer is unsafe.
vol_holders_all() {
  docker ps -a --filter "volume=$1" --format '{{.Names}} ({{.State}})' 2>/dev/null
}

# refuse_if_running dies if any volume_table() volume that exists is held
# open by a running container. Shared by export and import: export cannot
# take a torn copy of live data, and import must not load underneath a
# server that is already running against the target name.
refuse_if_running() {
  local table name desc holders found=""
  table="$(volume_table)"
  while IFS='|' read -r name desc; do
    [ -n "${name}" ] || continue
    vol_exists "${name}" || continue
    holders="$(vol_holders "${name}")"
    if [ -n "${holders}" ]; then
      found=yes
      printf '  %-42s held by: %s\n' "${name}" "${holders}" >&2
    fi
  done <<EOF
${table}
EOF
  if [ -n "${found}" ]; then
    printf 'innsegl-migrate: refusing: the stack is running. The volume(s) above are held\n' >&2
    printf '  by a container. Bring the stack down first, then try again.\n' >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# The log folder (BAK-024).
# ---------------------------------------------------------------------------

# dir_empty DIR — true when DIR does not exist or holds nothing at all.
dir_empty() { [ ! -e "$1" ] || [ -z "$(ls -A "$1" 2>/dev/null)" ]; }

# HASH_FILES_SH — the shell a helper runs, in the folder to list, to write
# every regular file's sha256 (`sha256sum`) and size (`stat -c '%s %n'`) to
# /out/<name>.sums and /out/<name>.sizes, and the NUL-counted number of files
# to /out/<name>.count. Batched through `find -exec ... +`: a folder holds
# tens of thousands of bodies, and a process per file is minutes.
hash_files_sh() {
  local name="$1"
  printf '%s' "find . -type f -exec sha256sum {} + >/out/${name}.sums \
&& find . -type f -exec stat -c '%s %n' {} + >/out/${name}.sizes \
&& find . -type f -print0 | tr -cd '\\000' | wc -c >/out/${name}.count"
}

# file_lines DIR NAME — "<sha256>\t<bytes>\t<path>" per file, sorted, from
# the three lists hash_files_sh wrote into DIR. Dies if a file name holds a
# tab or a newline, which the manifest's one-line-per-record format cannot
# carry: the line count would no longer match the NUL count.
file_lines() {
  local dir="$1" name="$2" want got
  LC_ALL=C awk '
    FNR == NR { sp = index($0, " "); size[substr($0, sp + 1)] = substr($0, 1, sp - 1); next }
    { path = substr($0, 67); if (index(path, "\t")) { bad = 1 }
      printf "%s\t%s\t%s\n", substr($0, 1, 64), size[path], path }
    END { if (bad) exit 3 }
  ' "${dir}/${name}.sizes" "${dir}/${name}.sums" | LC_ALL=C sort >"${dir}/${name}.lines" \
    || die "a file in the log folder has a tab in its name; the manifest cannot carry it"
  want="$(tr -dc '0-9' <"${dir}/${name}.count")"
  got="$(wc -l <"${dir}/${name}.lines" | tr -d ' ')"
  [ "${want:-0}" = "${got}" ] \
    || die "the log folder holds ${want} file(s) but ${got} line(s) were listed: a file name has a newline in it"
}

# folder_stats DIR — "<files> <bytes>" of DIR, read by a helper as root so a
# 0700 folder the services own reads the same as any other.
folder_stats() {
  run_helper -v "$1:/h:ro" -- \
    "cd /h && find . -type f -exec stat -c '%s' {} + | awk '{n++; b+=\$1} END {printf \"%d %d\", n, b}'" 2>/dev/null
}

# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------

cmd_export() {
  require_cmd docker
  require_cmd tar
  require_cmd jq

  local event_count="" archive=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --event-count) [ $# -ge 2 ] || usage_die "--event-count needs a number"; event_count="$2"; shift 2 ;;
      --event-count=*) event_count="${1#*=}"; shift ;;
      -h|--help) usage; exit 0 ;;
      --) shift; break ;;
      -*) usage_die "export: unknown flag $1" ;;
      *) [ -z "${archive}" ] || usage_die "export: too many arguments"; archive="$1"; shift ;;
    esac
  done
  [ -n "${archive}" ] || usage_die "export needs an archive path"
  case "${event_count}" in
    '') : ;;
    *[!0-9]*) usage_die "--event-count must be a whole number, got '${event_count}'" ;;
  esac
  [ -e "${archive}" ] && die "refusing: ${archive} already exists. Remove it first, or choose a different path."

  resolve_stack
  refuse_if_helper_leftover
  refuse_if_running

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-export.XXXXXX")" || die "could not create a scratch directory"
  mkdir -p "${WORK}/volumes"

  local manifest="${WORK}/manifest.txt"
  : >"${manifest}"
  printf 'schema\t2\n' >>"${manifest}"
  printf 'prefix\tstack\t%s\n' "$(name_prefix_stack)" >>"${manifest}"
  [ -z "$(name_prefix_trust)" ] || printf 'prefix\ttrust\t%s\n' "$(name_prefix_trust)" >>"${manifest}"
  printf 'created_at\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"${manifest}"
  printf 'tree_id\t%s\n' "$(pin_tree_id)" >>"${manifest}"

  if [ -n "${event_count}" ]; then
    printf 'ledger_event_count\t%s\n' "${event_count}" >>"${manifest}"
  else
    printf 'ledger_event_count\tunknown\n' >>"${manifest}"
    note "no --event-count given; the manifest records the ledger event count as unknown."
    note "  to capture it: while the stack is still UP, run"
    note "    scripts/innsegl-migrate.sh check"
    note "  which prints the current count, then pass it here as --event-count N."
  fi

  local table name desc n=0 skipped=0
  table="$(volume_table)"
  while IFS='|' read -r name desc; do
    [ -n "${name}" ] || continue
    if ! vol_exists "${name}"; then
      note "skipping ${name}: no such volume (not part of this deployment)"
      skipped=$((skipped + 1))
      continue
    fi
    note "archiving ${name} (${desc})"
    if ! run_helper -v "${name}:/v:ro" -v "${WORK}/volumes:/out" \
        -- "tar --numeric-owner -cf /out/${name}.tar -C /v ." 2>"${WORK}/${name}.err"; then
      die "could not archive volume ${name}: $(cat "${WORK}/${name}.err" 2>/dev/null)"
    fi
    local sum bytes labels_b64
    sum="$(sha256_of "${WORK}/volumes/${name}.tar")"
    bytes="$(wc -c <"${WORK}/volumes/${name}.tar" | tr -d ' ')"
    labels_b64="$(vol_labels_b64 "${name}")"
    printf 'volume\t%s\t%s\t%s\t%s\n' "${name}" "${sum}" "${bytes}" "${labels_b64}" >>"${manifest}"
    n=$((n + 1))
  done <<EOF
${table}
EOF

  [ "${n}" -gt 0 ] || die "no volumes were found to archive; nothing was written"

  local pin_src
  pin_src="$(pin_file_path)"
  if [ -f "${pin_src}" ]; then
    mkdir -p "${WORK}/pin"
    cp "${pin_src}" "${WORK}/pin/rekor-tlog-id"
    printf 'pin_file\tpresent\n' >>"${manifest}"
  else
    printf 'pin_file\tabsent\n' >>"${manifest}"
    note "no transparency-log pin file found at ${pin_src}; the archive carries none."
  fi

  # The log folder (BAK-024): one tar, and a manifest line per file.
  if [ -d "${LOG_DIR}" ]; then
    note "archiving the log folder ${LOG_DIR} (tool-call bodies, snapshots, telemetry)"
    mkdir -p "${WORK}/hostdirs"
    if ! run_helper -v "${LOG_DIR}:/h:ro" -v "${WORK}/hostdirs:/out" \
        -- "cd /h && tar --numeric-owner -cf /out/log.tar . && $(hash_files_sh log)" 2>"${WORK}/log.err"; then
      die "could not archive the log folder ${LOG_DIR}: $(cat "${WORK}/log.err" 2>/dev/null)"
    fi
    file_lines "${WORK}/hostdirs" log
    local lsum lbytes lfiles ltotal
    lsum="$(sha256_of "${WORK}/hostdirs/log.tar")"
    lbytes="$(wc -c <"${WORK}/hostdirs/log.tar" | tr -d ' ')"
    lfiles="$(wc -l <"${WORK}/hostdirs/log.lines" | tr -d ' ')"
    ltotal="$(awk -F'\t' '{b += $2} END {printf "%d", b}' "${WORK}/hostdirs/log.lines")"
    printf 'hostdir\tlog\tpresent\t%s\t%s\t%s\t%s\n' "${lsum}" "${lbytes}" "${lfiles}" "${ltotal}" >>"${manifest}"
    awk -F'\t' '{printf "file\tlog\t%s\t%s\t%s\n", $1, $2, $3}' "${WORK}/hostdirs/log.lines" >>"${manifest}"
    rm -f "${WORK}/hostdirs/log.sums" "${WORK}/hostdirs/log.sizes" "${WORK}/hostdirs/log.count" "${WORK}/hostdirs/log.lines"
    note "  ${lfiles} file(s), ${ltotal} bytes"
  else
    printf 'hostdir\tlog\tabsent\n' >>"${manifest}"
    note "no log folder at ${LOG_DIR}; the archive carries none."
  fi

  # manifest.txt now carries every volume's labels as plain text, and a
  # label is exactly as sensitive as the trust it stands for
  # (dev.innsegl.trust-root names what the volume holds). Its own checksum,
  # a sibling file rather than a line inside it, is what import verifies
  # BEFORE trusting a single byte read from manifest.txt — including a
  # label.
  sha256_of "${manifest}" >"${WORK}/manifest.sha256"

  mkdir -p "$(dirname -- "${archive}")" 2>/dev/null || true
  local files="manifest.txt manifest.sha256 volumes"
  [ -d "${WORK}/pin" ] && files="${files} pin"
  [ -d "${WORK}/hostdirs" ] && files="${files} hostdirs"
  ( cd "${WORK}" && tar -cf "${archive}.tmp" ${files} ) || die "could not assemble ${archive}"
  chmod 0600 "${archive}.tmp"
  mv "${archive}.tmp" "${archive}"

  note "wrote ${archive} (${n} volume(s), ${skipped} skipped, mode 0600)"
}

# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

cmd_import() {
  require_cmd docker
  require_cmd tar
  require_cmd jq

  local replace="" archive=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --replace) replace=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --) shift; break ;;
      -*) usage_die "import: unknown flag $1" ;;
      *) [ -z "${archive}" ] || usage_die "import: too many arguments"; archive="$1"; shift ;;
    esac
  done
  [ -n "${archive}" ] || usage_die "import needs an archive path"
  [ -f "${archive}" ] || die "no such archive: ${archive}"

  resolve_stack
  if [ "${STACK_MODE}" = dev ]; then
    die "refusing: this host's stack is DEV (scripts/stack-mode.sh). A dev stack mints its own trust root and never takes another deployment's (ADR-0072). Import on the host that will be the live core, or run with INNSEGL_STACK=live if this one is meant to be. Nothing was written."
  fi
  refuse_if_helper_leftover
  refuse_if_running

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-import.XXXXXX")" || die "could not create a scratch directory"
  tar -xf "${archive}" -C "${WORK}" 2>/dev/null || die "refusing: ${archive} could not be extracted — it is not a valid archive, or is corrupted"
  [ -f "${WORK}/manifest.txt" ] || die "refusing: ${archive} has no manifest.txt — not a valid archive, or corrupted"

  # PASS 0 — the manifest's OWN checksum, before a single field of it is
  # trusted. A volume's data has its per-file checksum below; a label lives
  # as plain text inside manifest.txt itself, so this is what catches
  # damage to a label the same way the per-volume checksum catches damage
  # to a volume's bytes.
  [ -f "${WORK}/manifest.sha256" ] || die "refusing: ${archive} has no manifest.sha256 — not a valid archive, or corrupted"
  local manifest_want manifest_got
  manifest_want="$(tr -d ' \t\r\n' <"${WORK}/manifest.sha256")"
  manifest_got="$(sha256_of "${WORK}/manifest.txt")"
  if [ -z "${manifest_want}" ] || [ "${manifest_want}" != "${manifest_got}" ]; then
    die "refusing: ${archive}'s manifest failed verification (manifest says ${manifest_want:-<empty>}, archive has ${manifest_got}). Nothing was written to any volume."
  fi

  local schema
  schema="$(awk -F'\t' '$1=="schema"{print $2}' "${WORK}/manifest.txt")"
  case "${schema}" in
    1|2) : ;;
    *) die "refusing: ${archive} has manifest schema '${schema}', and this script reads 1 and 2. Nothing was written." ;;
  esac

  # Each volume is named by THIS host's prefixes (see PREFIXES above). An
  # archive that records none is imported under the names it carries.
  local src_stack src_trust dst_stack dst_trust
  src_stack="$(awk -F'\t' '$1=="prefix" && $2=="stack"{print $3}' "${WORK}/manifest.txt")"
  src_trust="$(awk -F'\t' '$1=="prefix" && $2=="trust"{print $3}' "${WORK}/manifest.txt")"
  dst_stack="$(name_prefix_stack)"
  dst_trust="$(name_prefix_trust)"
  target_name() {
    local n="$1"
    if [ -n "${src_trust}" ] && [ -n "${dst_trust}" ] && [ "${n#"${src_trust}"}" != "${n}" ]; then
      printf '%s%s' "${dst_trust}" "${n#"${src_trust}"}"
    elif [ -n "${src_stack}" ] && [ "${n#"${src_stack}"}" != "${n}" ]; then
      printf '%s%s' "${dst_stack}" "${n#"${src_stack}"}"
    else
      printf '%s' "${n}"
    fi
  }
  # target_labels JSON — a renamed volume's compose project label renamed
  # with it, by the same prefix rule. Carried unchanged, compose on this host
  # warns that each volume "was created for project" the old host's.
  target_labels() {
    local j="$1" proj
    [ "${src_stack}" != "${dst_stack}" ] && [ -n "${src_stack}" ] && [ "${j}" != "null" ] || { printf '%s' "${j}"; return; }
    proj="$(printf '%s' "${j}" | jq -r '."com.docker.compose.project" // empty')"
    if [ -n "${proj}" ] && [ "${proj#"${src_stack}"}" != "${proj}" ]; then
      printf '%s' "${j}" | jq -c --arg p "${dst_stack}${proj#"${src_stack}"}" '."com.docker.compose.project" = $p'
    else
      printf '%s' "${j}"
    fi
  }

  # PASS 1 — verify EVERY volume checksum, that every label decodes to valid
  # JSON, that no container — running or stopped — holds the target volume,
  # and that no existing target holds data without --replace: every check
  # that can fail, for EVERY volume in the manifest, before PASS 2 below
  # writes a single byte to any of them. A volume late in the manifest that
  # fails one of these checks must not leave volumes earlier in the manifest
  # already replaced.
  local bad="" vcount=0 kind src_name name sum bytes labels_b64
  while IFS="$(printf '\t')" read -r kind src_name sum bytes labels_b64; do
    [ "${kind}" = "volume" ] || continue
    case "${src_name}" in
      ''|.|..|*[!A-Za-z0-9_.-]*)
        printf '  refusing: manifest names an unsafe volume %s\n' "${src_name}" >&2
        bad=1; continue ;;
    esac
    name="$(target_name "${src_name}")"
    if [ "${name}" = "${src_name}" ]; then
      progress "verifying ${name} ..."
    else
      progress "verifying ${src_name} (into ${name}) ..."
    fi
    if ! known_volume "${name}"; then
      printf '  refusing: %s is not a volume this script manages\n' "${name}" >&2
      bad=1; continue
    fi
    local f="${WORK}/volumes/${src_name}.tar"
    if [ ! -f "${f}" ]; then
      printf '  missing tar for volume %s\n' "${name}" >&2
      bad=1; continue
    fi
    local got_sum got_bytes
    got_sum="$(sha256_of "${f}")"
    got_bytes="$(wc -c <"${f}" | tr -d ' ')"
    if [ "${got_sum}" != "${sum}" ] || [ "${got_bytes}" != "${bytes}" ]; then
      printf '  checksum mismatch for %s: manifest says %s (%s bytes), archive has %s (%s bytes)\n' \
        "${name}" "${sum}" "${bytes}" "${got_sum}" "${got_bytes}" >&2
      bad=1; continue
    fi
    local label_json
    label_json="$(labels_json_of_b64 "${labels_b64}")"
    if [ "${label_json}" != "null" ] && ! printf '%s' "${label_json}" | jq -e . >/dev/null 2>&1; then
      printf '  labels for %s do not decode to valid JSON\n' "${name}" >&2
      bad=1; continue
    fi
    if vol_exists "${name}"; then
      local holders
      holders="$(vol_holders_all "${name}")"
      if [ -n "${holders}" ]; then
        printf '  refusing: %s is held by the container(s) below. A stopped container\n' "${name}" >&2
        printf '  still holds its volume — remove it first; the data lives in the volume,\n' >&2
        printf '  not the container:\n' >&2
        printf '%s\n' "${holders}" | sed 's/^/    /' >&2
        bad=1; continue
      fi
      if ! vol_empty "${name}" && [ -z "${replace}" ]; then
        printf '  refusing: target volume %s already exists and is not empty. Pass --replace to overwrite it.\n' "${name}" >&2
        bad=1; continue
      fi
    fi
    vcount=$((vcount + 1))
  done <"${WORK}/manifest.txt"

  # The log folder (BAK-024), in the same pass: its tar's checksum, every
  # file in it re-hashed against its own manifest line, and the target
  # folder empty or --replace given — before anything is written.
  local log_state
  log_state="$(awk -F'\t' '$1=="hostdir" && $2=="log"{print $3}' "${WORK}/manifest.txt")"
  if [ "${log_state}" = "present" ]; then
    progress "verifying the log folder ..."
    local lsum lbytes lfiles
    lsum="$(awk -F'\t' '$1=="hostdir" && $2=="log"{print $4}' "${WORK}/manifest.txt")"
    lbytes="$(awk -F'\t' '$1=="hostdir" && $2=="log"{print $5}' "${WORK}/manifest.txt")"
    lfiles="$(awk -F'\t' '$1=="hostdir" && $2=="log"{print $6}' "${WORK}/manifest.txt")"
    if [ ! -f "${WORK}/hostdirs/log.tar" ]; then
      printf '  missing tar for the log folder\n' >&2
      bad=1
    elif [ "$(sha256_of "${WORK}/hostdirs/log.tar")" != "${lsum}" ] \
         || [ "$(wc -c <"${WORK}/hostdirs/log.tar" | tr -d ' ')" != "${lbytes}" ]; then
      printf '  checksum mismatch for the log folder: manifest says %s (%s bytes), archive has %s\n' \
        "${lsum}" "${lbytes}" "$(sha256_of "${WORK}/hostdirs/log.tar")" >&2
      bad=1
    else
      mkdir -p "${WORK}/verify"
      if ! run_helper -v "${WORK}/hostdirs:/backup:ro" -v "${WORK}/verify:/out" \
          -- "mkdir /x && tar -xf /backup/log.tar -C /x && cd /x && $(hash_files_sh log)" 2>"${WORK}/verify.err"; then
        printf '  the log folder tar could not be read: %s\n' "$(cat "${WORK}/verify.err" 2>/dev/null)" >&2
        bad=1
      else
        file_lines "${WORK}/verify" log
        awk -F'\t' '$1=="file" && $2=="log"{printf "%s\t%s\t%s\n", $3, $4, $5}' "${WORK}/manifest.txt" \
          | LC_ALL=C sort >"${WORK}/verify/want.lines"
        if ! cmp -s "${WORK}/verify/want.lines" "${WORK}/verify/log.lines"; then
          printf '  checksum mismatch in the log folder (manifest, then archive; first differences):\n' >&2
          diff "${WORK}/verify/want.lines" "${WORK}/verify/log.lines" | grep '^[<>]' | head -n 10 | sed 's/^/    /' >&2
          bad=1
        elif [ "$(wc -l <"${WORK}/verify/log.lines" | tr -d ' ')" != "${lfiles}" ]; then
          printf '  the log folder holds a different number of files than the manifest says (%s)\n' "${lfiles}" >&2
          bad=1
        fi
      fi
    fi
    if [ -e "${LOG_DIR}" ] && [ ! -d "${LOG_DIR}" ]; then
      printf '  refusing: the log folder %s exists and is not a directory\n' "${LOG_DIR}" >&2
      bad=1
    elif ! dir_empty "${LOG_DIR}" && [ -z "${replace}" ]; then
      printf '  refusing: the log folder %s already exists and is not empty. Pass --replace to overwrite it.\n' "${LOG_DIR}" >&2
      bad=1
    fi
  fi

  if [ -n "${bad}" ]; then
    die "refusing: ${archive} failed verification. Nothing was written to any volume or folder."
  fi
  [ "${vcount}" -gt 0 ] || die "refusing: ${archive} names no volumes"

  # PASS 2 — PASS 1 already confirmed, for every volume in the manifest,
  # that its checksum matches, that no container holds it, and that it is
  # either empty or --replace was given; nothing here re-checks any of that,
  # it only writes. Labels are applied on the SAME `docker volume create`
  # call that makes the volume — the fresh-create branch below, and the
  # --replace branch's recreate — because that is the only moment Docker
  # will accept one. If a docker command still fails here regardless (a race
  # with something outside this script, a daemon hiccup), done_list names
  # every volume this loop already finished, so import_die's message says
  # plainly what is already done and that the import must be re-run — this
  # never silently leaves some target volumes on the old data and some on
  # the new without saying so.
  local done_list=""
  import_die() {
    printf 'innsegl-migrate: %s\n' "$1" >&2
    if [ -n "${done_list}" ]; then
      printf 'innsegl-migrate: already replaced/loaded before this failure: %s\n' "${done_list}" >&2
      printf 'innsegl-migrate: the host is now partially imported. Fix the problem above, then\n' >&2
      printf '  re-run this import (with --replace) to finish the rest — the volumes named\n' >&2
      printf '  above already hold data from this archive, and loading them again is safe.\n' >&2
    else
      printf 'innsegl-migrate: no volume had been written yet.\n' >&2
    fi
    exit 1
  }
  while IFS="$(printf '\t')" read -r kind src_name sum bytes labels_b64; do
    [ "${kind}" = "volume" ] || continue
    name="$(target_name "${src_name}")"
    progress "importing ${name} ..."
    local label_json
    label_json="$(target_labels "$(labels_json_of_b64 "${labels_b64}")")"
    if vol_exists "${name}" && ! vol_empty "${name}"; then
      note "removing existing ${name} (--replace)"
      docker volume rm "${name}" >/dev/null || import_die "could not remove ${name}"
      create_volume_with_labels "${name}" "${label_json}" || import_die "could not create ${name}"
    elif vol_exists "${name}"; then
      note "${name} exists and is empty; loading into it (its labels, if any, are unchanged — Docker cannot relabel an existing volume)"
    else
      create_volume_with_labels "${name}" "${label_json}" || import_die "could not create ${name}"
    fi
    note "loading ${name}"
    run_helper -v "${name}:/v" -v "${WORK}/volumes:/backup:ro" \
      -- "tar --numeric-owner -xf /backup/${src_name}.tar -C /v" \
      || import_die "could not load ${name} from ${archive}"
    done_list="${done_list:+${done_list}, }${name}"
  done <"${WORK}/manifest.txt"

  if [ "${log_state}" = "present" ]; then
    progress "importing the log folder into ${LOG_DIR} ..."
    mkdir -p "${LOG_DIR}" || import_die "could not create the log folder ${LOG_DIR}"
    if ! dir_empty "${LOG_DIR}"; then
      note "emptying ${LOG_DIR} (--replace)"
      run_helper -v "${LOG_DIR}:/h" -- 'find /h -mindepth 1 -maxdepth 1 -exec rm -rf {} +' \
        || import_die "could not empty the log folder ${LOG_DIR}"
    fi
    run_helper -v "${LOG_DIR}:/h" -v "${WORK}/hostdirs:/backup:ro" \
      -- "tar --numeric-owner -xpf /backup/log.tar -C /h" \
      || import_die "could not load the log folder ${LOG_DIR} from ${archive}"
    done_list="${done_list:+${done_list}, }the log folder"
    note "loaded the log folder into ${LOG_DIR} (${lfiles} file(s))"
  elif [ "${log_state}" = "absent" ]; then
    note "the old host had no log folder; ${LOG_DIR} is left as it is."
  else
    note "this archive carries no log folder (written before RM-292); ${LOG_DIR} is left as it is."
  fi

  if [ -f "${WORK}/pin/rekor-tlog-id" ]; then
    local dest
    dest="$(pin_file_path)"
    mkdir -p "$(dirname -- "${dest}")" 2>/dev/null || true
    cp "${WORK}/pin/rekor-tlog-id" "${dest}"
    note "wrote the transparency-log pin to ${dest}"
  fi

  note "import complete (${vcount} volume(s))."
  note "next: bring the stack up on this host (deploy/compose/README.md), then run"
  note "  scripts/innsegl-migrate.sh check"
  note "to confirm the ledger and the transparency log agree with this archive."
}

# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

cmd_check() {
  require_cmd docker

  local archive=""
  if [ $# -gt 0 ]; then
    case "$1" in
      -h|--help) usage; exit 0 ;;
      -*) usage_die "check: unknown flag $1" ;;
      *) archive="$1"; shift ;;
    esac
  fi
  [ $# -eq 0 ] || usage_die "check takes at most one argument"

  resolve_stack
  local count tid
  count="$(ledger_event_count)"
  case "${count}" in ''|*[!0-9]*) count="" ;; esac
  tid="$(pin_tree_id)"

  # The log folder's own numbers (BAK-024). Read by a helper as root; the
  # folder is written by the services, not by whoever runs this.
  local live_files="" live_bytes=""
  if [ -d "${LOG_DIR}" ]; then
    local stats
    stats="$(folder_stats "${LOG_DIR}")"
    live_files="${stats%% *}"; live_bytes="${stats##* }"
  fi

  if [ -z "${archive}" ]; then
    [ -n "${count}" ] || die "the ledger is not reachable. Is the stack up?"
    note "ledger event count: ${count}"
    note "transparency-log tree id: ${tid}"
    if [ -n "${live_files}" ]; then
      note "log folder ${LOG_DIR}: ${live_files} file(s), ${live_bytes} bytes"
    else
      note "log folder ${LOG_DIR}: absent"
    fi
    note "note these down: 'export --event-count ${count}' records the count in the manifest."
    exit 0
  fi

  require_cmd tar
  [ -f "${archive}" ] || die "no such archive: ${archive}"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-check.XXXXXX")" || die "could not create a scratch directory"
  tar -xf "${archive}" -C "${WORK}" 2>/dev/null || die "refusing: ${archive} could not be extracted — it is not a valid archive, or is corrupted"
  [ -f "${WORK}/manifest.txt" ] || die "refusing: ${archive} has no manifest.txt — not a valid archive, or corrupted"
  if [ -f "${WORK}/manifest.sha256" ]; then
    local manifest_want manifest_got
    manifest_want="$(tr -d ' \t\r\n' <"${WORK}/manifest.sha256")"
    manifest_got="$(sha256_of "${WORK}/manifest.txt")"
    [ "${manifest_want}" = "${manifest_got}" ] \
      || die "refusing: ${archive}'s manifest failed verification (manifest says ${manifest_want:-<empty>}, archive has ${manifest_got})."
  fi

  local want_count want_tid
  want_count="$(awk -F'\t' '$1=="ledger_event_count"{print $2}' "${WORK}/manifest.txt")"
  want_tid="$(awk -F'\t' '$1=="tree_id"{print $2}' "${WORK}/manifest.txt")"

  local ok=1
  if [ -z "${count}" ]; then
    printf 'innsegl-migrate: check: the ledger is not reachable\n' >&2
    ok=0
  elif [ "${want_count}" = "unknown" ]; then
    note "ledger event count: manifest does not record one (export ran without --event-count); skipping that comparison"
  elif [ "${count}" != "${want_count}" ]; then
    printf 'innsegl-migrate: check: ledger event count MISMATCH: manifest %s, running stack %s\n' "${want_count}" "${count}" >&2
    ok=0
  else
    note "ledger event count: MATCH (${count})"
  fi

  # The log folder keeps growing once the stack is up, so the check is that
  # nothing the archive carried is missing: at least as many files.
  local want_files
  want_files="$(awk -F'\t' '$1=="hostdir" && $2=="log" && $3=="present"{print $6}' "${WORK}/manifest.txt")"
  if [ -z "${want_files}" ]; then
    note "log folder: the archive carries none; ${LOG_DIR} holds ${live_files:-no} file(s)"
  elif [ -z "${live_files}" ] || [ "${live_files}" -lt "${want_files}" ]; then
    printf 'innsegl-migrate: check: log folder MISMATCH: archive %s file(s), %s holds %s\n' "${want_files}" "${LOG_DIR}" "${live_files:-none}" >&2
    ok=0
  else
    note "log folder: MATCH (archive ${want_files} file(s), ${LOG_DIR} holds ${live_files})"
  fi

  if [ "${tid}" != "${want_tid}" ]; then
    printf 'innsegl-migrate: check: transparency-log tree id MISMATCH: manifest %s, running stack %s\n' "${want_tid}" "${tid}" >&2
    ok=0
  else
    note "transparency-log tree id: MATCH (${tid})"
  fi

  if [ "${ok}" -eq 1 ]; then
    note "MATCH"
    exit 0
  fi
  note "MISMATCH"
  exit 1
}

# ---------------------------------------------------------------------------
# volumes — what export would carry from this host, and import would fill.
# ---------------------------------------------------------------------------

cmd_volumes() {
  [ $# -eq 0 ] || usage_die "volumes takes no arguments"
  resolve_stack
  local table name desc
  table="$(volume_table)"
  while IFS='|' read -r name desc; do
    [ -n "${name}" ] || continue
    printf '%s\t%s\n' "${name}" "${desc}"
  done <<EOF
${table}
EOF
  printf 'log folder\t%s\n' "${LOG_DIR}"
  printf 'stack\t%s\n' "${STACK_MODE}"
}

# ---------------------------------------------------------------------------

cmd="${1:-}"
[ $# -ge 1 ] && shift || true

case "${cmd}" in
  export) cmd_export "$@" ;;
  import) cmd_import "$@" ;;
  check)  cmd_check "$@" ;;
  volumes) cmd_volumes "$@" ;;
  -h|--help|help) usage; exit 0 ;;
  '') usage_die "a command is required" ;;
  *) usage_die "unknown command: ${cmd}" ;;
esac

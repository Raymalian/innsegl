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
# innsegl.yml -> innsegl-core, sigstore.yml -> innsegl-sigstore); and
# innsegl.workrepo.yml's own `innsegl-sessions`, which is an overlay of the
# innsegl-core project and so carries that project's prefix too.
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
# IMPORT verifies every checksum in the manifest BEFORE writing a single byte
# to any volume. It refuses while any container holds a target volume, and
# refuses a target that already exists and holds data, unless --replace says
# to overwrite it.
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
#
# ENVIRONMENT
#   INNSEGL_MIGRATE_VOLUME_PREFIX   TEST ONLY. Set, volume_table() answers a
#                                   small synthetic table of throwaway
#                                   volumes under this prefix instead of the
#                                   real eighteen. scripts/innsegl-migrate-
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
#
# EXIT
#   0  done, or (check) the manifest and the running stack agree
#   1  refused, or failed, or (check) they disagree
#   2  the command line was not understood
#
# WHAT IT NEEDS: bash, docker, tar, and sha256sum or shasum on PATH. Nothing
# here starts, stops, or otherwise touches `docker compose` — an operator
# brings the stack up and down themselves, per deploy/compose/README.md.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# The pinned base image scripts/innsegl-migrate.sh tars and untars volumes
# with. Same digest the Dockerfile's runtime/backup/ca-bootstrap stages
# already build on (Dockerfile), so this is not a second image to audit.
readonly TAR_IMAGE="alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"

WORK=""
cleanup() { [ -n "${WORK}" ] && rm -rf "${WORK}"; }
trap cleanup EXIT

die()  { printf 'innsegl-migrate: %s\n' "$*" >&2; exit 1; }
usage_die() { usage >&2; printf 'innsegl-migrate: %s\n' "$*" >&2; exit 2; }
note() { printf 'innsegl-migrate: %s\n' "$*"; }

usage() {
  cat <<'EOF'
usage:
  innsegl-migrate.sh export [--event-count N] <archive>
  innsegl-migrate.sh import [--replace] <archive>
  innsegl-migrate.sh check [<archive>]
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

# ---------------------------------------------------------------------------
# volume_table — THE ONE PLACE the state volumes are named.
#
# "<name>|<what it holds>", one per line. Verified against
# deploy/compose/trust-volumes.sh (the five innsegl-trust-* suffixes),
# deploy/compose/spire.yml, innsegl.yml, innsegl.workrepo.yml and sigstore.yml
# (each project's `name:`, which is the prefix compose gives its own
# volumes), on 2026-09-28.
# ---------------------------------------------------------------------------
volume_table() {
  local prefix="${INNSEGL_MIGRATE_VOLUME_PREFIX:-}"
  if [ -n "${prefix}" ]; then
    # TEST ONLY. Two throwaway volumes under the caller's own prefix — never
    # the real eighteen. scripts/innsegl-migrate-selftest.sh is the only
    # caller that sets INNSEGL_MIGRATE_VOLUME_PREFIX.
    printf '%sledger-data|throwaway ledger volume (self-test)\n' "${prefix}"
    printf '%strillian-db|throwaway trillian volume (self-test)\n' "${prefix}"
    return 0
  fi
  cat <<'EOF'
innsegl-trust-ledger-data|the ledger hot tier: postgres's data directory
innsegl-trust-trillian-db|the transparency log itself: trillian's mysql data directory
innsegl-trust-rekor-key|the transparency log's signing key
innsegl-trust-fulcio-pki|the Fulcio CA certificate and encrypted key
innsegl-trust-identity-secret|this deployment's pseudonymisation secret
innsegl-spire_spire-server-data|the SPIRE server's datastore and keys
innsegl-spire_spire-pki-server|the SPIRE server's upstream CA cert+key and node CA cert
innsegl-spire_spire-pki-agent|the SPIRE agent's node identity and bootstrap trust bundle
innsegl-spire_spire-agent-data|the SPIRE agent's own data
innsegl-core_innsegl-object-data|sealed segments' bytes, under object lock
innsegl-core_innsegl-object-filer-data|the object store's metadata
innsegl-core_innsegl-s3-identities|the object gateway's S3 credentials
innsegl-core_innsegl-admin-key|the admin-credential private signing key
innsegl-core_innsegl-admin-jwks|the admin-credential public key set
innsegl-core_innsegl-sessions|the harness's session-to-run mapping
innsegl-core_innsegl-workspace|the working trees `repo` resolves under
innsegl-core_innsegl-backups|verified ledger backups and their reports
innsegl-sigstore_sigstore-rekor-search|Rekor's search index
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
  out="$(docker run --rm -v "$1:/d:ro" "${TAR_IMAGE}" sh -c 'ls -A /d 2>/dev/null | head -1' 2>/dev/null)"
  [ -z "${out}" ]
}

vol_holders() {
  docker ps -q --filter "volume=$1" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'
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
# export
# ---------------------------------------------------------------------------

cmd_export() {
  require_cmd docker
  require_cmd tar

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

  refuse_if_running

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-export.XXXXXX")" || die "could not create a scratch directory"
  mkdir -p "${WORK}/volumes"

  local manifest="${WORK}/manifest.txt"
  : >"${manifest}"
  printf 'schema\t1\n' >>"${manifest}"
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
    if ! docker run --rm -v "${name}:/v:ro" -v "${WORK}/volumes:/out" "${TAR_IMAGE}" \
        tar --numeric-owner -cf "/out/${name}.tar" -C /v . 2>"${WORK}/${name}.err"; then
      die "could not archive volume ${name}: $(cat "${WORK}/${name}.err" 2>/dev/null)"
    fi
    local sum bytes
    sum="$(sha256_of "${WORK}/volumes/${name}.tar")"
    bytes="$(wc -c <"${WORK}/volumes/${name}.tar" | tr -d ' ')"
    printf 'volume\t%s\t%s\t%s\n' "${name}" "${sum}" "${bytes}" >>"${manifest}"
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

  mkdir -p "$(dirname -- "${archive}")" 2>/dev/null || true
  local files="manifest.txt volumes"
  [ -d "${WORK}/pin" ] && files="${files} pin"
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

  refuse_if_running

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-import.XXXXXX")" || die "could not create a scratch directory"
  tar -xf "${archive}" -C "${WORK}" 2>/dev/null || die "refusing: ${archive} could not be extracted — it is not a valid archive, or is corrupted"
  [ -f "${WORK}/manifest.txt" ] || die "refusing: ${archive} has no manifest.txt — not a valid archive, or corrupted"

  # PASS 1 — verify EVERY checksum before writing anything to any volume.
  local bad="" vcount=0 kind name sum bytes
  while IFS="$(printf '\t')" read -r kind name sum bytes; do
    [ "${kind}" = "volume" ] || continue
    case "${name}" in
      ''|.|..|*[!A-Za-z0-9_.-]*)
        printf '  refusing: manifest names an unsafe volume %s\n' "${name}" >&2
        bad=1; continue ;;
    esac
    if ! known_volume "${name}"; then
      printf '  refusing: %s is not a volume this script manages\n' "${name}" >&2
      bad=1; continue
    fi
    local f="${WORK}/volumes/${name}.tar"
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
    vcount=$((vcount + 1))
  done <"${WORK}/manifest.txt"

  if [ -n "${bad}" ]; then
    die "refusing: ${archive} failed verification. Nothing was written to any volume."
  fi
  [ "${vcount}" -gt 0 ] || die "refusing: ${archive} names no volumes"

  # PASS 2 — every checksum verified; now it is safe to write.
  while IFS="$(printf '\t')" read -r kind name sum bytes; do
    [ "${kind}" = "volume" ] || continue
    if vol_exists "${name}"; then
      if ! vol_empty "${name}"; then
        if [ -z "${replace}" ]; then
          die "refusing: target volume ${name} already exists and is not empty. Pass --replace to overwrite it."
        fi
        local holders
        holders="$(vol_holders "${name}")"
        [ -z "${holders}" ] || die "refusing: ${name} is in use by ${holders}"
        note "removing existing ${name} (--replace)"
        docker volume rm "${name}" >/dev/null || die "could not remove ${name}"
        docker volume create "${name}" >/dev/null || die "could not create ${name}"
      else
        note "${name} exists and is empty; loading into it"
      fi
    else
      docker volume create "${name}" >/dev/null || die "could not create ${name}"
    fi
    note "loading ${name}"
    docker run --rm -v "${name}:/v" -v "${WORK}/volumes:/backup:ro" "${TAR_IMAGE}" \
      sh -c "tar --numeric-owner -xf /backup/${name}.tar -C /v" \
      || die "could not load ${name} from ${archive}"
  done <"${WORK}/manifest.txt"

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

  local count tid
  count="$(ledger_event_count)"
  case "${count}" in ''|*[!0-9]*) count="" ;; esac
  tid="$(pin_tree_id)"

  if [ -z "${archive}" ]; then
    [ -n "${count}" ] || die "the ledger is not reachable. Is the stack up?"
    note "ledger event count: ${count}"
    note "transparency-log tree id: ${tid}"
    note "note these down: 'export --event-count ${count}' records the count in the manifest."
    exit 0
  fi

  require_cmd tar
  [ -f "${archive}" ] || die "no such archive: ${archive}"
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/innsegl-migrate-check.XXXXXX")" || die "could not create a scratch directory"
  tar -xf "${archive}" -C "${WORK}" 2>/dev/null || die "refusing: ${archive} could not be extracted — it is not a valid archive, or is corrupted"
  [ -f "${WORK}/manifest.txt" ] || die "refusing: ${archive} has no manifest.txt — not a valid archive, or corrupted"

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

cmd="${1:-}"
[ $# -ge 1 ] && shift || true

case "${cmd}" in
  export) cmd_export "$@" ;;
  import) cmd_import "$@" ;;
  check)  cmd_check "$@" ;;
  -h|--help|help) usage; exit 0 ;;
  '') usage_die "a command is required" ;;
  *) usage_die "unknown command: ${cmd}" ;;
esac

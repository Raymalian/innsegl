#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The trust root's volumes, outside the compose project — OPS-032, OPS-033.
#
# WHY THESE FOUR LIVE OUTSIDE THE PROJECT
#
# A compose project's volumes are exactly what `down -v` removes. On
# 2026-09-16 the Fulcio CA key, the Rekor signing key, Trillian's database and
# the ledger were all in them, and one command took the ledger from 19,595
# chain positions to 60 and the transparency log from 525 entries to 3. Commits
# signed the previous day stopped verifying — the signature is intact and the
# trailer still matches the certificate; the CA that issued it and the log that
# recorded it are gone, and there is no repair.
#
# Declared external, `down -v` can only DETACH them. Destroying one then takes
# naming it, which is the difference between a decision and an accident.
# scripts/teardown-guard.sh stands in front of that too (doc 05 §2).
#
# THE FIFTH WAS FOUND BY LOSING IT. innsegl-identity-secret was not on this
# list, and proving OPS-032 destroyed it. The deployment minted a new one, and
# the SAME task string then pseudonymised to a different id — so a run
# registered minutes earlier could no longer claim a commit: "Agent-Task is
# 4a3f6604, which does not lowercase to the task 6ddc6071 in Agent-Identity".
# Nothing already signed stopped verifying; what broke is ATTRIBUTION. Every
# agent and task pseudonym already in the ledger names something no future run
# can reproduce, and ADR-0041 (#124) makes the secret per-deployment on purpose
# — which is exactly what makes it unrecoverable.
#
# WHY NOT MORE THAN THESE. Irreplaceable is a narrower word than important.
# The workspace is a checkout, the session store is a cache, and a sealed
# segment is derived from the ledger and can be sealed again — while the ledger
# is the only copy of the event bodies (runbooks/index-rebuild.md §0: "there is
# no rebuild-from-segments-alone"). A blanket `external: true` would make
# `down -v` a no-op and teach an operator to reach for `docker volume rm`.
#
# WHY SPIRE's CA IS NOT ONE OF THEM. Losing it costs a re-attestation: every
# workload gets a new SVID and carries on. No commit that already verifies
# stops verifying, because a gitsign certificate chains to Fulcio and not to
# SPIRE. That is the test for this list.
#
# THE STAMP
#
# The four are ONE trust root, and `ensure` stamps them with one deployment id
# (`dev.innsegl.deployment`). A set that does not agree on its id is not one
# trust root — it is one deployment's volumes with another deployment's mixed
# in, and `ensure` refuses rather than booting Fulcio onto somebody else's CA
# key. The id is printed on every run, so a set is never adopted silently.
#
# USAGE
#   deploy/compose/trust-volumes.sh ensure    create if absent, stamp, migrate
#   deploy/compose/trust-volumes.sh list      what exists, and whose it is
#   deploy/compose/trust-volumes.sh names     the four volume names, one per line
#   deploy/compose/trust-volumes.sh env       the VAR=value lines compose reads
#
# ENVIRONMENT
#   INNSEGL_TRUST_VOLUME_PREFIX   default innsegl-trust. A test or a second
#                                 deployment on one machine sets this; nothing
#                                 is migrated into a non-default prefix, so a
#                                 test can never inherit the real trust root.
#   INNSEGL_TRUST_LEGACY_PREFIX   migrate from "<prefix>-<suffix>" instead of
#                                 the built-in legacy names. Set only by a
#                                 test: it is what lets the migration be
#                                 measured without a test prefix ever being
#                                 pointed at the real deployment's volumes.
#   INNSEGL_DEPLOYMENT_ID         pin the stamp instead of minting one.
#
# EXIT
#   0  the four exist, agree on their deployment, and are stamped
#   2  the command line was not understood
#   5  docker is not reachable
#   7  REFUSED: the set does not belong to one deployment, or a migration
#      cannot be done safely
#
# Portability: the bash 3.2 that ships with macOS. No mapfile, no named arrays.

set -uo pipefail

readonly EXIT_USAGE=2
readonly EXIT_NO_DOCKER=5
readonly EXIT_REFUSED=7

readonly DEFAULT_PREFIX='innsegl-trust'
PREFIX="${INNSEGL_TRUST_VOLUME_PREFIX:-$DEFAULT_PREFIX}"

# "<suffix>|<compose env var>|<legacy project volume>|<what it holds>".
#
# The legacy column is where the bytes are on a deployment that predates this
# script — the names compose gave them under the shipped project names — and is
# what `ensure` migrates FROM, once, when the stack is down.
VOLUMES='ledger-data|INNSEGL_TRUST_LEDGER_VOLUME|innsegl-core_innsegl-ledger-data|the ledger: the hash chain and every event body
identity-secret|INNSEGL_TRUST_IDENTITY_SECRET_VOLUME|innsegl-core_innsegl-identity-secret|the pseudonymisation secret every agent and task id in the ledger was derived from
fulcio-pki|INNSEGL_TRUST_FULCIO_PKI_VOLUME|innsegl-sigstore_sigstore-fulcio-pki|the Fulcio CA key that issued every certificate
rekor-key|INNSEGL_TRUST_REKOR_KEY_VOLUME|innsegl-sigstore_sigstore-rekor-key|the Rekor key that signed every transparency-log entry
trillian-db|INNSEGL_TRUST_TRILLIAN_DB_VOLUME|innsegl-sigstore_sigstore-trillian-db-data|the transparency log itself'

# The label scripts/teardown-guard.sh reads. Its VALUE is the sentence above,
# so a volume explains itself with no table anywhere.
readonly TRUST_LABEL='dev.innsegl.trust-root'
readonly DEPLOY_LABEL='dev.innsegl.deployment'

usage() { sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'; }

volume_name() { printf '%s-%s' "$PREFIX" "$1"; }

label_of() {
  out=$(docker volume inspect "$1" --format "{{index .Labels \"$2\"}}" 2>/dev/null) || return 1
  [ "$out" = "<no value>" ] && out=""
  printf '%s' "$out"
}

exists() { docker volume inspect "$1" >/dev/null 2>&1; }

# empty reports whether a volume holds nothing. A destination that EXISTS and
# is EMPTY is the state a refused migration leaves behind, and it is what
# decides whether to copy — not whether the volume was just created. See
# cmd_ensure.
empty() {
  out=$(docker run --rm --volume "$1":/d:ro alpine:3.20 \
          sh -c 'ls -A /d 2>/dev/null | head -1' 2>/dev/null)
  [ -z "$out" ]
}

# legacy_source echoes the volume to migrate FROM, or nothing when there is
# none to consider. INNSEGL_TRUST_LEGACY_PREFIX overrides the built-in names;
# otherwise the built-ins apply only under the default prefix, which is the
# line that stops a test inheriting the real deployment's CA key.
legacy_source() {
  suffix="$1"; builtin_name="$2"
  if [ -n "${INNSEGL_TRUST_LEGACY_PREFIX:-}" ]; then
    printf '%s-%s' "$INNSEGL_TRUST_LEGACY_PREFIX" "$suffix"
    return
  fi
  [ "$PREFIX" = "$DEFAULT_PREFIX" ] || return 0
  printf '%s' "$builtin_name"
}

# using reports the containers holding a volume open. Copying a Postgres data
# directory out from under a running server produces a dump nobody can restore,
# so a migration with the stack up is refused rather than attempted.
using() { docker ps -q --filter "volume=$1" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }

# ---------------------------------------------------------------------------

cmd_names() {
  printf '%s\n' "$VOLUMES" | while IFS='|' read -r suffix _ _ _; do
    printf '%s\n' "$(volume_name "$suffix")"
  done
}

cmd_env() {
  echo "INNSEGL_TRUST_VOLUMES_EXTERNAL=true"
  printf '%s\n' "$VOLUMES" | while IFS='|' read -r suffix var _ _; do
    printf '%s=%s\n' "$var" "$(volume_name "$suffix")"
  done
}

cmd_list() {
  printf '%s\n' "$VOLUMES" | while IFS='|' read -r suffix _ _ what; do
    n=$(volume_name "$suffix")
    if exists "$n"; then
      printf '  %-34s %-18s %s\n' "$n" "$(label_of "$n" "$DEPLOY_LABEL")" "$what"
    else
      printf '  %-34s %-18s %s\n' "$n" "ABSENT" "$what"
    fi
  done
}

# current_stamp echoes the one deployment id the existing volumes agree on, or
# refuses if they do not. Nothing is created here — this decides only whose
# trust root this is.
current_stamp() {
  stamp=""
  conflict=""
  while IFS='|' read -r suffix _ _ _; do
    n=$(volume_name "$suffix")
    exists "$n" || continue
    got=$(label_of "$n" "$DEPLOY_LABEL")
    [ -n "$got" ] || got="(unstamped)"
    if [ -z "$stamp" ]; then
      stamp="$got"
    elif [ "$got" != "$stamp" ]; then
      conflict="$conflict  $n is stamped $got
"
    fi
  done <<EOT
$VOLUMES
EOT
  if [ -n "$conflict" ]; then
    {
      echo
      echo "REFUSED: these volumes do not belong to one deployment."
      echo
      echo "  the set is stamped $stamp, and:"
      printf '%s' "$conflict"
      echo
      echo "  The four are ONE trust root: a CA key, the log that recorded what it"
      echo "  signed, that log's own key, and the chain the events live in. Booting"
      echo "  onto a set that mixes two deployments produces certificates one log"
      echo "  has never heard of, which is a verification failure nobody can read."
      echo
      echo "  Nothing was created and nothing was changed. Either remove the volume"
      echo "  that does not belong — deliberately, by name — or point this"
      echo "  deployment somewhere else with INNSEGL_TRUST_VOLUME_PREFIX."
      echo
    } >&2
    return "$EXIT_REFUSED"
  fi
  printf '%s' "$stamp"
}

# migrate copies a legacy project volume into its external replacement, once.
#
# The condition is the DESTINATION BEING EMPTY, and that is a bug fix rather
# than a refinement: this used to run only when ensure had just CREATED the
# destination, so a run that created the volume and then correctly refused the
# copy — because the stack was still up — left an empty external volume that
# every later ensure reported "ok". Measured on the real deployment. Emptiness
# is also what makes this idempotent: a migrated volume is never overwritten.
migrate() {
  from="$1"; to="$2"; what="$3"
  [ -n "$from" ] || return 0
  exists "$from" || return 0
  empty "$to" || return 0
  holders=$(using "$from")
  if [ -n "$holders" ]; then
    {
      echo
      echo "REFUSED: $from still has $what in it and is open by a running container."
      echo
      echo "  Copying it now would take a torn copy of live data. Take the stack"
      echo "  down first — \`make innsegl-down\` keeps every volume — and run this"
      echo "  again."
      echo
    } >&2
    return "$EXIT_REFUSED"
  fi
  echo "  migrating $what"
  echo "    from $from (the compose project's — where \`down -v\` reaches)"
  echo "    into $to (external — where it does not)"
  docker run --rm \
    --volume "$from":/from:ro --volume "$to":/to \
    alpine:3.20 sh -c 'cp -a /from/. /to/ 2>/dev/null || true' >/dev/null 2>&1
  # The legacy volume is LEFT IN PLACE. Deleting the only other copy of a CA
  # key at the end of a script whose whole subject is not deleting CA keys
  # would be its own joke. Remove it by name when the new one has proved
  # itself: scripts/teardown-guard.sh will ask you to mean it.
  echo "    copied. $from is left in place — remove it by name once this has booted."
}

cmd_ensure() {
  stamp=$(current_stamp) || return "$EXIT_REFUSED"
  pinned="${INNSEGL_DEPLOYMENT_ID:-}"

  if [ -n "$pinned" ] && [ -n "$stamp" ] && [ "$pinned" != "$stamp" ]; then
    {
      echo
      echo "REFUSED: these volumes are stamped $stamp and INNSEGL_DEPLOYMENT_ID is $pinned."
      echo "  This deployment would be booting onto another deployment's trust root."
      echo
    } >&2
    return "$EXIT_REFUSED"
  fi

  minted=""
  if [ -z "$stamp" ]; then
    if [ -n "$pinned" ]; then
      stamp="$pinned"
    else
      # No hostname, no path, no user: doc 04 wants nothing here that
      # identifies the machine, and CLAUDE.md forbids an operator path in a
      # shipped file. Sixteen random hex characters carry neither.
      stamp=$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom 2>/dev/null | head -c 16)
      [ -n "$stamp" ] || stamp=$(date +%s)
      minted=yes
    fi
  elif [ "$stamp" = "(unstamped)" ]; then
    stamp="${pinned:-$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 16)}"
  fi

  if [ -n "$minted" ]; then
    echo "trust-volumes: no trust root under \"$PREFIX\" yet; minting deployment $stamp"
  else
    echo "trust-volumes: deployment $stamp"
  fi

  rc=0
  while IFS='|' read -r suffix _ legacy what; do
    n=$(volume_name "$suffix")
    from="$(legacy_source "$suffix" "$legacy")"
    if exists "$n"; then
      # Re-stamp only what is missing. A volume that already carries the id
      # is left exactly as it is: ensure must be a no-op on a healthy set.
      if [ -z "$(label_of "$n" "$DEPLOY_LABEL")" ]; then
        docker volume create --label "$TRUST_LABEL=$what" \
          --label "$DEPLOY_LABEL=$stamp" "$n" >/dev/null 2>&1
      fi
      printf '  %-34s ok\n' "$n"
      migrate "$from" "$n" "$what" || rc="$EXIT_REFUSED"
      continue
    fi
    if ! docker volume create \
        --label "$TRUST_LABEL=$what" \
        --label "$DEPLOY_LABEL=$stamp" "$n" >/dev/null; then
      echo "trust-volumes: could not create $n" >&2
      rc=1
      continue
    fi
    printf '  %-34s created\n' "$n"
    migrate "$from" "$n" "$what" || rc="$EXIT_REFUSED"
  done <<EOT
$VOLUMES
EOT
  return "$rc"
}

# ---------------------------------------------------------------------------

# `names` and `env` answer from the table alone. The Makefile expands them at
# parse time, on every single target, and a make that needed a running daemon
# to print its own help would be a poor trade for a naming convention.
case "${1:-}" in
  names) cmd_names; exit 0 ;;
  env)   cmd_env;   exit 0 ;;
  -h|--help) usage; exit 0 ;;
esac

if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  echo "trust-volumes: docker is not reachable" >&2
  exit "$EXIT_NO_DOCKER"
fi

case "${1:-}" in
  ensure) cmd_ensure; exit $? ;;
  list)   cmd_list;   exit 0 ;;
  *) usage >&2; exit "$EXIT_USAGE" ;;
esac

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The teardown gate — OPS-031.
#
# WHY THIS EXISTS, and it is not hypothetical.
#
# On 2026-09-16 a teardown with volumes removed, in one command, took the
# ledger from 19,595 chain positions to 60 and the transparency log from 525
# entries to 3, and minted a new Fulcio CA key and a new Rekor signing key.
# Commits signed the previous day stopped verifying. The signature is intact
# and the trailer still matches the certificate; what is gone is the CA that
# issued it and the log that recorded it. There is no repair — four merged
# branches had to be re-signed from scratch to pass the merge gate.
#
# This project already refuses to sign without an identity (IP §6.1) and
# refuses to merge a claim nothing supports (scripts/verify-branch.sh). It
# should refuse to delete the root of both. That is all this is.
#
# WHAT IT REFUSES
#
# Any command that would REMOVE a volume holding a key or the chain:
#
#   docker compose ... down -v          the volumes the project owns
#   docker volume rm <name>...          by name
#   docker volume prune                 every dangling volume
#
# A volume is a trust volume if either is true:
#
#   * it carries the label `dev.innsegl.trust-root` — stamped by
#     deploy/compose/trust-volumes.sh, and the only thing that identifies one
#     once it is external and compose no longer knows it exists; or
#   * its compose volume KEY, or its full name, is in the table below.
#
# Two mechanisms rather than one because each covers the other's blind spot. A
# fresh clone that has never run `trust-volumes.sh ensure` has no labels, and
# an external volume has no compose key.
#
# WHAT IT DOES NOT REFUSE, deliberately.
#
# Everything else. `down -v` on the workspace, the demo repository, the session
# store and the object store still works and must: a gate that stopped ordinary
# teardown would be switched off within a week, and a gate nobody runs protects
# nothing. The object store is not in the table for a reason of its own — a
# sealed segment is derived from the ledger and can be sealed again, while the
# ledger is the only copy of the event bodies (runbooks/index-rebuild.md §0:
# "there is no rebuild-from-segments-alone"). Irreplaceable is a narrower word
# than important.
#
# HOW AN OPERATOR WHO MEANS IT SAYS SO
#
#   INNSEGL_DESTROY_TRUST_ROOT=<volume>[,<volume>...]
#   scripts/teardown-guard.sh --destroy-trust-root=<volume>[,...] -- <command>
#
# The opt-out NAMES the volumes. Not a yes, not a 1 — those are what an
# accident looks like from the inside. A protected volume at risk that is not
# in the list still refuses, so an operator who means to destroy one of the
# four cannot destroy the other three by the same keystroke.
#
# USAGE
#   scripts/teardown-guard.sh [--destroy-trust-root=LIST] [--] <command> [args...]
#
# EXIT
#   0   the command ran (its own status is passed through)
#   2   the guard's own command line was not understood
#   9   REFUSED: the command would have destroyed a trust volume
#
# Portability: the bash 3.2 that ships with macOS. No mapfile, no named arrays,
# no ${var,,} — the discipline scripts/protected-surfaces.sh already keeps.

set -uo pipefail

readonly EXIT_USAGE=2
readonly EXIT_REFUSED=9

# ---------------------------------------------------------------------------
# The trust root, by compose volume key and by full volume name.
#
# "<kind>|<literal>|<what it holds>". The third field is what the refusal
# prints: an operator reading "innsegl-trust-fulcio-pki" at 09:41 needs to be
# told it is the CA key that issued every certificate, not left to remember.
#
# The full names cover a deployment that has not migrated to external volumes
# yet — the names compose gives them under the shipped project names.
# ---------------------------------------------------------------------------
TRUST_TABLE='key|innsegl-ledger-data|the ledger: the hash chain and every event body
key|innsegl-identity-secret|the pseudonymisation secret every agent and task id in the ledger was derived from
key|sigstore-fulcio-pki|the Fulcio CA key that issued every certificate
key|sigstore-rekor-key|the Rekor key that signed every transparency-log entry
key|sigstore-trillian-db-data|the transparency log itself
name|innsegl-core_innsegl-ledger-data|the ledger: the hash chain and every event body
name|innsegl-core_innsegl-identity-secret|the pseudonymisation secret every agent and task id in the ledger was derived from
name|innsegl-trust-identity-secret|the pseudonymisation secret every agent and task id in the ledger was derived from
name|innsegl-sigstore_sigstore-fulcio-pki|the Fulcio CA key that issued every certificate
name|innsegl-sigstore_sigstore-rekor-key|the Rekor key that signed every transparency-log entry
name|innsegl-sigstore_sigstore-trillian-db-data|the transparency log itself'

# The label deploy/compose/trust-volumes.sh stamps. Its VALUE is the human
# sentence above, so a labelled volume explains itself with no table at all.
readonly TRUST_LABEL='dev.innsegl.trust-root'

OPT_OUT="${INNSEGL_DESTROY_TRUST_ROOT:-}"

usage() {
  sed -n '/^# USAGE/,/^# EXIT/p' "$0" | sed 's/^# \{0,1\}//'
}

# --- the guard's own options, then the command ------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --destroy-trust-root=*) OPT_OUT="${OPT_OUT},${1#*=}"; shift ;;
    --destroy-trust-root)
      [ $# -ge 2 ] || { echo "teardown-guard: --destroy-trust-root needs a value" >&2; exit "$EXIT_USAGE"; }
      OPT_OUT="${OPT_OUT},${2}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

if [ $# -eq 0 ]; then
  echo "teardown-guard: no command to run" >&2
  usage >&2
  exit "$EXIT_USAGE"
fi

# ---------------------------------------------------------------------------
# What kind of command is this?
# ---------------------------------------------------------------------------

# has_token reports whether the command line contains an exact token.
has_token() {
  needle="$1"; shift
  for a in "$@"; do
    [ "$a" = "$needle" ] && return 0
  done
  return 1
}

# index_of echoes the 1-based position of a token, or 0.
index_of() {
  needle="$1"; shift
  i=0
  for a in "$@"; do
    i=$((i + 1))
    [ "$a" = "$needle" ] && { printf '%s' "$i"; return 0; }
  done
  printf '0'
}

# is_compose_down_v: a compose teardown that removes the project's volumes.
# The -v is required to appear AFTER `down`: `docker compose -v` is a version
# query and carries no risk at all.
is_compose_down_v() {
  case "$1" in
    *docker-compose) : ;;
    *docker) has_token compose "$@" || return 1 ;;
    *) return 1 ;;
  esac
  d=$(index_of down "$@")
  [ "$d" -gt 0 ] || return 1
  i=0
  for a in "$@"; do
    i=$((i + 1))
    [ "$i" -gt "$d" ] || continue
    case "$a" in
      -v|--volumes|--volumes=true) return 0 ;;
    esac
  done
  return 1
}

# is_volume_subcommand: `docker volume rm|prune`, the other door into the same
# bytes. Once the four are external, `down -v` can only detach them and this is
# what actually destroys one — a guard that watched only compose would be
# guarding the door nobody uses.
volume_subcommand() {
  case "$1" in *docker) : ;; *) printf ''; return ;; esac
  v=$(index_of volume "$@")
  [ "$v" -gt 0 ] || { printf ''; return; }
  i=0
  for a in "$@"; do
    i=$((i + 1))
    [ "$i" -eq $((v + 1)) ] || continue
    case "$a" in rm|remove|prune) printf '%s' "$a" ;; *) printf '' ;; esac
    return
  done
  printf ''
}

# ---------------------------------------------------------------------------
# Which volumes would go?
#
# For compose this asks DOCKER, not the YAML: a project's own volumes carry
# `com.docker.compose.project` and `com.docker.compose.volume` labels, and an
# external volume carries neither because compose did not create it. So the
# label query returns exactly the set `down -v` removes, which is the question
# being asked — no YAML parsing, and no way for the file and the daemon to
# disagree.
# ---------------------------------------------------------------------------

# compose_project echoes the project name compose itself resolves, by replaying
# the same global flags (everything between `compose` and `down`) at `config`.
compose_project() {
  c=$(index_of compose "$@")
  d=$(index_of down "$@")
  if [ "$c" -eq 0 ]; then   # the docker-compose v1 spelling
    c=1
  fi
  n=$((d - c - 1))
  [ "$n" -ge 0 ] || n=0
  # ${@:offset:length} is bash 3.2; the globals start one past `compose`.
  set -- "${@:$((c + 1)):$n}"
  docker compose "$@" config --format json 2>/dev/null \
    | sed -n 's/^[[:space:]]*"name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

# at_risk_volumes echoes "<name>|<compose key>" lines.
at_risk_volumes() {
  project=$(compose_project "$@")
  [ -n "$project" ] || return 0
  docker volume ls --filter "label=com.docker.compose.project=$project" \
    --format '{{.Name}}' 2>/dev/null \
  | while IFS= read -r v; do
      [ -n "$v" ] || continue
      k=$(docker volume inspect "$v" \
            --format '{{index .Labels "com.docker.compose.volume"}}' 2>/dev/null)
      [ "$k" = "<no value>" ] && k=""
      printf '%s|%s\n' "$v" "$k"
    done
}

# named_volumes echoes the volume names a `docker volume rm` would remove.
named_volumes() {
  v=$(index_of volume "$@")
  i=0
  for a in "$@"; do
    i=$((i + 1))
    [ "$i" -gt $((v + 1)) ] || continue
    case "$a" in -*) continue ;; esac
    printf '%s|\n' "$a"
  done
}

# dangling_volumes echoes what `docker volume prune` would take.
dangling_volumes() {
  docker volume ls --filter dangling=true --format '{{.Name}}' 2>/dev/null \
    | while IFS= read -r v; do [ -n "$v" ] && printf '%s|\n' "$v"; done
}

# ---------------------------------------------------------------------------
# Is a volume a trust volume, and what does it hold?
# ---------------------------------------------------------------------------

table_lookup() {
  kind="$1"; literal="$2"
  printf '%s\n' "$TRUST_TABLE" | while IFS='|' read -r k lit what; do
    [ "$k" = "$kind" ] && [ "$lit" = "$literal" ] && printf '%s' "$what"
  done
}

# what_it_holds echoes the sentence to print, or nothing if the volume is not
# part of the trust root.
what_it_holds() {
  name="$1"; key="${2:-}"
  role=$(docker volume inspect "$name" \
           --format "{{index .Labels \"$TRUST_LABEL\"}}" 2>/dev/null)
  [ "$role" = "<no value>" ] && role=""
  if [ -n "$role" ]; then printf '%s' "$role"; return; fi
  if [ -n "$key" ]; then
    role=$(table_lookup key "$key")
    if [ -n "$role" ]; then printf '%s' "$role"; return; fi
  fi
  table_lookup name "$name"
}

# opted_out reports whether the operator named this volume.
#
# WORD SPLITTING AND NOT A PIPELINE, and that is a bug fix rather than a style
# preference. This was `printf | tr | while read | grep -q`, and under
# `set -o pipefail` the while-subshell's exit status is the status of its LAST
# iteration — which is 1 whenever the final name in the list is not the one
# being asked about. So an opt-out naming three volumes released only the third
# and refused the other two, while an opt-out naming one always worked. Watched
# happening on a real teardown; OPS-031 now passes a list of more than one name
# for exactly this reason.
opted_out() {
  want="$1"
  saved_ifs="$IFS"
  IFS=', '
  # shellcheck disable=SC2086 # deliberate: the list is split on commas/spaces.
  set -- $OPT_OUT
  IFS="$saved_ifs"
  for n in "$@"; do
    [ "$n" = "$want" ] && return 0
  done
  return 1
}

# ---------------------------------------------------------------------------
# Decide.
# ---------------------------------------------------------------------------

CANDIDATES=""
KIND=""
if is_compose_down_v "$@"; then
  KIND="compose down -v"
  CANDIDATES=$(at_risk_volumes "$@")
else
  case "$(volume_subcommand "$@")" in
    rm|remove) KIND="docker volume rm"; CANDIDATES=$(named_volumes "$@") ;;
    prune)     KIND="docker volume prune"; CANDIDATES=$(dangling_volumes "$@") ;;
  esac
fi

if [ -z "$KIND" ]; then
  exec "$@"
fi

REFUSED=""
ALLOWED=""
nrefused=0
while IFS='|' read -r name key; do
  [ -n "$name" ] || continue
  holds=$(what_it_holds "$name" "$key")
  [ -n "$holds" ] || continue
  if opted_out "$name"; then
    ALLOWED="$ALLOWED  $name — $holds
"
    continue
  fi
  REFUSED="$REFUSED  $name
      holds $holds
"
  nrefused=$((nrefused + 1))
done <<EOT
$CANDIDATES
EOT

if [ "$nrefused" -gt 0 ]; then
  {
    echo
    echo "REFUSED: this $KIND would destroy the trust root."
    echo
    printf '%s' "$REFUSED"
    echo
    echo "  A commit's proof depends on the CA that issued its certificate, the log"
    echo "  that recorded it and the chain that holds the event. None of the three"
    echo "  can be rebuilt, and every commit already signed against them stops"
    echo "  verifying the moment one is gone. This happened here on 2026-09-16."
    echo
    echo "  Nothing was removed and nothing was stopped."
    echo
    echo "  If you mean it, say which one — the naming IS the decision:"
    echo
    printf '    INNSEGL_DESTROY_TRUST_ROOT=%s \\\n' \
      "$(printf '%s' "$REFUSED" | sed -n 's/^  \([^ ].*\)$/\1/p' | paste -sd, -)"
    echo "      $*"
    echo
  } >&2
  exit "$EXIT_REFUSED"
fi

if [ -n "$ALLOWED" ]; then
  {
    echo "teardown-guard: destroying the trust root, because you named it:"
    printf '%s' "$ALLOWED"
  } >&2
fi

exec "$@"

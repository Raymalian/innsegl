#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end proof that the reference SPIRE compose stack does NOT issue an
# agent run's identity to a workload, whatever labels it carries (ADR-0053).
#
# A run's credential has one path: the MCP's get_credential, which mints through
# the admin API's MintJWTSVID and writes a ledger event. A run's entry carries
# one selector, innsegl:run:<run_id>, of a type no workload attestor emits, so
# no workload can match it. Until ADR-0053 run entries selected on three docker
# labels instead, and a container carrying a live run's labels and the Workload
# API socket was issued that run's SVIDs with no MCP and no record (I3). This
# script shows that path is closed on a running stack:
#
#   1. register a run exactly as register_agent does: one entry, the one run
#      selector, short TTL
#   2. register a CONTROL identity on the verify workload's own labels and uid,
#      outside the agent subtree
#   3. start the verify workload, which carries the run's three labels and
#      mounts the Workload API socket, and fetch its SVIDs until the control
#      identity appears
#   4. assert the run's SPIFFE ID is NOT among them
#   5. delete both entries
#
# Step 3's control is what keeps step 4 from passing vacuously. A stack that
# issues nothing, a socket that is not mounted, or an agent that has not yet
# synced the run's entry would all also "not issue the run's identity". The
# control is created after the run's entry, and the agent syncs entries as a
# whole, so once the control identity is served the run's entry is on the
# agent too, and it was not matched.
#
# Exit status is the verdict: 0 only if the control identity was issued, the
# run's was not, and both entries were cleaned up.

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_FILE="${SCRIPT_DIR}/../spire.yml"
readonly TRUST_DOMAIN="innsegl.dev"
readonly ADMIN_SOCKET="/run/spire/admin/api.sock"

# The run being registered. Overridable so the script can be pointed at a
# second run without editing it. The verify workload is started with these
# three values as its labels.
AGENT_TYPE="${INNSEGL_DEMO_AGENT_TYPE:-demo}"
TASK_ID="${INNSEGL_DEMO_TASK_ID:-rm-014}"
RUN_ID="${INNSEGL_DEMO_RUN_ID:-run-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
export INNSEGL_DEMO_AGENT_TYPE="${AGENT_TYPE}"
export INNSEGL_DEMO_TASK_ID="${TASK_ID}"
export INNSEGL_DEMO_RUN_ID="${RUN_ID}"

readonly EXPECTED_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT_TYPE}/${TASK_ID}/${RUN_ID}"
# Outside /agent/ on purpose: the control proves the workload attests, and
# must not itself be a run identity.
readonly CONTROL_ID="spiffe://${TRUST_DOMAIN}/verify/${RUN_ID}"

log()  { printf '\nverify: %s\n' "$*"; }
fail() { printf 'verify: FAIL: %s\n' "$*" >&2; exit 1; }

compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }
spire()   { compose exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath "${ADMIN_SOCKET}"; }

RUN_ENTRY=""
CONTROL_ENTRY=""
cleanup() {
  # Runs on every exit path, including failure: an orphaned entry is work for
  # RM-017's reaper, and this script should not manufacture any.
  local id
  for id in "${RUN_ENTRY}" "${CONTROL_ENTRY}"; do
    if [ -n "${id}" ]; then
      printf '\nverify: deleting entry %s\n' "${id}"
      spire entry delete -entryID "${id}" || true
    fi
  done
  RUN_ENTRY=""
  CONTROL_ENTRY=""
}
trap cleanup EXIT

agent_spiffe_id() { spire agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -n 1; }
entry_id() { sed -n 's/^Entry ID *: *//p' | head -n 1; }

main() {
  local parent out attempt

  parent="$(agent_spiffe_id || true)"
  [ -n "${parent}" ] || fail 'no attested agent — bring the stack up first'

  log "registering run ${RUN_ID} the way register_agent does"
  printf '  agent-type : %s\n  task-id    : %s\n  run-id     : %s\n  parent     : %s\n' \
    "${AGENT_TYPE}" "${TASK_ID}" "${RUN_ID}" "${parent}"

  # One selector, of a type no workload attestor emits (ADR-0053). TTL 300s:
  # doc 01 §1, "short TTL, created at registration, deleted at retirement".
  out="$(spire entry create \
    -parentID "${parent}" \
    -spiffeID "${EXPECTED_ID}" \
    -selector "innsegl:run:${RUN_ID}" \
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300)"
  printf '%s\n' "${out}"
  RUN_ENTRY="$(printf '%s\n' "${out}" | entry_id)"
  [ -n "${RUN_ENTRY}" ] || fail 'run entry create returned no entry ID'

  # The control: the verify workload's own labels and non-root uid, the
  # selector set a run entry carried before ADR-0053, under an identity that
  # is not a run's.
  log "registering the control identity ${CONTROL_ID}"
  out="$(spire entry create \
    -parentID "${parent}" \
    -spiffeID "${CONTROL_ID}" \
    -selector "docker:label:dev.innsegl.run-id:${RUN_ID}" \
    -selector "docker:label:dev.innsegl.agent-type:${AGENT_TYPE}" \
    -selector "docker:label:dev.innsegl.task-id:${TASK_ID}" \
    -selector "unix:uid:10001" \
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300)"
  printf '%s\n' "${out}"
  CONTROL_ENTRY="$(printf '%s\n' "${out}" | entry_id)"
  [ -n "${CONTROL_ENTRY}" ] || fail 'control entry create returned no entry ID'

  # Entries reach the agent through its cache, not synchronously. Poll for the
  # control rather than sleep on a guess.
  log 'fetching SVIDs from a workload carrying the run'"'"'s labels'
  attempt=0
  while :; do
    attempt=$((attempt + 1))
    if out="$(compose --profile verify run --rm --quiet-pull spire-verify-workload 2>&1)" \
      && printf '%s\n' "${out}" | grep -qF "${CONTROL_ID}"; then
      break
    fi
    [ "${attempt}" -lt 20 ] || { printf '%s\n' "${out}"; fail 'control identity not issued after 20 attempts'; }
    sleep 3
  done
  printf '%s\n' "${out}"
  log "control issued after ${attempt} attempt(s): the workload attests and the agent has synced"

  if printf '%s\n' "${out}" | grep -qF "${EXPECTED_ID}"; then
    fail "a workload carrying the run's labels was issued ${EXPECTED_ID}: the label path is open"
  fi
  log "not issued ${EXPECTED_ID}: a run's identity is reachable only through the MCP"

  cleanup
  log 'OK'
}

main "$@"

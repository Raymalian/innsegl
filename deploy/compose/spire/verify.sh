#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end proof that the reference SPIRE compose stack issues an SVID for an
# agent run (RM-014, #22).
#
# A compose file that has never been booted is a guess, and a stack that boots
# but has never issued an SVID has not been shown to do the one thing it is for.
# This script does the whole loop and prints what came back:
#
#   1. register a run: one entry, per-run selectors, short TTL
#   2. start a workload carrying those selectors and nothing else
#   3. fetch its SVID over the shared Workload API socket
#   4. assert the SPIFFE ID is spiffe://innsegl.dev/agent/{type}/{task}/{run}
#      — the grammar of doc 01 §1, a PROTECTED STRING
#   5. retire it: delete the entry, then show the fetch now fails
#
# Steps 1 and 5 are the shape RM-015 (#23) implements inside the MCP; this
# script is not that implementation and must not become it. It exists so the
# infrastructure can be checked on its own, before the MCP exists, and so
# TC-SPI has a stack it can be pointed at.
#
# Exit status is the verdict: 0 only if a correctly-formed SVID was issued and
# the entry was cleaned up.

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly COMPOSE_FILE="${SCRIPT_DIR}/../spire.yml"
readonly TRUST_DOMAIN="innsegl.dev"
readonly ADMIN_SOCKET="/run/spire/admin/api.sock"

# The run being registered. Overridable so the script can be pointed at a
# second run without editing it.
AGENT_TYPE="${INNSEGL_DEMO_AGENT_TYPE:-demo}"
TASK_ID="${INNSEGL_DEMO_TASK_ID:-rm-014}"
RUN_ID="${INNSEGL_DEMO_RUN_ID:-run-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
export INNSEGL_DEMO_AGENT_TYPE="${AGENT_TYPE}"
export INNSEGL_DEMO_TASK_ID="${TASK_ID}"
export INNSEGL_DEMO_RUN_ID="${RUN_ID}"

readonly EXPECTED_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT_TYPE}/${TASK_ID}/${RUN_ID}"

log()  { printf '\nverify: %s\n' "$*"; }
fail() { printf 'verify: FAIL: %s\n' "$*" >&2; exit 1; }

compose() { docker compose -f "${COMPOSE_FILE}" "$@"; }
spire()   { compose exec -T spire-server /opt/spire/bin/spire-server "$@" -socketPath "${ADMIN_SOCKET}"; }

ENTRY_ID=""
retire() {
  # Retirement deletes the SPIRE entry and nothing else (I4: retirement never
  # touches ledger content). Runs on every exit path, including failure —
  # an orphaned entry outliving its run is exactly what RM-017's reaper exists
  # to catch, and this script should not be manufacturing work for it.
  if [ -n "${ENTRY_ID}" ]; then
    printf '\nverify: retiring — deleting entry %s\n' "${ENTRY_ID}"
    spire entry delete -entryID "${ENTRY_ID}" || true
    ENTRY_ID=""
  fi
}
trap retire EXIT

agent_spiffe_id() { spire agent list 2>/dev/null | sed -n 's/^SPIFFE ID *: *//p' | head -n 1; }

main() {
  local parent workload_image image_config_digest out attempt

  parent="$(agent_spiffe_id || true)"
  [ -n "${parent}" ] || fail 'no attested agent — bring the stack up first'

  # The image the workload will run. spire-verify-workload and spire-agent
  # share the *spire-agent-image anchor in spire.yml, so reading it off the
  # running agent container gives exactly the value the docker workload
  # attestor will report — no second copy of a digest to drift.
  workload_image="$(docker inspect --format '{{.Image}}' innsegl-spire-agent)"
  image_config_digest="${workload_image}"

  log "registering run ${RUN_ID}"
  printf '  agent-type : %s\n  task-id    : %s\n  run-id     : %s\n  parent     : %s\n' \
    "${AGENT_TYPE}" "${TASK_ID}" "${RUN_ID}" "${parent}"

  # ------------------------------------------------------------------
  # The per-run selector set. Doc 04: "Weak selectors are the realistic
  # failure." Every one of these must match; SPIRE ANDs them.
  #
  #   docker:label:dev.innsegl.run-id     one entry ≡ one run (doc 01 §1).
  #     Without it, any container from the same image answers to any run.
  #   docker:label:dev.innsegl.agent-type
  #   docker:label:dev.innsegl.task-id    the other two path components, so a
  #     container cannot claim a run it was not started for even if the run-id
  #     leaks.
  #   docker:image_config_digest          the exact image, content-addressed.
  #     A run is registered against the image the operator approved, not
  #     against a tag that can move underneath it.
  #   unix:uid:10001                      a non-root workload. unix:uid:0 would
  #     select every container on the node and is the weak selector doc 04
  #     names; see agent.conf.
  #
  # TTL 300s. Doc 01 §1: "short TTL, created at registration, deleted at
  # retirement."
  # ------------------------------------------------------------------
  out="$(spire entry create \
    -parentID "${parent}" \
    -spiffeID "${EXPECTED_ID}" \
    -selector "docker:label:dev.innsegl.run-id:${RUN_ID}" \
    -selector "docker:label:dev.innsegl.agent-type:${AGENT_TYPE}" \
    -selector "docker:label:dev.innsegl.task-id:${TASK_ID}" \
    -selector "docker:image_config_digest:${image_config_digest}" \
    -selector "unix:uid:10001" \
    -x509SVIDTTL 300 \
    -jwtSVIDTTL 300)"
  printf '%s\n' "${out}"
  ENTRY_ID="$(printf '%s\n' "${out}" | sed -n 's/^Entry ID *: *//p' | head -n 1)"
  [ -n "${ENTRY_ID}" ] || fail 'entry create returned no entry ID'

  # Entries reach the agent through its cache, not synchronously. Poll rather
  # than sleep on a guess.
  log 'fetching the SVID from the workload'
  attempt=0
  while :; do
    attempt=$((attempt + 1))
    if out="$(compose --profile verify run --rm --quiet-pull spire-verify-workload 2>&1)"; then
      break
    fi
    [ "${attempt}" -lt 20 ] || { printf '%s\n' "${out}"; fail 'no SVID after 20 attempts'; }
    sleep 3
  done
  printf '%s\n' "${out}"

  printf '%s\n' "${out}" | grep -qF "${EXPECTED_ID}" \
    || fail "SVID did not carry ${EXPECTED_ID}"
  log "SVID SPIFFE ID matches spiffe://${TRUST_DOMAIN}/agent/{type}/{task}/{run}: ${EXPECTED_ID}"

  # Retirement, and the proof it took effect: the same workload, the same
  # selectors, no entry, no identity.
  #
  # MEASURED, NOT ASSUMED: SPIRE's refusal is *eventual*, not immediate. The
  # deleted entry has to fall out of the server's entry cache and then out of
  # the agent's, so for a few seconds after the delete the agent still serves
  # the SVID it already minted. Observed on this stack: the first fetch after
  # `entry delete` still succeeds; convergence follows within the cache
  # interval, and this loop reports how long it actually took.
  #
  # That is the SPIRE-layer behaviour, and it is exactly why IP §6.2 puts the
  # obligation somewhere else: "Test that retirement is effective immediately
  # (no cached-credential grace path *through the MCP*)". SPI-004's
  # "immediate credential refusal" is the MCP refusing, not SPIRE forgetting.
  # RM-015 (#23) owns that; this script measures the floor it has to sit on.
  retire
  log 'after retirement, waiting for the agent to converge on refusal'
  local started elapsed
  started="$(date +%s)"
  attempt=0
  while :; do
    attempt=$((attempt + 1))
    if ! out="$(compose --profile verify run --rm spire-verify-workload 2>&1)"; then
      elapsed=$(( $(date +%s) - started ))
      printf '%s\n' "${out}" | tail -n 3
      log "refused after ${elapsed}s (${attempt} attempt(s)) — SPIRE convergence is eventual, see the note in this script"
      break
    fi
    [ "${attempt}" -lt 20 ] || { printf '%s\n' "${out}"; fail 'still issuing an SVID for a deleted entry after 20 attempts'; }
    sleep 3
  done

  log 'OK'
}

main "$@"

#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# doc 05 §1's `demo-agent` row (RM-076, #109).
#
#   demo-agent | built | Scripted agent that registers, makes a scratch-repo
#                        commit, retires | This is the OPS-004 smoke test body
#
# It is an MCP client and nothing else. It speaks the shipped streamable-HTTP
# transport to the shipped server over a published port and calls the four
# IP §4 tools by their protected names — no in-process wiring, no privileged
# access to the ledger or to SPIRE, no second implementation of the two-phase
# protocol. What it can do is exactly what any agent holding the MCP's address
# can do, which is the property that makes it a demonstration rather than a
# fixture.
#
# WHY THIS IS A SHELL SCRIPT AND NOT A GO PROGRAM. doc 05 §3.1's one-verifier
# rule — "the verification BFF is the same Go binary as the CLI, never a second
# implementation" — is about the verifier. The opposite argument applies to a
# demonstration client: written in Go against internal/mcp it would share the
# tool names, the argument shapes and the transport with the server it is
# demonstrating, and would keep working through a wire-format change that broke
# every third-party client. curl and a JSON-RPC envelope share nothing with the
# server but the protocol, which is the thing being shown.
#
# `test/smoke`'s Go demo agent is the same run, driven through the official Go
# SDK, and asserted in far more detail — OPS-004 is the release gate and this
# is the operator-facing artifact. Two clients over one protocol is the point.
#
# RUN IT:
#   docker compose -f deploy/compose/innsegl.yml --profile demo run --rm demo-agent

set -eu

readonly TOOL_REGISTER="register_agent"
readonly TOOL_CREDENTIAL="get_credential"
readonly TOOL_SIGN="sign_commit"
readonly TOOL_RETIRE="retire_agent"

# internal/signing's AudienceSigstore. A credential minted for anything else is
# one Fulcio will not accept.
readonly AUDIENCE="sigstore"

MCP_URL="${INNSEGL_MCP_URL:-http://innsegl-mcp:8080}"
WORKSPACE="${INNSEGL_WORKSPACE:-/work}"
# doc 02 §5's host/org/name. It is an IDENTIFIER, not a path: the MCP resolves
# it beneath its own workspace root, and this script stages into the same tree
# through the shared volume.
REPO="${INNSEGL_DEMO_REPO:-github.com/innsegl-demo/scratch}"
AGENT_TYPE="${INNSEGL_DEMO_AGENT_TYPE:-demo}"
TASK_REF="${INNSEGL_DEMO_TASK_REF:-compose-demo}"
# A different key per run, so re-running the demo is a new run rather than an
# idempotent replay of the first one (IP §6.6).
RUN_TAG="${INNSEGL_DEMO_RUN_TAG:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

log()  { printf 'demo-agent: %s\n' "$*"; }
fail() { printf 'demo-agent: FAIL: %s\n' "$*" >&2; exit 1; }

SESSION=""

# SESSION_FILE is where rpc() leaves the Mcp-Session-Id it saw.
#
# IT IS A FILE AND NOT A VARIABLE FOR ONE REASON, and it is the kind of thing
# that costs an hour if it is not written down: every caller below invokes rpc
# inside a command substitution — `init="$(rpc ...)"` — and a command
# substitution runs in a SUBSHELL. An assignment to SESSION inside rpc would be
# discarded the moment rpc returned, and the session id would be silently empty
# on every request after initialize. Measured, on the first run of this script
# against the real server: "no Mcp-Session-Id on the initialize response",
# reported while the response in the same message plainly carried one.
SESSION_FILE="$(mktemp)"
cleanup() { rm -f "${SESSION_FILE}"; }
trap cleanup EXIT

# rpc METHOD PARAMS_JSON — posts one JSON-RPC message and prints the response
# payload. The transport answers a POST with a text/event-stream frame, so the
# payload is the `data:` line; internal/mcp/server_test.go's sseData does the
# same thing for the same reason.
rpc() {
  method="$1"
  params="$2"
  body="$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' "${method}" "${params}")"

  headers="$(mktemp)"
  raw="$(curl -sS --fail-with-body \
      --max-time 300 \
      --dump-header "${headers}" \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      ${SESSION:+-H "Mcp-Session-Id: ${SESSION}"} \
      --data-binary "${body}" \
      "${MCP_URL}")" || { rm -f "${headers}"; fail "POST ${method}: ${raw:-transport error}"; }

  sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d:[[:space:]]*//p' "${headers}" \
    | tr -d '\r' | head -n 1 > "${SESSION_FILE}"
  rm -f "${headers}"

  # Either an SSE frame or bare JSON, depending on what the server chose.
  payload="$(printf '%s' "${raw}" | sed -n 's/^data: //p' | head -n 1)"
  [ -n "${payload}" ] || payload="${raw}"
  printf '%s' "${payload}"
}

# notify METHOD — a JSON-RPC notification carries no id and gets no result.
notify() {
  curl -sS --fail-with-body --max-time 60 \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "Mcp-Session-Id: ${SESSION}" \
    --data-binary "$(printf '{"jsonrpc":"2.0","method":"%s"}' "$1")" \
    "${MCP_URL}" >/dev/null
}

# tool NAME ARGS_JSON — calls one tool and prints its structuredContent.
# A tool that returns isError is fatal: this is the happy path.
tool() {
  params="$(printf '{"name":"%s","arguments":%s}' "$1" "$2")"
  out="$(rpc "tools/call" "${params}")"
  if [ "$(printf '%s' "${out}" | jq -r '.error // empty')" != "" ]; then
    fail "$1: JSON-RPC error: $(printf '%s' "${out}" | jq -c '.error')"
  fi
  if [ "$(printf '%s' "${out}" | jq -r '.result.isError // false')" = "true" ]; then
    fail "$1 refused on the happy path: $(printf '%s' "${out}" | jq -c '.result.structuredContent')"
  fi
  printf '%s' "${out}" | jq -c '.result.structuredContent'
}

# tool_expect_refusal NAME ARGS_JSON — calls one tool and insists it refused.
tool_expect_refusal() {
  params="$(printf '{"name":"%s","arguments":%s}' "$1" "$2")"
  out="$(rpc "tools/call" "${params}")"
  if [ "$(printf '%s' "${out}" | jq -r '.result.isError // false')" = "true" ]; then
    printf '%s' "${out}" | jq -c '.result.structuredContent'
    return 0
  fi
  if [ "$(printf '%s' "${out}" | jq -r '.error // empty')" != "" ]; then
    printf '%s' "${out}" | jq -c '.error'
    return 0
  fi
  return 1
}

# git, with the host's configuration kept out of it. The MCP signs in this same
# tree, so a stray global gitconfig here is a difference between what was
# staged and what was signed.
demo_git() {
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_GLOBAL="${WORKTREE}/no-such-gitconfig" \
  git -C "${WORKTREE}" "$@"
}

# ---------------------------------------------------------------------------
# 0. Wait for the server. A demo that raced the MCP's start-up would fail with
#    a connection error rather than a verdict.
# ---------------------------------------------------------------------------
waited=0
until curl -sS --max-time 5 -o /dev/null \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        --data-binary '{"jsonrpc":"2.0","id":0,"method":"ping"}' "${MCP_URL}"; do
  waited=$((waited + 1))
  [ "${waited}" -lt 120 ] || fail "the MCP at ${MCP_URL} never answered"
  sleep 1
done

# ---------------------------------------------------------------------------
# 1. The MCP session.
# ---------------------------------------------------------------------------
init="$(rpc "initialize" '{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"innsegl-demo-agent","version":"v0"}}')"
SESSION="$(cat "${SESSION_FILE}")"
[ -n "${SESSION}" ] || fail "no Mcp-Session-Id on the initialize response: ${init}"
notify "notifications/initialized"
log "session with $(printf '%s' "${init}" | jq -r '.result.serverInfo.name // "?"') at ${MCP_URL}"

# ---------------------------------------------------------------------------
# 2. register_agent — I1: no identity without attestation.
# ---------------------------------------------------------------------------
registered="$(tool "${TOOL_REGISTER}" "$(jq -nc \
  --arg t "${AGENT_TYPE}" --arg k "${TASK_REF}" --arg i "demo-${RUN_TAG}-register" \
  '{agent_type:$t, task_id:$k, idempotency_key:$i}')")"
RUN_ID="$(printf '%s' "${registered}" | jq -r '.run_id')"
SPIFFE_ID="$(printf '%s' "${registered}" | jq -r '.spiffe_id')"
[ -n "${RUN_ID}" ] && [ "${RUN_ID}" != "null" ] || fail "register_agent returned no run_id: ${registered}"
log "registered ${SPIFFE_ID} (run ${RUN_ID}, expires $(printf '%s' "${registered}" | jq -r '.expires_at'))"

# ---------------------------------------------------------------------------
# 3. get_credential — a real JWT-SVID, for the one audience Fulcio accepts.
# ---------------------------------------------------------------------------
credential="$(tool "${TOOL_CREDENTIAL}" "$(jq -nc \
  --arg r "${RUN_ID}" --arg a "${AUDIENCE}" '{run_id:$r, audience:$a}')")"
JWT="$(printf '%s' "${credential}" | jq -r '.jwt_svid')"
case "${JWT}" in
  *.*.*) : ;;
  *) fail "get_credential returned something that is not a JWT" ;;
esac
log "holds a JWT-SVID for audience ${AUDIENCE} until $(printf '%s' "${credential}" | jq -r '.expires_at')"

# ---------------------------------------------------------------------------
# 4. The scratch repository, staged in the tree the MCP signs in.
# ---------------------------------------------------------------------------
WORKTREE="${WORKSPACE}/${REPO}"
mkdir -p "${WORKTREE}"
if [ ! -d "${WORKTREE}/.git" ]; then
  demo_git init -q -b main
fi
printf 'innsegl: the first thing an adopter'"'"'s agent ever wrote (%s)\n' "${RUN_TAG}" \
  > "${WORKTREE}/work.txt"
demo_git add work.txt
STAGED="$(demo_git write-tree)"
log "staged tree ${STAGED} in ${WORKTREE}"

# ---------------------------------------------------------------------------
# 5. sign_commit — I2: no signing without identity. The commit is signed by the
#    Fulcio this stack booted and logged in the Rekor this stack booted.
# ---------------------------------------------------------------------------
signed="$(tool "${TOOL_SIGN}" "$(jq -nc \
  --arg r "${RUN_ID}" --arg repo "${REPO}" --arg tree "${STAGED}" \
  --arg m "feat(demo): the first commit an adopter's agent signs" \
  --arg task "${TASK_REF}" --arg i "demo-${RUN_TAG}-sign" \
  '{run_id:$r, repo:$repo, staged_ref:$tree, message:$m, task_ref:$task, idempotency_key:$i}')")"
COMMIT="$(printf '%s' "${signed}" | jq -r '.commit_sha')"
log "signed commit ${COMMIT}"
log "  rekor entry $(printf '%s' "${signed}" | jq -r '.rekor_entry.uuid') at log index $(printf '%s' "${signed}" | jq -r '.rekor_entry.log_index')"
printf '%s' "${signed}" | jq -r '.trailers[] | "demo-agent:   trailer \(.key): \(.value)"'

HEAD="$(demo_git rev-parse HEAD)"
[ "${HEAD}" = "${COMMIT}" ] || fail "sign_commit returned ${COMMIT}; HEAD is ${HEAD}"

# ---------------------------------------------------------------------------
# 6. retire_agent, and the refusal that makes retirement mean something.
#
# IP §6.2: retirement is effective IMMEDIATELY at the MCP — SPIRE's own
# convergence is eventual. A demo that retired an identity and could still
# spend it would be demonstrating the opposite of the claim, so the refusal is
# part of the demonstration rather than an afterthought.
# ---------------------------------------------------------------------------
retired="$(tool "${TOOL_RETIRE}" "$(jq -nc --arg r "${RUN_ID}" '{run_id:$r}')")"
log "retired ${RUN_ID} at $(printf '%s' "${retired}" | jq -r '.retired_at')"

refusal="$(tool_expect_refusal "${TOOL_CREDENTIAL}" "$(jq -nc \
  --arg r "${RUN_ID}" --arg a "${AUDIENCE}" '{run_id:$r, audience:$a}')")" || \
  fail "get_credential SUCCEEDED after retire_agent. IP §6.2 makes retirement effective immediately, with no cached-credential grace path"
log "get_credential after retirement is refused: ${refusal}"

printf '\n'
log "done. Verify it from outside this deployment, with no route to the ledger:"
printf '\n    make innsegl-verify-commit COMMIT=%s\n\n' "${COMMIT}"

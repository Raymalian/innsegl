# Codex capture

## Purpose

`innsegl codex` launches experimental HTTP Responses capture for Codex CLI versions
that support the launch configuration and Responses request shape used here. The
launcher does not pin an exact CLI version; the gateway records the version from
the request User-Agent while recognizing the Codex Responses route and identity
metadata.
The gateway records function and custom tool calls and pairs results by call ID.
Custom tool scripts are stored as text; they are never evaluated by the recorder.
Tool outcomes are `unknown`: this wire format carries no authoritative error flag.
The exact backend Responses route also observes SSE when Content-Type is absent
or text/plain, as measured with the supported CLI. Forwarded bytes stay unchanged.

When both the client and core advertise linked-thread support, child sessions are
recorded as separate runs and linked only after a matching observed spawn call.
Session and thread values come from Codex's hook and request metadata. The core
checks them against the observed spawn and pending call; they are attribution
assertions rather than cryptographic credentials for isolating hostile processes
inside one enrolled installation.
The launcher selects HTTP/SSE by setting `supports_websockets=false`; the
installed Codex 0.163.0 API-key probe completed over HTTP without attempting a
WebSocket upgrade. The gateway also accepts Responses WebSocket upgrades on
the exact API and ChatGPT route paths. It observes complete upstream JSON
events, pairs client `response.create` tool outputs, reassembles bounded
text-message fragments, and marks known calls incomplete when a connection
ends before their complete event. The frame relay remains byte-for-byte. The
gateway records Codex tool-result and denied/aborted
tool-decision OTel events when OTel is enabled. The run page labels incomplete
Responses observations explicitly. Commit signing is an experimental opt-in
described below. Synthetic transport probes do not establish every provider
feature or auth-refresh behavior. Unsupported client versions are refused.

## Commands

With an upgraded, enrolled client and core:

```sh
innsegl status
innsegl codex
# Existing API-key authentication instead of ChatGPT login:
innsegl codex --api
# Forward ordinary Codex arguments after --:
innsegl codex -- exec --ephemeral 'Inspect this repository'
```

In the interactive session, review and trust the lifecycle commands in `/hooks`
before the first task. The launcher installs SessionStart, UserPromptSubmit and
SessionEnd commands for this invocation. Existing hook sources still apply.
A model request without a workspace statement receives HTTP 428 with setup guidance.
The launcher does not bypass hook trust. Its lifecycle commands use capture-only
mode: they do not install signing hooks or push branches at session end.

## Commit signing

Use `innsegl codex --sign-commits` to select the existing commit path for direct
shell calls. Both client and core must advertise structured signing support;
a capture-only core is refused during setup. The signing mode uses the same
version-independent CLI launch path and requires the gateway's structured-signing
capability.

This invocation sets `features.code_mode.enabled=true` and
`features.code_mode.direct_only_tool_namespaces=["functions"]`. That Codex
configuration is under development. It exposes shell commands directly so the
core can match the wire call ID, function-call kind and structured command to the hook.
The supported CLI emits flat `exec_command` names; explicit `functions` namespaces
are also recognized. Custom-script items cannot qualify as direct functions.
An arbitrary outer JavaScript script is not eligible for signing.

Review and trust the session and Bash hooks in `/hooks`. The signing lifecycle
links the repository through the existing Git hooks, and the tool hook adds the
call ID and existing per-command signing configuration. Codex requires
`permissionDecision: allow` alongside rewritten input. In this opt-in mode an
actual linked-repository commit rewrite carries that decision; it can approve
the whole shell invocation, including other commands in it. The Claude hook and
default capture mode do not gain that permission output.

The core still independently requires a complete pending call from the same
installation, recognized Codex harness and direct shell function, inside the existing
window. Ambiguous, foreign, completed, stale, truncated and unknown calls are
refused. Trailers, author checks, signing and transparency recording use the
existing path. No signature is authorized by the hook alone. An installed,
root-owned build matching the hooks is required; development builds do not
bypass that existing requirement.

## Settings

The launcher chooses a custom Responses provider on the client's loopback listener,
disables WebSockets, and enables lifecycle hooks for the invocation. It enables
Codex agents only when the enrolled client and core both advertise linked-thread
support, and then installs SubagentStart/SubagentStop lifecycle hooks. Older cores
continue to launch in root-only mode.
Configuration, profile, alternate provider and remote overrides are rejected.
Authentication remains with Codex. Provider credentials are forwarded transiently;
the journal strips authorization, account and gateway credentials.

The client first checks the core's capabilities over its enrolled channel.
An old core is an explicit setup error, not a reason to send this format to the
Messages upstream. Provider routing is fixed by exact request path.

## Files/volumes/containers

User Codex configuration and authentication files are not edited. Existing client
configuration, enrollment, statements and outbox are reused. Upgrade both binaries
before trying this command; installing only the launcher is insufficient.

## Exit codes and error classes

The child Codex exit status is preserved. An unavailable client, missing capability,
revoked enrollment or missing installed hook binary prevents launch. An unsupported
Codex version or routing override is a usage error.

## Tests

OAI-001–005 cover decoded request observations, results, SSE calls and root shape;
OAI-013/014/016/021 cover direct-call provenance, signing hooks, replay
ambiguity and commit observation. Signing launcher tests also require trusted
hook selection; replay tests preserve the original signing lifetime.
OAI-008/010 cover format and upstream separation; OAI-011 covers journal redaction.
OAI-020 is an opt-in installed-CLI HTTP probe against a synthetic provider through
the real gateway route; it asserts that the supported CLI does not attempt a
WebSocket upgrade. OAI-022 verifies complete and fragmented Responses WebSocket
events, connection-end observations, and the routed handshake. OAI-024 also verifies the fixed model-catalog routes for API
and ChatGPT endpoints. OAI-023–025 cover capability negotiation, provider
selection, missing lifecycle statements and explicit incomplete observations.
Run the probe with:

```sh
INNSEGL_CODEX_PROBE=1 go test ./internal/client -run TestOAI020 -v -count=1
```

This uses a temporary CLI home and synthetic key, not a deployed identity service
or a live model provider. Interrupted and malformed reply streams with a known
tool-call ID are stored as incomplete, input-free observations and shown as a
warning on the run page. An unknown tool-call ID remains unknown. Do not treat
capture as an attestation that every action or successful result has been witnessed.

## Decisions

[ADR-0085](../docs/adr/0085-capture-additional-wire-formats-through-adapters-in-the-one-gateway.md)
is proposed. ADR-0057 and ADR-0068 continue to govern forwarding and journaling.
The signing path also accepts bounded `call_` IDs, scoped to independently observed direct Codex calls; existing `toolu_` IDs retain their Claude path.

## Runbooks

If launch fails, check `innsegl status`, client enrollment and the versions of both
client and core. Restore revoked enrollment through the normal connect flow.
For HTTP 428, review the invocation's lifecycle hooks, trust them, and retry the
prompt. Do not reset networking or substitute guessed provider URLs.

Before relying on a deployment, verify a real root session and paired tool result
in its records. Live provider parity, lifecycle hook execution and deployment
verification are separate from the local synthetic transport probe.

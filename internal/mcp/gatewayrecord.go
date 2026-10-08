// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"

	"innsegl.dev/innsegl/internal/event"
)

// gatewayrecord.go — #381 (RM-236), E16: the in-process seam through which
// the gateway's own recorder (internal/gateway/record.go) appends one
// `tool_call` event for a tool_use/tool_result pair OBSERVED IN TRAFFIC
// (ADR-0057), reusing observe_tool_call's own configured service end to
// end — the same body store, the same digest construction (event.Digest
// over the exact body bytes), the same idempotency claim on (run_id,
// digest) (ADR-0017) — in process, the same pattern gateway.go's own
// RegisterRunForGateway and RetireRunForGateway already use for
// register_agent and retire_agent: a thin translation over a tool
// this package already owns and already tests, with no rule re-decided
// here.
//
// # What is NOT reused, and why that is one function's worth of difference
//
// observe_tool_call's own `observe` method (observe.go) is the WIRE tool:
// it authenticates a caller with a run token, accepts a run_id OR a
// session_id (registering a session on first sight), and answers doc 01
// §4's fixed four-argument reply. None of that applies to a call the
// gateway itself makes about a run its OWN identity guard already
// resolved and is not lying about — the same reason RegisterRunForGateway
// calls register_agent's tool body directly rather than authenticating to
// itself. So this file adds one new method, recordGatewayToolCall, beside
// observeService's existing store method rather than widening store's own
// signature or observeToolCallIn's own wire shape: the wire tool's
// contract (doc 01 §4, ADR-0048) is unmoved by this file, byte for byte.
//
// The one new fact this path can carry that the wire tool cannot —
// workspace_tree_hash (ADR-0061 member 3, schema 4) — is optional and is
// simply another member of the SAME ledger.Fields map store already builds;
// recordGatewayToolCall's own append is the smallest change that could
// carry it without touching store's signature or its callers.

// GatewayToolCallInput is what the gateway's own recorder hands this
// wrapper for one paired tool_use/tool_result observed in traffic.
type GatewayToolCallInput struct {
	// RunID is the run this tool call belongs to, already resolved by the
	// gateway's own identity guard (internal/gateway/identity.go). Required.
	RunID string
	// Tool names the agent tool that was invoked (ADR-0021), recorded as
	// the appended event's tool_name under the same grammar
	// observe_tool_call already holds its own `tool` argument to.
	// Required.
	Tool string
	// Body is the recorded call's own bytes — tool name, input, result,
	// is_error and any truncation markers, already assembled by the
	// caller (internal/gateway/record.go builds this shape; this file does
	// not interpret it further). Digested and stored exactly as
	// observe_tool_call already digests and stores one (observe.go), under
	// the SAME MaxObservedBodyBytes bound.
	Body []byte
	// WorkspaceTreeHash is the workspace snapshot taken when the request
	// carrying this tool call's result reached the gateway, before it was
	// forwarded (ADR-0061 member 3): the tree's state after the tool ran.
	// Empty means none — a snapshot failure, or no snapshotter configured,
	// records the tool call without it; this member is optional on
	// tool_call under schema 4 for exactly that reason.
	WorkspaceTreeHash string
}

// GatewayToolCallOutput mirrors observe_tool_call's own reply shape
// (observeToolCallOut) field for field, so a recorded reply produced by
// either path decodes identically.
type GatewayToolCallOutput struct {
	// Digest is doc 02 §1's hash form over Body, the same value the
	// appended tool_call carries as payload_digest.
	Digest string `json:"digest"`
	// Stored says the body is retained on the operator's volume. True on
	// every successful reply, for the same reason observeToolCallOut.Stored
	// always is: a call that could not store refuses instead.
	Stored bool `json:"stored"`
}

// RecordGatewayToolCall appends one `tool_call` event for a tool_use/
// tool_result pair the gateway observed directly in traffic (ADR-0057),
// through observe_tool_call's own configured service — in process, the
// same seam RegisterRunForGateway and RetireRunForGateway already use
// (gateway.go). It is idempotent on (run_id, digest), the same
// guarantee observe_tool_call gives an external caller (ADR-0017): a
// replay with the identical body appends nothing a second time.
//
// A deployment that has not configured observe_tool_call (no -observe-body-
// dir) cannot record from the gateway either — I3 admits no action without
// a record, and there is nowhere to write one — and this is refused exactly
// as observeToolCall's own bound-but-unconfigured case is (observe.go).
func RecordGatewayToolCall(ctx context.Context, in GatewayToolCallInput) (GatewayToolCallOutput, error) {
	svc := installed(&active.observe)
	if svc == nil {
		return GatewayToolCallOutput{}, Errorf(ClassInvariantViolation, in.RunID,
			"observe_tool_call is not configured; the gateway cannot record this tool call (I3)")
	}
	return svc.recordGatewayToolCall(ctx, in)
}

// recordGatewayToolCall is observe's own shape, minus the two gates that do
// not apply to an in-process caller: no run token (the gateway is not
// authenticating to itself over the wire it sits in front of), and no
// session_id path (the gateway's identity guard has already resolved a run
// id before this is ever called — RunIDFromContext, identity.go). Every
// remaining check is EXACTLY observe_tool_call's own: the tool name grammar
// (ADR-0021), the body bound (MaxObservedBodyBytes), the run's existence
// and retirement, and the body-before-event ordering I3's converse requires
// (see observe.go's own package doc comment).
func (c *observeService) recordGatewayToolCall(ctx context.Context, in GatewayToolCallInput) (GatewayToolCallOutput, error) {
	if err := event.ValidateIdentifier(in.RunID); err != nil {
		return GatewayToolCallOutput{}, Errorf(ClassRunNotFound, "",
			"%q is not a run id: %v", in.RunID, err)
	}

	toolName, err := observeToolName(in.RunID, in.Tool)
	if err != nil {
		return GatewayToolCallOutput{}, err
	}

	body, err := observeBody(in.RunID, string(in.Body))
	if err != nil {
		return GatewayToolCallOutput{}, err
	}
	digest := event.Digest(body)

	key := observeIdempotencyKey(in.RunID, digest)
	outcome, err := c.idem.Do(ctx, Call{
		Tool: string(ToolObserveToolCall),
		Key:  key,
		Params: map[string]any{
			"run_id":         in.RunID,
			"tool_name":      toolName,
			"payload_digest": digest,
		},
	}, func(ctx context.Context) (any, error) {
		return c.storeGatewayToolCall(ctx, in.RunID, toolName, digest, key, in.WorkspaceTreeHash, body)
	})
	if err != nil {
		return GatewayToolCallOutput{}, err
	}

	var out GatewayToolCallOutput
	if err := json.Unmarshal(outcome.Response, &out); err != nil {
		return GatewayToolCallOutput{}, Errorf(ClassInvariantViolation, in.RunID,
			"the recorded reply for this gateway-observed tool call is not a tool_call result: %w", err)
	}
	return out, nil
}

// storeGatewayToolCall resolves the run, writes the body, and appends the
// `tool_call`, carrying workspace_tree_hash when the gateway has one
// (ADR-0061 member 3). It is observe_tool_call's store too, with treeHash
// empty: one recorder, checked identically whichever path reached it.
func (c *observeService) storeGatewayToolCall(
	ctx context.Context, runID, toolName, digest, key, treeHash string, body []byte,
) (any, error) {
	if _, err := appendToolCall(ctx, c.runs, c.ledger, toolCall{
		runID: runID, toolName: toolName, digest: digest, key: key,
		treeHash: treeHash, body: body, bodyDir: c.bodyDir,
	}); err != nil {
		return nil, err
	}
	// Neither member is read back off the appended record, because neither is
	// the ledger's to assign: the digest is this path's own derivation from
	// bytes it holds, and `stored` is a fact about a file it has just written.
	return observeToolCallOut{Digest: digest, Stored: true}, nil
}

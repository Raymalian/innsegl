// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// agentmessage.go — RM-237 (#382), E16 (#358), ADR-0057 and ADR-0061: the
// in-process seam internal/gateway reaches through to record the brief an
// agent received and the text it produced, as one `agent_message` event
// each — the same seam gateway.go (RM-231, #376) already gives
// internal/gateway/registrar.go for register_agent and retire_agent,
// extended here for a
// type doc 01 names no wire-facing MCP tool for at all: ADR-0061 decision 2
// adds `agent_message` to doc 02 §3's schema, and doc 08 surface 4 (the
// eight-tool list, tools.go) is closed and unrelated — nothing here binds
// an sdk.Tool or grows that list, and internal/gateway never reaches this
// file over the wire.
//
// # Everything below is composed from work this package already has and
// already tests
//
//   - observe_tool_call's body volume (observe.go's observeWriteBody,
//     MaxObservedBodyBytes): the same directory, the same one-file-per-digest
//     layout, the same durability. A brief or a message is content this
//     tool's caller observed, exactly as a tool call's body is, and doc 05's
//     "stays on the operator's machine" applies to it identically.
//   - The idempotency store (idempotency.go) and the run directory
//     (runs.go's CredentialRuns, credentialRunIdentity,
//     credentialLedgerError): the same claim-then-act shape observe_tool_call
//     and record_event already use, so a replay of the same brief or the
//     same assistant turn appends nothing a second time (ADR-0017, IP §6.6).
//   - agentmessagekey.go's DeriveAgentMessageKey: the keyed grammar
//     ADR-0061 decision 2 requires for this ONE type's payload_digest, in
//     place of the plain sha256: grammar internal/event still gives every
//     other type.
//
// # What is genuinely new
//
// The event this file appends carries no body of its own in the envelope
// (doc 02 §2: "never diffs, code, or tool-call bodies" applies to
// agent_message exactly as it does to tool_call) — only `role` and a KEYED
// `payload_digest`. The plain digest that addresses the body on disk and the
// keyed digest that goes on the chain are DELIBERATELY two different
// values, computed over the same bytes: see (*agentMessageService).record.

// AgentMessageRoleBrief and AgentMessageRoleAssistant are ADR-0061's
// `agent_message.role` enum, doc 02 §3's errata for this type
// (internal/event's own validate.go holds the ledger to the identical two
// spellings — this is not a second definition, it is the vocabulary a
// caller on this side of the seam has to spell correctly for
// internal/event's checkAgentMessageRole to accept). Protected strings from
// the moment schema 4 ships, like every other enum value in doc 02 §3.
const (
	AgentMessageRoleBrief     = "brief"
	AgentMessageRoleAssistant = "assistant"
)

// agentMessageIdempotencyTool names this recording in the idempotency
// store's own Call.Tool and Record.Tool columns. It is a plain descriptive
// string, not one of tools.go's eight ToolName values — this recorder binds
// no sdk.Tool and is never reached over the wire, so it has no place in
// that closed, protected list (see this file's own doc comment).
const agentMessageIdempotencyTool = "agent_message"

const (
	// agentMessageKeyPrefix and agentMessageKeyDigestChars shape the derived
	// idempotency key, the same construction observeIdempotencyKey
	// (observe.go) already uses for tool_call, extended with `role`: a brief
	// and an assistant turn that happened to digest identically would
	// otherwise share observe_tool_call's own (run_id, digest) key, and the
	// two are different claims about the same run.
	agentMessageKeyPrefix      = "amsg-"
	agentMessageKeyDigestChars = 32
)

// AgentMessageLedger is the ledger surface this recorder needs. *ledger.Store
// satisfies it. Declared here rather than reused from ObserveToolCallLedger
// (observe.go) or RecordEventLedger (record_event.go) for the same reason
// each of those declares its own: a fake built against one must not be free
// to drift from what THIS file will actually be handed, even though all
// three read identically today.
type AgentMessageLedger interface {
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

var _ AgentMessageLedger = (*ledger.Store)(nil)

// AgentMessageRecorderConfig is what RecordAgentMessageForGateway runs on.
// Install it with ConfigureAgentMessageRecorder before internal/gateway
// calls in.
type AgentMessageRecorderConfig struct {
	// Runs resolves run_id to the run it names. Required — the same
	// interface get_credential and observe_tool_call already share, so this
	// recorder cannot disagree with either about what is a run.
	Runs CredentialRuns
	// Ledger is the append-only event store. Required: I3 admits no action
	// without a record, so a recorder with nowhere to write must not run.
	Ledger AgentMessageLedger
	// Idempotency records the reply of each keyed call (ADR-0017). Required:
	// without it, a caller that re-observes the same brief or the same
	// assistant turn — which a growing conversation's resent history makes
	// routine, not exceptional — would append a second event for it.
	Idempotency *IdempotencyStore
	// BodyDir is the local volume bodies are written under. Required, and
	// the SAME volume ConfigureObserveToolCall is given: one directory per
	// run, one file per digest, exactly observe.go's ported layout. A
	// deployment with nowhere to put bodies would append agent_message
	// events for a brief or a message it kept no evidence of, which is the
	// same failure ObserveToolCallConfig.BodyDir being required already
	// guards against for tool_call.
	BodyDir string
	// IdentitySecret is the per-deployment secret ADR-0061 decision 2 keys
	// agent_message.payload_digest from — the same secret
	// DeriveRunTokenSecret already derives the run-token secret from
	// (RM-212). Required: ADR-0061 gives this member no unkeyed fallback,
	// so a recorder with no secret to derive from has nothing it may
	// honestly write and must refuse configuration rather than accept one
	// it cannot use.
	IdentitySecret string
	// KeyID is the key id in effect for every agent_message this recorder
	// appends from now on (ADR-0061's 2026-09-28 amendment). Required, and
	// validated against doc 02 §5's identifier grammar at configuration
	// time — a malformed key id is refused here, once, rather than on every
	// call it would otherwise poison. Rotation is deploying a new value
	// here; an event already on the chain under an earlier key id stays
	// verifiable under that id forever (DeriveAgentMessageKey takes the id
	// as its own argument, not this recorder's current one).
	KeyID string
}

// agentMessageService is the configured recorder.
type agentMessageService struct {
	runs    CredentialRuns
	ledger  AgentMessageLedger
	idem    *IdempotencyStore
	bodyDir string
	keyID   string
	// key is DeriveAgentMessageKey's own result for keyID, computed once at
	// Configure time rather than on every call: IdentitySecret and KeyID are
	// both fixed for the lifetime of this configuration, so recomputing the
	// derivation per message would be the identical work for the identical
	// answer, on a call path ADR-0061 already asks to stay a witness rather
	// than a bottleneck.
	key string
}

// ConfigureAgentMessageRecorder installs the dependencies
// RecordAgentMessageForGateway runs on, and returns a function restoring
// whatever was installed before.
//
// Every dependency is required, unlike ObserveToolCallConfig.RunTokenSecret
// (observe.go's one optional field, an auth on/off switch an operator may
// deliberately leave unset). ADR-0061 gives agent_message.payload_digest no
// equivalent unkeyed path — ConfigureAgentMessageRecorder refuses a config
// that cannot key that digest rather than install one that would produce a
// value internal/event's own checkAgentMessagePayloadDigest can never
// accept.
func ConfigureAgentMessageRecorder(cfg AgentMessageRecorderConfig) (func(), error) {
	switch {
	case cfg.Runs == nil:
		return nil, agentMessageMisconfigured(
			"no run directory: an agent_message cannot say which run a brief or a message " +
				"belongs to, and doc 02 §2 requires a run_id on every event")
	case cfg.Ledger == nil:
		return nil, agentMessageMisconfigured(
			"no ledger: I3 admits no action without a record, so there is nothing to record into")
	case cfg.Idempotency == nil:
		return nil, agentMessageMisconfigured(
			"no idempotency store: a replay could append a second agent_message for one brief " +
				"or one assistant turn (IP §6.6, ADR-0017)")
	case cfg.BodyDir == "":
		return nil, agentMessageMisconfigured(
			"no body volume: the keyed digest in the chain is only checkable against a body " +
				"that was kept, and an agent_message for a body that was never stored is a " +
				"record of a message nobody has (I3)")
	}

	key, err := DeriveAgentMessageKey(cfg.IdentitySecret, cfg.KeyID)
	if err != nil {
		return nil, agentMessageMisconfigured("agent-message key: " + err.Error())
	}

	svc := &agentMessageService{
		runs:    cfg.Runs,
		ledger:  cfg.Ledger,
		idem:    cfg.Idempotency,
		bodyDir: cfg.BodyDir,
		keyID:   cfg.KeyID,
		key:     key,
	}
	return install(&active.agentMessage, svc), nil
}

// agentMessageMisconfigured names a dependency this recorder cannot run
// without.
func agentMessageMisconfigured(detail string) error {
	return Errorf(ClassInvariantViolation, "", "agent-message recorder configuration: %s", detail)
}

// agentMessageRecordOut is what one recorded call answers: the keyed digest
// that went on the chain, so a caller (or a test) can check the ledger and
// the returned value agree without re-deriving anything.
type agentMessageRecordOut struct {
	Digest string `json:"digest"`
}

// RecordAgentMessageForGateway reaches this recorder's configured path in
// process: the same idempotency claim (ADR-0017) and the same
// ledger-before-body-store-verification-on-read shape observe_tool_call
// already uses, adapted to the one type doc 01 names no wire-facing tool
// for. There is no sdk.CallToolRequest to build and no transport to cross —
// the whole point of calling this from inside the same process
// internal/gateway already sits in front of.
//
// role must be AgentMessageRoleBrief or AgentMessageRoleAssistant. body is
// the brief's or the message's own text, digested twice over: once plainly,
// to address it on the body volume exactly as observe_tool_call's own
// bodies are addressed, and once under this recorder's keyed derivation
// (agentmessagekey.go), which is the value that becomes the appended
// event's payload_digest. The two are never the same string, and the plain
// one is never written to the ledger for this type — see this file's own
// doc comment and ADR-0061 decision 2.
//
// Idempotent on (run_id, role, the plain digest of body): a caller that
// observes the identical brief or the identical assistant turn again for
// the same run appends nothing a second time and is handed back the digest
// the first call produced (ADR-0017, IP §6.6). Deriving the key from
// exactly that triple, rather than accepting one from the caller, is what
// makes replaying a growing, resent conversation history safe to call
// this repeatedly for.
//
// A misconfigured deployment (this file's own Configure never called) is
// refused exactly as a wire-facing tool would refuse a call reaching it
// unbound — an INVARIANT_VIOLATION (ADR-0016), never a panic reaching into
// internal/gateway's own request path.
//
// Every error answered here carries one of IP §4's classes, for the
// identical reason internal/mcp/gateway.go's own wrappers apply Classify on
// their own way out: calling this recorder's implementation directly is
// calling it WITHOUT server.go's own dispatch loop, which is what gives a
// wire-facing tool's unclassified failure a class before a caller ever sees
// it.
func RecordAgentMessageForGateway(ctx context.Context, runID, role string, body []byte) (string, error) {
	svc := installed(&active.agentMessage)
	if svc == nil {
		// Alert-level: a caller with nothing configured behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		return "", Errorf(ClassInvariantViolation, "",
			"the agent-message recorder is not configured; no brief or message can be recorded (I3)")
	}
	return svc.record(ctx, runID, role, body)
}

// record is the recorder: check the request, then act. Every pure check
// runs before any dependency is consulted or any state is touched — the
// same ordering observe.go's own observe method holds to, and for the
// identical reason: a malformed call costs one comparison and leaves no
// run behind it.
func (c *agentMessageService) record(ctx context.Context, runID, role string, body []byte) (string, error) {
	if err := event.ValidateIdentifier(runID); err != nil {
		return "", Errorf(ClassRunNotFound, "", "%q is not a run id: %v", runID, err)
	}
	if role != AgentMessageRoleBrief && role != AgentMessageRoleAssistant {
		return "", Errorf(ClassInvariantViolation, runID,
			"role must be %q or %q (ADR-0061 decision 2), not %q",
			AgentMessageRoleBrief, AgentMessageRoleAssistant, role)
	}
	switch {
	case len(body) == 0:
		return "", Errorf(ClassInvariantViolation, runID,
			"body is required: agent_message records a brief or a message that was observed, "+
				"and there is nothing to record without one")
	case len(body) > MaxObservedBodyBytes:
		return "", Errorf(ClassInvariantViolation, runID,
			"body is %d bytes and this recorder stores at most %d in one call; nothing was "+
				"stored and no event was appended", len(body), MaxObservedBodyBytes)
	}

	plainDigest := event.Digest(body)
	keyedDigest := c.keyedDigest(body)

	// The key is derived from the CHECKED role and the CHECKED body's own
	// digest, never the raw arguments: nothing that failed a gate above can
	// reach the store, and a caller naming the same run, role and content
	// again always resolves to the identical claim (ADR-0017).
	key := agentMessageIdempotencyKey(runID, role, plainDigest)
	outcome, err := c.idem.Do(ctx, Call{
		Tool: agentMessageIdempotencyTool,
		Key:  key,
		Params: map[string]any{
			"run_id":         runID,
			"role":           role,
			"payload_digest": keyedDigest,
		},
	}, func(ctx context.Context) (any, error) {
		return c.store(ctx, runID, role, plainDigest, keyedDigest, key, body)
	})
	if err != nil {
		return "", err
	}

	var out agentMessageRecordOut
	if err := json.Unmarshal(outcome.Response, &out); err != nil {
		return "", Errorf(ClassInvariantViolation, runID,
			"the recorded reply for this agent_message is not one this recorder produced: %w", err)
	}
	return out.Digest, nil
}

// keyedDigest computes ADR-0061 decision 2's keyed grammar over body, under
// this recorder's own derived key and key id. Computing this is the whole
// reason DeriveAgentMessageKey exists; nothing here re-derives it from the
// identity secret on the call path — that happened once, at Configure time
// (see agentMessageService.key's own doc comment).
func (c *agentMessageService) keyedDigest(body []byte) string {
	mac := hmac.New(sha256.New, []byte(c.key))
	mac.Write(body)
	return "hmac-sha256:" + c.keyID + ":" + hex.EncodeToString(mac.Sum(nil))
}

// store resolves the run, writes the body, and appends the agent_message —
// the identical three-step shape and ordering observe.go's own store holds
// to, and for the identical reason (see that function's doc comment on I3's
// converse): no record of an observation whose body was not kept.
func (c *agentMessageService) store(
	ctx context.Context, runID, role, plainDigest, keyedDigest, key string, body []byte,
) (any, error) {
	// The one run gate, scoped (#264). A context carrying no admin scope —
	// every call internal/gateway makes — admits everything; the scope is
	// checked for the deployments that DO enforce one.
	run, spiffeID, err := resolveRun(ctx, c.runs, runID, runGate{scoped: true})
	if err != nil {
		return nil, err
	}

	// The SAME body volume and layout observe_tool_call already writes to
	// and internal/api/runlog.go and internal/reconciler/writes.go already
	// read from (observe.go's own doc comment): one directory per run, one
	// file per PLAIN digest. Two calls whose bodies happen to be byte-
	// identical — a tool_call and an agent_message, or two agent_messages —
	// address the same file and overwrite it with the same bytes, which is
	// harmless by construction.
	if err := observeWriteBody(c.bodyDir, runID, plainDigest, body); err != nil {
		return nil, err
	}

	if _, err := c.ledger.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeAgentMessage,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: key,
		event.FieldRole:           role,
		// The KEYED grammar, never the plain sha256: form every other
		// payload_digest in doc 02 uses — ADR-0061 decision 2's whole point.
		event.FieldPayloadDigest: keyedDigest,
	}); err != nil {
		return nil, credentialLedgerError(runID, err)
	}

	return agentMessageRecordOut{Digest: keyedDigest}, nil
}

// agentMessageIdempotencyKey derives the key for one recorded call:
// (run_id, role, the plain digest of the checked body). Half the digest,
// for the identical reason observeIdempotencyKey (observe.go) halves its
// own: doc 02 §2 bounds an idempotency_key at 128 bytes, and 128 bits of a
// SHA-256 is not a collision this store will ever meet — if one were ever
// met, the store fingerprints the whole request (Call.Params) and refuses
// the second call as a DIFFERENT request rather than silently answering it
// with the first one's reply. The truncation can therefore cost a refusal
// and never a wrong answer.
func agentMessageIdempotencyKey(runID, role, digest string) string {
	hex := strings.TrimPrefix(digest, event.HashPrefix)
	if len(hex) > agentMessageKeyDigestChars {
		hex = hex[:agentMessageKeyDigestChars]
	}
	return agentMessageKeyPrefix + runID + "-" + role + "-" + hex
}

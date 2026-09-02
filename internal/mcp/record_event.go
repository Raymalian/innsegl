// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// record_event — RM-024 (#32), IP §4:
//
//	record_event(run_id, event_type, payload_digest, idempotency_key) →
//	    {event_id, chain_position}.
//
// # E4 is the substance of this file
//
// "The ledger stores references and hashes … never diffs, code, or tool-call
// bodies." RM-007 made that mechanical in the schema — the member set of every
// event type is closed, every member that exists is bounded, and the whole
// canonical record is capped at 4 KB — and this tool is the one surface an
// agent can reach that schema through. So the job here is narrow and exact:
// do not become the hole. Every value this file puts into an event is either
// server-decided (`schema_version`, `event_type`, `source`, `spiffe_id`) or a
// caller value that has been held to a grammar first (`run_id`,
// `payload_digest`, `tool_name`, `idempotency_key`). No caller string reaches
// the ledger unchecked, and a refusal never quotes the rejected value back —
// an error message is a second place a payload could come to rest.
//
// # Which event type a caller may record, and why it is not their choice
//
// ADR-0021 is the decision. In one paragraph: doc 02 §3 has eleven event
// types and this tool writes exactly one of them, `tool_call`. Six are
// unreachable by construction — ADR-0004 forbids `idempotency_key` on
// `credential_issued` and `run_retired`, which this tool always carries, and
// doc 02 §3 attributes `commit_intent_expired`, `run_expired`,
// `unattributed_signature_detected`, `ledger_drift_detected` and
// `segment_sealed` to the reconciler, the reaper and the sealer rather than to
// an MCP tool call. The remaining four all require members IP §4 gives this
// tool no argument for, and each is another tool's output: forging a
// `run_registered` claims an identity SPIRE never issued (I1), and forging a
// `commit_recorded` claims a Rekor entry that may not exist (I2, I5) — which
// is precisely the state the reconciler raises `ledger_drift_detected` about.
//
// So `event_type` does not select the event type. It names the AGENT TOOL that
// was invoked, and is recorded as doc 02 §3's `tool_name`: "One agent tool
// invocation; body only as `payload_digest`." IP §4's four arguments map one
// for one onto the four caller-supplied members of a `tool_call` event —
// run_id, tool_name, payload_digest, idempotency_key — and everything else in
// the envelope is the ledger's to assign. A caller that passes one of the
// eleven event_type spellings is refused, loudly, with a message saying what
// the argument is for; recording it as a tool named after an event type would
// put a confusable string in an append-only chain forever.
//
// # Where the run is checked, and why it is inside the claim
//
// The run must exist and must not be retired (MCP-009, MCP-010), and that
// check happens INSIDE the idempotency claim rather than before it. IP §6.6
// requires a replay to return the original result; a run that has since been
// retired must not turn a completed call's replay into a refusal, and the
// stored reply is only consulted for a claim that was taken. Argument
// validation stays outside the claim: it is a property of the request alone,
// so a malformed call costs nothing and reserves no key.

func init() { RegisterTool(ToolRecordEvent, bindRecordEvent) }

// recordEventIn is IP §4's argument list, verbatim. The member names are part
// of the tool contract MCP-003 pins.
type recordEventIn struct {
	// RunID is the run whose action is being recorded.
	RunID string `json:"run_id"`
	// EventType names the agent tool that was invoked; it becomes the event's
	// `tool_name` (doc 02 §3). See the note above and ADR-0021 for why this
	// argument does not select an event_type.
	EventType string `json:"event_type"`
	// PayloadDigest is the digest of the out-of-band body, or empty when the
	// invocation had none. doc 02 §2: "Present iff a payload exists"; doc 02
	// §1 admits no empty-string placeholder, so empty means the member is
	// omitted rather than written blank.
	PayloadDigest string `json:"payload_digest"`
	// IdempotencyKey makes the call repeatable (IP §6.6, ADR-0004, which
	// requires the key on a `tool_call` appended by an MCP tool).
	IdempotencyKey string `json:"idempotency_key"`
}

// recordEventOut is IP §4's result shape, verbatim: the two members the ledger
// assigned, read back off the record it appended rather than predicted.
type recordEventOut struct {
	EventID       string `json:"event_id"`
	ChainPosition int64  `json:"chain_position"`
}

// RecordEventLedger is the ledger surface this tool needs. *ledger.Store
// satisfies it.
type RecordEventLedger interface {
	// Append writes one event; an append whose idempotency_key has already
	// been used returns the original event and writes nothing (LED-008).
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// The production implementation must satisfy the interface above, or the fakes
// the contract tests use would be free to drift from what this tool will
// actually be handed.
var _ RecordEventLedger = (*ledger.Store)(nil)

// RecordEventConfig is what record_event runs on. Install it with
// ConfigureRecordEvent before serving.
type RecordEventConfig struct {
	// Runs resolves run_id to the run it names. Required.
	//
	// It is get_credential's interface and not a second one: RM-023 wrote that
	// "the run directory is shared with the other four tools, and a second
	// definition of what is a run is a second thing that can disagree about
	// retirement", and this is one of those four tools.
	Runs CredentialRuns
	// Ledger is the append-only event store. Required — I3 admits no action
	// without a record, so a tool with nowhere to write must not run.
	Ledger RecordEventLedger
	// Idempotency records the reply of each keyed call (ADR-0017). Required.
	Idempotency *IdempotencyStore
}

// recordEventService is the configured tool.
type recordEventService struct {
	runs   CredentialRuns
	ledger RecordEventLedger
	idem   *IdempotencyStore
}

// recordEventState holds the installed configuration.
//
// It is package state because ADR-0016 §5 fixes the seam: a tool file
// registers its own binder from its own init and the binder receives only the
// *Server, so there is nowhere else for a tool's dependencies to be handed in
// without a file every tool author would have to edit.
var (
	recordEventMu     sync.RWMutex
	recordEventActive *recordEventService
)

// ConfigureRecordEvent installs the dependencies record_event runs on and
// returns a function restoring whatever was installed before.
//
// A configuration missing a dependency is refused here rather than at the
// first call: each one is a gate, and an operator finds out at start-up rather
// than when an agent does.
func ConfigureRecordEvent(cfg RecordEventConfig) (func(), error) {
	switch {
	case cfg.Runs == nil:
		return nil, recordEventMisconfigured(
			"no run directory: record_event cannot say which run acted, and doc 02 §2 requires a tool_call to name one")
	case cfg.Ledger == nil:
		return nil, recordEventMisconfigured(
			"no ledger: I3 admits no action without a record, so there is nothing to record into")
	case cfg.Idempotency == nil:
		return nil, recordEventMisconfigured(
			"no idempotency store: a replay could append a second event (IP §6.6, ADR-0017)")
	}

	svc := &recordEventService{runs: cfg.Runs, ledger: cfg.Ledger, idem: cfg.Idempotency}
	recordEventMu.Lock()
	defer recordEventMu.Unlock()
	previous := recordEventActive
	recordEventActive = svc
	return func() {
		recordEventMu.Lock()
		defer recordEventMu.Unlock()
		recordEventActive = previous
	}, nil
}

// recordEventMisconfigured names a dependency the tool cannot run without.
func recordEventMisconfigured(detail string) error {
	return Errorf(ClassInvariantViolation, "", "record_event configuration: %s", detail)
}

func bindRecordEvent(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolRecordEvent),
		Description: "Record one agent tool invocation against a run, by reference only. " +
			"event_type names the agent tool that was invoked; payload_digest is the " +
			"sha256: digest of its body, which is never sent and never stored. " +
			"The same idempotency_key always names the same event.",
	}, recordEvent)
}

func recordEvent(ctx context.Context, _ *sdk.CallToolRequest, in recordEventIn) (recordEventOut, error) {
	recordEventMu.RLock()
	svc := recordEventActive
	recordEventMu.RUnlock()
	if svc == nil {
		// Alert-level: a bound tool with no dependencies behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		return recordEventOut{}, Errorf(ClassInvariantViolation, "",
			"record_event is bound but not configured; no action can be recorded (I3)")
	}
	return svc.record(ctx, in)
}

// record is the tool: check the request, claim the key, then act.
func (c *recordEventService) record(ctx context.Context, in recordEventIn) (recordEventOut, error) {
	// Gate 1 — a run id that cannot name a run names no run. Checked before
	// any dependency is consulted, so a malformed id costs nothing and
	// reserves no idempotency key.
	if err := event.ValidateIdentifier(in.RunID); err != nil {
		return recordEventOut{}, Errorf(ClassRunNotFound, "",
			"%q is not a run id: %v", in.RunID, err)
	}

	// Gate 2 — the tool that was invoked (ADR-0021).
	toolName, err := recordEventToolName(in.RunID, in.EventType)
	if err != nil {
		return recordEventOut{}, err
	}

	// Gate 3 — a digest, or nothing. IP E4 lives here.
	digest, err := recordEventPayloadDigest(in.RunID, in.PayloadDigest)
	if err != nil {
		return recordEventOut{}, err
	}

	// The key is validated by the store, which owns doc 02 §2's bound on it
	// and refuses a key naming a different request (ADR-0017 §3).
	//
	// The fingerprint is taken over the CHECKED values, not the raw arguments:
	// nothing that failed a gate above can reach the store, so a rejected body
	// is never even digested.
	outcome, err := c.idem.Do(ctx, Call{
		Tool: string(ToolRecordEvent),
		Key:  in.IdempotencyKey,
		Params: map[string]any{
			"run_id":         in.RunID,
			"tool_name":      toolName,
			"payload_digest": digest,
		},
	}, func(ctx context.Context) (any, error) {
		return c.append(ctx, in.RunID, toolName, digest, in.IdempotencyKey)
	})
	if err != nil {
		return recordEventOut{}, err
	}

	var out recordEventOut
	if err := json.Unmarshal(outcome.Response, &out); err != nil {
		return recordEventOut{}, Errorf(ClassInvariantViolation, in.RunID,
			"the recorded reply for idempotency_key %q is not a record_event result: %w",
			in.IdempotencyKey, err)
	}
	return out, nil
}

// append resolves the run and writes the `tool_call` event.
//
// The run checks are here, inside the claim, on purpose: see the note at the
// top of this file. A replay of a completed call never reaches them.
func (c *recordEventService) append(ctx context.Context, runID, toolName, digest, key string) (any, error) {
	// The ledger is what knows the difference between a run that was retired
	// and one that never existed; SPIRE cannot tell them apart, because both
	// have no entry.
	run, found, err := c.runs.CredentialRun(ctx, runID)
	if err != nil {
		return nil, credentialLedgerError(runID, err)
	}
	if !found {
		return nil, Errorf(ClassRunNotFound, runID, "no run %q", runID)
	}
	if run.Retired() {
		// I4: retirement removes the identity, never the record. A retired
		// run's history stays readable; it stops growing.
		return nil, Errorf(ClassRunAlreadyRetired, runID,
			"run %q was retired at %s; retirement is effective immediately (IP §6.2)",
			runID, event.NewTimestamp(run.RetiredAt))
	}

	// The directory's answer is checked, not trusted — the same check
	// get_credential makes, from the one implementation of it, so that an
	// event cannot be attributed to another run's identity (I2).
	spiffeID, _, err := credentialRunIdentity(runID, run)
	if err != nil {
		return nil, err
	}

	record, err := c.ledger.Append(ctx, recordEventBody(run.RunID, spiffeID, toolName, digest, key))
	if err != nil {
		return nil, credentialLedgerError(runID, err)
	}
	return recordEventResult(runID, record)
}

// recordEventBody is the `tool_call` event of doc 02 §3.
//
// Every member name here is a protected string. `source` is `mcp` because an
// MCP tool call appended it, and `idempotency_key` is present because ADR-0004
// requires it on exactly the events whose originating tool accepts one.
// event_id, ts, chain_position, prev_event_hash and event_hash are the
// ledger's to assign and are deliberately absent.
//
// There is no member for a body, and that is the point: doc 02 §3's row is
// "body only as `payload_digest`", so a payload has nowhere to live even if a
// caller found a way to supply one (IP E4).
func recordEventBody(runID, spiffeID, toolName, digest, key string) event.Fields {
	body := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: key,
		event.FieldToolName:       toolName,
	}
	// doc 02 §2: payload_digest is "Present iff a payload exists", and doc 02
	// §1 makes absent and empty distinct states with only absent allowed for a
	// missing value. So a tool call with no body omits the member rather than
	// writing it blank.
	if digest != "" {
		body[event.FieldPayloadDigest] = digest
	}
	return body
}

// recordEventResult reads IP §4's reply off the record the ledger appended.
//
// Both members are the ledger's to assign, so both are read back rather than
// predicted — a reply naming a position the chain does not hold would be a
// claim about the ledger made by something that is not the ledger. A record
// missing either is a defect, not a result to paper over with a zero value.
func recordEventResult(runID string, record event.Fields) (recordEventOut, error) {
	rawID, present := record[event.FieldEventID]
	if !present {
		return recordEventOut{}, Errorf(ClassInvariantViolation, runID,
			"the appended record carries no %s", event.FieldEventID)
	}
	id, ok := rawID.(string)
	if !ok {
		return recordEventOut{}, Errorf(ClassInvariantViolation, runID,
			"the appended record's %s is %T, want a string", event.FieldEventID, rawID)
	}
	if err := event.ValidateEventID(id); err != nil {
		return recordEventOut{}, Errorf(ClassInvariantViolation, runID,
			"the appended record's %s is not one: %v", event.FieldEventID, err)
	}

	rawPosition, present := record[event.FieldChainPosition]
	if !present {
		return recordEventOut{}, Errorf(ClassInvariantViolation, runID,
			"the appended record carries no %s", event.FieldChainPosition)
	}
	position, ok := rawPosition.(int64)
	if !ok {
		return recordEventOut{}, Errorf(ClassInvariantViolation, runID,
			"the appended record's %s is %T, want an integer", event.FieldChainPosition, rawPosition)
	}
	return recordEventOut{EventID: id, ChainPosition: position}, nil
}

// recordEventToolNamePattern is the grammar a tool name is held to.
//
// doc 02 gives `tool_name` no grammar — only the reference bound that
// validate.go's own E4 note relies on ("A body cannot be smuggled into
// `reason` or `tool_name`, because a reference is at most
// MaxReferenceBytes"). This tool narrows that bound to a name: it starts
// alphanumeric and continues in the punctuation tool names actually use, which
// covers `bash`, `Read`, `str_replace_editor`, `mcp__codemap__search_symbol`,
// `github.com/acme/api` and `slack:post`, and admits no whitespace, no line
// break, no quote and no brace.
//
// That is what turns "a reference is short" into "a reference is a name": a
// JSON body, a diff hunk, a shell transcript and a sentence of prose are all
// refused on their punctuation whatever their length, and invalid UTF-8 is
// refused because a replacement rune is outside the class. Narrowing what the
// schema accepts is always safe; widening it would not be.
var recordEventToolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+_-]*$`)

// recordEventToolName holds IP §4's `event_type` argument to what it names: an
// agent tool (ADR-0021).
//
// The last refusal is the one that matters most. Any of doc 02 §3's eleven
// `event_type` spellings is what a caller reading IP §4 literally would send,
// and it must fail loudly with a message saying what the argument is for —
// recording it would put a string confusable with an event type into an
// append-only chain forever.
//
// No refusal quotes the rejected value back except that one, whose value is by
// definition one of eleven known strings: an error message is a second place a
// payload could come to rest.
func recordEventToolName(runID, s string) (string, error) {
	reject := func(format string, args ...any) (string, error) {
		return "", Errorf(ClassInvariantViolation, runID, format, args...)
	}
	switch {
	case s == "":
		return reject("event_type is required: it names the agent tool that was invoked, " +
			"which doc 02 §3 records as the tool_call event's tool_name (ADR-0021)")
	case len(s) > event.MaxReferenceBytes:
		// Length first, so a body is refused on its size without a regexp
		// being run over it.
		return reject("event_type is %d bytes and names a tool, which doc 02 §3 bounds at %d; "+
			"the ledger stores references, never payloads (IP E4)", len(s), event.MaxReferenceBytes)
	case !recordEventToolNamePattern.MatchString(s):
		return reject("event_type does not name a tool: it must match %s. "+
			"The ledger stores references, never payloads (IP E4)",
			recordEventToolNamePattern)
	case event.IsEventType(s):
		return reject("event_type %q spells one of doc 02 §3's event types. record_event writes "+
			"exactly one event type, %s, and the caller does not choose it; the argument names "+
			"the agent tool that was invoked and is recorded as that event's %s (ADR-0021)",
			s, event.EventTypeToolCall, event.FieldToolName)
	}
	return s, nil
}

// recordEventPayloadDigest holds IP §4's `payload_digest` to doc 02 §1's hash
// form, or reads it as absent.
//
// This is IP E4 at its narrowest point. `sha256:` followed by exactly 64
// lowercase hex digits is a shape no body has, so a caller cannot hand the
// ledger a diff, a transcript or a file by putting it where a digest belongs.
// The refusal does not echo what was supplied: an error message is a second
// place a payload could come to rest.
func recordEventPayloadDigest(runID, s string) (string, error) {
	if s == "" {
		// doc 02 §2: "Present iff a payload exists." An invocation with no
		// out-of-band body has no digest, and doc 02 §1 forbids writing an
		// empty-string placeholder for one.
		return "", nil
	}
	if err := event.ValidateDigest(s); err != nil {
		return "", Errorf(ClassInvariantViolation, runID,
			"payload_digest must be %s followed by 64 lowercase hex digits (doc 02 §1); "+
				"%d bytes of something else were supplied. The ledger stores references and "+
				"hashes, never payloads (IP E4): digest the body and send the digest",
			event.HashPrefix, len(s))
	}
	return s, nil
}

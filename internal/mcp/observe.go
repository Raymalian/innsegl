// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// observe_tool_call — RM-127 (#206), E11. doc 01 §4:
//
//	observe_tool_call(run_id, tool, body, run_token?) → {digest, stored}.
//	Digests the body, stores it under the MCP's local volume, and appends the
//	`tool_call` event.
//
// # What this replaces, and why it is here rather than in a shim
//
// The reference harness hook did three things for every observed tool call: it
// digested the body with `shasum -a 256`, it called record_event with that
// digest, and it wrote the body to `$LOG/<run_id>/<hex>.json`. The middle step
// is the only one that needed the MCP. The other two are pure derivation that
// every other harness would have to reimplement IDENTICALLY — the same hash
// construction over the same bytes, the same directory layout — and get
// byte-exactly right, because internal/api/runlog.go and
// internal/reconciler/writes.go both re-derive the path from a digest in the
// chain and check the file against it. A layout that disagreed by one
// character would produce a run whose every body reads as missing.
//
// So the layout below is PORTED, not designed: one directory per run, one file
// per digest, the digest's 64 hex characters as the file name, `.json` as the
// extension, the body's own bytes as the content. The two readers named above
// are the specification of that, and this file is the second writer of it.
//
// # Bodies are written and never sent
//
// A tool-call body carries file contents, commands and paths — it is the most
// sensitive data this system touches, and doc 05 is explicit that it stays on
// the operator's machine. The MCP is a local container, so it may WRITE one,
// to a volume the operator controls, and it may send it nowhere: not to the
// ledger (doc 02 §3 gives `tool_call` no member for a body, and IP E4 makes
// that mechanical), not to the idempotency store (which fingerprints a request
// and never stores it), and not back in a reply or an error message. This file
// dials nothing and imports nothing that could; MCP-046 holds it to that
// against the source as well as against one execution.
//
// # Idempotent on (run_id, digest)
//
// doc 01 §4 fixes the pair. A replay returns the stored result and appends
// nothing, because a second event would be a second claim about one observed
// call: a reader counting `tool_call` events would see an agent that did the
// work twice. The tool takes no idempotency_key — ADR-0004 makes the argument
// required exactly where IP §4 gives one, and IP §4 gives this tool none —
// while ADR-0004 equally requires the KEY on the `tool_call` it appends. Both
// are satisfied by deriving the key from the pair: see observeIdempotencyKey.
//
// # The run token, and the refusal that is not an oracle
//
// get_credential's, unchanged and from the one implementation of it. A run_id
// is public — it is in the `Agent-Run` trailer of every commit — so an unknown
// run and a bad token are answered with the same class and the same message,
// before the run directory is consulted at all. Answered differently, this
// tool would tell an unauthenticated caller which run ids are real.
//
// # No `tool_call` for a body that was not kept
//
// I3 admits no action without a record. The converse is what the order in
// store below holds: no record of an observation that was not actually kept. A
// `tool_call` naming a digest whose body failed to reach the volume would be a
// permanent entry pointing at evidence that never existed, and the reconciler
// would later count it as an uncorroborated write. So the body is written
// first, and the event only after the write returned.
//
// The reverse leftover is harmless and deliberate: a body whose append then
// failed is an unreferenced file that no reader opens and the retention window
// collects.

func init() { RegisterTool(ToolObserveToolCall, bindObserveToolCall) }

// MaxObservedBodyBytes bounds one body.
//
// A body is one harness event: a command and its output, or a file write. The
// bound exists because this tool is the one surface that commits the
// operator's DISK on a caller's say-so — the ledger's own 4 KB cap does not
// apply, since the body never enters the chain — and an unbounded body is an
// unbounded write. A mebibyte is larger than any harness event the reference
// shim forwarded and small enough that a run's retained bodies stay a
// manageable directory.
//
// It is not a protected surface: doc 08 protects tool names, error classes and
// the schema, not limits, so a deployment that needs another number changes
// this one in a minor release.
const MaxObservedBodyBytes = 1 << 20

const (
	// observeBodyExt is the ported file extension. The two readers join it
	// onto the digest's hex, so it is part of the layout and not a preference.
	observeBodyExt = ".json"

	// observeDirMode and observeBodyMode keep the bodies to the operator.
	// These files are the most sensitive data in the system; every innsegl
	// service that reads them runs as the same uid and mounts the volume
	// read-only, so nothing needs group or world access to work.
	observeDirMode  os.FileMode = 0o700
	observeBodyMode os.FileMode = 0o600

	// observeKeyPrefix and observeKeyDigestChars shape the derived idempotency
	// key. See observeIdempotencyKey.
	observeKeyPrefix      = "otc-"
	observeKeyDigestChars = 32
)

// observeToolCallIn is doc 01 §4's argument list, verbatim.
type observeToolCallIn struct {
	// RunID is the run whose tool call was observed.
	RunID string `json:"run_id"`
	// Tool names the agent tool that was invoked. It becomes doc 02 §3's
	// `tool_name`, under the grammar record_event holds its own argument to
	// (ADR-0021).
	Tool string `json:"tool"`
	// Body is the observed call's own bytes. It is digested, written to the
	// volume, and sent nowhere.
	Body string `json:"body"`
	// RunToken is the secret register_agent handed this run once. Required
	// when the deployment configures RunTokenSecret; ignored when it does not.
	RunToken string `json:"run_token,omitempty"`
}

// observeToolCallOut is doc 01 §4's result shape, verbatim.
type observeToolCallOut struct {
	// Digest is doc 02 §1's hash form over the body's own bytes, and is the
	// value the appended `tool_call` carries as `payload_digest`. It is what
	// lets a reader check the stored body later without trusting this process.
	Digest string `json:"digest"`
	// Stored says the body is retained on the operator's volume.
	//
	// It is true on every reply, because a call that could not store refuses
	// rather than returning false (see the note on I3's converse above). The
	// member exists so that a shim can ASSERT the property instead of assuming
	// it, and so a future deployment that deliberately retains nothing has a
	// place to say so without a change to this tool's result shape.
	Stored bool `json:"stored"`
}

// ObserveToolCallLedger is the ledger surface this tool needs. *ledger.Store
// satisfies it.
type ObserveToolCallLedger interface {
	// Append writes one event; an append whose idempotency_key has already
	// been used returns the original event and writes nothing (LED-008).
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// The production implementation must satisfy the interface above, or the fakes
// the contract tests use would be free to drift from what this tool will
// actually be handed.
var _ ObserveToolCallLedger = (*ledger.Store)(nil)

// ObserveToolCallConfig is what observe_tool_call runs on. Install it with
// ConfigureObserveToolCall before serving.
type ObserveToolCallConfig struct {
	// Runs resolves run_id to the run it names. Required.
	//
	// It is get_credential's interface and not a second one: a second
	// definition of what is a run is a second thing that can disagree about
	// retirement.
	Runs CredentialRuns
	// Ledger is the append-only event store. Required — I3 admits no action
	// without a record, so a tool with nowhere to write must not run.
	Ledger ObserveToolCallLedger
	// Idempotency records the reply of each keyed call (ADR-0017). Required:
	// without it a replay would append a second event.
	Idempotency *IdempotencyStore
	// BodyDir is the local volume bodies are written under. Required.
	//
	// Required rather than optional on purpose. A deployment with nowhere to
	// put bodies would append `tool_call` events for observations it kept
	// nothing of, and an operator would discover that only when a run's
	// activity log turned out to be a list of digests with no evidence behind
	// any of them. Refusing at start-up is the same reading of I3 that makes
	// Ledger required.
	BodyDir string
	// RunTokenSecret keys the per-run token this tool requires (runtoken.go).
	// Empty means no authentication, exactly as it does for get_credential:
	// enabling it is an operator's decision, not a silent break of every
	// running shim.
	RunTokenSecret string
}

// observeService is the configured tool.
type observeService struct {
	runs      CredentialRuns
	ledger    ObserveToolCallLedger
	idem      *IdempotencyStore
	bodyDir   string
	runSecret string
}

// observeActive holds the installed configuration.
//
// Package state because ADR-0016 §5 fixes the seam: a tool file registers its
// own binder from its own init and the binder receives only the *Server, so
// there is nowhere else for a tool's dependencies to be handed in without a
// file every tool author would have to edit.
var (
	observeMu     sync.RWMutex
	observeActive *observeService
)

// ConfigureObserveToolCall installs the dependencies observe_tool_call runs on
// and returns a function restoring whatever was installed before.
//
// A configuration missing a dependency is refused here rather than at the
// first call: each one is a gate, and an operator finds out at start-up rather
// than when a harness does.
func ConfigureObserveToolCall(cfg ObserveToolCallConfig) (func(), error) {
	switch {
	case cfg.Runs == nil:
		return nil, observeMisconfigured(
			"no run directory: observe_tool_call cannot say which run was observed, and doc 02 §2 requires a tool_call to name one")
	case cfg.Ledger == nil:
		return nil, observeMisconfigured(
			"no ledger: I3 admits no action without a record, so there is nothing to record into")
	case cfg.Idempotency == nil:
		return nil, observeMisconfigured(
			"no idempotency store: a replay could append a second event for one observed call (IP §6.6, ADR-0017)")
	case cfg.BodyDir == "":
		return nil, observeMisconfigured(
			"no body volume: the digest in the chain is only checkable against a body that was kept, " +
				"and a tool_call for a body that was never stored is a record of an observation nobody has (I3)")
	}

	svc := &observeService{
		runs:      cfg.Runs,
		ledger:    cfg.Ledger,
		idem:      cfg.Idempotency,
		bodyDir:   cfg.BodyDir,
		runSecret: cfg.RunTokenSecret,
	}
	observeMu.Lock()
	defer observeMu.Unlock()
	previous := observeActive
	observeActive = svc
	return func() {
		observeMu.Lock()
		defer observeMu.Unlock()
		observeActive = previous
	}, nil
}

// observeMisconfigured names a dependency the tool cannot run without.
func observeMisconfigured(detail string) error {
	return Errorf(ClassInvariantViolation, "", "observe_tool_call configuration: %s", detail)
}

func bindObserveToolCall(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolObserveToolCall),
		Description: "Record one tool call a harness OBSERVED, with its body. " +
			"The body is digested and written to the MCP's own local volume and is " +
			"never sent anywhere; the event carries the digest and the tool name only. " +
			"The same body observed twice for one run is one event.",
	}, observeToolCall)
}

func observeToolCall(ctx context.Context, _ *sdk.CallToolRequest, in observeToolCallIn) (observeToolCallOut, error) {
	observeMu.RLock()
	svc := observeActive
	observeMu.RUnlock()
	if svc == nil {
		// Alert-level: a bound tool with no dependencies behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		return observeToolCallOut{}, Errorf(ClassInvariantViolation, "",
			"observe_tool_call is bound but not configured; nothing can be observed (I3)")
	}
	return svc.observe(ctx, in)
}

// observe is the tool: check the request, claim the key, then act.
func (c *observeService) observe(ctx context.Context, in observeToolCallIn) (observeToolCallOut, error) {
	// Gate 1 — a run id that cannot name a run names no run. Checked before
	// any dependency is consulted, so a malformed id costs nothing and
	// reserves no idempotency key.
	if err := event.ValidateIdentifier(in.RunID); err != nil {
		return observeToolCallOut{}, Errorf(ClassRunNotFound, "",
			"%q is not a run id: %v", in.RunID, err)
	}

	// Gate 2 — the run's own token, when the deployment requires one.
	//
	// Before every gate that touches state, and answered identically to an
	// unknown run: get_credential's rule, its message and its class. The gates
	// below report whether a run exists and whether it was retired, which for
	// an unauthenticated caller would be an oracle over every run id read off
	// a commit trailer.
	if c.runSecret != "" && !RunTokenValid(c.runSecret, in.RunID, in.RunToken) {
		return observeToolCallOut{}, Errorf(ClassRunNotFound, in.RunID,
			"no run %q", in.RunID)
	}

	// Gate 3 — the tool that was invoked (ADR-0021).
	toolName, err := observeToolName(in.RunID, in.Tool)
	if err != nil {
		return observeToolCallOut{}, err
	}

	// Gate 4 — a body, inside the bound. Checked before it is digested and
	// before the volume is touched, so an oversized body costs one length
	// comparison and writes nothing.
	body, err := observeBody(in.RunID, in.Body)
	if err != nil {
		return observeToolCallOut{}, err
	}
	digest := event.Digest(body)

	// The key is derived from the pair doc 01 §4 makes this tool idempotent
	// on, and the fingerprint is taken over the CHECKED values: nothing that
	// failed a gate above can reach the store, and the body itself never does
	// — only its digest, which is the whole point of the split.
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
		return c.store(ctx, in.RunID, toolName, digest, key, body)
	})
	if err != nil {
		return observeToolCallOut{}, err
	}

	var out observeToolCallOut
	if err := json.Unmarshal(outcome.Response, &out); err != nil {
		return observeToolCallOut{}, Errorf(ClassInvariantViolation, in.RunID,
			"the recorded reply for this observation is not an observe_tool_call result: %w", err)
	}
	return out, nil
}

// store resolves the run, writes the body, and appends the `tool_call`.
//
// The run checks are here, inside the claim, for record_event's reason: IP §6.6
// requires a replay to return the original result, so a run retired after a
// completed call must not turn that call's replay into a refusal. A replay
// never reaches them.
//
// The order of the last two steps is the substance of this function. See the
// note on I3's converse at the top of the file.
func (c *observeService) store(ctx context.Context, runID, toolName, digest, key string, body []byte) (any, error) {
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
	// observation cannot be attributed to another run's identity (I2).
	spiffeID, _, err := credentialRunIdentity(runID, run)
	if err != nil {
		return nil, err
	}

	if err := observeWriteBody(c.bodyDir, runID, digest, body); err != nil {
		return nil, err
	}

	if _, err := c.ledger.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: key,
		event.FieldToolName:       toolName,
		// doc 02 §2: "Present iff a payload exists." One always does here —
		// this tool refuses an empty body — so unlike record_event there is no
		// absent case to spell.
		event.FieldPayloadDigest: digest,
	}); err != nil {
		return nil, credentialLedgerError(runID, err)
	}

	// Neither member is read back off the appended record, because neither is
	// the ledger's to assign: the digest is this tool's own derivation from
	// bytes it holds, and `stored` is a fact about a file it has just written.
	return observeToolCallOut{Digest: digest, Stored: true}, nil
}

// observeWriteBody writes one body to the operator's volume, at the path the
// reference shim wrote it to and the two readers read it from.
//
// The write is not in place: the bytes go to a temporary name in the run's own
// directory and are moved onto the final one. A body is read back by digest
// and a torn file fails that check, so a reader would render a half-written
// body as ALTERED — which internal/api/runlog.go shows as a loud red state.
// An interrupted write must leave no file at all rather than a file that
// accuses the agent.
//
// The temporary name is derived from the digest rather than randomised,
// because the caller holds the idempotency claim on (run_id, digest) for the
// whole of this function: no second call for the same body is running, so
// there is no second writer for the name to collide with.
func observeWriteBody(dir, runID, digest string, body []byte) error {
	// filepath.Base as well as the grammar the run id already passed. This is
	// the line that turns a caller's string into a path, and the guard belongs
	// beside it rather than forty lines away where a future caller can miss it
	// — the same reason both readers keep one here.
	runDir := filepath.Join(dir, filepath.Base(runID))
	if err := os.MkdirAll(runDir, observeDirMode); err != nil {
		return observeVolumeError(runID, "could not create the run's directory on the body volume", err)
	}

	hex := strings.TrimPrefix(digest, event.HashPrefix)
	final := filepath.Join(runDir, hex+observeBodyExt)
	partial := filepath.Join(runDir, "."+hex+".part")
	if err := os.WriteFile(partial, body, observeBodyMode); err != nil {
		return observeVolumeError(runID, "could not write the body to the body volume", err)
	}
	if err := os.Rename(partial, final); err != nil {
		// Leaving the partial file behind would put a copy of a body on the
		// operator's disk under a name no reader opens and no retention sweep
		// matches. The removal's own failure is not reported over it: the
		// caller's problem is the write that did not land.
		_ = os.Remove(partial)
		return observeVolumeError(runID, "could not move the body into place on the body volume", err)
	}
	return nil
}

// observeVolumeError reports a body that could not be kept.
//
// LEDGER_UNAVAILABLE, and retryable. The class vocabulary of IP §4 is closed
// and protected (doc 08 §3), so there is no BODY_STORE_UNAVAILABLE to add and
// this tool does not invent one. Of the eleven, this is the one that gives the
// caller the instruction the situation actually warrants — the volume is a
// dependency outside the request, a mount that came back or a disk that was
// freed clears it, and a retry is what should happen. It is the same reading
// ADR-0017 records for the idempotency store's own in-flight case.
//
// The underlying error is carried for errors.Is and named in the message, so
// an operator sees ENOSPC or ENOTDIR rather than a shrug. The body is not:
// an error message is a second place a payload could come to rest.
func observeVolumeError(runID, what string, cause error) error {
	return classifyAs(ClassLedgerUnavailable, runID,
		what+": "+cause.Error()+". No tool_call was appended: a record of an observation "+
			"whose body was not kept would point at evidence that never existed (I3)",
		true, "the body volume", cause)
}

// observeIdempotencyKey derives the key for one observation.
//
// doc 01 §4 gives this tool no idempotency_key argument and makes it idempotent
// on (run_id, digest); ADR-0004 requires the KEY on the `tool_call` it appends.
// Deriving it from exactly that pair satisfies both, and it takes the choice
// away from the caller — which matters, because a caller choosing keys could
// record one observation twice under two keys, or two observations once under
// one.
//
// Half the digest, because doc 02 §2 bounds the key at 128 bytes and a run id
// may be 63. 128 bits of a SHA-256 is not a collision anyone will meet; if one
// were ever met, the store fingerprints the whole request and would refuse the
// second call as DUPLICATE_REQUEST rather than answer it with the first one's
// reply. The truncation can therefore cost a refusal and never a wrong answer.
func observeIdempotencyKey(runID, digest string) string {
	hex := strings.TrimPrefix(digest, event.HashPrefix)
	if len(hex) > observeKeyDigestChars {
		hex = hex[:observeKeyDigestChars]
	}
	return observeKeyPrefix + runID + "-" + hex
}

// observeToolName holds doc 01 §4's `tool` argument to what it names: an agent
// tool (ADR-0021).
//
// The grammar is record_event's, from the one definition of it, because the two
// arguments become the same member of the same event type — a name this tool
// accepted and record_event refused would be one `tool_name` with two meanings.
// The messages differ because the arguments are spelled differently in IP §4,
// and a refusal that named the wrong argument would send a shim author looking
// in the wrong place.
//
// No refusal quotes the rejected value back except the event-type one, whose
// value is by definition one of eleven known strings: an error message is a
// second place a payload could come to rest.
func observeToolName(runID, s string) (string, error) {
	reject := func(format string, args ...any) (string, error) {
		return "", Errorf(ClassInvariantViolation, runID, format, args...)
	}
	switch {
	case s == "":
		return reject("tool is required: it names the agent tool that was observed, " +
			"which doc 02 §3 records as the tool_call event's tool_name (ADR-0021)")
	case len(s) > event.MaxReferenceBytes:
		// Length first, so a body is refused on its size without a regexp
		// being run over it.
		return reject("tool is %d bytes and names a tool, which doc 02 §3 bounds at %d; "+
			"the ledger stores references, never payloads (IP E4). The body goes in body, "+
			"and stays on this machine", len(s), event.MaxReferenceBytes)
	case !recordEventToolNamePattern.MatchString(s):
		return reject("tool does not name a tool: it must match %s. The ledger stores "+
			"references, never payloads (IP E4). The body goes in body, and stays on this machine",
			recordEventToolNamePattern)
	case event.IsEventType(s):
		return reject("tool %q spells one of doc 02 §3's event types. observe_tool_call writes "+
			"exactly one event type, %s, and the caller does not choose it; the argument names "+
			"the agent tool that was observed and is recorded as that event's %s (ADR-0021)",
			s, event.EventTypeToolCall, event.FieldToolName)
	}
	return s, nil
}

// observeBody holds the body to what one call may commit of the operator's
// disk.
//
// An empty body is refused rather than stored: there is no observation without
// one, and a file of zero bytes under the digest of zero bytes would be
// evidence of nothing, indistinguishable for every run that sent one.
//
// Neither refusal echoes the body, not even its beginning.
func observeBody(runID, s string) ([]byte, error) {
	switch {
	case s == "":
		return nil, Errorf(ClassInvariantViolation, runID,
			"body is required: observe_tool_call records a call that was observed, and the "+
				"body is what is observed of it. A call with no body is record_event's")
	case len(s) > MaxObservedBodyBytes:
		return nil, Errorf(ClassInvariantViolation, runID,
			"body is %d bytes and this tool stores at most %d in one call; "+
				"nothing was stored and no event was appended", len(s), MaxObservedBodyBytes)
	}
	return []byte(s), nil
}

// SPDX-License-Identifier: Apache-2.0

package gateway

// record.go — #381 (RM-236), E16: pairs each observed tool_use (from the
// model's reply, keyed by tool_use id, on the agent's run — sse.go's own
// ToolUse, seen as its content_block_stop event arrives) with its
// tool_result, once the NEXT request of that agent carries it, and records
// ONE `tool_call` event per pair through the MCP's own observe_tool_call
// service, in process (internal/mcp/gatewayrecord.go), attaching
// workspace_tree_hash from the Snapshotter (snapshot.go) when its trigger
// fires for that request.
//
// # Witness, never a gate (ADR-0057)
//
// Nothing in this file may ever refuse or delay forwarding a request or a
// reply. ToolCallRecorder.OnToolUseContext runs on the same path that is
// streaming a reply's bytes to the caller (sse.go's own doc comment on
// ToolUseObserver: "a slow observer is a slow gateway"), and
// ToolCallRecordGuard.Check runs before Proxy.ServeHTTP forwards a request
// at all — so the one thing this file does synchronously on either path is
// bookkeeping in memory (claiming a pending tool_use, matching a result
// against it) plus, deliberately, taking the workspace snapshot itself:
// ADR-0060 decision 5 and ADR-0061 member 3 both fix that timing —
// "before that request was forwarded" — as part of what the snapshot
// MEANS, not as an implementation detail this file is free to move. What
// is never synchronous is the actual RECORDING: the call into
// mcp.RecordGatewayToolCall, which round-trips to Postgres and the body
// store, always runs on a goroutine of its own (sse.go's own advice: "A
// consumer that might block hands off to a channel or a goroutine of its
// own rather than doing the work here"). A recording failure is never
// returned to a caller of this package; it is handed to
// ToolCallRecorderConfig.OnRecordFailure and counted (FailedRecordings),
// which is this file's whole answer to "logged loudly and counted".
//
// # Only new turns
//
// Claude Code resends the whole conversation history on every request
// (facts.go's own doc comment), so the SAME tool_result reaches this
// gateway again on every later request of the same agent. This file tracks
// "already handled" with nothing more than the pending map itself: once a
// tool_use is claimed — paired with its result, or evicted — it is removed
// from pending, and a later request naming the same tool_use id again
// finds nothing pending for it and records nothing a second time. No
// separate "already recorded" set is needed or kept.
//
// # Bounded memory for pending tool_uses
//
// A harness-asserted run id and tool_use id are not authenticated
// (identity.go's own DefaultIdentityCacheSize gives the identical
// reasoning for its own cache), so the pending map is capped
// (DefaultMaxPendingToolCalls) and evicts the OLDEST entry, FIFO, to make
// room for a new one. An evicted entry is not silently dropped: it is
// recorded immediately, asynchronously, input-only, with that fact stated
// in the body it is recorded under (buildToolCallBody's own Note field,
// set whenever it is handed a nil result).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
)

const (
	// DefaultMaxPendingToolCalls bounds ToolCallRecorder's own in-memory
	// table of tool_use blocks seen but not yet paired with a result — the
	// same reasoning identity.go's DefaultIdentityCacheSize gives its own
	// bounded cache, applied to a different table.
	DefaultMaxPendingToolCalls = 8192

	// recordTimeout bounds one asynchronous recording attempt (the call
	// into mcp.RecordGatewayToolCall): a round trip to Postgres and the
	// body store that must not run forever just because nothing is left to
	// forward it alongside any more.
	recordTimeout = 30 * time.Second
)

// ---------------------------------------------------------------------------
// The pending table: tool_use blocks seen, not yet paired with a result.
// ---------------------------------------------------------------------------

type pendingKey struct {
	runID     string
	toolUseID string
}

// pendingCall is what OnToolUseContext captured about one tool_use block,
// held until its result arrives or it is evicted.
type pendingCall struct {
	tool       string
	input      json.RawMessage
	truncated  bool
	observedAt time.Time
}

// claimedPair is one tool_use matched against the tool_result the next
// request of that run carried for it.
type claimedPair struct {
	toolUseID string
	call      pendingCall
	result    observedToolResult
}

// snapshotWitness is the seam *Snapshotter.Snapshot satisfies (snapshot.go),
// declared here rather than depending on that concrete type directly, so
// this package's own tests can exercise how ToolCallRecorder uses a
// snapshot's outcome without standing up a real git repository for every
// case. *Snapshotter implements this with no change of its own.
type snapshotWitness interface {
	Snapshot(ctx context.Context, workingDirectory string) SnapshotOutcome
}

var _ snapshotWitness = (*Snapshotter)(nil)

// ToolCallRecorderConfig configures a ToolCallRecorder.
type ToolCallRecorderConfig struct {
	// Snapshots takes the per-request workspace witness (snapshot.go). Nil
	// means this recorder never attaches workspace_tree_hash — every
	// tool_call it records carries none, exactly as a snapshot failure
	// already leaves it (ADR-0061 member 3 is optional for precisely this
	// case). A production caller passes a *Snapshotter directly; it
	// satisfies this interface with no wrapping.
	//
	// LEAVE THIS FIELD UNSET rather than assigning a nil *Snapshotter to
	// it: an interface holding a typed nil pointer is not itself nil, and
	// snapshotIfTriggered's own nil check would then call Snapshot on a
	// nil receiver instead of skipping it. A caller building this from an
	// optional *Snapshotter variable sets the field only inside the `if
	// snapshotter != nil` branch that built it (cmd/innsegl/gateway.go's
	// own openIdentityStack does exactly this).
	Snapshots snapshotWitness
	// Trigger decides whether a request's tool results are worth
	// snapshotting (snapshot.go's own SnapshotTrigger). Required whenever
	// Snapshots is set; ignored otherwise.
	Trigger *SnapshotTrigger
	// MaxPending bounds the pending table. Zero or less means
	// DefaultMaxPendingToolCalls.
	MaxPending int
	// OnRecordFailure, when set, is called for every recording attempt
	// this recorder could not complete — an evicted pending tool_use
	// included. Nil means failures are only counted (FailedRecordings),
	// never reported anywhere; a production caller passes a function that
	// logs loudly (cmd/innsegl/gateway.go's own openIdentityStack does).
	OnRecordFailure func(error)

	// record is the seam this package's own tests replace, so they need
	// neither a real ledger nor a real body store to exercise the pairing,
	// eviction and snapshot-triggering logic above it. Unexported: a
	// caller outside this package always gets the real thing.
	record func(ctx context.Context, in mcp.GatewayToolCallInput) (mcp.GatewayToolCallOutput, error)
	// onRecorded, when set, is called once after each asynchronous
	// recording attempt this recorder fires finishes — success or
	// failure. It is a test seam for synchronizing on a goroutine this
	// package deliberately fires and forgets (this file's own doc
	// comment, "witness, never a gate"), the same shape
	// idempotency.go's own onEnteringWait already uses for the identical
	// reason. Nil on every production path.
	onRecorded func()
}

// ToolCallRecorder is #381's own witness: it holds tool_use blocks pending
// their result (OnToolUseContext, fed from Proxy.ToolUse) and pairs each
// one against a tool_result the next request of that run carries
// (HandleResults, fed from ToolCallRecordGuard.Check), recording one
// `tool_call` per NEW pair. Safe for concurrent use.
type ToolCallRecorder struct {
	mu      sync.Mutex
	pending map[pendingKey]pendingCall
	order   []pendingKey // oldest first; kept in sync with pending's keys.
	max     int

	snapshots snapshotWitness
	trigger   *SnapshotTrigger

	record     func(ctx context.Context, in mcp.GatewayToolCallInput) (mcp.GatewayToolCallOutput, error)
	onFailure  func(error)
	onRecorded func()

	failed atomic.Int64
}

// NewToolCallRecorder builds a ToolCallRecorder from cfg.
func NewToolCallRecorder(cfg ToolCallRecorderConfig) *ToolCallRecorder {
	maxPending := cfg.MaxPending
	if maxPending <= 0 {
		maxPending = DefaultMaxPendingToolCalls
	}
	record := cfg.record
	if record == nil {
		record = mcp.RecordGatewayToolCall
	}
	onFailure := cfg.OnRecordFailure
	if onFailure == nil {
		onFailure = func(error) {}
	}
	return &ToolCallRecorder{
		pending:    make(map[pendingKey]pendingCall),
		max:        maxPending,
		snapshots:  cfg.Snapshots,
		trigger:    cfg.Trigger,
		record:     record,
		onFailure:  onFailure,
		onRecorded: cfg.onRecorded,
	}
}

// PendingCount reports how many tool_use blocks are currently held pending
// a result. Exported for a caller's own observability; this package makes
// no claim about it beyond what it counts.
func (r *ToolCallRecorder) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// FailedRecordings is how many recording attempts — an ordinary pair or an
// evicted, input-only one — this recorder could not complete, over its
// whole lifetime. The "counted" half of this issue's "logged loudly and
// counted" requirement; OnRecordFailure is the "logged loudly" half.
func (r *ToolCallRecorder) FailedRecordings() int64 { return r.failed.Load() }

// ---------------------------------------------------------------------------
// The response side: ToolUseObserver / ContextToolUseObserver.
// ---------------------------------------------------------------------------

var (
	_ ToolUseObserver        = (*ToolCallRecorder)(nil)
	_ ContextToolUseObserver = (*ToolCallRecorder)(nil)
)

// OnToolUse implements the plain ToolUseObserver interface. Without a
// request context there is no run id to key a pending entry on, so this
// does nothing — proxy.go's boundToolUseObserver always prefers
// OnToolUseContext when the observer implements it, which every production
// wiring of this recorder does (see CombineToolUseObservers).
func (r *ToolCallRecorder) OnToolUse(ToolUse) {}

// OnToolUseContext implements ContextToolUseObserver: every tool_use block
// a reply streams, spawn tool_use blocks included — ADR-0057 records every
// tool call, and SpawnRecorder recording its own thing off the same block
// is not a reason for this recorder to skip it — is held pending its
// result, keyed by (run id, tool_use id).
func (r *ToolCallRecorder) OnToolUseContext(ctx context.Context, t ToolUse) {
	if t.ID == "" {
		// Nothing to key a later result on. Observed, per sse.go's own
		// contract, only when a harness sends no id at all — never for an
		// ordinary tool_use, which always carries one.
		return
	}
	runID, ok := RunIDFromContext(ctx)
	if !ok || runID == "" {
		return
	}
	//nolint:contextcheck // deliberate: addPending's own eventual recording (on eviction) uses
	// a detached, bounded context of its own rather than ctx -- see recordAsync's own doc
	// comment for why a request/reply's context must never be allowed to cut a recording short.
	r.addPending(runID, t)
}

// addPending records t as pending, evicting and recording the oldest
// pending entry (input-only) first if the table is already at its cap.
func (r *ToolCallRecorder) addPending(runID string, t ToolUse) {
	key := pendingKey{runID: runID, toolUseID: t.ID}
	call := pendingCall{
		tool:       t.Name,
		input:      append(json.RawMessage(nil), t.Input...),
		truncated:  t.Truncated,
		observedAt: time.Now(),
	}

	var evictedKey pendingKey
	var evictedCall pendingCall
	evicted := false

	r.mu.Lock()
	if _, exists := r.pending[key]; !exists {
		if r.max > 0 && len(r.order) >= r.max && len(r.order) > 0 {
			evictedKey = r.order[0]
			r.order = r.order[1:]
			if c, ok := r.pending[evictedKey]; ok {
				evictedCall, evicted = c, true
			}
			delete(r.pending, evictedKey)
		}
		r.order = append(r.order, key)
	}
	r.pending[key] = call
	r.mu.Unlock()

	if evicted {
		go r.recordAsync(evictedKey.runID, evictedKey.toolUseID, evictedCall, nil, "")
	}
}

// ---------------------------------------------------------------------------
// The request side: HandleResults, fed from ToolCallRecordGuard.Check.
// ---------------------------------------------------------------------------

// HandleResults claims every result in results this recorder still has a
// pending tool_use for, takes ONE workspace snapshot for the whole request
// if facts' trigger fires, and records each claimed pair asynchronously,
// carrying that one snapshot's hash. Never blocks the request it was
// called for beyond the snapshot capture itself (this file's own doc
// comment, "witness, never a gate").
func (r *ToolCallRecorder) HandleResults(ctx context.Context, runID string, facts RequestFacts, results []observedToolResult) {
	pairs := r.claimPending(runID, results)
	if len(pairs) == 0 {
		return
	}

	treeHash := r.snapshotIfTriggered(ctx, runID, facts)

	for _, p := range pairs {
		result := p.result
		//nolint:contextcheck,gosec // G118: deliberate, not an oversight. recordAsync builds
		// its own detached, bounded context (context.Background plus recordTimeout) rather
		// than ctx (the request's own): ctx is cancelled once the response this call is
		// witnessing finishes, and a Postgres round trip that must complete regardless is
		// exactly this file's own "witness, never a gate" requirement (see the package doc
		// comment) -- a cancelled request must never cut short a recording already under way.
		go r.recordAsync(runID, p.toolUseID, p.call, &result, treeHash)
	}
}

// claimPending removes and returns the pending entry for every result that
// has one, keeping order in sync with pending so a later eviction still
// evicts the genuinely oldest entry still waiting.
func (r *ToolCallRecorder) claimPending(runID string, results []observedToolResult) []claimedPair {
	r.mu.Lock()
	defer r.mu.Unlock()

	var claimed []claimedPair
	for _, res := range results {
		key := pendingKey{runID: runID, toolUseID: res.ToolUseID}
		call, found := r.pending[key]
		if !found {
			// Either never observed by this recorder at all, or already
			// claimed or evicted on an earlier request carrying the same
			// resent history — "only new turns" (this file's own doc
			// comment). There is no tool name to record this result
			// under, so it is not recorded on its own (ADR-0021 requires
			// one, and guessing one would misattribute the call).
			continue
		}
		delete(r.pending, key)
		r.order = removePendingKey(r.order, key)
		claimed = append(claimed, claimedPair{toolUseID: res.ToolUseID, call: call, result: res})
	}
	return claimed
}

func removePendingKey(order []pendingKey, key pendingKey) []pendingKey {
	for i, k := range order {
		if k == key {
			return append(order[:i], order[i+1:]...)
		}
	}
	return order
}

// snapshotIfTriggered takes ONE workspace snapshot for this request when
// this recorder has a Snapshotter and Trigger configured and Trigger.Fire
// reports a new tool result — synchronously, per ADR-0060 decision 5 and
// ADR-0061 member 3's own timing ("before that request was forwarded"; see
// this file's own package doc comment for why that is deliberate and not
// moved onto a goroutine like the recording itself. A snapshot failure —
// or no Snapshotter at all — answers "", which every caller here already
// reads as "record without a tree hash", never as a reason to refuse.
func (r *ToolCallRecorder) snapshotIfTriggered(ctx context.Context, runID string, facts RequestFacts) string {
	if r.snapshots == nil || r.trigger == nil {
		return ""
	}
	if !r.trigger.Fire(runID, facts) {
		return ""
	}
	outcome := r.snapshots.Snapshot(ctx, facts.WorkingDirectory)
	if !outcome.Snapshotted() {
		r.onFailure(fmt.Errorf(
			"gateway: workspace snapshot for run %q: %s", runID, outcome.Reason))
		return ""
	}
	return outcome.TreeHash
}

// ---------------------------------------------------------------------------
// Recording, always asynchronous.
// ---------------------------------------------------------------------------

// recordAsync builds the body for one tool_use — paired with result when
// result is non-nil, input-only otherwise (an eviction) — and calls
// r.record under a bounded, detached context: never the request's own
// context, which may already be gone by the time a Postgres round trip
// finishes. A failure is handed off to onFailure and counted; it is never
// returned to anything, because there is nothing left in this call chain
// to return it to.
func (r *ToolCallRecorder) recordAsync(runID, toolUseID string, call pendingCall, result *observedToolResult, treeHash string) {
	ctx, cancel := context.WithTimeout(context.Background(), recordTimeout)
	defer cancel()

	body := buildToolCallBody(call, result)
	_, err := r.record(ctx, mcp.GatewayToolCallInput{
		RunID: runID, Tool: call.tool, Body: body, WorkspaceTreeHash: treeHash,
	})
	if err != nil {
		r.failed.Add(1)
		r.onFailure(fmt.Errorf(
			"gateway: recording tool_call for run %q tool_use %q: %w", runID, toolUseID, err))
	}
	if r.onRecorded != nil {
		r.onRecorded()
	}
}

// gatewayToolCallBody is what buildToolCallBody assembles: tool name,
// input, result, is_error and truncation markers — the shape this issue's
// own body is, stored under observe_tool_call's own body store and digest
// unchanged (internal/mcp/gatewayrecord.go).
type gatewayToolCallBody struct {
	Tool            string          `json:"tool"`
	Input           json.RawMessage `json:"input,omitempty"`
	InputTruncated  bool            `json:"input_truncated,omitempty"`
	ResultObserved  bool            `json:"result_observed"`
	Result          json.RawMessage `json:"result,omitempty"`
	IsError         bool            `json:"is_error,omitempty"`
	ResultTruncated bool            `json:"result_truncated,omitempty"`
	Note            string          `json:"note,omitempty"`
}

// buildToolCallBody assembles one tool_call's recorded body. result is nil
// exactly when call was evicted before its result was observed — never
// when a result was observed and happened to be empty, which
// observedToolResult.Content already represents as an empty
// json.RawMessage rather than a nil result.
func buildToolCallBody(call pendingCall, result *observedToolResult) []byte {
	b := gatewayToolCallBody{
		Tool:           call.tool,
		Input:          call.input,
		InputTruncated: call.truncated,
	}
	if result != nil {
		b.ResultObserved = true
		b.Result = result.Content
		b.IsError = result.IsError
		b.ResultTruncated = result.Truncated
	} else {
		b.Note = "this tool_use was evicted from the gateway's bounded pending set " +
			"before its result was observed; recorded input-only"
	}
	out, err := json.Marshal(b)
	if err != nil {
		// gatewayToolCallBody holds only raw JSON, strings and bools, none
		// of which json.Marshal can fail to encode; this is defensive
		// rather than reachable, and still names the tool and the problem
		// rather than losing the record entirely.
		return []byte(fmt.Sprintf(
			`{"tool":%q,"note":"the recorded body could not be encoded: %s"}`,
			call.tool, err.Error()))
	}
	return out
}

// ---------------------------------------------------------------------------
// The request-side Guard: extracts tool_result content and is_error (never
// captured by RequestFacts, which the identity guard already reads for its
// own narrower purpose — Brief, FirstAssistant, WorkingDirectory,
// ToolResultIDs) and hands every one found to HandleResults. Never
// refuses: whatever it does or does not find, the request is forwarded
// unchanged either way.
// ---------------------------------------------------------------------------

// ToolCallRecordGuard is #381's own Guard, passed to guard.go's Guards as
// one of its witnesses so it can read the run id and RequestFacts an
// earlier IdentityGuard.Check already attached to the request's context
// (identity.go, facts.go) -- Guards places every witness after the
// identity guard for exactly that reason.
type ToolCallRecordGuard struct {
	recorder *ToolCallRecorder
}

// NewToolCallRecordGuard returns a Guard that feeds recorder from every
// request carrying a resolved run id.
func NewToolCallRecordGuard(recorder *ToolCallRecorder) *ToolCallRecordGuard {
	return &ToolCallRecordGuard{recorder: recorder}
}

var _ Guard = (*ToolCallRecordGuard)(nil)

// Check implements Guard. It never returns a *Refusal.
func (g *ToolCallRecordGuard) Check(r *http.Request) (*http.Request, *Refusal) {
	if g.recorder == nil {
		return nil, nil
	}
	runID, ok := RunIDFromContext(r.Context())
	if !ok || runID == "" {
		// No earlier guard resolved an identity for this request (no
		// identity guard configured at all, or one that refused it before
		// this guard could ever run) — nothing to pair a result against.
		return nil, nil
	}

	results := extractToolResults(r)
	if len(results) == 0 {
		return r, nil
	}

	facts, _ := RequestFactsFromContext(r.Context())
	g.recorder.HandleResults(r.Context(), runID, facts, results)
	return r, nil
}

// ---------------------------------------------------------------------------
// Composing this ToolUseObserver with an earlier one.
//
// A second Guard (this file's ToolCallRecordGuard, messages.go's
// MessageRecorder) needs no composing helper of its own any more: guard.go's
// own Guards function takes every witness directly, as its own variadic
// witnesses parameter, so a caller with several just passes all of them —
// see that function's own doc comment for why a second, hand-maintained
// guard list built OUTSIDE of it (this package used to ship ChainGuards for
// exactly that, composing the identity guard and RM-236's own witness
// together before handing the result to Guards' single identity slot) is
// the one thing never allowed to exist here again.
//
// Proxy.ToolUse (proxy.go) is a DIFFERENT shape: one field, not a slice, so
// there is nowhere to hand it more than one ToolUseObserver directly.
// CombineToolUseObservers below is what stays needed for exactly that
// reason — SpawnRecorder and ToolCallRecorder both want that single slot —
// and it composes observers, never guards, so it is not the pattern
// Guards' witnesses parameter just closed.
// ---------------------------------------------------------------------------

// CombineToolUseObservers composes several ToolUseObservers into one that
// notifies each in order — the seam that lets a caller share Proxy's own
// single ToolUse field (proxy.go) between more than one observer. A nil
// observer among observers is skipped, so a caller building this from
// optional pieces need not filter first; nil altogether returns nil, so a
// caller with nothing to observe need not special-case that either.
func CombineToolUseObservers(observers ...ToolUseObserver) ToolUseObserver {
	kept := make([]ToolUseObserver, 0, len(observers))
	for _, o := range observers {
		if o != nil {
			kept = append(kept, o)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return combinedToolUseObserver(kept)
}

type combinedToolUseObserver []ToolUseObserver

var (
	_ ToolUseObserver        = combinedToolUseObserver(nil)
	_ ContextToolUseObserver = combinedToolUseObserver(nil)
)

// OnToolUse implements the plain ToolUseObserver interface, for a caller
// that never had a request context to give (see sse.go's own
// boundToolUseObserver — production always prefers OnToolUseContext when
// it is available, which it is here).
func (c combinedToolUseObserver) OnToolUse(t ToolUse) {
	for _, o := range c {
		o.OnToolUse(t)
	}
}

// OnToolUseContext implements ContextToolUseObserver: each of c's own
// observers is called through boundToolUseObserver (proxy.go), so an
// observer that itself implements ContextToolUseObserver (SpawnRecorder,
// ToolCallRecorder) is handed ctx, and one that does not is called through
// its own plain OnToolUse exactly as before.
func (c combinedToolUseObserver) OnToolUseContext(ctx context.Context, t ToolUse) {
	for _, o := range c {
		boundToolUseObserver(ctx, o).OnToolUse(t)
	}
}

// ---------------------------------------------------------------------------
// Reading a request's own tool_result blocks — content and is_error, never
// captured by RequestFacts.ToolResultIDs (facts.go), which exists only to
// name WHICH tool_use ids a request carries a result for, not what those
// results say. This reads the body the identical bounded, restore-after
// way facts.go's own ExtractRequestFacts does, independently: this file
// does not import facts.go's own unexported helpers, and reads the body a
// second time rather than widen RequestFacts for one caller's own need.
// ---------------------------------------------------------------------------

const (
	// maxToolCallRecordBodyBytes bounds how much of one request's body
	// this extractor ever reads looking for tool_result blocks — the same
	// bound facts.go's own maxRequestFactsBodyBytes uses, for the
	// identical reason: Claude Code resends the whole conversation
	// history on every request. Past it, no tool_result is extracted at
	// all — this file never guesses at a partial one — and the request is
	// still forwarded exactly as it arrived (GW-001): deciding whether an
	// agent may proceed without usable facts is the identity guard's job,
	// never this file's, and this file decides nothing about forwarding
	// either way.
	maxToolCallRecordBodyBytes = 32 << 20 // 32 MiB

	// maxToolResultContentBytes bounds how much of one tool_result
	// block's own content this extractor holds — the same order
	// sse.go's own maxToolUseInputBytes holds for one tool_use block's
	// input. Past it, the content is dropped and the block is reported
	// as truncated (GREC-007), never reassembled from a prefix.
	maxToolResultContentBytes = 8 << 20 // 8 MiB
)

// observedToolResult is one tool_result content block this request
// carries: what it answers (ToolUseID), what it says (Content, the
// block's own "content" field, exactly as sent — a string or a further
// array of blocks, kept as raw JSON either way), and whether the harness
// itself marked it an error or a refusal (IsError) — ADR-0057's own
// finding that "a failed command surfaced as a tool result carrying
// is_error... a refused action surfaced the same way".
type observedToolResult struct {
	ToolUseID string
	Content   json.RawMessage
	IsError   bool
	Truncated bool
}

// extractToolResults reads r's body once, bounded by
// maxToolCallRecordBodyBytes, and returns every tool_result block it
// found — empty, never an error, if the body is absent, malformed, not
// JSON, or over the bound. r.Body is always replaced with a fresh reader
// over exactly the same bytes before this function returns, so the
// request forwards unchanged (GW-001) no matter what was found, the same
// contract facts.go's own ExtractRequestFacts holds for r.
func extractToolResults(r *http.Request) []observedToolResult {
	if r.Body == nil {
		return nil
	}

	orig := r.Body
	limited := io.LimitReader(orig, maxToolCallRecordBodyBytes+1)
	buf, readErr := io.ReadAll(limited)

	r.Body = &restoredRecordBody{
		Reader: io.MultiReader(bytes.NewReader(buf), orig),
		closer: orig,
	}

	if readErr != nil || len(buf) > maxToolCallRecordBodyBytes {
		return nil
	}
	return parseToolResults(buf)
}

// restoredRecordBody is facts.go's own restoredBody, restated here rather
// than reused: that type is unexported to its own file, and this file
// reads the request body a second, independent time for a different
// purpose (see this section's own doc comment above) rather than widen
// what facts.go's single read already extracts.
type restoredRecordBody struct {
	io.Reader
	closer io.Closer
}

func (b *restoredRecordBody) Close() error { return b.closer.Close() }

// toolResultRawBlock is one Anthropic Messages API content block, read
// loosely: only the fields a tool_result block carries are read, and a
// block of any other type contributes nothing (Type is checked by the
// caller, parseToolResults).
type toolResultRawBlock struct {
	Type      string          `json:"type"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

// parseToolResults is extractToolResults' pure core: buf in,
// []observedToolResult out, no I/O. A body that is not a JSON object, or a
// message whose content is not a content-block array (the bare-string
// shape a plain text message uses, which can never carry a tool_result),
// contributes nothing rather than erroring — the same "drop what cannot be
// parsed" posture facts.go's own parseRequestFacts and sse.go's own
// scanner both take.
func parseToolResults(buf []byte) []observedToolResult {
	var body struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(buf, &body); err != nil {
		return nil
	}

	var out []observedToolResult
	for _, m := range body.Messages {
		var blocks []toolResultRawBlock
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type != "tool_result" || b.ToolUseID == "" {
				continue
			}
			content := b.Content
			truncated := false
			if len(content) > maxToolResultContentBytes {
				content = nil
				truncated = true
			}
			out = append(out, observedToolResult{
				ToolUseID: b.ToolUseID, Content: content, IsError: b.IsError, Truncated: truncated,
			})
		}
	}
	return out
}

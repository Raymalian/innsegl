// SPDX-License-Identifier: Apache-2.0

package gateway

// messages.go — RM-237 (#382), E16 (#358): the brief an agent received and
// the text it produced are part of its record (ADR-0057, ADR-0061). This
// file is the ONE new piece internal/gateway needs for it: a Guard,
// MessageRecorder, that witnesses every request this package already lets
// through and records, through internal/mcp's in-process wrapper
// (internal/mcp/agentmessage.go), the brief exactly once per run and each
// NEW assistant text turn as it appears in the traffic.
//
// # Where the text comes from, and why it is not RequestFacts
//
// Claude Code resends the whole conversation history on every request
// (facts.go's own doc comment). RequestFacts already gives this package
// Brief (the first user message, reminders stripped) and FirstAssistant
// (the conversation's first assistant turn, canonically encoded for
// fingerprinting) — but FirstAssistant is exactly one turn, encoded for
// hashing rather than kept as readable text, and this file needs EVERY
// assistant turn's own text. lifecycle_contract.go is #416's frozen
// contract file and gains no new member for this, so extractAssistantTexts
// below reads the SAME already-restored request body a second time,
// reusing facts.go's own rawMessage/contentBlocks/joinText and its
// restoredBody pattern rather than inventing either again. Reading the body
// twice per request is the cost of that: bounded exactly as facts.go's own
// read already is, and never a second copy of the bytes that reach the
// upstream.
//
// # Witness, never a gate
//
// Check never returns a non-nil *Refusal: a failure to record a brief or a
// message is not a reason to stop forwarding a request, the same posture
// sse.go's own ToolUseObserver doc comment states for tool_use ("This is a
// witness on top of the forwarded bytes, not a gate in front of them").
// The actual recording call — a body-store write and a ledger append,
// through internal/mcp — is dispatched onto its own goroutine rather than
// run inline in Check, for the identical reason ToolUseObserver's own doc
// comment gives: "An implementation must return quickly ... A consumer
// that might block hands off to a channel or a goroutine of its own rather
// than doing the work here." Check's own cost is an in-memory JSON parse of
// a bounded body and a handful of map operations; nothing in it waits on a
// network call, so a caller of this Guard never has a request's forwarding
// delayed by whatever the ledger or the body volume happen to be doing.
//
// # Only new turns, and why an eviction is not a correctness bug
//
// byRun is a bounded, in-memory table — one entry per run this process has
// witnessed a brief or an assistant turn for — so a request only dispatches
// a recording call for whatever it has not already dispatched: GREC-004's
// "storage grows with new turns only." It is bounded the same way
// identity.go's own identityCache is (insertion-order eviction, not
// least-recently-used), and for the identical reason that is not a
// correctness gap here either: internal/mcp's recorder derives its
// idempotency key from (run_id, role, the digest of the exact text), so a
// run whose tracking entry was evicted and then re-seen dispatches calls
// this process has already made before, and every one of them lands on the
// SAME ledger row rather than a second one (ADR-0017). Eviction can only
// cost a redundant call, never a duplicate event.
//
// # Expose ONE function/type the command can wire
//
// NewMessageRecorder is that one function. It returns a *MessageRecorder,
// which implements Guard — cmd/innsegl/gateway.go (#381's file) adds it to
// the Guards slice Guards() already returns, after the identity guard
// (this Guard reads RunIDFromContext and RequestFactsFromContext, both of
// which only the identity guard attaches — see identity.go — so a
// MessageRecorder that ran ahead of it would find neither and record
// nothing). It needs an AgentMessageRecorder; MCPAgentMessageRecorder below
// is the one every deployment wires by default, exactly the same shape
// MCPRegistrar (registrar.go) already is for Registrar.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
)

// AgentMessageRecorder records one brief or one assistant text turn on a
// run. Declared here, rather than reused from lifecycle_contract.go, for
// the reason this file's own doc comment gives: that file is #416's frozen
// contract and gains no new interface for this issue.
type AgentMessageRecorder interface {
	// RecordAgentMessage stores body and appends one agent_message event
	// for runID under role (mcp.AgentMessageRoleBrief or
	// mcp.AgentMessageRoleAssistant). Idempotent on (runID, role, the
	// digest of body) — see internal/mcp/agentmessage.go.
	RecordAgentMessage(ctx context.Context, runID, role string, body []byte) (string, error)
}

// MCPAgentMessageRecorder implements AgentMessageRecorder by calling
// straight into internal/mcp's in-process wrapper
// (RecordAgentMessageForGateway, internal/mcp/agentmessage.go) — the same
// "no client, no socket, no state of its own" shape MCPRegistrar
// (registrar.go) already is for register_agent and retire_agent.
type MCPAgentMessageRecorder struct{}

// NewMCPAgentMessageRecorder returns the AgentMessageRecorder every
// deployment wires by default.
func NewMCPAgentMessageRecorder() MCPAgentMessageRecorder { return MCPAgentMessageRecorder{} }

var _ AgentMessageRecorder = MCPAgentMessageRecorder{}

// RecordAgentMessage implements AgentMessageRecorder.
func (MCPAgentMessageRecorder) RecordAgentMessage(ctx context.Context, runID, role string, body []byte) (string, error) {
	return mcp.RecordAgentMessageForGateway(ctx, runID, role, body)
}

// ---------------------------------------------------------------------------
// The bounded per-run tracking table.
// ---------------------------------------------------------------------------

// DefaultMessageRecorderCacheSize bounds MessageRecorder's own in-memory
// table of which runs it has already witnessed a brief or an assistant turn
// for — the same reasoning identity.go's DefaultIdentityCacheSize gives its
// own bounded cache: a table sized to the number of runs a harness can
// assert is not itself a memory-exhaustion vector independent of anything
// this table's callers bound.
const DefaultMessageRecorderCacheSize = 8192

// messageRecorderState is what this Guard has already dispatched for one
// run: whether the brief was, and how many assistant turns (by position in
// the resent history) were.
type messageRecorderState struct {
	briefDone     bool
	assistantSeen int
}

// messageRecorderTable is byRun's own bounded map, factored out so its
// eviction rule is written once. Insertion-order eviction, deliberately —
// see this file's own doc comment on why that is not a correctness gap for
// this Guard's callers.
type messageRecorderTable struct {
	mu       sync.Mutex
	capacity int
	order    []string
	byRun    map[string]messageRecorderState
}

func newMessageRecorderTable(capacity int) *messageRecorderTable {
	return &messageRecorderTable{capacity: capacity, byRun: make(map[string]messageRecorderState)}
}

// mutate reads runID's current state (the zero value if this is the first
// time runID is seen), lets fn change it, and stores the result, evicting
// the oldest tracked run first when a NEW run would put this table over its
// bound. fn runs under the table's own lock, so two requests for the same
// run never race on whether a given turn has already been claimed.
func (t *messageRecorderTable) mutate(runID string, fn func(*messageRecorderState)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.byRun[runID]
	if !ok {
		if t.capacity > 0 && len(t.order) >= t.capacity {
			oldest := t.order[0]
			t.order = t.order[1:]
			delete(t.byRun, oldest)
		}
		t.order = append(t.order, runID)
	}
	fn(&st)
	t.byRun[runID] = st
}

// ---------------------------------------------------------------------------
// The Guard.
// ---------------------------------------------------------------------------

// messageRecorderDispatchTimeout bounds how long one dispatched recording
// call (a body-store write and a ledger append through internal/mcp) may
// run before this Guard gives up on it. Detached from the request's own
// context deliberately — see dispatch's own doc comment — so this is the
// only thing that ever ends a stuck call; without it a dependency that
// never answers would leak one goroutine per witnessed turn forever.
const messageRecorderDispatchTimeout = 30 * time.Second

// MessageRecorderConfig is what a MessageRecorder runs on.
type MessageRecorderConfig struct {
	// Recorder is where a claimed brief or assistant turn is sent.
	// Required. MCPAgentMessageRecorder is what every deployment wires by
	// default (NewMCPAgentMessageRecorder).
	Recorder AgentMessageRecorder
	// CacheSize bounds the in-memory table of runs this Guard has already
	// witnessed a brief or a turn for. Zero or less means
	// DefaultMessageRecorderCacheSize.
	CacheSize int
}

// MessageRecorder is the Guard that witnesses the brief (RequestFacts.Brief,
// facts.go) and every new assistant text turn a request's resent history
// carries, dispatching each to Recorder exactly once. It never refuses: see
// this file's own doc comment, "Witness, never a gate".
type MessageRecorder struct {
	recorder AgentMessageRecorder
	table    *messageRecorderTable
}

var _ Guard = (*MessageRecorder)(nil)

// NewMessageRecorder builds a MessageRecorder, or refuses — the same
// "refuse rather than silently run half-wired" posture NewIdentityGuard
// (identity.go) and NewBackstop (lifecycle.go) already take.
func NewMessageRecorder(cfg MessageRecorderConfig) (*MessageRecorder, error) {
	if cfg.Recorder == nil {
		return nil, errors.New("innsegl gateway: message recorder configuration: no AgentMessageRecorder")
	}
	size := cfg.CacheSize
	if size <= 0 {
		size = DefaultMessageRecorderCacheSize
	}
	return &MessageRecorder{recorder: cfg.Recorder, table: newMessageRecorderTable(size)}, nil
}

// Check implements Guard. It never returns a non-nil *Refusal (see this
// file's own doc comment, "Witness, never a gate") and always returns r
// unchanged: unlike the guards ahead of it in the chain, this one attaches
// nothing further to the request's context, because nothing later needs to
// read anything from it.
func (m *MessageRecorder) Check(r *http.Request) (*http.Request, *Refusal) {
	runID, ok := RunIDFromContext(r.Context())
	if !ok || runID == "" {
		// No identity was resolved for this request -- either no identity
		// guard is wired ahead of this one (E15/#380's stack is off), or an
		// earlier guard already refused and this one is never reached. Either
		// way there is no run to witness anything against.
		return r, nil
	}

	if facts, ok := RequestFactsFromContext(r.Context()); ok && facts.Brief != "" {
		if m.claimBrief(runID) {
			m.dispatch(r.Context(), runID, mcp.AgentMessageRoleBrief, []byte(facts.Brief))
		}
	}

	for _, text := range m.claimNewAssistantTurns(runID, r) {
		if text == "" {
			// A turn with no text content -- every block in it was a
			// tool_use or a thinking block (#381's and #416's own concern,
			// never this Guard's) -- is claimed exactly like any other, so
			// it is never reconsidered on a later request, but there is
			// nothing to send: an empty body would be observe.go's own
			// "there is no observation without one" refusal, and this
			// Guard's whole point is to witness text that exists.
			continue
		}
		m.dispatch(r.Context(), runID, mcp.AgentMessageRoleAssistant, []byte(text))
	}

	return r, nil
}

// claimBrief reports whether this call is the first, for runID, to see a
// non-empty Brief -- true at most once per run, ever (until table eviction;
// see this file's own doc comment on why that is not a correctness gap).
// OnReplyText implements ReplyTextObserver: GREC-005's turn read from the
// reply itself, because an agent's last reply is never resent in a later
// request's history. It claims no position in the resent-history count, so
// the same turn arriving again that way is dispatched again, and lands once:
// an agent_message's idempotency key is derived from its body.
func (m *MessageRecorder) OnReplyText(ctx context.Context, text string) {
	runID, ok := RunIDFromContext(ctx)
	if !ok || runID == "" || text == "" {
		return
	}
	m.dispatch(ctx, runID, mcp.AgentMessageRoleAssistant, []byte(text))
}

func (m *MessageRecorder) claimBrief(runID string) bool {
	var first bool
	m.table.mutate(runID, func(st *messageRecorderState) {
		first = !st.briefDone
		st.briefDone = true
	})
	return first
}

// claimNewAssistantTurns extracts every assistant turn's text from r's
// resent history (extractAssistantTexts) and returns only the ones this
// table has not already claimed for runID, in order — GREC-004's "only new
// turns are recorded." The claim (advancing how many turns are considered
// seen) happens before this returns, under the table's own lock, so two
// concurrent requests for the same run can never both claim the same turn.
func (m *MessageRecorder) claimNewAssistantTurns(runID string, r *http.Request) []string {
	texts := extractAssistantTexts(r)
	if len(texts) == 0 {
		return nil
	}
	var start int
	m.table.mutate(runID, func(st *messageRecorderState) {
		start = st.assistantSeen
		if len(texts) > st.assistantSeen {
			st.assistantSeen = len(texts)
		}
	})
	if start >= len(texts) {
		return nil
	}
	return texts[start:]
}

// dispatch sends one claimed brief or turn to m.recorder on its own
// goroutine, over a context derived from requestCtx with
// context.WithoutCancel: any VALUE requestCtx carries (a trace span, for
// instance) is preserved, but its cancellation is not — the request this
// text was witnessed on can finish, and net/http cancels its context the
// moment it does, long before a body-store write and a ledger append have
// actually landed, and this recording must not be cancelled just because
// the conversation that produced it moved on. messageRecorderDispatchTimeout
// is what DOES end it, deliberately, so a dependency that never answers
// cannot leak one goroutine per witnessed turn forever. Nothing here
// reports a failure anywhere further: this package never logs (proxy.go's
// own doc comment), and a witness whose recording call failed has no
// caller left to tell — the request it was witnessing was already
// forwarded, unaffected either way.
func (m *MessageRecorder) dispatch(requestCtx context.Context, runID, role string, body []byte) {
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(requestCtx), messageRecorderDispatchTimeout)
		defer cancel()
		discardAgentMessageResult(m.recorder.RecordAgentMessage(ctx, runID, role, body))
	}()
}

// discardAgentMessageResult is dispatch's own named discard, the same
// pattern identity.go's discardSpawnError and facts.go's
// discardWriteError already use: this package never logs, and a witness
// whose recording call failed has no caller left to tell.
func discardAgentMessageResult(string, error) {}

// ---------------------------------------------------------------------------
// Reading every assistant turn's text out of a request's resent history.
// ---------------------------------------------------------------------------

// extractAssistantTexts reads r's body ONCE MORE, bounded exactly as
// ExtractRequestFacts (facts.go) already bounds its own read, and returns
// one string per "assistant"-role message found, in the order the
// conversation's history has them — the concatenation of that message's own
// "text" content blocks (facts.go's joinText), which is empty for a turn
// that was pure tool_use.
//
// r.Body is always restored to a fresh reader over exactly the same bytes
// before this returns, via facts.go's own restoredBody, so a request that
// reaches this Guard still forwards byte for byte (GW-001) whatever this
// function found or failed to find.
func extractAssistantTexts(r *http.Request) []string {
	if r.Body == nil {
		return nil
	}

	orig := r.Body
	limited := io.LimitReader(orig, maxRequestFactsBodyBytes+1)
	buf, readErr := io.ReadAll(limited)
	r.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), closer: orig}

	if readErr != nil || len(buf) > maxRequestFactsBodyBytes {
		return nil
	}

	var body struct {
		Messages []rawMessage `json:"messages"`
	}
	if err := json.Unmarshal(buf, &body); err != nil {
		return nil
	}

	var texts []string
	for _, msg := range body.Messages {
		if msg.Role != "assistant" {
			continue
		}
		blocks, ok := contentBlocks(msg.Content)
		if !ok {
			continue
		}
		texts = append(texts, joinText(blocks))
	}
	return texts
}

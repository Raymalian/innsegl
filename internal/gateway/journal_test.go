// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"innsegl.dev/innsegl/internal/clientjournal"
	"innsegl.dev/innsegl/internal/mcp"
)

// ADR-0068: the core says on every reply it relays whether it recorded the
// exchange, and replays a journaled exchange through the same guards and
// observers a live one passes.

func recordedHeaderAfter(t *testing.T, guard Guard, upstreamSays string) string {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if upstreamSays != "" {
			w.Header().Set(clientjournal.RecordedHeader, upstreamSays)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(upstream.Close)
	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{Upstream: up, Guards: []Guard{guard}}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader("{}")))
	if rec.Code != http.StatusOK {
		t.Fatalf("relayed status %d: %s", rec.Code, rec.Body.String())
	}
	if n := len(rec.Header().Values(clientjournal.RecordedHeader)); n != 1 {
		t.Fatalf("%d %s headers, want exactly one", n, clientjournal.RecordedHeader)
	}
	return rec.Header().Get(clientjournal.RecordedHeader)
}

// JRN-003: "true" with a run, "false" inside a repository the core did not
// record, "none" otherwise; an upstream's own value never reaches the client.
func TestJRN003TheCoreSaysWhetherItRecorded(t *testing.T) {
	withRun := guardFunc(func(r *http.Request) (*http.Request, *Refusal) {
		return r.WithContext(WithRunID(r.Context(), "run-1")), nil
	})
	unrecorded := guardFunc(func(r *http.Request) (*http.Request, *Refusal) {
		ctx := withUnrecordedMark(r.Context())
		markUnrecordedRepo(ctx, "github.com/acme/app")
		return r.WithContext(ctx), nil
	})
	nothing := guardFunc(func(r *http.Request) (*http.Request, *Refusal) { return r, nil })

	for name, tc := range map[string]struct {
		guard    Guard
		upstream string
		want     string
	}{
		"recorded":           {withRun, "", clientjournal.RecordedTrue},
		"unrecorded in repo": {unrecorded, "", clientjournal.RecordedFalse},
		"no repository":      {nothing, "", clientjournal.RecordedNone},
		"upstream lies":      {nothing, clientjournal.RecordedTrue, clientjournal.RecordedNone},
	} {
		if got := recordedHeaderAfter(t, tc.guard, tc.upstream); got != tc.want {
			t.Errorf("%s: %s = %q, want %q", name, clientjournal.RecordedHeader, got, tc.want)
		}
	}
}

// JRN-003: an out-of-scope repository, from the registry or from the header,
// marks the request as unrecorded inside a repository; a session outside any
// repository does not.
func TestJRN003OutOfScopeIsMarkedUnrecordedInARepository(t *testing.T) {
	f := newIdentityFixture(t)
	g, _ := neverStuckGuard(t, f, true, &fakeHeaderStatements{verdict: StatementOutOfScope})

	f.sessionWorkspaces.RecordStated("held", "", StatedWorkspace{Cwd: "/w", Repo: rivalRepo, Branch: "main", Task: "t1"})
	out, ref := hostedCheck(t, g, Identification{SessionID: "held", AgentID: mainAgentID}, cgInstA)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	if got := unrecordedRepo(out.Context()); got != rivalRepo {
		t.Fatalf("registry out of scope: unrecorded repo %q, want %q", got, rivalRepo)
	}

	id := Identification{SessionID: "rival", AgentID: mainAgentID}
	r := withStatementHeader(identityRequest(t, id, "hello", ""),
		`{"Cwd":"/w/held","Repo":"`+rivalRepo+`","Branch":"main","Task":"t1"}`)
	out, ref = hostedCheckRequest(g, r, cgInstA)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	if got := unrecordedRepo(out.Context()); got != rivalRepo {
		t.Fatalf("header out of scope: unrecorded repo %q, want %q", got, rivalRepo)
	}

	f.sessionWorkspaces.Record("home", "", "/client/notes")
	out, ref = hostedCheck(t, g, Identification{SessionID: "home", AgentID: mainAgentID}, cgInstA)
	if ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	if got := unrecordedRepo(out.Context()); got != "" {
		t.Fatalf("a session outside any repository is marked unrecorded in %q", got)
	}
}

type ctxToolUses struct {
	mu   sync.Mutex
	seen []string // journal entry per tool use
}

func (c *ctxToolUses) OnToolUse(ToolUse) {}
func (c *ctxToolUses) OnToolUseContext(ctx context.Context, _ ToolUse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, _ := JournalEntryFromContext(ctx)
	c.seen = append(c.seen, entry)
}

const journalSSE = "event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{}}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}` + "\n\n" +
	"event: content_block_stop\n" +
	`data: {"type":"content_block_stop","index":0}` + "\n\n"

// JRN-004: a replay passes the guards (never the per-session rate limit:
// a backlog is not a runaway loop), reaches no upstream, and hands the
// journaled reply to the same observers, with the entry it came from.
func TestJRN004AReplayRunsTheGuardsAndObserversWithoutTheRateLimit(t *testing.T) {
	limiter, err := NewSessionRateLimiter(SessionRateLimit{Rate: 1, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	observed := &ctxToolUses{}
	var witnessed int
	witness := guardFunc(func(r *http.Request) (*http.Request, *Refusal) {
		if IsReplay(r.Context()) {
			witnessed++
		}
		return r, nil
	})
	identity := guardFunc(func(r *http.Request) (*http.Request, *Refusal) {
		return r.WithContext(WithRunID(r.Context(), "run-7")), nil
	})
	p := &Proxy{ToolUse: observed, Guards: Guards(limiter, identity, witness)}

	for i := range 3 {
		r := httptest.NewRequestWithContext(WithJournalEntry(context.Background(), "sha256:e"+strings.Repeat("0", 63)),
			http.MethodPost, "/v1/messages", strings.NewReader(`{"messages":[]}`))
		r.Header.Set("X-Claude-Code-Session-Id", "33333333-3333-4333-8333-333333333333")
		out := p.Replay(r, "text/event-stream", []byte(journalSSE))
		if out.Refusal != nil {
			t.Fatalf("replay %d refused: %+v", i, out.Refusal)
		}
		if out.RunID != "run-7" {
			t.Fatalf("replay %d: run %q, want run-7", i, out.RunID)
		}
	}
	if witnessed != 3 {
		t.Fatalf("the witness saw %d replays, want 3", witnessed)
	}
	if len(observed.seen) != 3 || observed.seen[0] != "sha256:e"+strings.Repeat("0", 63) {
		t.Fatalf("observer saw %v, want three tool uses carrying the entry", observed.seen)
	}

	// A harness shape the guards refuse is the refusal, observed by no one.
	bad := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/other", strings.NewReader(`{}`))
	if out := p.Replay(bad, "text/event-stream", []byte(journalSSE)); out.Refusal == nil || out.Refusal.Status != http.StatusBadRequest {
		t.Fatalf("unrecognised shape replayed: %+v", out)
	}
	if len(observed.seen) != 3 {
		t.Fatal("a refused replay reached the observer")
	}
}

// JRN-004: a tool call first seen in a journaled reply is recorded with the
// entry's hash in its body, so the chain commits to the signed entry.
func TestJRN004AJournaledToolCallNamesItsEntry(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	done := make(chan struct{}, 1)
	rec := NewToolCallRecorder(ToolCallRecorderConfig{
		record: func(_ context.Context, in mcp.GatewayToolCallInput) (mcp.GatewayToolCallOutput, error) {
			mu.Lock()
			bodies = append(bodies, in.Body)
			mu.Unlock()
			return mcp.GatewayToolCallOutput{}, nil
		},
		onRecorded: func() { done <- struct{}{} },
	})
	entry := "sha256:" + strings.Repeat("ab", 32)
	ctx := WithJournalEntry(WithRunID(context.Background(), "run-1"), entry)
	rec.OnToolUseContext(ctx, ToolUse{ID: "toolu_1", Name: "Bash", Input: json.RawMessage(`{"command":"ls"}`)})
	rec.HandleResults(context.Background(), "run-1", RequestFacts{}, []observedToolResult{{ToolUseID: "toolu_1", Content: json.RawMessage(`"ok"`)}})
	<-done
	mu.Lock()
	defer mu.Unlock()
	var got gatewayToolCallBody
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if got.JournalEntry != entry {
		t.Fatalf("journal_entry = %q, want %q", got.JournalEntry, entry)
	}
}

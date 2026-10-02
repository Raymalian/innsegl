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
)

// RM-313: a session never gets stuck on "the session hook has not stated".
// The statement travels with every request from the client service, a
// request with no statement at all is forwarded unrecorded, and a repository
// the installation may not record is forwarded unrecorded with a finding.
// Nothing here is a 503 loop.

const rivalRepo = "github.com/rival/held"

// fakeHeaderStatements reads the statement as plain JSON from the header; the
// real decoding and validation are cmd/innsegl's (statementheader.go).
type fakeHeaderStatements struct {
	mu      sync.Mutex
	verdict StatementVerdict
	admits  int
}

func (f *fakeHeaderStatements) Decode(r *http.Request, _ Identification) (string, StatedWorkspace, bool) {
	raw := r.Header.Get(StatementHeader)
	if raw == "" {
		return "", StatedWorkspace{}, false
	}
	var in struct {
		AgentID, Cwd, Repo, Branch, Task string
	}
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return "", StatedWorkspace{}, false
	}
	return in.AgentID, StatedWorkspace{Cwd: in.Cwd, Repo: in.Repo, Branch: in.Branch, Task: in.Task}, true
}

func (f *fakeHeaderStatements) Admit(context.Context, string, StatedWorkspace) (StatementVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admits++
	return f.verdict, nil
}

type findings struct {
	mu  sync.Mutex
	got []UnrecordedFinding
}

func (f *findings) add(u UnrecordedFinding) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, u)
}

func (f *findings) all() []UnrecordedFinding {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]UnrecordedFinding(nil), f.got...)
}

func neverStuckGuard(t *testing.T, f *identityFixture, hosted bool, hs HeaderStatements) (*IdentityGuard, *findings) {
	t.Helper()
	found := &findings{}
	cfg := IdentityGuardConfig{
		Mappings: f.mappings, Tree: f.tree, Policy: NewPolicy(), Registrar: f.registrar,
		Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
		HeaderStatements: hs, OnUnrecorded: found.add,
	}
	if hosted {
		cfg.Pins, cfg.Scope = NewSessionPins(0), ptScope()
	}
	g, err := NewIdentityGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g, found
}

func withStatementHeader(r *http.Request, st string) *http.Request {
	r.Header.Set(StatementHeader, st)
	return r
}

func hostedCheckRequest(g *IdentityGuard, r *http.Request, installation string) (*http.Request, *Refusal) {
	return g.Check(r.WithContext(WithInstallation(r.Context(), installation)))
}

// The core restarted: its registry is empty, but the request carries the
// client service's cached statement, so the run is registered from it.
func TestRM313CoreRestartUsesTheHeaderStatement(t *testing.T) {
	f := newIdentityFixture(t)
	hs := &fakeHeaderStatements{verdict: StatementAdmitted}
	g, found := neverStuckGuard(t, f, true, hs)
	id := Identification{SessionID: "restarted", AgentID: mainAgentID}
	r := withStatementHeader(identityRequest(t, id, "hello", ""),
		`{"Cwd":"/w/app","Repo":"`+ptRepo+`","Branch":"main","Task":"t1"}`)

	out, ref := hostedCheckRequest(g, r, cgInstA)
	if ref != nil {
		t.Fatalf("a request carrying its statement was refused: %+v", ref)
	}
	if mustRunID(t, out) == "" || f.registrar.lastSeen.Workspace.Repo != ptRepo {
		t.Fatalf("registered under %+v, want %s", f.registrar.lastSeen.Workspace, ptRepo)
	}
	if st, ok := f.sessionWorkspaces.LookupStated("restarted", mainAgentID); !ok || st.Repo != ptRepo {
		t.Fatalf("the header statement was not kept: %+v %v", st, ok)
	}
	if len(found.all()) != 0 {
		t.Fatalf("findings %v for a recorded session", found.all())
	}
}

// A header statement never overrides what the hook stated to this core.
func TestRM313TheRegistryWinsOverTheHeader(t *testing.T) {
	f := newIdentityFixture(t)
	hs := &fakeHeaderStatements{verdict: StatementAdmitted}
	g, _ := neverStuckGuard(t, f, true, hs)
	f.sessionWorkspaces.RecordStated("known", "", StatedWorkspace{Cwd: "/w/app", Repo: ptRepo, Branch: "main", Task: "t1"})
	id := Identification{SessionID: "known", AgentID: mainAgentID}
	r := withStatementHeader(identityRequest(t, id, "hello", ""),
		`{"Cwd":"/w/other","Repo":"github.com/acme/other","Branch":"main","Task":"t2"}`)
	if _, ref := hostedCheckRequest(g, r, cgInstA); ref != nil {
		t.Fatalf("refused: %+v", ref)
	}
	if hs.admits != 0 || f.registrar.lastSeen.Workspace.Repo != ptRepo {
		t.Fatalf("header admitted %d times, registered under %q; want the registry's %q",
			hs.admits, f.registrar.lastSeen.Workspace.Repo, ptRepo)
	}
}

// No statement anywhere (no hooks, no header): forwarded unrecorded, and the
// finding is reported once, not on every request.
func TestRM313HostedNoStatementIsForwardedUnrecorded(t *testing.T) {
	f := newIdentityFixture(t)
	g, found := neverStuckGuard(t, f, true, &fakeHeaderStatements{})
	id := Identification{SessionID: "unstated", AgentID: mainAgentID}
	for range 2 {
		out, ref := hostedCheck(t, g, id, cgInstA)
		if ref != nil {
			t.Fatalf("no statement: refused %+v, want it forwarded", ref)
		}
		if runID, ok := RunIDFromContext(out.Context()); ok || runID != "" {
			t.Fatalf("an unstated session carries run %q", runID)
		}
	}
	if len(f.registrar.calls) != 0 || len(f.mappings.rows) != 0 {
		t.Fatalf("registered %v, rows %v for an unstated session", f.registrar.calls, f.mappings.rows)
	}
	got := found.all()
	if len(got) != 1 || got[0].Reason != UnrecordedNoStatement || got[0].SessionID != "unstated" ||
		got[0].Installation != cgInstA {
		t.Fatalf("findings = %+v, want one no-statement finding for the session", got)
	}
}

// Single-host mode too: no statement is not a 503 loop.
func TestRM313SingleHostNoStatementIsForwardedUnrecorded(t *testing.T) {
	f := newIdentityFixture(t)
	g, found := neverStuckGuard(t, f, false, nil)
	out, ref := g.Check(identityRequest(t, Identification{SessionID: "s-unstated", AgentID: mainAgentID}, "hello", ""))
	if ref != nil {
		t.Fatalf("no statement: refused %+v, want it forwarded", ref)
	}
	if runID, ok := RunIDFromContext(out.Context()); ok || runID != "" {
		t.Fatalf("an unstated session carries run %q", runID)
	}
	if f.workspaces.calls != 0 || len(f.registrar.calls) != 0 {
		t.Fatalf("resolver calls %d, registrar calls %v", f.workspaces.calls, f.registrar.calls)
	}
	if got := found.all(); len(got) != 1 || got[0].Reason != UnrecordedNoStatement {
		t.Fatalf("findings = %+v, want one no-statement finding", got)
	}
}

// A repository the installation may not record (an explicit list leaves it
// out, or another organisation holds it): forwarded unrecorded, a finding
// names it, nothing is registered.
func TestRM313OutOfScopeIsForwardedUnrecordedWithAFinding(t *testing.T) {
	f := newIdentityFixture(t)
	g, found := neverStuckGuard(t, f, true, nil)
	f.sessionWorkspaces.RecordStated("held", "", StatedWorkspace{Cwd: "/w", Repo: rivalRepo, Branch: "main", Task: "t1"})
	out, ref := hostedCheck(t, g, Identification{SessionID: "held", AgentID: mainAgentID}, cgInstA)
	if ref != nil {
		t.Fatalf("out of scope: refused %+v, want it forwarded", ref)
	}
	if runID, ok := RunIDFromContext(out.Context()); ok || runID != "" {
		t.Fatalf("an out-of-scope session carries run %q", runID)
	}
	if len(f.registrar.calls) != 0 {
		t.Fatalf("registrar calls %v for an out-of-scope repository", f.registrar.calls)
	}
	got := found.all()
	if len(got) != 1 || got[0].Reason != UnrecordedOutOfScope || got[0].Repo != rivalRepo {
		t.Fatalf("findings = %+v, want one out-of-scope finding naming %s", got, rivalRepo)
	}
}

// A header statement for a repository another organisation holds is not
// recorded, and the request is forwarded; the session is then a session
// outside any repository, so the scope is not asked again on every request.
func TestRM313HeaderStatementForAnotherOrgsRepoIsForwardedUnrecorded(t *testing.T) {
	f := newIdentityFixture(t)
	hs := &fakeHeaderStatements{verdict: StatementOutOfScope}
	g, found := neverStuckGuard(t, f, true, hs)
	id := Identification{SessionID: "rival", AgentID: mainAgentID}
	for range 2 {
		r := withStatementHeader(identityRequest(t, id, "hello", ""),
			`{"Cwd":"/w/held","Repo":"`+rivalRepo+`","Branch":"main","Task":"t1"}`)
		out, ref := hostedCheckRequest(g, r, cgInstA)
		if ref != nil {
			t.Fatalf("refused %+v, want it forwarded", ref)
		}
		if runID, ok := RunIDFromContext(out.Context()); ok || runID != "" {
			t.Fatalf("carries run %q", runID)
		}
	}
	if len(f.registrar.calls) != 0 || hs.admits != 1 {
		t.Fatalf("registrar calls %v, scope asked %d times; want none and once", f.registrar.calls, hs.admits)
	}
	if st, _ := f.sessionWorkspaces.LookupStated("rival", mainAgentID); st.HasRepo() || st.Cwd != "/w/held" {
		t.Fatalf("kept %+v, want the directory alone", st)
	}
	if got := found.all(); len(got) != 1 || got[0].Reason != UnrecordedOutOfScope || got[0].Repo != rivalRepo {
		t.Fatalf("findings = %+v, want one out-of-scope finding", got)
	}
}

// A pinned session stays pinned: another installation's request is the 401,
// header or not.
func TestRM313AnotherInstallationIsStillRefused(t *testing.T) {
	f := newIdentityFixture(t)
	g, _ := neverStuckGuard(t, f, true, &fakeHeaderStatements{verdict: StatementAdmitted})
	id := Identification{SessionID: "pinned", AgentID: mainAgentID}
	if _, ref := hostedCheck(t, g, id, cgInstA); ref != nil {
		t.Fatalf("first use: %+v", ref)
	}
	r := withStatementHeader(identityRequest(t, id, "hello", ""),
		`{"Cwd":"/w/app","Repo":"`+ptRepo+`","Branch":"main","Task":"t1"}`)
	if _, ref := hostedCheckRequest(g, r, cgInstB); ref == nil || ref.Status != http.StatusUnauthorized {
		t.Fatalf("another installation: %+v, want 401", ref)
	}
}

// The statement header is the client's to the core, never the provider's.
func TestRM313TheStatementHeaderIsNeverForwardedUpstream(t *testing.T) {
	got := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	up, err := NewUpstream(upstream.URL, upstream.Client())
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewServer(&Proxy{Upstream: up})
	defer gw.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.URL+"/v1/messages", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerClaudeCodeSessionID, validSessionID)
	req.Header.Set(StatementHeader, "eyJjd2QiOiIvaG9tZS9zZWNyZXQifQ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if h := <-got; h.Get(StatementHeader) != "" {
		t.Fatalf("the upstream saw %s: %q", StatementHeader, h.Get(StatementHeader))
	}
}

func TestRM313KnowsIsPerAgent(t *testing.T) {
	ws := NewSessionWorkspaces(0)
	if ws.Knows("s", mainAgentID) {
		t.Fatal("an empty table knows a session")
	}
	ws.Record("s", "", "/w")
	if !ws.Knows("s", mainAgentID) || !ws.Knows("s", "") {
		t.Fatal("the main agent's statement is not known")
	}
	if ws.Knows("s", "a1") {
		t.Fatal("a subagent with no statement of its own is known")
	}
	ws.Record("s", "a1", "/w/sub")
	if !ws.Knows("s", "a1") {
		t.Fatal("a subagent's own statement is not known")
	}
}

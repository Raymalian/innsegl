// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"testing"

	"innsegl.dev/innsegl/internal/ledger"
)

// Hosted mode, as amended 2026-10-02 (ADR-0063): a session that is not in a
// git repository passes through unrecorded; a session in one is recorded;
// and a recorded session stays recorded when it leaves the repository.

const ptRepo = "github.com/acme/app"

func newHostedIdentityGuard(t *testing.T, f *identityFixture, scope ScopeChecker) *IdentityGuard {
	t.Helper()
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: f.mappings, Tree: f.tree, Policy: NewPolicy(), Registrar: f.registrar,
		Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
		Pins: NewSessionPins(0), Scope: scope,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func hostedCheck(t *testing.T, g *IdentityGuard, id Identification, installation string) (*http.Request, *Refusal) {
	t.Helper()
	r := identityRequest(t, id, "hello", "")
	return g.Check(r.WithContext(WithInstallation(r.Context(), installation)))
}

func ptScope() *cgInstallations {
	return &cgInstallations{active: map[string]bool{cgInstA: true}, scope: map[string]bool{cgInstA + " " + ptRepo: true}}
}

func TestHostedSessionOutsideAnyRepositoryPassesThroughUnrecorded(t *testing.T) {
	f := newIdentityFixture(t)
	g := newHostedIdentityGuard(t, f, ptScope())
	f.sessionWorkspaces.Record("home", "", "/client/notes")

	for _, agent := range []string{mainAgentID, "a0123456789abcdef"} {
		out, ref := hostedCheck(t, g, Identification{SessionID: "home", AgentID: agent}, cgInstA)
		if ref != nil {
			t.Fatalf("%s: a session outside any repository was refused: %+v", agent, ref)
		}
		if out == nil {
			t.Fatalf("%s: no request to forward", agent)
		}
		if runID, ok := RunIDFromContext(out.Context()); ok || runID != "" {
			t.Fatalf("%s: a pass-through request carries run %q", agent, runID)
		}
	}
	if len(f.registrar.calls) != 0 {
		t.Fatalf("registrar calls %v for an unrecorded session", f.registrar.calls)
	}
	if len(f.mappings.rows) != 0 {
		t.Fatalf("mapping rows %v for an unrecorded session", f.mappings.rows)
	}
	// Still pinned: another installation cannot use the session.
	if _, ref := hostedCheck(t, g, Identification{SessionID: "home", AgentID: mainAgentID}, cgInstB); ref == nil ||
		ref.Status != http.StatusUnauthorized {
		t.Fatalf("another installation on a pass-through session: %+v, want 401", ref)
	}
}

// No statement at all is not "outside a repository": the hook has not run
// yet, so the request waits for it rather than passing unrecorded.
func TestHostedSessionWithNoStatementIsAskedToRetry(t *testing.T) {
	f := newIdentityFixture(t)
	g := newHostedIdentityGuard(t, f, ptScope())
	_, ref := hostedCheck(t, g, Identification{SessionID: "unstated", AgentID: mainAgentID}, cgInstA)
	if ref == nil || ref.Status != http.StatusServiceUnavailable {
		t.Fatalf("no statement: %+v, want 503", ref)
	}
}

// A session recorded in a repository stays recorded after it states a
// directory outside one (CwdChanged): its main agent continues its run, and a
// new subagent is registered under the same repository.
func TestHostedRecordingIsStickyAfterLeavingTheRepository(t *testing.T) {
	f := newIdentityFixture(t)
	g := newHostedIdentityGuard(t, f, ptScope())
	f.sessionWorkspaces.RecordStated("rec", "", StatedWorkspace{Cwd: "/w/app", Repo: ptRepo, Branch: "main", Task: "t1"})
	main := Identification{SessionID: "rec", AgentID: mainAgentID}
	out, ref := hostedCheck(t, g, main, cgInstA)
	if ref != nil {
		t.Fatalf("in a repository: refused %+v", ref)
	}
	runID := mustRunID(t, out)
	f.runStates.set(runID, ledger.RunActive)

	f.sessionWorkspaces.Record("rec", "", "/tmp")
	out, ref = hostedCheck(t, g, main, cgInstA)
	if ref != nil || mustRunID(t, out) != runID {
		t.Fatalf("main agent after leaving the repository: %+v, want run %s", ref, runID)
	}
	sub := Identification{SessionID: "rec", AgentID: "a0123456789abcdef"}
	out, ref = hostedCheck(t, g, sub, cgInstA)
	if ref != nil {
		t.Fatalf("subagent after leaving the repository: refused %+v", ref)
	}
	if mustRunID(t, out) == "" || f.registrar.lastSeen.Workspace.Repo != ptRepo {
		t.Fatalf("subagent registered under %q, want %q", f.registrar.lastSeen.Workspace.Repo, ptRepo)
	}
}

// Sticky across a core restart: the in-memory statements are gone, but the
// session's run mapping still says it was recorded, and the run's own
// registration names the repository.
func TestHostedRecordingIsStickyAcrossARestart(t *testing.T) {
	f := newIdentityFixture(t)
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-main", SessionID: "rec", AgentID: mainAgentID, Fingerprint: "fp-1", ClientID: cgInstA,
	}); err != nil {
		t.Fatal(err)
	}
	f.runStates.set("run-main", ledger.RunActive)
	f.runStates.register("run-main", RunRegistration{AgentType: mainAgentID, TaskID: "t1", Repo: ptRepo})
	g := newHostedIdentityGuard(t, f, ptScope())
	f.sessionWorkspaces.Record("rec", "", "/tmp")

	out, ref := hostedCheck(t, g, Identification{SessionID: "rec", AgentID: "a0123456789abcdef"}, cgInstA)
	if ref != nil {
		t.Fatalf("subagent of a recorded session after a restart: refused %+v", ref)
	}
	if mustRunID(t, out) == "" || f.registrar.lastSeen.Workspace.Repo != ptRepo || f.registrar.lastSeen.Workspace.Task != "t1" {
		t.Fatalf("subagent registered under %+v, want %s / t1", f.registrar.lastSeen.Workspace, ptRepo)
	}
}

// A repository the installation may not act on (another organisation holds
// it, or an explicit list leaves it out) is the client refusal, and nothing
// is registered.
func TestHostedRepositoryOutOfScopeIsRefused(t *testing.T) {
	f := newIdentityFixture(t)
	g := newHostedIdentityGuard(t, f, ptScope())
	f.sessionWorkspaces.RecordStated("held", "", StatedWorkspace{Cwd: "/w", Repo: "github.com/rival/held", Branch: "main", Task: "t1"})
	_, ref := hostedCheck(t, g, Identification{SessionID: "held", AgentID: mainAgentID}, cgInstA)
	if ref == nil || ref.Status != http.StatusUnauthorized || ref.Reason != ClientRefusalMessage {
		t.Fatalf("held by another organisation: %+v, want the 401 client refusal", ref)
	}
	if len(f.registrar.calls) != 0 {
		t.Fatalf("registrar calls %v after a refusal", f.registrar.calls)
	}
}

// The session table remembers the newest statement that named a repository,
// even after a directory-only statement replaces the current one.
func TestSessionWorkspacesRememberTheLastRepository(t *testing.T) {
	s := NewSessionWorkspaces(0)
	if _, ok := s.LastRepo("s"); ok {
		t.Fatal("an unknown session has a repository")
	}
	s.Record("s", "", "/home")
	if _, ok := s.LastRepo("s"); ok {
		t.Fatal("a directory-only session has a repository")
	}
	s.RecordStated("s", "", StatedWorkspace{Cwd: "/w", Repo: ptRepo, Branch: "main", Task: "t1"})
	s.Record("s", "", "/tmp")
	if st, _ := s.LookupStated("s", ""); st.HasRepo() || st.Cwd != "/tmp" {
		t.Fatalf("current statement %+v, want /tmp with no repository", st)
	}
	st, ok := s.LastRepo("s")
	if !ok || st.Repo != ptRepo || st.Task != "t1" {
		t.Fatalf("LastRepo = %+v, %v; want %s", st, ok, ptRepo)
	}
}

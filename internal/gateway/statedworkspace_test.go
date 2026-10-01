// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"
	"testing"
)

// RM-282 (#458): the client derives the workspace and states it.

// GID-013: a session that stated {repo, branch, task} registers a run with
// exactly those, and the filesystem resolver is never asked.
func TestIdentityGuardGID013RegistersTheWorkspaceTheClientStated(t *testing.T) {
	f := newIdentityFixture(t)
	f.sessionWorkspaces.RecordStated("s-stated", "", StatedWorkspace{
		Cwd: "/client/only/path", Repo: "github.com/example-org/example-repo",
		Worktree: "wt", Branch: "dev/rm282", Task: "rm282", Head: strings.Repeat("a", 40),
	})
	id := Identification{SessionID: "s-stated", AgentID: mainAgentID}

	r2, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if f.workspaces.calls != 0 {
		t.Errorf("filesystem resolver calls = %d, want 0: a stated workspace needs no filesystem", f.workspaces.calls)
	}
	want := Workspace{Repo: "github.com/example-org/example-repo", Branch: "dev/rm282", Task: "rm282"}
	if got := f.registrar.lastSeen.Workspace; got != want {
		t.Errorf("registered workspace = %+v, want %+v", got, want)
	}
	facts, _ := RequestFactsFromContext(r2.Context())
	if facts.WorkingDirectory != "/client/only/path" {
		t.Errorf("WorkingDirectory = %q, want the stated cwd (the recorder snapshots it)", facts.WorkingDirectory)
	}
}

// GID-014: a session that stated only a cwd still resolves through the
// existing resolver (the single-host shape).
func TestIdentityGuardGID014ResolvesACwdOnlyStatementThroughTheResolver(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if f.workspaces.calls != 1 || f.workspaces.dir != fixtureDirectory {
		t.Errorf("resolver calls = %d dir = %q, want one call for %q", f.workspaces.calls, f.workspaces.dir, fixtureDirectory)
	}
	want := Workspace{Repo: "acme/id-test", Branch: "main", Task: "task-1"}
	if got := f.registrar.lastSeen.Workspace; got != want {
		t.Errorf("registered workspace = %+v, want %+v", got, want)
	}
}

func TestSessionWorkspacesStoresAStatedWorkspace(t *testing.T) {
	s := NewSessionWorkspaces(0)
	st := StatedWorkspace{Cwd: "/w", Repo: "github.com/o/r", Worktree: "wt", Branch: "b", Task: "t", Head: strings.Repeat("0", 40)}
	s.RecordStated("s1", "", st)
	got, ok := s.LookupStated("s1", "")
	if !ok || got != st {
		t.Fatalf("LookupStated = %+v, %v; want %+v", got, ok, st)
	}
	if dir, _ := s.Lookup("s1", ""); dir != "/w" {
		t.Errorf("Lookup = %q, want the stated cwd", dir)
	}
}

func TestSessionWorkspacesNewerCwdOnlyStatementDropsTheStatedRepo(t *testing.T) {
	s := NewSessionWorkspaces(0)
	s.RecordStated("s1", "", StatedWorkspace{Cwd: "/a", Repo: "github.com/o/r", Branch: "b", Task: "t"})
	s.Record("s1", "", "/elsewhere")
	got, _ := s.LookupStated("s1", "")
	if got.Repo != "" || got.Cwd != "/elsewhere" {
		t.Errorf("LookupStated = %+v: a later cwd-only statement must not keep the old repo", got)
	}
}

func TestSessionWorkspacesAStatedSubagentKeepsItsOwnWorkspace(t *testing.T) {
	s := NewSessionWorkspaces(0)
	const sub = "aa328d4891c7406b1"
	s.RecordStated("s1", "", StatedWorkspace{Cwd: "/a", Repo: "github.com/o/main", Branch: "b", Task: "t"})
	s.RecordStated("s1", sub, StatedWorkspace{Cwd: "/b", Repo: "github.com/o/sub", Branch: "b2", Task: "t2"})
	if got, _ := s.LookupStated("s1", sub); got.Repo != "github.com/o/sub" {
		t.Errorf("subagent Repo = %q", got.Repo)
	}
	if got, _ := s.LookupStated("s1", "unnamed-agent"); got.Repo != "github.com/o/sub" {
		t.Errorf("unnamed agent Repo = %q, want the session's newest statement", got.Repo)
	}
	if _, ok := s.LookupStated("unseen", ""); ok {
		t.Error("an unseen session must be unknown")
	}
}

func TestStatedWorkspaceResolverUsesTheStatementWithoutTheFallback(t *testing.T) {
	fb := &fakeWorkspaceResolver{}
	r := StatedWorkspaceResolver{Fallback: fb}
	got, err := r.ResolveStated(t.Context(), StatedWorkspace{Cwd: "/c", Repo: "github.com/o/r", Branch: "b", Task: "t"})
	if err != nil || got != (Workspace{Repo: "github.com/o/r", Branch: "b", Task: "t"}) || fb.calls != 0 {
		t.Fatalf("got %+v, %v, fallback calls %d", got, err, fb.calls)
	}
}

func TestStatedWorkspaceResolverFallsBackForACwdOnlyStatement(t *testing.T) {
	fb := &fakeWorkspaceResolver{ws: Workspace{Repo: "x/y/z", Branch: "main", Task: "main"}}
	r := StatedWorkspaceResolver{Fallback: fb}
	got, err := r.ResolveStated(t.Context(), StatedWorkspace{Cwd: "/c"})
	if err != nil || got != fb.ws || fb.dir != "/c" {
		t.Fatalf("got %+v, %v, dir %q", got, err, fb.dir)
	}
}

func TestStatedWorkspaceResolverRefusesAStatementWithNothingToResolve(t *testing.T) {
	r := StatedWorkspaceResolver{Fallback: &fakeWorkspaceResolver{}}
	if _, err := r.ResolveStated(t.Context(), StatedWorkspace{}); !errors.Is(err, errDirectoryNotStated) {
		t.Fatalf("err = %v, want errDirectoryNotStated", err)
	}
}

// SPDX-License-Identifier: Apache-2.0

package gateway

// workspace_test.go — ADR-0071: the core reads no client tree, so a statement
// that names only a directory is refused by name rather than resolved through
// a projects mount the core does not have.

import (
	"strings"
	"testing"
)

func TestDirectoryOnlyStatementsAreRefusedByName(t *testing.T) {
	ws, err := NoTreeResolver{}.Resolve(t.Context(), "/srv/example")
	if err == nil {
		t.Fatalf("a directory resolved to %+v; the core reads no client tree", ws)
	}
	if ws != (Workspace{}) {
		t.Errorf("a refusal carried a workspace: %+v", ws)
	}
	for _, want := range []string{"/srv/example", "ADR-0071", "innsegl hook session"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not contain %q", err, want)
		}
	}
}

func TestAStatedWorkspaceNeedsNoTree(t *testing.T) {
	r := StatedWorkspaceResolver{Fallback: NoTreeResolver{}}
	got, err := r.ResolveStated(t.Context(), StatedWorkspace{Cwd: "/c", Repo: "github.com/o/r", Branch: "b", Task: "t"})
	if err != nil || got != (Workspace{Repo: "github.com/o/r", Branch: "b", Task: "t"}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := r.ResolveStated(t.Context(), StatedWorkspace{Cwd: "/c"}); err == nil {
		t.Fatal("a cwd-only statement resolved without a tree to read")
	}
}

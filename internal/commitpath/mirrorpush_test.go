// SPDX-License-Identifier: Apache-2.0

package commitpath_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mirror"
)

// What a hosted client pushes to the core's mirror besides a commit's
// staging objects: its branch (#465) and its workspace snapshots (#467).
// The core here is the real receive endpoint over a real mirror, behind a
// stand-in for the client service.

const (
	mpInstallation = "0123456789abcdef0123456789abcdef"
	mpRepo         = "github.com/acme/widgets"
	mpToolUseID    = "toolu_01mirrorpushfixture"
)

type mpAllow struct{}

func (mpAllow) InScope(context.Context, string, string) (bool, error) { return true, nil }

func mpCore(t *testing.T) (*httptest.Server, *mirror.Store) {
	t.Helper()
	store, err := mirror.New(filepath.Join(t.TempDir(), "mirror"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := mirror.NewHandler(mirror.HandlerConfig{
		Store: store, Scope: mpAllow{},
		Installation: func(context.Context) (string, bool) { return mpInstallation, true },
		Refuse:       func(w http.ResponseWriter) { http.Error(w, "refused", http.StatusUnauthorized) },
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_client/status", func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(map[string]string{"installation_id": mpInstallation}); err != nil {
			t.Error(err)
		}
	})
	mux.Handle(commitpath.GitPathPrefix, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

func mpGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@innsegl.invalid",
		"GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@innsegl.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// mpRepoDir is a client checkout with an origin and one commit.
func mpRepoDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mpGit(t, dir, "init", "-q", "-b", "main")
	mpGit(t, dir, "remote", "add", "origin", "https://"+mpRepo+".git")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mpGit(t, dir, "add", "a.txt")
	mpGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	return dir
}

func mpRef(t *testing.T, store *mirror.Store, ref string) string {
	t.Helper()
	dir, err := store.Dir(mpRepo)
	if err != nil {
		return ""
	}
	out, err := exec.CommandContext(t.Context(), "git", "-C", dir, "rev-parse", "--verify", "--quiet", ref).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// SNAP-006: the branch reaches the core's mirror under its own name.
func TestSNAP006PushBranchSendsTheBranchToTheMirror(t *testing.T) {
	srv, store := mpCore(t)
	dir := mpRepoDir(t)
	head := mpGit(t, dir, "rev-parse", "HEAD")
	c := commitpath.Client{BaseURL: srv.URL}
	if err := c.PushBranch(t.Context(), dir, "main", head); err != nil {
		t.Fatalf("PushBranch: %v", err)
	}
	if got := mpRef(t, store, "refs/heads/main"); got != head {
		t.Fatalf("mirror's main = %q, want %s", got, head)
	}
	if err := c.PushBranch(t.Context(), dir, "", head); err == nil {
		t.Fatal("PushBranch accepted no branch")
	}
	if err := c.PushBranch(t.Context(), dir, "main", "not-an-oid"); err == nil {
		t.Fatal("PushBranch accepted a malformed commit")
	}
	// Against the single-host core (https) nothing is pushed.
	if err := (commitpath.Client{BaseURL: "https://127.0.0.1:1"}).PushBranch(t.Context(), dir, "main", head); err != nil {
		t.Fatalf("PushBranch against a single-host core: %v, want nothing done", err)
	}
}

// SNAP-007: a snapshot is taken with a private index into a private store,
// so the repository's own index, objects and refs are untouched, and is
// pushed to the installation's snapshot ref for the tool call.
func TestSNAP007ASnapshotLeavesTheRepositoryUntouchedAndReachesTheMirror(t *testing.T) {
	srv, store := mpCore(t)
	dir := mpRepoDir(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("edited by a tool\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.txt"), []byte("created by a tool\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(dir, ".git")
	indexBefore, err := os.ReadFile(filepath.Join(gitDir, "index"))
	if err != nil {
		t.Fatal(err)
	}
	objectsBefore := mpGit(t, dir, "count-objects", "-v")
	refsBefore := mpGit(t, dir, "for-each-ref")

	snap, err := commitpath.TakeSnapshot(t.Context(), dir)
	if err != nil {
		t.Fatalf("TakeSnapshot: %v", err)
	}

	indexAfter, err := os.ReadFile(filepath.Join(gitDir, "index"))
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("the repository's own index changed")
	}
	if got := mpGit(t, dir, "count-objects", "-v"); got != objectsBefore {
		t.Fatalf("the repository's own objects changed:\n%s\nwant\n%s", got, objectsBefore)
	}
	if got := mpGit(t, dir, "for-each-ref"); got != refsBefore {
		t.Fatalf("the repository's refs changed:\n%s", got)
	}
	if mpGit(t, dir, "status", "--porcelain") == "" {
		t.Fatal("the working tree's changes are gone")
	}

	c := commitpath.Client{BaseURL: srv.URL}
	if perr := c.PushSnapshot(t.Context(), dir, snap, mpToolUseID); perr != nil {
		t.Fatalf("PushSnapshot: %v", perr)
	}
	tree, held, err := store.SnapshotTree(t.Context(), mpRepo, mpInstallation, mpToolUseID)
	if err != nil || !held || tree != snap.Tree {
		t.Fatalf("SnapshotTree = %q %v %v, want %s", tree, held, err, snap.Tree)
	}
	// The tree is the working tree as the tool left it.
	dirMirror, err := store.Dir(mpRepo)
	if err != nil {
		t.Fatal(err)
	}
	if got := mpGit(t, dirMirror, "show", tree+":new.txt"); got != "created by a tool" {
		t.Fatalf("the snapshot's new.txt = %q", got)
	}

	// The same snapshot taken again is the same commit: nothing changed.
	again, err := commitpath.TakeSnapshot(t.Context(), dir)
	if err != nil || again.Commit != snap.Commit {
		t.Fatalf("a second snapshot of the same tree = %+v %v, want commit %s", again, err, snap.Commit)
	}
	if err := c.PushSnapshot(t.Context(), dir, snap, "nope"); err == nil {
		t.Fatal("PushSnapshot accepted a malformed tool call id")
	}
	if _, err := commitpath.TakeSnapshot(t.Context(), t.TempDir()); err == nil {
		t.Fatal("TakeSnapshot outside a repository succeeded")
	}
}

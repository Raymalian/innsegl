// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// The core's receive endpoint and per-repository mirror (#464, ADR-0065).
// Every push below is made by the real git binary over smart HTTP, against
// the real handler: a fake of git's wire protocol would prove nothing about
// what git actually sends.

const (
	tRepo         = "github.com/acme/widgets"
	tOtherRepo    = "github.com/acme/elsewhere"
	tInstallation = "0123456789abcdef0123456789abcdef"
	tOtherInst    = "fedcba9876543210fedcba9876543210"
	tToolUseID    = "toolu_01mirrortestabcdefghij"
)

// tGit runs git in dir with no system or global configuration.
func tGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := tGitErr(t, dir, args...)
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return out
}

func tGitErr(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-global-gitconfig"),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@innsegl.invalid",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@innsegl.invalid",
		"GIT_TERMINAL_PROMPT=0",
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost",
	)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// clientRepo is a client's checkout: one commit, and a second change staged
// whose tree exists only here.
func clientRepo(t *testing.T) (dir, commit, tree string) {
	t.Helper()
	dir = t.TempDir()
	tGit(t, dir, "init", "-q", "-b", "main")
	tGit(t, dir, "remote", "add", "origin", "https://"+tRepo+".git")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tGit(t, dir, "add", "a.txt")
	tGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tGit(t, dir, "add", "a.txt")
	tree = tGit(t, dir, "write-tree")
	commit = tGit(t, dir, "commit-tree", "--no-gpg-sign", "-p", "HEAD", "-m", "staging", tree)
	return dir, commit, tree
}

// scope answers in-scope for exactly one installation and repository.
type scope struct {
	installation, repo string
	err                error
}

func (s scope) InScope(_ context.Context, installation, repo string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return installation == s.installation && repo == s.repo, nil
}

type installationKey struct{}

// served is the handler behind a stand-in for the client guard: the
// installation the request carries is the one the test put on it.
func served(t *testing.T, store *Store, installation string, sc ScopeChecker, maxBytes int64) *httptest.Server {
	t.Helper()
	h, err := NewHandler(HandlerConfig{
		Store: store, Scope: sc, MaxBytes: maxBytes,
		Installation: func(ctx context.Context) (string, bool) {
			id, ok := ctx.Value(installationKey{}).(string)
			return id, ok && id != ""
		},
		Refuse: func(w http.ResponseWriter) { http.Error(w, "innsegl core: request refused", http.StatusUnauthorized) },
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if installation != "" {
			r = r.WithContext(context.WithValue(r.Context(), installationKey{}, installation))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "mirror"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func remoteURL(srv *httptest.Server, repo string) string {
	return srv.URL + commitpath.GitPathPrefix + repo + ".git"
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func refIn(t *testing.T, store *Store, ref string) (string, bool) {
	t.Helper()
	dir, err := store.Dir(tRepo)
	if err != nil {
		return "", false
	}
	out, err := tGitErr(t, dir, "rev-parse", "--verify", "--quiet", ref)
	return out, err == nil
}

func TestAnInScopeInstallationPushesAStagingRef(t *testing.T) {
	store := newStore(t)
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
	dir, commit, tree := clientRepo(t)
	ref := commitpath.StagingRef(tInstallation, tToolUseID)

	if out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tRepo), "+"+commit+":"+ref); err != nil {
		t.Fatalf("push of a staging ref was refused: %v: %s", err, out)
	}
	got, ok := refIn(t, store, ref)
	if !ok || got != commit {
		t.Fatalf("mirror's %s = %q (present %v), want %s", ref, got, ok, commit)
	}
	missing, err := store.Missing(t.Context(), tRepo, []string{tree, commit})
	if err != nil || len(missing) != 0 {
		t.Fatalf("Missing after the push = %v, %v; want none", missing, err)
	}

	// The same tool call's ref may be pushed again (an amend in the same
	// call): it is staging, not history.
	tGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "second")
	again := tGit(t, dir, "commit-tree", "--no-gpg-sign", "-m", "staging", tGit(t, dir, "write-tree"))
	if out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tRepo), "+"+again+":"+ref); err != nil {
		t.Fatalf("re-push of the same staging ref was refused: %v: %s", err, out)
	}
}

func TestTheMirrorRefusesEveryOtherPush(t *testing.T) {
	for _, tc := range []struct {
		name, ref string
	}{
		{"a branch", "refs/heads/main"},
		{"a tag", "refs/tags/v1"},
		{"another installation's staging ref", commitpath.StagingRef(tOtherInst, tToolUseID)},
		{"a staging ref with no tool call id", "refs/innsegl/staging/" + tInstallation + "/not-a-tool-call"},
		{"a staging ref one level too deep", commitpath.StagingRef(tInstallation, tToolUseID) + "/x"},
		{"another innsegl namespace", "refs/innsegl/other/" + tInstallation + "/" + tToolUseID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
			dir, commit, _ := clientRepo(t)
			out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tRepo), "+"+commit+":"+tc.ref)
			if err == nil {
				t.Fatalf("push to %s was accepted: %s", tc.ref, out)
			}
			if !strings.Contains(out, "403") {
				t.Fatalf("push to %s failed, but not with the endpoint's 403: %s", tc.ref, out)
			}
			if _, ok := refIn(t, store, tc.ref); ok {
				t.Fatalf("%s exists in the mirror after a refused push", tc.ref)
			}
		})
	}
}

func TestTheMirrorRefusesADelete(t *testing.T) {
	store := newStore(t)
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
	dir, commit, _ := clientRepo(t)
	ref := commitpath.StagingRef(tInstallation, tToolUseID)
	tGit(t, dir, "push", "--no-verify", remoteURL(srv, tRepo), "+"+commit+":"+ref)

	if out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tRepo), ":"+ref); err == nil || !strings.Contains(out, "403") {
		t.Fatalf("a delete was not refused with the endpoint's 403: %v: %s", err, out)
	}
	if _, ok := refIn(t, store, ref); !ok {
		t.Fatal("the staging ref is gone after a refused delete")
	}
}

func TestTheEndpointRefusesWithTheGuardsOneRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, installation, repo string
	}{
		{"no installation", "", tRepo},
		{"a repository outside the installation's scope", tInstallation, tOtherRepo},
		{"another installation", tOtherInst, tRepo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			srv := served(t, store, tc.installation, scope{tInstallation, tRepo, nil}, 0)
			status, body := get(t, remoteURL(srv, tc.repo)+"/info/refs?service=git-receive-pack")
			if status != http.StatusUnauthorized || !strings.Contains(body, "innsegl core: request refused") {
				t.Fatalf("advertisement: %d %q, want the guard's 401", status, body)
			}
			dir, commit, _ := clientRepo(t)
			if out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tc.repo),
				"+"+commit+":"+commitpath.StagingRef(tInstallation, tToolUseID)); err == nil {
				t.Fatalf("push accepted: %s", out)
			}
			if _, err := store.Dir(tc.repo); err == nil {
				t.Fatal("a refused request created a mirror")
			}
		})
	}
}

func TestTheEndpointAnswers503WhenScopeCannotBeRead(t *testing.T) {
	srv := served(t, newStore(t), tInstallation, scope{err: errors.New("db down")}, 0)
	if status, _ := get(t, remoteURL(srv, tRepo)+"/info/refs?service=git-receive-pack"); status != http.StatusServiceUnavailable {
		t.Fatalf("scope outage: %d, want 503", status)
	}
}

func TestTheEndpointServesNoFetch(t *testing.T) {
	srv := served(t, newStore(t), tInstallation, scope{tInstallation, tRepo, nil}, 0)
	if status, _ := get(t, remoteURL(srv, tRepo)+"/info/refs?service=git-upload-pack"); status != http.StatusForbidden {
		t.Fatalf("upload-pack advertisement: %d, want 403", status)
	}
	for _, path := range []string{"/git-upload-pack", "/HEAD", "/objects/info/packs"} {
		if status, _ := get(t, remoteURL(srv, tRepo)+path); status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: %d, want 404 or 405", path, status)
		}
	}
}

func TestTheEndpointRefusesARepositoryThatIsNotAnIdentifier(t *testing.T) {
	srv := served(t, newStore(t), tInstallation, scope{tInstallation, tRepo, nil}, 0)
	for _, repo := range []string{"github.com/acme", "GitHub.com/acme/widgets", "github.com/../widgets", "github.com/acme/widgets/extra"} {
		if status, _ := get(t, remoteURL(srv, repo)+"/info/refs?service=git-receive-pack"); status == http.StatusOK {
			t.Errorf("%s: advertised", repo)
		}
	}
}

func TestThePushIsBounded(t *testing.T) {
	store := newStore(t)
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 256)
	dir, commit, _ := clientRepo(t)
	ref := commitpath.StagingRef(tInstallation, tToolUseID)
	if out, err := tGitErr(t, dir, "push", "--no-verify", remoteURL(srv, tRepo), "+"+commit+":"+ref); err == nil {
		t.Fatalf("a push over the bound was accepted: %s", out)
	} else {
		t.Logf("over the bound: %s", out)
	}
	if _, ok := refIn(t, store, ref); ok {
		t.Fatal("a push over the bound wrote its ref")
	}
}

func TestTheMirrorRunsNoHooks(t *testing.T) {
	store := newStore(t)
	dir, err := store.Ensure(t.Context(), tRepo)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "hook-ran")
	hook := filepath.Join(dir, "hooks", "pre-receive")
	if werr := os.WriteFile(hook, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); werr != nil {
		t.Fatal(werr)
	}
	srv := served(t, store, tInstallation, scope{tInstallation, tRepo, nil}, 0)
	client, commit, _ := clientRepo(t)
	tGit(t, client, "push", "--no-verify", remoteURL(srv, tRepo), "+"+commit+":"+commitpath.StagingRef(tInstallation, tToolUseID))
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("a hook in the mirror ran on push")
	}
}

func TestStoreDirMissingAndDropStaging(t *testing.T) {
	store := newStore(t)
	if _, err := store.Dir(tRepo); !errors.Is(err, ErrNoMirror) {
		t.Fatalf("Dir before any push: %v, want ErrNoMirror", err)
	}
	if _, err := store.Dir("not/a"); err == nil {
		t.Fatal("Dir accepted a malformed repository")
	}
	if _, err := store.Ensure(t.Context(), "../x/y"); err == nil {
		t.Fatal("Ensure accepted a malformed repository")
	}
	bare, err := store.Ensure(t.Context(), tRepo)
	if err != nil {
		t.Fatal(err)
	}
	if again, aerr := store.Ensure(t.Context(), tRepo); aerr != nil || again != bare {
		t.Fatalf("Ensure twice: %q %v, want %q", again, aerr, bare)
	}
	if got, derr := store.Dir(tRepo); derr != nil || got != bare {
		t.Fatalf("Dir = %q %v, want %q", got, derr, bare)
	}
	if !strings.HasPrefix(bare, store.Root()) {
		t.Fatalf("mirror %s is outside the root %s", bare, store.Root())
	}

	client, commit, tree := clientRepo(t)
	missing, err := store.Missing(t.Context(), tRepo, []string{tree, commit})
	if err != nil || len(missing) != 2 {
		t.Fatalf("Missing before a push = %v %v, want both", missing, err)
	}
	if _, merr := store.Missing(t.Context(), tRepo, []string{"not-an-oid"}); merr == nil {
		t.Fatal("Missing accepted a malformed object id")
	}

	ref := commitpath.StagingRef(tInstallation, tToolUseID)
	tGit(t, client, "push", "--no-verify", bare, "+"+commit+":"+ref)
	if derr := store.DropStaging(t.Context(), tRepo, tInstallation, tToolUseID); derr != nil {
		t.Fatalf("DropStaging: %v", derr)
	}
	if _, ok := refIn(t, store, ref); ok {
		t.Fatal("the staging ref survived DropStaging")
	}
	if derr := store.DropStaging(t.Context(), tRepo, tInstallation, tToolUseID); derr != nil {
		t.Fatalf("DropStaging of an absent ref: %v", derr)
	}
	if derr := store.DropStaging(t.Context(), tRepo, tInstallation, "nope"); derr == nil {
		t.Fatal("DropStaging accepted a malformed tool call id")
	}
}

func TestNewRefusesNoRoot(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New accepted an empty root")
	}
	if _, err := NewHandler(HandlerConfig{}); err == nil {
		t.Fatal("NewHandler accepted an empty configuration")
	}
}

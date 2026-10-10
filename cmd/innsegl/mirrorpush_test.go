// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mirror"
)

// #465 and #467 on the client: a linked repository's branch reaches the
// core's mirror after a signed commit and at session end (SNAP-006), and a
// workspace snapshot after each tool call (SNAP-007). Neither ever holds up
// the commit or the tool call: the push runs in a process of its own.

// slowCore is a fake client service in front of the REAL receive endpoint
// over a real mirror. Once armed, every git request waits delay first, so a
// push that blocked its caller would show in the caller's time.
type slowCore struct {
	srv   *httptest.Server
	store *mirror.Store
	armed atomic.Bool
	gits  atomic.Int64
	delay time.Duration
}

func newSlowCore(t *testing.T, delay time.Duration) *slowCore {
	t.Helper()
	store, err := mirror.New(filepath.Join(t.TempDir(), "mirror"))
	if err != nil {
		t.Fatal(err)
	}
	c := &slowCore{store: store, delay: delay}
	h, err := mirror.NewHandler(mirror.HandlerConfig{
		Store: store, Scope: allowAll{},
		Installation: func(context.Context) (string, bool) { return pushInstallation, true },
		Refuse:       func(w http.ResponseWriter) { http.Error(w, "refused", http.StatusUnauthorized) },
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(client.StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(w).Encode(client.Status{InstallationID: pushInstallation}); err != nil {
			t.Errorf("fake core: %v", err)
		}
	})
	mux.Handle(commitpath.GitPathPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.gits.Add(1)
		if c.armed.Load() {
			time.Sleep(c.delay)
		}
		h.ServeHTTP(w, r)
	}))
	mux.HandleFunc(commitpath.SignPath, func(w http.ResponseWriter, _ *http.Request) {
		// Every git request after the signature is the post-commit push.
		c.armed.Store(true)
		if err := json.NewEncoder(w).Encode(commitpath.SignResponse{
			Signature: []byte("innsegl-fake-signature-push"),
			Status:    []byte("[GNUPG:] SIG_CREATED S 0 9 00 0 1 0 x\n"),
		}); err != nil {
			t.Errorf("fake core: %v", err)
		}
	})
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *slowCore) ref(t *testing.T, ref string) string {
	t.Helper()
	dir, err := c.store.Dir(pushRepo)
	if err != nil {
		return ""
	}
	out, err := exec.CommandContext(t.Context(), "git", "-C", dir, "rev-parse", "--verify", "--quiet", ref).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// waitRef waits for the mirror's ref to read want.
func (c *slowCore) waitRef(t *testing.T, ref, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if c.ref(t, ref) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the mirror's %s = %q after %v, want %s", ref, c.ref(t, ref), within, want)
}

// installPostCommit writes the post-commit hook `innsegl link` installs,
// pointing at this test binary in helper mode.
func installPostCommit(t *testing.T, dir string) {
	t.Helper()
	bin := signHelperBinary(t)
	hook := filepath.Join(dir, ".git", "hooks", "post-commit")
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte(linkPostCommitScript(bin, hook+linkPreviousSuffix)), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSNAP006LinkInstallsAPostCommitHookAndRemoveRestoresWhatWasThere(t *testing.T) {
	repo, _ := linkRepo(t)
	hook := filepath.Join(repo, ".git", "hooks", "post-commit")
	const original = "#!/bin/sh\necho mine\n"
	if err := os.WriteFile(hook, []byte(original), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: exit %d: %s", code, stderr)
	}
	body, err := os.ReadFile(hook)
	if err != nil || !strings.Contains(string(body), linkPostCommitMarker) {
		t.Fatalf("post-commit after link = %q %v, want innsegl's hook", body, err)
	}
	if kept, kerr := os.ReadFile(hook + linkPreviousSuffix); kerr != nil || string(kept) != original {
		t.Fatalf("the repository's own post-commit hook was not kept aside: %q %v", kept, kerr)
	}
	for _, want := range []string{"git-hook post-commit", `"$@"`, linkPreviousSuffix} {
		if !strings.Contains(string(body), want) {
			t.Errorf("post-commit does not contain %q:\n%s", want, body)
		}
	}
	if code, _, stderr := runLink(t, "-remove", repo); code != exitOK {
		t.Fatalf("innsegl link -remove: exit %d: %s", code, stderr)
	}
	if got, gerr := os.ReadFile(hook); gerr != nil || string(got) != original {
		t.Fatalf("post-commit after -remove = %q %v, want the original", got, gerr)
	}
}

// A repository linked before this hook existed gains it the next time the
// session hook sees it.
func TestSNAP006LinkEnsureAddsThePostCommitHookToARepositoryLinkedBefore(t *testing.T) {
	repo, _ := linkRepo(t)
	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: exit %d: %s", code, stderr)
	}
	hook := filepath.Join(repo, ".git", "hooks", "post-commit")
	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}
	installed, err := linkEnsure(t.Context(), repo)
	if err != nil || !installed {
		t.Fatalf("linkEnsure = %v %v, want the missing hook installed", installed, err)
	}
	if body, rerr := os.ReadFile(hook); rerr != nil || !strings.Contains(string(body), linkPostCommitMarker) {
		t.Fatalf("post-commit after linkEnsure = %q %v", body, rerr)
	}
}

// SNAP-006: a signed agent commit's branch reaches the mirror, and the
// commit does not wait for it.
func TestSNAP006ASignedCommitsBranchReachesTheMirrorWithoutHoldingUpTheCommit(t *testing.T) {
	const delay = 15 * time.Second
	bin := signHelperBinary(t)
	dir, env := pushTestRepo(t)
	script := signHelperScript(t, dir, bin)
	installPostCommit(t, dir)
	core := newSlowCore(t, delay)
	env = append(env, linkTestHelperEnv+"=1", "INNSEGL_TOOL_USE_ID="+pushToolUseID,
		"INNSEGL_CORE_URL="+core.srv.URL, "NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")

	start := time.Now()
	if out, err := signAttemptCommit(t, dir, env, script); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	if took := time.Since(start); took >= delay-5*time.Second {
		t.Fatalf("the commit took %v; the push held it up (the core delays every push %v)", took, delay)
	}
	head, err := signGit(t, dir, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	core.waitRef(t, "refs/heads/main", strings.TrimSpace(head), delay+20*time.Second)
}

// SNAP-006: a commit innsegl did not sign -- a person's own -- sends nothing.
func TestSNAP006AnUnsignedCommitSendsNothing(t *testing.T) {
	dir, env := pushTestRepo(t)
	installPostCommit(t, dir)
	core := newSlowCore(t, 0)
	env = append(env, linkTestHelperEnv+"=1", "INNSEGL_CORE_URL="+core.srv.URL,
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
	if out, err := signGit(t, dir, env, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "mine"); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	time.Sleep(2 * time.Second)
	if n := core.gits.Load(); n != 0 {
		t.Fatalf("%d git requests reached the core for a commit innsegl did not sign", n)
	}
}

// sessionEndInput is the harness's SessionEnd hook input for cwd.
func sessionEndInput(cwd string) string {
	return `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","cwd":` + strconv.Quote(cwd) +
		`,"hook_event_name":"SessionEnd"}`
}

// SNAP-006: at session end the branch of a linked repository is pushed; an
// unlinked repository sends nothing.
func TestSNAP006SessionEndPushesALinkedRepositorysBranchOnly(t *testing.T) {
	t.Setenv(linkTestHelperEnv, "1") // the push runs as this binary, in helper mode
	core := newSlowCore(t, 0)
	getenv := env2(map[string]string{commitpath.EnvCoreURL: core.srv.URL})
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	unlinked, _ := pushTestRepo(t)
	_, post := capturePosts(nil)
	if code := runHookSession(strings.NewReader(sessionEndInput(unlinked)), &bytes.Buffer{}, &bytes.Buffer{}, getenv, post); code != exitOK {
		t.Fatalf("hook session exit %d", code)
	}
	time.Sleep(2 * time.Second)
	if n := core.gits.Load(); n != 0 {
		t.Fatalf("%d git requests reached the core from an unlinked repository", n)
	}

	linked, env := pushTestRepo(t)
	if out, err := signGit(t, linked, env, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "work"); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	if code, _, stderr := runLink(t, linked); code != exitOK {
		t.Fatalf("innsegl link: exit %d: %s", code, stderr)
	}
	head, err := signGit(t, linked, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := runHookSession(strings.NewReader(sessionEndInput(linked)), &bytes.Buffer{}, &errOut, getenv, post); code != exitOK {
		t.Fatalf("hook session exit %d: %s", code, errOut.String())
	}
	core.waitRef(t, "refs/heads/main", strings.TrimSpace(head), 20*time.Second)
}

// postToolUseInput is the harness's PostToolUse hook input.
func postToolUseInput(cwd, toolUseID string) string {
	return `{"session_id":"7dc5d783-9896-4aef-84d9-a82114505fff","hook_event_name":"PostToolUse",` +
		`"tool_name":"Write","tool_use_id":` + strconv.Quote(toolUseID) + `,"cwd":` + strconv.Quote(cwd) + `}`
}

// SNAP-007: after a tool call in a linked repository, the workspace as the
// tool left it reaches the mirror as that tool call's snapshot ref; the
// repository's own index is untouched; an unlinked repository sends nothing.
func TestSNAP007AToolCallsSnapshotReachesTheMirrorFromALinkedRepositoryOnly(t *testing.T) {
	t.Setenv(linkTestHelperEnv, "1")
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	core := newSlowCore(t, 0)
	getenv := env2(map[string]string{commitpath.EnvCoreURL: core.srv.URL})

	unlinked, _ := pushTestRepo(t)
	if code := runHookPostToolUse(strings.NewReader(postToolUseInput(unlinked, pushToolUseID)), &bytes.Buffer{}, getenv); code != exitOK {
		t.Fatalf("hook post-tool-use exit %d", code)
	}
	time.Sleep(2 * time.Second)
	if n := core.gits.Load(); n != 0 {
		t.Fatalf("%d git requests reached the core from an unlinked repository", n)
	}

	linked, _ := pushTestRepo(t)
	if code, _, stderr := runLink(t, linked); code != exitOK {
		t.Fatalf("innsegl link: exit %d: %s", code, stderr)
	}
	if err := os.WriteFile(filepath.Join(linked, "tool.txt"), []byte("written by a tool\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(linked, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	var errOut bytes.Buffer
	if code := runHookPostToolUse(strings.NewReader(postToolUseInput(linked, pushToolUseID)), &errOut, getenv); code != exitOK {
		t.Fatalf("hook post-tool-use exit %d: %s", code, errOut.String())
	}
	if after, rerr := os.ReadFile(filepath.Join(linked, ".git", "index")); rerr != nil || !bytes.Equal(after, index) {
		t.Fatal("the repository's own index changed")
	}
	ref := commitpath.SnapshotRef(pushInstallation, pushToolUseID)
	deadline := time.Now().Add(20 * time.Second)
	for core.ref(t, ref) == "" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	tree, held, err := core.store.SnapshotTree(t.Context(), pushRepo, pushInstallation, pushToolUseID)
	if err != nil || !held {
		t.Fatalf("no snapshot in the mirror: %v %v; stderr %s", held, err, errOut.String())
	}
	mdir, err := core.store.Dir(pushRepo)
	if err != nil {
		t.Fatal(err)
	}
	if out, gerr := exec.CommandContext(t.Context(), "git", "-C", mdir, "show", tree+":tool.txt").Output(); gerr != nil ||
		strings.TrimSpace(string(out)) != "written by a tool" {
		t.Fatalf("the snapshot's tool.txt = %q %v", out, gerr)
	}
}

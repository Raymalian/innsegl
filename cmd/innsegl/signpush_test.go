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
	"strings"
	"sync"
	"testing"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mirror"
	"innsegl.dev/innsegl/internal/signing"
)

// #465: on a hosted client, `innsegl sign` pushes the objects the payload
// names to the core's mirror before it asks for a signature, because the core
// computes the change's identity from them and they exist nowhere else.

const (
	pushInstallation = "0123456789abcdef0123456789abcdef"
	pushRepo         = "github.com/acme/widgets"
	pushToolUseID    = "toolu_01signpushfixture"
)

type allowAll struct{}

func (allowAll) InScope(context.Context, string, string) (bool, error) { return true, nil }

// pushCore is a fake hosted core behind a fake client service: the status
// route names the installation, the git route is the REAL receive endpoint
// over a real mirror, and the signing route records whether every object the
// payload names had already arrived when it was asked.
type pushCore struct {
	srv   *httptest.Server
	store *mirror.Store

	mu          sync.Mutex
	order       []string
	signedAfter bool // the objects were in the mirror when the sign request arrived
}

func newPushCore(t *testing.T, gitStatus int) *pushCore {
	t.Helper()
	store, err := mirror.New(filepath.Join(t.TempDir(), "mirror"))
	if err != nil {
		t.Fatal(err)
	}
	c := &pushCore{store: store}
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
		c.note("status")
		if err := json.NewEncoder(w).Encode(client.Status{InstallationID: pushInstallation}); err != nil {
			t.Errorf("fake core: %v", err)
		}
	})
	mux.Handle(commitpath.GitPathPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.note("git " + r.Method)
		if gitStatus != 0 {
			http.Error(w, "down", gitStatus)
			return
		}
		h.ServeHTTP(w, r)
	}))
	mux.HandleFunc(commitpath.SignPath, func(w http.ResponseWriter, r *http.Request) {
		c.note("sign")
		var req commitpath.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("fake core: %v", err)
		}
		parsed, err := signing.ParseCommitPayload(req.Payload)
		if err != nil {
			t.Errorf("fake core: %v", err)
		}
		missing, merr := store.Missing(r.Context(), pushRepo, append([]string{parsed.Tree}, parsed.Parents...))
		dir, derr := store.Dir(pushRepo)
		ref := exec.CommandContext(r.Context(), "git", "-C", dir, "rev-parse", "--verify", "--quiet",
			commitpath.StagingRef(pushInstallation, req.ToolUseID))
		c.mu.Lock()
		c.signedAfter = derr == nil && merr == nil && len(missing) == 0 && ref.Run() == nil
		c.mu.Unlock()
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

func (c *pushCore) note(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order = append(c.order, s)
}

func (c *pushCore) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.order...)
}

// pushTestRepo is a client checkout with an origin, one commit, and a second
// change staged: a commit with a parent, whose tree exists only here.
func pushTestRepo(t *testing.T) (string, []string) {
	t.Helper()
	dir, env := newSignTestRepo(t)
	for _, args := range [][]string{
		{"remote", "add", "origin", "https://" + pushRepo + ".git"},
		{"-c", "commit.gpgsign=false", "commit", "-q", "-m", "base"},
	} {
		if out, err := signGit(t, dir, env, args...); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("second change\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := signGit(t, dir, env, "add", "work.txt"); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	return dir, env
}

func TestSignPushesTheCommitsObjectsBeforeAskingForASignature(t *testing.T) {
	bin := signHelperBinary(t)
	dir, env := pushTestRepo(t)
	script := signHelperScript(t, dir, bin)
	core := newPushCore(t, 0)
	env = append(env, "INNSEGL_TOOL_USE_ID="+pushToolUseID, "INNSEGL_CORE_URL="+core.srv.URL,
		"NO_PROXY=127.0.0.1,localhost", "no_proxy=127.0.0.1,localhost")
	before := signRepoObjects(t, dir, env)

	if out, err := signAttemptCommit(t, dir, env, script); err != nil {
		t.Fatalf("git commit through innsegl sign: %v: %s", err, out)
	}
	if !core.signedAfter {
		t.Fatalf("the core was asked to sign before the payload's objects arrived; requests: %v", core.seen())
	}
	seen := core.seen()
	if len(seen) == 0 || seen[len(seen)-1] != "sign" {
		t.Fatalf("requests %v, want the push before the sign request", seen)
	}

	// The throwaway staging commit is not left in the client's repository:
	// the only new commit is the signed one git wrote.
	head, err := signGit(t, dir, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	for obj, typ := range signRepoObjects(t, dir, env) {
		if typ == "commit" && before[obj] != "commit" && obj != strings.TrimSpace(head) {
			t.Errorf("a commit object %s other than the signed one was left in the client's repository", obj)
		}
	}
}

func TestSignAgainstTheSingleHostCorePushesNothing(t *testing.T) {
	dir, env := pushTestRepo(t)
	t.Chdir(dir)
	var paths []string
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if err := json.NewEncoder(w).Encode(commitpath.SignResponse{Signature: []byte("S"), Status: []byte("[GNUPG:] SIG_CREATED\n")}); err != nil {
			t.Errorf("fake core: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	var stdout, stderr bytes.Buffer
	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "k"}, strings.NewReader(signPushPayload(t, dir, env)),
		&stdout, &stderr, func(k string) string {
			if k == commitpath.EnvToolUseID {
				return pushToolUseID
			}
			return ""
		}, commitpath.Client{BaseURL: srv.URL, HTTP: srv.Client()})
	if code != 0 {
		t.Fatalf("runSign: %d: %s", code, stderr.String())
	}
	if len(paths) != 1 || paths[0] != commitpath.SignPath {
		t.Fatalf("the single-host core saw %v, want only %s", paths, commitpath.SignPath)
	}
}

func TestSignStillAsksTheCoreWhenThePushFails(t *testing.T) {
	dir, env := pushTestRepo(t)
	t.Chdir(dir)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")
	core := newPushCore(t, http.StatusBadGateway)

	var stdout, stderr bytes.Buffer
	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "k"}, strings.NewReader(signPushPayload(t, dir, env)),
		&stdout, &stderr, func(k string) string {
			if k == commitpath.EnvToolUseID {
				return pushToolUseID
			}
			return ""
		}, commitpath.Client{BaseURL: core.srv.URL, HTTP: core.srv.Client()})
	if code != 0 {
		t.Fatalf("runSign: %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "pushing") {
		t.Fatalf("stderr %q does not say the push failed", stderr.String())
	}
	if seen := core.seen(); seen[len(seen)-1] != "sign" {
		t.Fatalf("requests %v: the core was not asked after the push failed", seen)
	}
}

// signPushPayload is the unsigned commit object git would hand its signing
// program for the staged change.
func signPushPayload(t *testing.T, dir string, env []string) string {
	t.Helper()
	tree, err := signGit(t, dir, env, "write-tree")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := signGit(t, dir, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return "tree " + strings.TrimSpace(tree) + "\nparent " + strings.TrimSpace(parent) + "\n" +
		"author A <a@innsegl.invalid> 1700000000 +0000\ncommitter A <a@innsegl.invalid> 1700000000 +0000\n\nmsg\n"
}

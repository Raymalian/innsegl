// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// SNAP-009: the mirror refuses a rewritten branch and keeps its copy (no
// rewrites). The refusal is not silent: the detached push records it once,
// `innsegl status` says the mirror's copy is behind, why, and what to do,
// and the next push the mirror takes clears it.
func TestSNAP009ARefusedBranchIsRecordedAndStatusSaysWhatToDo(t *testing.T) {
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	core := newSlowCore(t, 0)
	dir, env := pushTestRepo(t)
	if out, err := signGit(t, dir, env, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "work"); err != nil {
		t.Fatalf("git commit: %v: %s", err, out)
	}
	head := func() string {
		out, err := signGit(t, dir, env, "rev-parse", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(out)
	}
	deps := statusFixture(t, `[{"name":"ledger","up":true}]`, true)
	t.Setenv("HOME", deps.home)
	paths := client.ClientPaths(deps.home)
	push := func() int {
		var errOut bytes.Buffer
		return runGitHookPushMirror([]string{dir, "branch", core.srv.URL, "main", head()}, &errOut)
	}

	if code := push(); code != exitOK {
		t.Fatalf("first push exit %d", code)
	}
	if out, err := signGit(t, dir, env, "commit", "-q", "--amend", "--no-gpg-sign", "-m", "rewritten"); err != nil {
		t.Fatalf("amend: %v: %s", err, out)
	}
	if code := push(); code == exitOK {
		t.Fatal("the mirror took a rewritten branch")
	}
	time.Sleep(10 * time.Millisecond)
	if code := push(); code == exitOK {
		t.Fatal("the mirror took a rewritten branch")
	}
	behind, err := client.ReadMirrorBehind(paths)
	if err != nil || len(behind) != 1 || behind[0].Repo != pushRepo || behind[0].Branch != "main" {
		t.Fatalf("recorded %+v %v, want main of %s once", behind, err, pushRepo)
	}

	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
		t.Fatalf("status exit %d; a branch behind is a warning, not an outage:\n%s", code, errOut.String())
	}
	for _, want := range []string{"WARN", "main", pushRepo, "behind", "not a fast-forward", "merge"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out.String())
		}
	}

	// Building on the mirror's copy again (here: back to it, then on) clears it.
	if out, rerr := signGit(t, dir, env, "reset", "-q", "--hard", "HEAD@{1}"); rerr != nil {
		t.Fatalf("reset: %v: %s", rerr, out)
	}
	if out, cerr := signGit(t, dir, env, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "on top"); cerr != nil {
		t.Fatalf("commit: %v: %s", cerr, out)
	}
	if code := push(); code != exitOK {
		t.Fatalf("a fast-forward was refused: exit %d", code)
	}
	if behind, err = client.ReadMirrorBehind(paths); err != nil || len(behind) != 0 {
		t.Fatalf("after a push the mirror took: %+v %v, want nothing recorded", behind, err)
	}
}

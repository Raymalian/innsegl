// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// INIT-001 (proposed, doc 07 layer U): `innsegl init` writes and reads
// exactly the repository's --local git configuration, never anything global.
//
// initTestRepo builds a throwaway repository with an isolated HOME and
// GIT_CONFIG_GLOBAL, so a test that "sets global config by mistake" fails
// loudly instead of leaking into the machine running the suite.
func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+filepath.Join(dir, ".gitconfig-global-unused"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "operator@example.com")
	run("config", "user.name", "Operator")
	return dir
}

func TestINIT001LocalConfigRoundTrips(t *testing.T) {
	repo := initTestRepo(t)
	g := newGitLocal("git", repo)
	ctx := context.Background()

	if _, ok, err := g.configGet(ctx, "gpg.format"); err != nil || ok {
		t.Fatalf("configGet on an unset key = (ok=%v, err=%v), want ok=false, err=nil", ok, err)
	}

	if err := g.configSet(ctx, "gpg.format", "x509"); err != nil {
		t.Fatalf("configSet: %v", err)
	}
	got, ok, err := g.configGet(ctx, "gpg.format")
	if err != nil || !ok || got != "x509" {
		t.Fatalf("configGet after configSet = (%q, %v, %v), want (\"x509\", true, nil)", got, ok, err)
	}

	if err := g.configUnset(ctx, "gpg.format"); err != nil {
		t.Fatalf("configUnset: %v", err)
	}
	if _, ok, err := g.configGet(ctx, "gpg.format"); err != nil || ok {
		t.Fatalf("configGet after configUnset = (ok=%v, err=%v), want ok=false, err=nil", ok, err)
	}

	// Unsetting an already-absent key is not an error: --undo must be able to
	// call this twice without failing.
	if err := g.configUnset(ctx, "gpg.format"); err != nil {
		t.Fatalf("configUnset on an absent key: %v, want nil (idempotent)", err)
	}
}

func TestINIT001ConfigListIsLocalOnlyAndSorted(t *testing.T) {
	repo := initTestRepo(t)
	g := newGitLocal("git", repo)
	ctx := context.Background()

	if err := g.configSet(ctx, "innsegl.zzz", "1"); err != nil {
		t.Fatal(err)
	}
	if err := g.configSet(ctx, "innsegl.aaa", "1"); err != nil {
		t.Fatal(err)
	}

	list, err := g.configList(ctx)
	if err != nil {
		t.Fatalf("configList: %v", err)
	}
	var aIdx, zIdx = -1, -1
	for i, line := range list {
		if strings.HasPrefix(line, "innsegl.aaa=") {
			aIdx = i
		}
		if strings.HasPrefix(line, "innsegl.zzz=") {
			zIdx = i
		}
	}
	if aIdx < 0 || zIdx < 0 || aIdx > zIdx {
		t.Fatalf("configList is not sorted: %v", list)
	}
	// The global config this test isolated must never appear: every line is
	// local to this repository.
	for _, line := range list {
		if strings.Contains(line, "gitconfig-global-unused") {
			t.Fatalf("configList leaked global configuration: %v", list)
		}
	}
}

// TestINIT002ApplyAndUndoRestoreTheExactPriorConfig is the acceptance proof
// itself (#117 §Acceptance, third bullet): `git config --local --list` before
// and after --undo must match.
func TestINIT002ApplyAndUndoRestoreTheExactPriorConfig(t *testing.T) {
	repo := initTestRepo(t)
	g := newGitLocal("git", repo)
	ctx := context.Background()

	// The operator already had an opinion about one of the three keys init
	// writes. Undo must restore exactly that opinion, not merely unset it.
	if err := g.configSet(ctx, "commit.gpgsign", "false"); err != nil {
		t.Fatal(err)
	}

	before, err := g.configList(ctx)
	if err != nil {
		t.Fatal(err)
	}

	rec := newGitSigningRecorder(g)
	if applyErr := rec.apply(ctx, gitsignSetup{
		GitsignPath: "/opt/gitsign/gitsign",
	}); applyErr != nil {
		t.Fatalf("apply: %v", applyErr)
	}

	// Applied: the three keys now hold init's values.
	v, ok, gerr := g.configGet(ctx, "gpg.format")
	if gerr != nil || !ok || v != "x509" {
		t.Fatalf("gpg.format = (%q, %v, %v), want (x509, true, nil)", v, ok, gerr)
	}
	v, ok, gerr = g.configGet(ctx, "commit.gpgsign")
	if gerr != nil || !ok || v != "true" {
		t.Fatalf("commit.gpgsign = (%q, %v, %v), want (true, true, nil)", v, ok, gerr)
	}

	// Running apply a second time changes nothing further (idempotency,
	// acceptance bullet one): the backup must not be overwritten by the
	// second run's own values.
	if applyErr := rec.apply(ctx, gitsignSetup{GitsignPath: "/opt/gitsign/gitsign"}); applyErr != nil {
		t.Fatalf("second apply: %v", applyErr)
	}

	rec2, loadErr := loadGitSigningRecorder(ctx, g)
	if loadErr != nil {
		t.Fatalf("loadGitSigningRecorder: %v", loadErr)
	}
	if undoErr := rec2.undo(ctx); undoErr != nil {
		t.Fatalf("undo: %v", undoErr)
	}

	after, err := g.configList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("config --local --list differs after undo.\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

func TestINIT002UndoWithNothingAppliedRefuses(t *testing.T) {
	repo := initTestRepo(t)
	g := newGitLocal("git", repo)
	ctx := context.Background()

	if _, err := loadGitSigningRecorder(ctx, g); err == nil {
		t.Fatal("loadGitSigningRecorder on a repository init never touched: want an error, got nil")
	}
}

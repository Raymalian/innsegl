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
//
// commit.gpgsign is deliberately set here BEFORE apply runs, to the opposite
// of what init once wrote — and apply must leave it exactly alone. Under the
// design settled in #158, init never configures a human's own `git commit` to
// sign (the orchestrator signs, through `sign_commit`, with an identity the
// MCP server issued; the operator never signs as themselves), so
// commit.gpgsign is not one of the keys apply manages at all. This test
// proves that a pre-existing opinion about it — any opinion — survives apply
// untouched, which is a stronger guarantee than "undo restores it": apply
// never had reason to back it up in the first place.
func TestINIT002ApplyAndUndoRestoreTheExactPriorConfig(t *testing.T) {
	repo := initTestRepo(t)
	g := newGitLocal("git", repo)
	ctx := context.Background()

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

	// Applied: the two keys init manages now hold init's values...
	v, ok, gerr := g.configGet(ctx, "gpg.format")
	if gerr != nil || !ok || v != "x509" {
		t.Fatalf("gpg.format = (%q, %v, %v), want (x509, true, nil)", v, ok, gerr)
	}
	// ...and commit.gpgsign — a key init never writes (#158) — is untouched:
	// still the operator's own pre-existing "false", not init's old "true"
	// and not backed-up-and-forced either.
	v, ok, gerr = g.configGet(ctx, "commit.gpgsign")
	if gerr != nil || !ok || v != "false" {
		t.Fatalf("commit.gpgsign after apply = (%q, %v, %v), want (false, true, nil) — "+
			"apply must never write commit.gpgsign (#158)", v, ok, gerr)
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

// TestINIT010ApplyNeverConfiguresCommitToSign is INIT-010 (proposed, doc 07
// layer U, a fresh ID — not editing doc 07 itself; INIT-008/009 are already
// taken by initsignintegration_test.go): the defect #158 names directly.
// `commit.gpgsign=true` demands of a human exactly the credential the
// architecture deliberately never gives them (only the orchestrator signs,
// through `sign_commit`, with an MCP-issued identity) — so on a repository
// with no prior opinion at all, apply must leave commit.gpgsign completely
// unset, while still recording the verified gpg.format / gpg.x509.program
// pair (inert without commit.gpgsign or an explicit `-S`, and worth keeping
// on disk as a record of which pinned, checksummed gitsign this deployment
// trusts).
func TestINIT010ApplyNeverConfiguresCommitToSign(t *testing.T) {
	repo := initTestRepo(t)
	g := newGitLocal("git", repo)
	ctx := context.Background()

	rec := newGitSigningRecorder(g)
	if err := rec.apply(ctx, gitsignSetup{GitsignPath: "/opt/gitsign/gitsign"}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if v, ok, err := g.configGet(ctx, keyGPGFormat); err != nil || !ok || v != "x509" {
		t.Errorf("gpg.format = (%q, %v, %v), want (x509, true, nil)", v, ok, err)
	}
	if v, ok, err := g.configGet(ctx, keyGPGX509Program); err != nil || !ok || v != "/opt/gitsign/gitsign" {
		t.Errorf("gpg.x509.program = (%q, %v, %v), want (/opt/gitsign/gitsign, true, nil)", v, ok, err)
	}
	if _, ok, err := g.configGet(ctx, keyCommitGPGSign); err != nil || ok {
		t.Errorf("commit.gpgsign after apply on a fresh repo = (ok=%v, err=%v), want ok=false: "+
			"init must never configure a human's `git commit` to sign (#158)", ok, err)
	}

	// undo must not need to restore commit.gpgsign either — there was never
	// anything to back up for a key apply never touched.
	rec2, err := loadGitSigningRecorder(ctx, g)
	if err != nil {
		t.Fatalf("loadGitSigningRecorder: %v", err)
	}
	if err := rec2.undo(ctx); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, ok, err := g.configGet(ctx, keyCommitGPGSign); err != nil || ok {
		t.Errorf("commit.gpgsign after undo = (ok=%v, err=%v), want ok=false", ok, err)
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

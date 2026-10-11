// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The ref backstop (#584, CMT-022). The PreToolUse guard reads command text,
// so a script file, plumbing, or a rebase with signing off passes it. The
// reference-transaction hook `innsegl link` installs sees every branch
// update git makes, whatever made it, and in an agent session refuses one
// that would put an unsigned commit on a branch. The operator's own commits
// are left alone.

// reftxFakeSigner writes a stand-in for git's x509 signing program: it
// prints a signature and the status line git waits for. What matters here
// is only that the commit object carries a gpgsig header.
func reftxFakeSigner(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-sign")
	script := "#!/bin/sh\ncat >/dev/null\n" +
		"printf '%s\\n' '-----BEGIN SIGNED MESSAGE-----' 'CMT022' '-----END SIGNED MESSAGE-----'\n" +
		"echo '[GNUPG:] SIG_CREATED S 0 9 00 0 1 0 cmt022' >&2\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// reftxRepo is a linked repository with one signed commit on main, its
// reference-transaction hook running this test binary as the real CLI.
// It returns the repository, git, the operator's environment and an agent
// session's environment.
func reftxRepo(t *testing.T) (repo, git string, operator, agent []string, signer string) {
	t.Helper()
	git = ghGitOrSkip(t)
	repo, env := linkRepo(t)
	signer = reftxFakeSigner(t)
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")
	ghRun(t, git, repo, env, "-c", "commit.gpgsign=true", "-c", "gpg.format=x509",
		"-c", "gpg.x509.program="+signer, "commit", "-q", "-m", "one")

	bin, err := innseglBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(repo, ".git", "hooks", "reference-transaction")
	if err := os.WriteFile(hook, []byte(linkRefTxScript(bin, hook+linkPreviousSuffix)), 0o755); err != nil {
		t.Fatal(err)
	}
	operator = append(append([]string{}, env...), linkTestHelperEnv+"=1")
	agent = append(append([]string{}, operator...), envAgentSession+"=1")
	return repo, git, operator, agent, signer
}

// reftxGit runs git and returns its combined output and whether it succeeded.
func reftxGit(t *testing.T, git, dir string, env []string, args ...string) (string, bool) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), git, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func reftxRev(t *testing.T, git, repo string, env []string, rev string) string {
	t.Helper()
	return strings.TrimSpace(ghRun(t, git, repo, env, "rev-parse", rev))
}

// reftxUnsignedCommit makes an unsigned commit on top of HEAD the way a
// script would, with plumbing that never touches a ref.
func reftxUnsignedCommit(t *testing.T, git, repo string, env []string) string {
	t.Helper()
	tree := strings.TrimSpace(ghRun(t, git, repo, env, "rev-parse", "HEAD^{tree}"))
	return strings.TrimSpace(ghRun(t, git, repo, env, "commit-tree", "-p", "HEAD", "-m", "by a script", tree))
}

// CMT-022: a script's commit-tree + update-ref, in an agent session, is
// refused, and the branch stays where it was.
func TestCMT022ScriptUpdateRefToAnUnsignedCommitIsRefused(t *testing.T) {
	repo, git, _, agent, _ := reftxRepo(t)
	before := reftxRev(t, git, repo, agent, "main")
	unsigned := reftxUnsignedCommit(t, git, repo, agent)

	out, ok := reftxGit(t, git, repo, agent, "update-ref", "refs/heads/main", unsigned)
	if ok {
		t.Fatalf("update-ref to an unsigned commit succeeded in an agent session:\n%s", out)
	}
	if !strings.Contains(out, "not signed") || !strings.Contains(out, unsigned[:12]) {
		t.Errorf("refusal does not name the unsigned commit:\n%s", out)
	}
	if !strings.Contains(out, "do not retry with signing off") {
		t.Errorf("refusal does not tell the agent not to turn signing off:\n%s", out)
	}
	if got := reftxRev(t, git, repo, agent, "main"); got != before {
		t.Errorf("main moved to %s; want it left at %s", got, before)
	}

	// A new branch at that commit is a branch update too.
	if out, ok := reftxGit(t, git, repo, agent, "branch", "side", unsigned); ok {
		t.Errorf("a new branch at an unsigned commit was created:\n%s", out)
	}
}

// CMT-022: a rebase with signing turned off, in an agent session, is
// refused and the branch keeps its signed commits.
func TestCMT022RebaseWithSigningOffIsRefused(t *testing.T) {
	repo, git, _, agent, signer := reftxRepo(t)
	signing := []string{"-c", "commit.gpgsign=true", "-c", "gpg.format=x509", "-c", "gpg.x509.program=" + signer}
	ghRun(t, git, repo, agent, "checkout", "-q", "-b", "topic")
	if err := os.WriteFile(filepath.Join(repo, "b.txt"), []byte("b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, agent, "add", "b.txt")
	ghRun(t, git, repo, agent, append(signing, "commit", "-q", "-m", "two")...)
	before := reftxRev(t, git, repo, agent, "topic")

	out, ok := reftxGit(t, git, repo, agent, "rebase", "--no-gpg-sign", "--force-rebase", "main")
	if ok {
		t.Fatalf("a rebase with signing off moved the branch in an agent session:\n%s", out)
	}
	if !strings.Contains(out, "not signed") {
		t.Errorf("refusal does not say why:\n%s", out)
	}
	_, _ = reftxGit(t, git, repo, agent, "rebase", "--abort")
	if got := reftxRev(t, git, repo, agent, "topic"); got != before {
		t.Errorf("topic moved to %s; want it left at %s", got, before)
	}
}

// CMT-022: signed commits pass, and so do branch moves that bring no new
// commit (a new branch at an existing commit, a reset, a delete).
func TestCMT022SignedUpdatesPass(t *testing.T) {
	repo, git, _, agent, signer := reftxRepo(t)
	signing := []string{"-c", "commit.gpgsign=true", "-c", "gpg.format=x509", "-c", "gpg.x509.program=" + signer}
	if err := os.WriteFile(filepath.Join(repo, "c.txt"), []byte("c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, agent, "add", "c.txt")
	if out, ok := reftxGit(t, git, repo, agent, append(signing, "commit", "-q", "-m", "signed")...); !ok {
		t.Fatalf("a signed commit was refused:\n%s", out)
	}
	ghRun(t, git, repo, agent, "branch", "copy", "HEAD~1")
	ghRun(t, git, repo, agent, "reset", "-q", "--hard", "HEAD~1")
	ghRun(t, git, repo, agent, "branch", "-D", "copy")

	// A signed rebase passes too.
	ghRun(t, git, repo, agent, "checkout", "-q", "-b", "topic")
	if err := os.WriteFile(filepath.Join(repo, "d.txt"), []byte("d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, agent, "add", "d.txt")
	ghRun(t, git, repo, agent, append(signing, "commit", "-q", "-m", "d")...)
	if out, ok := reftxGit(t, git, repo, agent, append(signing, "rebase", "--force-rebase", "main")...); !ok {
		t.Fatalf("a signed rebase was refused:\n%s", out)
	}
}

// CMT-022, operator decision 6: outside an agent session the operator's own
// unsigned commits are unchanged.
func TestCMT022TheOperatorsOwnCommitsPass(t *testing.T) {
	repo, git, operator, _, _ := reftxRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "o.txt"), []byte("o\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, operator, "add", "o.txt")
	if out, ok := reftxGit(t, git, repo, operator, "commit", "-q", "-m", "operator, unsigned"); !ok {
		t.Fatalf("the operator's own unsigned commit was refused:\n%s", out)
	}
	unsigned := reftxUnsignedCommit(t, git, repo, operator)
	if out, ok := reftxGit(t, git, repo, operator, "update-ref", "refs/heads/main", unsigned); !ok {
		t.Fatalf("the operator's own update-ref was refused:\n%s", out)
	}
}

// An unsigned commit already on a remote-tracking branch is published
// history, not a new commit: a branch created from it passes.
func TestCMT022PublishedUnsignedHistoryIsNotNew(t *testing.T) {
	repo, git, operator, agent, _ := reftxRepo(t)
	unsigned := reftxUnsignedCommit(t, git, repo, operator)
	ghRun(t, git, repo, operator, "update-ref", "refs/remotes/origin/main", unsigned)
	if out, ok := reftxGit(t, git, repo, agent, "branch", "from-origin", "origin/main"); !ok {
		t.Fatalf("a branch at published history was refused:\n%s", out)
	}
}

// A hook the repository had is kept and still runs, with the same input.
func TestCMT022APreviousReferenceTransactionHookStillRuns(t *testing.T) {
	repo, git, operator, agent, signer := reftxRepo(t)
	hook := filepath.Join(repo, ".git", "hooks", "reference-transaction")
	seen := filepath.Join(t.TempDir(), "seen")
	prev := "#!/bin/sh\necho \"$1\" >> '" + seen + "'\ncat >> '" + seen + "'\n"
	if err := os.WriteFile(hook+linkPreviousSuffix, []byte(prev), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "p.txt"), []byte("p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, operator, "add", "p.txt")
	ghRun(t, git, repo, agent, "-c", "commit.gpgsign=true", "-c", "gpg.format=x509",
		"-c", "gpg.x509.program="+signer, "commit", "-q", "-m", "p")
	got, err := os.ReadFile(seen)
	if err != nil {
		t.Fatalf("the previous hook did not run: %v", err)
	}
	if !strings.Contains(string(got), "prepared") || !strings.Contains(string(got), "refs/heads/main") {
		t.Errorf("the previous hook did not get git's arguments and input:\n%s", got)
	}
}

// `innsegl link` installs the backstop beside the other hooks, and removes it.
func TestCMT022LinkInstallsAndRemovesTheBackstop(t *testing.T) {
	repo, _ := linkRepo(t)
	hook := filepath.Join(repo, ".git", "hooks", "reference-transaction")
	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: exit %d: %s", code, stderr)
	}
	body, err := os.ReadFile(hook)
	if err != nil {
		t.Fatalf("no reference-transaction hook after link: %v", err)
	}
	if !strings.Contains(string(body), linkRefTxMarker) {
		t.Errorf("the hook is not innsegl's:\n%s", body)
	}
	if code, _, stderr := runLink(t, "-remove", repo); code != exitOK {
		t.Fatalf("innsegl link -remove: exit %d: %s", code, stderr)
	}
	if _, err := os.Stat(hook); !os.IsNotExist(err) {
		t.Errorf("the hook is still there after -remove: %v", err)
	}
}

func TestLinkRefTxScriptIsPOSIXShOnly(t *testing.T) {
	script := linkRefTxScript("/opt/innsegl/bin/innsegl", "/repo/.git/hooks/reference-transaction.innsegl-previous")
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Fatalf("no POSIX sh shebang: %q", script)
	}
	for _, bashism := range []string{"[[", "local ", "function ", "bash", "=~", "((", "declare ", "<<<"} {
		if strings.Contains(script, bashism) {
			t.Errorf("script contains %q:\n%s", bashism, script)
		}
	}
}

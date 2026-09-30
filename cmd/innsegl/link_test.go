// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// linkTestHelperEnv switches this test binary into acting as the real
// innsegl CLI (`run`, cli.go), for a real git to invoke as the
// prepare-commit-msg hook `innsegl link` installs. It mirrors sign_test.go's
// own signHelperEnv and hook_test.go's hookFakeSignEnv: never set except by
// this file's own tests, and never true during an ordinary `go test` run.
//
// It is generic — unlike githook_test.go's TestHelperProcess, which only
// knows how to be prepare-commit-msg — because the script linkHookScript
// writes invokes this binary exactly as production does:
// `<bin> git-hook prepare-commit-msg "$@"`, with no test-only flags in
// between. Faithfully reproducing that means this helper has to dispatch
// through the same `run` entry point production's own main() does.
// ---------------------------------------------------------------------------

const linkTestHelperEnv = "INNSEGL_LINK_TEST_HELPER_PROCESS"

func init() {
	if os.Getenv(linkTestHelperEnv) != "1" {
		return
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// ---------------------------------------------------------------------------
// Unit-level: linkHookPaths, linkHookScript, shellQuoteSingle.
// ---------------------------------------------------------------------------

func TestShellQuoteSingle(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/usr/local/bin/innsegl", "'/usr/local/bin/innsegl'"},
		{"", "''"},
		{"it's", `'it'\''s'`},
		{"a b", "'a b'"},
	}
	for _, c := range cases {
		if got := shellQuoteSingle(c.in); got != c.want {
			t.Errorf("shellQuoteSingle(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLinkHookScriptIsPOSIXShOnly(t *testing.T) {
	script := linkHookScript("/opt/innsegl/bin/innsegl", "/repo/.git/hooks/prepare-commit-msg.innsegl-previous")
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Fatalf("script does not start with a POSIX sh shebang: %q", script)
	}
	for _, bashism := range []string{"[[", "local ", "function ", "bash", "=~", "((", "declare "} {
		if strings.Contains(script, bashism) {
			t.Errorf("script contains %q, which is not POSIX sh:\n%s", bashism, script)
		}
	}
	if !strings.Contains(script, linkHookMarker) {
		t.Errorf("script does not carry linkHookMarker:\n%s", script)
	}
	for _, want := range []string{"set -eu", `"$@"`, "git-hook prepare-commit-msg"} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not contain %q:\n%s", want, script)
		}
	}
}

// ---------------------------------------------------------------------------
// Real git: hook placement, respecting core.hooksPath, idempotency, chaining,
// never losing an existing hook, and -remove restoring exactly what was
// there. No core needed for any of this — installing the hook never talks
// to it.
// ---------------------------------------------------------------------------

// linkRepo builds an isolated, unlinked repository and returns its path and
// the git env every invocation against it should use — the same isolation
// githook_test.go's ghRepo uses, without pre-installing any hook.
func linkRepo(t *testing.T) (repo string, env []string) {
	t.Helper()
	git := ghGitOrSkip(t)
	home := t.TempDir()
	repo = filepath.Join(home, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	env = ghIsolatedEnv(home)
	ghRun(t, git, repo, env, "init", "-q", "-b", "main")
	return repo, env
}

func runLink(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = runLinkCommand(t.Context(), args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestLinkInstallsAHookWithNoneThereBefore(t *testing.T) {
	repo, _ := linkRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "prepare-commit-msg")

	code, stdout, stderr := runLink(t, repo)
	if code != exitOK {
		t.Fatalf("innsegl link: exit %d, stderr %q", code, stderr)
	}
	if stdout == "" {
		t.Error("stdout is empty; want a report of what was installed")
	}

	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("stat %s: %v", hookPath, err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("%s is not executable: mode %v", hookPath, info.Mode())
	}
	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read %s: %v", hookPath, err)
	}
	if !strings.Contains(string(body), linkHookMarker) {
		t.Errorf("%s does not carry linkHookMarker:\n%s", hookPath, body)
	}

	// No previous hook existed, so nothing is saved.
	if _, err := os.Stat(hookPath + linkPreviousSuffix); !os.IsNotExist(err) {
		t.Errorf("%s%s exists with nothing to have saved: %v", hookPath, linkPreviousSuffix, err)
	}
}

func TestLinkIsIdempotent(t *testing.T) {
	repo, _ := linkRepo(t)
	hookPath := filepath.Join(repo, ".git", "hooks", "prepare-commit-msg")

	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("first link: exit %d, stderr %q", code, stderr)
	}
	first, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("second link: exit %d, stderr %q", code, stderr)
	}
	second, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("running link twice changed the installed hook:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if _, err := os.Stat(hookPath + linkPreviousSuffix); !os.IsNotExist(err) {
		t.Errorf("linking twice saved innsegl's own hook as a \"previous\" one: %v", err)
	}
}

func TestLinkMovesAnExistingHookAsideAndTheInstalledHookChainsToIt(t *testing.T) {
	repo, env := linkRepo(t)
	git := ghGitOrSkip(t)
	hooksDir := filepath.Join(repo, ".git", "hooks")
	hookPath := filepath.Join(hooksDir, "prepare-commit-msg")
	previousPath := hookPath + linkPreviousSuffix

	marker := filepath.Join(repo, "previous-hook-ran")
	previousScript := "#!/bin/sh\ntouch " + shellQuoteSingle(marker) + "\n"
	if err := os.WriteFile(hookPath, []byte(previousScript), 0o755); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runLink(t, repo)
	if code != exitOK {
		t.Fatalf("innsegl link: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, previousPath) {
		t.Errorf("stdout = %q, want it to name %s", stdout, previousPath)
	}

	movedBody, err := os.ReadFile(previousPath)
	if err != nil {
		t.Fatalf("the existing hook was not moved to %s: %v", previousPath, err)
	}
	if string(movedBody) != previousScript {
		t.Errorf("moved hook body = %q, want %q", movedBody, previousScript)
	}
	info, err := os.Stat(previousPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("%s lost its executable bit in the move", previousPath)
	}

	newBody, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(newBody), previousPath) {
		t.Errorf("installed hook does not reference %s:\n%s", previousPath, newBody)
	}

	// Drive it with real git: an agent's own path is not what this test is
	// about, so drive a plain commit through it with the helper process
	// acting as innsegl, and confirm the previous hook actually ran.
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")
	commitEnv := append(append([]string{}, env...), linkTestHelperEnv+"=1")
	cmd := exec.CommandContext(t.Context(), git, "commit", "-m", "chore: chain test")
	cmd.Dir = repo
	cmd.Env = commitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the pre-existing hook did not run as part of the chain: %v", err)
	}
}

func TestLinkRefusesWhenBothTheHookAndAPreviousOneAlreadyExist(t *testing.T) {
	repo, _ := linkRepo(t)
	hooksDir := filepath.Join(repo, ".git", "hooks")
	hookPath := filepath.Join(hooksDir, "prepare-commit-msg")
	previousPath := hookPath + linkPreviousSuffix

	const currentBody = "#!/bin/sh\necho current\n"
	const previousBody = "#!/bin/sh\necho previous\n"
	if err := os.WriteFile(hookPath, []byte(currentBody), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousPath, []byte(previousBody), 0o755); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runLink(t, repo)
	if code == exitOK {
		t.Fatalf("innsegl link succeeded with an ambiguous existing state; stdout=%q", stdout)
	}
	if stderr == "" {
		t.Error("no refusal reached stderr")
	}

	got, err := os.ReadFile(hookPath)
	if err != nil || string(got) != currentBody {
		t.Errorf("hookPath changed: got %q (err %v), want %q", got, err, currentBody)
	}
	got, err = os.ReadFile(previousPath)
	if err != nil || string(got) != previousBody {
		t.Errorf("previousPath changed: got %q (err %v), want %q", got, err, previousBody)
	}
}

func TestLinkRemoveRestoresExactlyWhatWasThereBefore(t *testing.T) {
	repo, _ := linkRepo(t)
	hooksDir := filepath.Join(repo, ".git", "hooks")
	hookPath := filepath.Join(hooksDir, "prepare-commit-msg")
	previousPath := hookPath + linkPreviousSuffix

	const original = "#!/bin/sh\necho original hook\n"
	const mode = 0o750
	if err := os.WriteFile(hookPath, []byte(original), mode); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: exit %d, stderr %q", code, stderr)
	}

	code, stdout, stderr := runLink(t, "-remove", repo)
	if code != exitOK {
		t.Fatalf("innsegl link -remove: exit %d, stderr %q", code, stderr)
	}
	if stdout == "" {
		t.Error("stdout is empty; want a report of what was restored")
	}

	if _, err := os.Stat(previousPath); !os.IsNotExist(err) {
		t.Errorf("%s still exists after -remove: %v", previousPath, err)
	}
	got, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read back the restored hook: %v", err)
	}
	if string(got) != original {
		t.Errorf("restored hook body = %q, want %q", got, original)
	}
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Errorf("restored hook mode = %v, want %v", info.Mode().Perm(), os.FileMode(mode))
	}
}

func TestLinkRemoveWithNothingLinkedIsANoOp(t *testing.T) {
	repo, _ := linkRepo(t)

	code, stdout, stderr := runLink(t, "-remove", repo)
	if code != exitOK {
		t.Fatalf("innsegl link -remove: exit %d, stderr %q", code, stderr)
	}
	if stdout == "" {
		t.Error("stdout is empty; want a report that there was nothing to remove")
	}
}

func TestLinkRemoveRefusesAHookItDoesNotOwn(t *testing.T) {
	repo, _ := linkRepo(t)
	hooksDir := filepath.Join(repo, ".git", "hooks")
	hookPath := filepath.Join(hooksDir, "prepare-commit-msg")
	const original = "#!/bin/sh\necho not innsegl's\n"
	if err := os.WriteFile(hookPath, []byte(original), 0o755); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runLink(t, "-remove", repo)
	if code == exitOK {
		t.Fatal("innsegl link -remove succeeded on a hook it does not own")
	}
	if stderr == "" {
		t.Error("no refusal reached stderr")
	}

	got, err := os.ReadFile(hookPath)
	if err != nil || string(got) != original {
		t.Errorf("the unmanaged hook changed: got %q (err %v), want %q", got, err, original)
	}
}

// TestLinkRespectsCoreHooksPath proves the hook lands wherever
// core.hooksPath points, relative or absolute, not always .git/hooks.
func TestLinkRespectsCoreHooksPath(t *testing.T) {
	repo, env := linkRepo(t)
	git := ghGitOrSkip(t)

	customDir := filepath.Join(repo, "custom-hooks")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "config", "core.hooksPath", "custom-hooks")

	code, stdout, stderr := runLink(t, repo)
	if code != exitOK {
		t.Fatalf("innsegl link: exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "custom-hooks") {
		t.Errorf("stdout = %q, want it to name the custom hooks directory", stdout)
	}

	customHook := filepath.Join(customDir, "prepare-commit-msg")
	if _, err := os.Stat(customHook); err != nil {
		t.Errorf("no hook at %s: %v", customHook, err)
	}
	defaultHook := filepath.Join(repo, ".git", "hooks", "prepare-commit-msg")
	if _, err := os.Stat(defaultHook); err == nil {
		t.Errorf("a hook also landed at the default location %s, which core.hooksPath overrides", defaultHook)
	}
}

// TestLinkTouchesNoOtherRepositoryConfig proves .git/config is byte-identical
// before and after `innsegl link` — the command's own promise, and part of
// ENF-005's premise for hook.go: the signing configuration lives in the
// child git process's own environment (hook.go), never in the repository.
func TestLinkTouchesNoOtherRepositoryConfig(t *testing.T) {
	repo, _ := linkRepo(t)
	configPath := filepath.Join(repo, ".git", "config")

	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read .git/config before: %v", err)
	}

	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: exit %d, stderr %q", code, stderr)
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read .git/config after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf(".git/config changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// ---------------------------------------------------------------------------
// ENF-004 (I): a human `git commit` in a linked repository -> no trailers, no
// innsegl signing, git's own configuration decides; an existing
// prepare-commit-msg hook still runs.
// ---------------------------------------------------------------------------

func TestENF004HumanCommitInALinkedRepositoryIsLeftAlone(t *testing.T) {
	repo, env := linkRepo(t)
	git := ghGitOrSkip(t)

	hooksDir := filepath.Join(repo, ".git", "hooks")
	marker := filepath.Join(repo, "previous-hook-ran")
	previousScript := "#!/bin/sh\ntouch " + shellQuoteSingle(marker) + "\n"
	if err := os.WriteFile(filepath.Join(hooksDir, "prepare-commit-msg"), []byte(previousScript), 0o755); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := runLink(t, repo); code != exitOK {
		t.Fatalf("innsegl link: exit %d, stderr %q", code, stderr)
	}

	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ghRun(t, git, repo, env, "add", "a.txt")

	// INNSEGL_TOOL_USE_ID deliberately absent: a human's own commit.
	commitEnv := append(append([]string{}, env...), linkTestHelperEnv+"=1")
	cmd := exec.CommandContext(t.Context(), git, "commit", "-m", "docs: notes")
	cmd.Dir = repo
	cmd.Env = commitEnv
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}

	msg := ghRun(t, git, repo, env, "log", "-1", "--format=%B")
	if strings.TrimRight(msg, "\n") != "docs: notes" {
		t.Errorf("commit message = %q, want the original message untouched", msg)
	}
	for _, trailer := range []string{"Agent-Identity:", "Agent-Run:", "Agent-Task:"} {
		if strings.Contains(msg, trailer) {
			t.Errorf("commit message carries %q; a human commit must gain no trailer:\n%s", trailer, msg)
		}
	}

	obj := ghRun(t, git, repo, env, "cat-file", "commit", "HEAD")
	if strings.Contains(obj, "gpgsig") {
		t.Errorf("commit object carries a gpgsig; a human commit must not be signed:\n%s", obj)
	}
	getGpgsign := exec.CommandContext(t.Context(), git, "config", "--get", "commit.gpgsign")
	getGpgsign.Dir = repo
	getGpgsign.Env = env
	if out, err := getGpgsign.Output(); err == nil {
		t.Errorf("commit.gpgsign = %q in the repository's own config, want unset", out)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Errorf("the pre-existing prepare-commit-msg hook did not run: %v", err)
	}
}

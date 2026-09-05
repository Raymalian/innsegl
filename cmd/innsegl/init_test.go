// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// INIT-007 (proposed, doc 07 layer U): `innsegl init` end to end — the
// acceptance criteria of #117, exercised against seams (initDeps) rather
// than a real SPIRE/Fulcio/Rekor stack. spireSignVerifier.Run, the
// production self-hosted signing path these seams replace, is NOT exercised
// by an automated integration test in this change — see the implementation
// report for why, and initsign.go's production wiring for what it is built
// from (internal/signing, internal/spire, internal/verify, unchanged).

func fakeInitDeps(sha string) initDeps {
	return initDeps{
		installGitsign: func(context.Context, gitsignInstallOptions) (string, error) {
			return "/fake/gitsign", nil
		},
		signVerifier: fakeSignVerifier{run: func(context.Context, smokeTestRequest) (smokeTestResult, error) {
			return smokeTestResult{CommitSHA: sha, Ref: initVerifyRef}, nil
		}},
	}
}

func minimalInitArgs(repo string, extra ...string) []string {
	return append([]string{
		"-repo", repo,
		"-trust-root", "self-hosted",
		"-fulcio-url", "https://fulcio.internal",
		"-rekor-url", "https://rekor.internal",
		"-oidc-issuer", "http://spire-oidc:8080",
		"-trust-domain", "innsegl.dev",
		"-spire-address", "spire:8081",
		"-identity-secret", "0123456789abcdef0123456789abcdef",
	}, extra...)
}

func TestINIT007SuccessfulRunWritesConfigAndReportsVerified(t *testing.T) {
	repo := initTestRepo(t)
	writeInitTestCommit(t, repo)
	var stdout, stderr bytes.Buffer

	code := runInitCommand(context.Background(), minimalInitArgs(repo), &stdout, &stderr, fakeInitDeps("deadbeef"))

	if code != exitOK {
		t.Fatalf("runInitCommand = %d, want %d (exitOK). stderr:\n%s", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "deadbeef") {
		t.Errorf("stdout %q does not report the verified commit", stdout.String())
	}

	g := newGitLocal("git", repo)
	ctx := context.Background()
	v, ok, gerr := g.configGet(ctx, "gpg.format")
	if gerr != nil || !ok || v != "x509" {
		t.Errorf("gpg.format = (%q, %v, %v), want (x509, true, nil)", v, ok, gerr)
	}
	v, ok, gerr = g.configGet(ctx, "gpg.x509.program")
	if gerr != nil || !ok || v != "/fake/gitsign" {
		t.Errorf("gpg.x509.program = (%q, %v, %v), want (/fake/gitsign, true, nil)", v, ok, gerr)
	}
	// commit.gpgsign is NOT one of the keys init writes (#158): the settled
	// design signs through the orchestrator's `sign_commit` MCP tool, using an
	// identity the MCP server issued — never through a human's own plain
	// `git commit`. Configuring commit.gpgsign here would demand of the
	// operator exactly the credential the architecture deliberately never
	// gives them, and their very next commit would fail with no explanation
	// attached to it.
	if _, ok, gerr := g.configGet(ctx, "commit.gpgsign"); gerr != nil || ok {
		t.Errorf("commit.gpgsign = (ok=%v, err=%v), want ok=false: init must not configure "+
			"a human's git to sign (#158)", ok, gerr)
	}
	if _, statErr := os.Stat(deployConfigPath(repo)); statErr != nil {
		t.Errorf("deploy config was not written: %v", statErr)
	}

	// The report must not read as "this repository now signs" (#158): it must
	// be unmistakable that what was proved is the DEPLOYMENT's signing path —
	// through the orchestrator and sign_commit — not the operator's own.
	report := stdout.String()
	if !strings.Contains(report, "sign_commit") {
		t.Errorf("report %q does not name sign_commit as the path that signs", report)
	}
	if !strings.Contains(report, "commit.gpgsign") || !strings.Contains(report, "not") {
		t.Errorf("report %q does not say plainly that commit.gpgsign was not configured", report)
	}
}

func TestINIT007RunningTwiceChangesNothingFurther(t *testing.T) {
	repo := initTestRepo(t)
	writeInitTestCommit(t, repo)
	var out1, err1, out2, err2 bytes.Buffer

	code1 := runInitCommand(context.Background(), minimalInitArgs(repo), &out1, &err1, fakeInitDeps("sha1"))
	if code1 != exitOK {
		t.Fatalf("first run = %d, want %d: %s", code1, exitOK, err1.String())
	}
	g := newGitLocal("git", repo)
	afterFirst, lerr := g.configList(context.Background())
	if lerr != nil {
		t.Fatal(lerr)
	}

	code2 := runInitCommand(context.Background(), minimalInitArgs(repo), &out2, &err2, fakeInitDeps("sha2"))
	if code2 != exitOK {
		t.Fatalf("second run = %d, want %d: %s", code2, exitOK, err2.String())
	}
	afterSecond, lerr := g.configList(context.Background())
	if lerr != nil {
		t.Fatal(lerr)
	}
	if strings.Join(afterFirst, "\n") != strings.Join(afterSecond, "\n") {
		t.Fatalf("config changed on the second run.\nfirst:\n%s\nsecond:\n%s",
			strings.Join(afterFirst, "\n"), strings.Join(afterSecond, "\n"))
	}
}

func TestINIT007UndoRestoresTheExactPriorConfig(t *testing.T) {
	repo := initTestRepo(t)
	writeInitTestCommit(t, repo)
	g := newGitLocal("git", repo)
	ctx := context.Background()

	before, err := g.configList(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := runInitCommand(ctx, minimalInitArgs(repo), &out, &errOut, fakeInitDeps("sha")); code != exitOK {
		t.Fatalf("apply run: %d: %s", code, errOut.String())
	}
	if _, statErr := os.Stat(deployConfigPath(repo)); statErr != nil {
		t.Fatalf("deploy config missing after apply: %v", statErr)
	}

	var undoOut, undoErr bytes.Buffer
	code := runInitCommand(ctx, []string{"-repo", repo, "-undo"}, &undoOut, &undoErr, initDeps{})
	if code != exitOK {
		t.Fatalf("runInitCommand -undo = %d, want %d: %s", code, exitOK, undoErr.String())
	}

	after, err := g.configList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("config --local --list differs after --undo.\nbefore:\n%s\nafter:\n%s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	if _, err := os.Stat(deployConfigPath(repo)); !os.IsNotExist(err) {
		t.Errorf("deploy config still present after --undo: %v", err)
	}
	if undoOut.Len() == 0 {
		t.Error("--undo printed nothing; #117 point 6 requires it to print exactly what it changed")
	}
}

func TestINIT007UndoWithNothingToUndoReportsInconclusive(t *testing.T) {
	repo := initTestRepo(t)
	var out, errOut bytes.Buffer
	code := runInitCommand(context.Background(), []string{"-repo", repo, "-undo"}, &out, &errOut, initDeps{})
	if code == exitOK {
		t.Fatal("runInitCommand -undo on a never-initialised repository: want a non-zero exit")
	}
}

func TestINIT007PublicTrustRootRefusesAndReportsWhy(t *testing.T) {
	repo := initTestRepo(t)
	writeInitTestCommit(t, repo)
	var stdout, stderr bytes.Buffer

	args := []string{
		"-repo", repo, "-trust-root", "public",
		"-identity-mode", "pseudonymous",
	}
	code := runInitCommand(context.Background(), args, &stdout, &stderr, fakeInitDeps("unused"))

	if code == exitOK {
		t.Fatal("runInitCommand with -trust-root public: want a non-zero exit, got exitOK")
	}
	if !strings.Contains(stderr.String(), "ADR-0010") {
		t.Errorf("stderr %q does not cite the reason", stderr.String())
	}
}

func TestINIT007RequiredFlagsForSelfHostedAreEnforced(t *testing.T) {
	repo := initTestRepo(t)
	var stdout, stderr bytes.Buffer
	code := runInitCommand(context.Background(),
		[]string{"-repo", repo, "-trust-root", "self-hosted"}, &stdout, &stderr, fakeInitDeps("x"))
	if code != exitUsage {
		t.Fatalf("runInitCommand with no -fulcio-url etc. = %d, want %d (exitUsage): %s",
			code, exitUsage, stderr.String())
	}
}

func TestINIT007HelpDoesNotRequireAnyFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runInitCommand(context.Background(), []string{"-h"}, &stdout, &stderr, initDeps{})
	if code != exitOK {
		t.Fatalf("runInitCommand -h = %d, want %d", code, exitOK)
	}
	// -h's usage goes to stderr, matching every other subcommand's
	// convention (seal.go, reap.go: fs.SetOutput(stderr)).
	if !strings.Contains(stderr.String(), "innsegl init") {
		t.Errorf("usage does not name the subcommand: %q", stderr.String())
	}
}

// writeInitTestCommit gives the repository the one real commit
// createVerificationCommit requires HEAD to resolve to.
func writeInitTestCommit(t *testing.T, repo string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", repo}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", "README.md")
	run("commit", "-q", "-m", "initial")
}

// TestINIT007PrePushHookInstallIsOptOutAndReversible covers #117 point 5:
// "Optionally installs a pre-push hook refusing unsigned commits." Opt-in
// (the default is off), idempotent over its own output, and refuses to
// clobber a hook it did not write — the same marker-file discipline
// writeDeployConfig uses for .innsegl/deploy.env (initdeploy.go).
func TestINIT007PrePushHookInstallIsOptOutAndReversible(t *testing.T) {
	repo := initTestRepo(t)
	ctx := context.Background()

	paths, err := installPrePushHook(ctx, repo)
	if err != nil {
		t.Fatalf("installPrePushHook: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("installPrePushHook returned %d paths, want 1", len(paths))
	}
	info, statErr := os.Stat(paths[0])
	if statErr != nil {
		t.Fatalf("hook file missing: %v", statErr)
	}
	if info.Mode()&0o111 == 0 {
		t.Errorf("hook file is not executable: mode %v", info.Mode())
	}
	body, readErr := os.ReadFile(paths[0])
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(body), prePushHookMarker) {
		t.Errorf("hook file does not carry the managed marker")
	}

	// Idempotent: a second install over its own output succeeds.
	if _, err := installPrePushHook(ctx, repo); err != nil {
		t.Fatalf("second installPrePushHook over its own output: %v", err)
	}
}

func TestINIT007PrePushHookInstallRefusesAnUnmanagedHook(t *testing.T) {
	repo := initTestRepo(t)
	ctx := context.Background()

	hookDir := filepath.Join(repo, ".git", "hooks")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(hookDir, "pre-push")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho custom\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := installPrePushHook(ctx, repo); err == nil {
		t.Fatal("installPrePushHook over an unmanaged pre-push hook: want a refusal, got nil")
	}
	body, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "#!/bin/sh\necho custom\n" {
		t.Errorf("the unmanaged hook was modified: %s", body)
	}
}

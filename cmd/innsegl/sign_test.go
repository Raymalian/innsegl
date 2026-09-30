// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/commitpath"
)

// `innsegl sign`'s own tests: CMT-013 (U) and CMT-014 (C) from doc 07, plus
// the unit cases behind them.
//
// CMT-013 and CMT-014 are driven against a REAL git in a temp repository —
// see the helper-process block below — because the thing under test is a
// contract git itself defines (ADR-0031 decision 1: `gpg.x509.program` is
// invoked with the unsigned commit object on stdin and is expected to answer
// on stdout and a status fd), and a fake git would only prove this program
// agrees with itself about what that contract says. Only the core is a
// double: an httptest server standing in for the one boundary these tests
// have no business crossing for real (Fulcio, Rekor, the ledger).
//
// The rest of the cases below — argument parsing, the fail-closed shape,
// what reaches the core and what does not — run against a fakeSignClient and
// no git process at all, for the same reason ADR-0059's own contract tests
// do: they are about this file's own decisions, not about git's.

// ---------------------------------------------------------------------------
// The helper-process re-exec that lets a real git invoke this same test
// binary as its signing program.
//
// cmd/innsegl already has one TestMain (apiharness_test.go), and Go allows
// only one per package, so this cannot add a second. An init() that exits
// before testing.Main ever runs reaches the same place without touching it:
// set signHelperEnv and this file's init hijacks the process before any flag
// is parsed or any test runs.
// ---------------------------------------------------------------------------

// signHelperEnv switches this test binary into acting as `innsegl sign`
// itself, reading os.Args[1:] as git's own arguments. Never set except by the
// wrapper script signHelperScript writes, and never true during an ordinary
// `go test` run.
const signHelperEnv = "INNSEGL_SIGN_TEST_HELPER_PROCESS"

func init() {
	if os.Getenv(signHelperEnv) != "1" {
		return
	}
	client := commitpath.ClientFromEnv(os.Getenv)
	os.Exit(runSign(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv, client))
}

// signHelperBinary returns the path to the currently running test binary,
// which is what the wrapper script re-execs. `go test` compiles one before
// running any test and leaves it on disk for the run's duration, so the path
// is stable across every subtest that needs it.
func signHelperBinary(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolving the running test binary's path: %v", err)
	}
	if fi, err := os.Stat(bin); err != nil || fi.IsDir() {
		t.Skipf("the compiled test binary is not at %s; cannot drive real git through it", bin)
	}
	return bin
}

// signHelperScript writes a POSIX sh script that re-execs bin with
// signHelperEnv set, forwarding whatever git calls it with. This is what
// `gpg.x509.program` names: git invokes the script, the script becomes this
// same test binary in helper mode, and helper mode calls runSign for real.
func signHelperScript(t *testing.T, dir, bin string) string {
	t.Helper()
	script := filepath.Join(dir, "innsegl-sign-helper")
	body := "#!/bin/sh\n" + signHelperEnv + "=1 exec " + shQuote(bin) + " \"$@\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing the sign helper script: %v", err)
	}
	return script
}

// shQuote single-quotes s for a POSIX sh command line, escaping any embedded
// single quote. Good enough for a temp-directory path; it does not need to be
// a general shell quoter.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// A real, disposable git repository, isolated from the host's own config.
// ---------------------------------------------------------------------------

const (
	signTestAuthorName  = "Innsegl Sign Fixture"
	signTestAuthorEmail = "sign-fixture@innsegl.invalid"
)

// signTestGitEnv builds a git environment with no ambient configuration: no
// system or global gitconfig, no terminal prompt, and a fixed author and
// committer — the same posture test/contract's scGitEnv takes, so the host's
// own ~/.gitconfig can never leak into what gets signed.
func signTestGitEnv(dir string) []string {
	return append(os.Environ(),
		"HOME="+dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME="+signTestAuthorName,
		"GIT_AUTHOR_EMAIL="+signTestAuthorEmail,
		"GIT_COMMITTER_NAME="+signTestAuthorName,
		"GIT_COMMITTER_EMAIL="+signTestAuthorEmail,
	)
}

func signGit(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// newSignTestRepo creates a fresh repository with one file staged, ready for
// a commit attempt.
func newSignTestRepo(t *testing.T) (dir string, env []string) {
	t.Helper()
	dir = t.TempDir()
	env = signTestGitEnv(dir)
	if out, err := signGit(t, dir, env, "init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("innsegl sign fixture\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture file: %v", err)
	}
	if out, err := signGit(t, dir, env, "add", "work.txt"); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	return dir, env
}

// signAttemptCommit runs the exact invocation ADR-0031 decision 1 and
// ADR-0059 decision 3 describe: `-c gpg.format=x509 -c gpg.x509.program=...`.
func signAttemptCommit(t *testing.T, dir string, env []string, gpgProgram string) (string, error) {
	t.Helper()
	return signGit(t, dir, env,
		"-c", "gpg.format=x509",
		"-c", "gpg.x509.program="+gpgProgram,
		"-c", "commit.gpgsign=true",
		"-c", "user.signingkey=innsegl-test-key",
		"commit", "-q", "-m", "innsegl sign contract probe",
	)
}

// signRepoObjects is CMT-014's own evidence: the whole object database, not
// HEAD, keyed by object id and holding each one's type. `git commit` writes
// tree (and, for a fresh blob, blob) objects to build the unsigned commit
// object it hands the signing program on stdin — that happens before
// signing, so those are expected regardless of outcome. A COMMIT object is
// what a signature attaches to, and IP §6.3's guarantee is about that: a
// refused signing attempt leaves no new one, not that the object database is
// untouched.
func signRepoObjects(t *testing.T, dir string, env []string) map[string]string {
	t.Helper()
	out, err := signGit(t, dir, env, "cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)")
	if err != nil {
		t.Fatalf("cat-file --batch-all-objects: %v: %s", err, out)
	}
	objs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("cat-file --batch-check produced an unparseable line %q", line)
		}
		objs[fields[0]] = fields[1]
	}
	return objs
}

// ---------------------------------------------------------------------------
// The fake core: an httptest server answering commitpath.SignPath.
// ---------------------------------------------------------------------------

// fakeSigningCore answers every request to commitpath.SignPath with resp,
// requiring the tool call id to be wantToolUseID and, when checkArgs is not
// nil, handing it the args this program forwarded — how CMT-013 pins down the
// measured argv rather than merely asserting a commit resulted.
func fakeSigningCore(t *testing.T, wantToolUseID string, resp commitpath.SignResponse, checkArgs func(t *testing.T, args []string)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(commitpath.SignPath, func(w http.ResponseWriter, r *http.Request) {
		var req commitpath.SignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("fake core: decoding the sign request: %v", err)
		}
		if req.ToolUseID != wantToolUseID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			if _, err := w.Write([]byte(`{"error":"innsegl: no relayed git commit has that tool call id"}`)); err != nil {
				t.Errorf("fake core: writing the refusal: %v", err)
			}
			return
		}
		if checkArgs != nil {
			checkArgs(t, req.Args)
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("fake core: encoding the response: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fakeRefusingCore answers every request with a 403 and the core's own
// reason, standing in for a core that resolved the tool call id and refused
// it (as opposed to being unreachable at all).
func fakeRefusingCore(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(`{"error":"innsegl: no relayed git commit has tool call id toolu_cmt014"}`)); err != nil {
			t.Errorf("fake core: writing the refusal: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---------------------------------------------------------------------------
// CMT-013 (U): invoked as git's gpg.x509.program, this program reads the
// payload on stdin, forwards it with the tool call id, and writes the
// signature to stdout and git's status lines to the status fd.
// ---------------------------------------------------------------------------

func TestCMT013InvokedAsGitsSigningProgramSignsARealCommit(t *testing.T) {
	bin := signHelperBinary(t)
	dir, env := newSignTestRepo(t)
	script := signHelperScript(t, dir, bin)

	const toolUseID = "toolu_cmt013fixture"
	const wantSignature = "innsegl-fake-signature-cmt013"

	var gotArgs []string
	srv := fakeSigningCore(t, toolUseID, commitpath.SignResponse{
		Signature: []byte(wantSignature),
		Status:    []byte("[GNUPG:] SIG_CREATED S 0 9 00 0 1 0 " + toolUseID + "\n"),
	}, func(_ *testing.T, args []string) { gotArgs = args })

	env = append(env, "INNSEGL_TOOL_USE_ID="+toolUseID, "INNSEGL_CORE_URL="+srv.URL)

	out, err := signAttemptCommit(t, dir, env, script)
	if err != nil {
		t.Fatalf("git commit through innsegl sign failed: %v: %s", err, out)
	}

	// Measured argv, ADR-0059 decision 3 / ADR-0031 decision 1: git invokes
	// `gpg.x509.program` as `--status-fd=2 -bsau <signing key>` with the
	// unsigned commit object on stdin.
	wantArgs := []string{"--status-fd=2", "-bsau", "innsegl-test-key"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Errorf("git invoked the signing program with %v, want %v", gotArgs, wantArgs)
	}

	got, err := signGit(t, dir, env, "cat-file", "commit", "HEAD")
	if err != nil {
		t.Fatalf("cat-file commit HEAD: %v: %s", err, got)
	}
	if !strings.Contains(got, "gpgsig "+wantSignature) {
		t.Errorf("the committed object carries no gpgsig %q; full object:\n%s", wantSignature, got)
	}
}

// ---------------------------------------------------------------------------
// CMT-014 (C): the core unreachable, or any refusal, means git creates no
// commit. Measured by enumerating every object in the repository before and
// after, not by reading HEAD.
// ---------------------------------------------------------------------------

func TestCMT014CoreUnreachableOrRefusalMeansGitCreatesNoCommit(t *testing.T) {
	bin := signHelperBinary(t)

	cases := []struct {
		name    string
		coreURL func(t *testing.T) string
	}{
		{
			name:    "core unreachable",
			coreURL: func(*testing.T) string { return "http://127.0.0.1:1" },
		},
		{
			name:    "core refuses the tool call",
			coreURL: func(t *testing.T) string { return fakeRefusingCore(t).URL },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, env := newSignTestRepo(t)
			script := signHelperScript(t, dir, bin)
			env = append(env, "INNSEGL_TOOL_USE_ID=toolu_cmt014fixture", "INNSEGL_CORE_URL="+c.coreURL(t))

			before := signRepoObjects(t, dir, env)

			out, err := signAttemptCommit(t, dir, env, script)
			if err == nil {
				t.Fatalf("git commit succeeded with no usable core; output:\n%s", out)
			}

			after := signRepoObjects(t, dir, env)
			for obj, typ := range after {
				if typ == "commit" && before[obj] != "commit" {
					t.Errorf("commit object %s exists after a refused commit; git created one anyway", obj)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Unit cases: this file's own argument handling and fail-closed shape,
// against a fakeSignClient and no git process at all.
// ---------------------------------------------------------------------------

type fakeSignClient struct {
	resp    commitpath.SignResponse
	err     error
	calls   int
	lastReq commitpath.SignRequest
}

func (f *fakeSignClient) Sign(_ context.Context, req commitpath.SignRequest) (commitpath.SignResponse, error) {
	f.calls++
	f.lastReq = req
	return f.resp, f.err
}

func signTestGetenv(toolUseID string) func(string) string {
	return func(k string) string {
		if k == commitpath.EnvToolUseID {
			return toolUseID
		}
		return ""
	}
}

func TestRunSignRefusesWithNoToolCallID(t *testing.T) {
	client := &fakeSignClient{resp: commitpath.SignResponse{Signature: []byte("SIG"), Status: []byte("status")}}
	var stdout, stderr bytes.Buffer

	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "key"}, strings.NewReader("payload"),
		&stdout, &stderr, signTestGetenv(""), client)

	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty (fail closed)", stdout.String())
	}
	if !strings.Contains(stderr.String(), commitpath.EnvToolUseID) {
		t.Errorf("stderr = %q, want it to name %s", stderr.String(), commitpath.EnvToolUseID)
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times, want 0: a missing tool call id must never reach it", client.calls)
	}
}

func TestRunSignRefusesVerifyMode(t *testing.T) {
	client := &fakeSignClient{}
	var stdout, stderr bytes.Buffer

	code := runSign(t.Context(), []string{"--status-fd=1", "--verify"}, strings.NewReader(""),
		&stdout, &stderr, signTestGetenv("toolu_x"), client)

	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "gitsign") {
		t.Errorf("stderr = %q, want it to name gitsign as the verifier", stderr.String())
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times for a --verify invocation, want 0", client.calls)
	}
}

func TestRunSignRefusesAnOversizedPayload(t *testing.T) {
	client := &fakeSignClient{}
	var stdout, stderr bytes.Buffer
	huge := strings.NewReader(strings.Repeat("a", signMaxPayloadBytes+1))

	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "key"}, huge,
		&stdout, &stderr, signTestGetenv("toolu_x"), client)

	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if client.calls != 0 {
		t.Errorf("the core was called %d times with an oversized payload, want 0", client.calls)
	}
}

func TestRunSignRefusesWhenStatusFDCannotBeUsed(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing entirely", []string{"-bsau", "key"}},
		{"not a number", []string{"--status-fd=x", "-bsau", "key"}},
		{"split form with no value", []string{"-bsau", "key", "--status-fd"}},
		{"fd 3 is neither stdout nor stderr", []string{"--status-fd=3", "-bsau", "key"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := &fakeSignClient{}
			var stdout, stderr bytes.Buffer

			code := runSign(t.Context(), c.args, strings.NewReader("payload"),
				&stdout, &stderr, signTestGetenv("toolu_x"), client)

			if code == 0 {
				t.Errorf("exit code = 0 for args %v, want non-zero", c.args)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q for args %v, want empty", stdout.String(), c.args)
			}
			if client.calls != 0 {
				t.Errorf("the core was called %d times for args %v, want 0", client.calls, c.args)
			}
		})
	}
}

func TestRunSignRefusesWhenTheCoreRefuses(t *testing.T) {
	client := &fakeSignClient{err: errors.New("innsegl: the core refused (403): no relayed git commit has tool call id toolu_x")}
	var stdout, stderr bytes.Buffer

	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "key"}, strings.NewReader("tree abc\n"),
		&stdout, &stderr, signTestGetenv("toolu_x"), client)

	if code == 0 {
		t.Fatalf("exit code = 0, want non-zero")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "no relayed git commit") {
		t.Errorf("stderr = %q, want the core's own reason", stderr.String())
	}
	if client.calls != 1 {
		t.Errorf("the core was called %d times, want exactly 1", client.calls)
	}
}

func TestRunSignWritesTheSignatureToStdoutAndStatusToFD2(t *testing.T) {
	client := &fakeSignClient{resp: commitpath.SignResponse{
		Signature: []byte("CMSSIGNATURE"),
		Status:    []byte("[GNUPG:] SIG_CREATED S\n"),
	}}
	var stdout, stderr bytes.Buffer

	code := runSign(t.Context(), []string{"--status-fd=2", "-bsau", "key"}, strings.NewReader("tree abc\n"),
		&stdout, &stderr, signTestGetenv("toolu_x"), client)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: stderr=%s", code, stderr.String())
	}
	if stdout.String() != "CMSSIGNATURE" {
		t.Errorf("stdout = %q, want exactly the signature", stdout.String())
	}
	if !strings.Contains(stderr.String(), "SIG_CREATED") {
		t.Errorf("stderr = %q, want git's status lines", stderr.String())
	}
}

func TestRunSignWritesStatusToStdoutWhenTheFDIs1(t *testing.T) {
	client := &fakeSignClient{resp: commitpath.SignResponse{
		Signature: []byte("SIG"),
		Status:    []byte("[GNUPG:] SIG_CREATED S\n"),
	}}
	var stdout, stderr bytes.Buffer

	code := runSign(t.Context(), []string{"--status-fd", "1", "-bsau", "key"}, strings.NewReader("tree abc\n"),
		&stdout, &stderr, signTestGetenv("toolu_x"), client)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0: stderr=%s", code, stderr.String())
	}
	if stdout.String() != "SIG[GNUPG:] SIG_CREATED S\n" {
		t.Errorf("stdout = %q, want the signature then the status lines", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty when status goes to stdout", stderr.String())
	}
}

func TestRunSignForwardsGitsArgsAndThePayloadToTheCore(t *testing.T) {
	client := &fakeSignClient{resp: commitpath.SignResponse{Signature: []byte("S"), Status: []byte("st")}}
	var stdout, stderr bytes.Buffer

	args := []string{"--status-fd=2", "-bsau", "innsegl-test-key"}
	payload := "tree abc\nauthor a <a@example.invalid> 1 +0000\ncommitter a <a@example.invalid> 1 +0000\n\nmsg\n"

	code := runSign(t.Context(), args, strings.NewReader(payload), &stdout, &stderr, signTestGetenv("toolu_forward"), client)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0: stderr=%s", code, stderr.String())
	}
	if client.lastReq.ToolUseID != "toolu_forward" {
		t.Errorf("ToolUseID = %q, want %q", client.lastReq.ToolUseID, "toolu_forward")
	}
	if !reflect.DeepEqual(client.lastReq.Args, args) {
		t.Errorf("Args = %v, want %v", client.lastReq.Args, args)
	}
	if string(client.lastReq.Payload) != payload {
		t.Errorf("Payload = %q, want %q", client.lastReq.Payload, payload)
	}
}

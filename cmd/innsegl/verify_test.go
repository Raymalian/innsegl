// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/verify"
)

// `innsegl verify`'s command-line contract. The three checks themselves belong
// to internal/verify and TC-VER; what is asserted here is the surface an
// operator and a CI job see — the flags, the four exit statuses, and the fact
// that there is no way to point this command at a database.

// unreachableSigstore is a syntactically valid pair of endpoints on a port
// nothing listens on. The cases that use it never reach the network, and if
// one ever did it would fail loudly rather than silently contact something.
const (
	unreachableFulcio = "http://127.0.0.1:1"
	unreachableRekor  = "http://127.0.0.1:1"
)

func unsignedRepo(t *testing.T) (dir, sha string) {
	t.Helper()
	dir = t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-such-gitconfig"),
			"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", "a.txt")
	git("-c", "user.name=A Human", "-c", "user.email=human@example.com",
		"commit", "--no-gpg-sign", "-m", "an ordinary commit")
	return dir, git("rev-parse", "HEAD")
}

// VER-006 through the shipped command: the exit status distinguishes
// "unattributed" from every kind of failure, because a script that treated
// them the same would be doc 06 anti-pattern 2 in a shell.
func TestVerifyCommandExitsUnattributedForAnUnsignedCommit(t *testing.T) {
	repo, sha := unsignedRepo(t)
	var stdout, stderr bytes.Buffer

	code := run([]string{"verify", sha, "--repo", repo,
		"--fulcio-url", unreachableFulcio, "--rekor-url", unreachableRekor}, &stdout, &stderr)

	if code != exitVerifyUnattributed {
		t.Fatalf("exit = %d, want %d (unattributed)\n%s%s",
			code, exitVerifyUnattributed, stdout.String(), stderr.String())
	}
	if !strings.Contains(strings.ToLower(stdout.String()), "unattributed") {
		t.Errorf("stdout does not say unattributed:\n%s", stdout.String())
	}
}

func TestVerifyCommandWritesJSONWhenAsked(t *testing.T) {
	repo, sha := unsignedRepo(t)
	var stdout, stderr bytes.Buffer

	code := run([]string{"verify", sha, "--repo", repo, "--json",
		"--fulcio-url", unreachableFulcio, "--rekor-url", unreachableRekor}, &stdout, &stderr)

	if code != exitVerifyUnattributed {
		t.Fatalf("exit = %d, want %d\n%s", code, exitVerifyUnattributed, stderr.String())
	}
	var report verify.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not the JSON report: %v\n%s", err, stdout.String())
	}
	if report.CommitSHA != sha {
		t.Errorf("report.commit_sha = %q, want %q", report.CommitSHA, sha)
	}
	if report.Verdict != verify.VerdictUnattributed {
		t.Errorf("report.verdict = %q, want %q", report.Verdict, verify.VerdictUnattributed)
	}
}

func TestVerifyCommandRefusesAConfigurationThatCannotVerify(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no commit at all", []string{"verify"}, exitUsage},
		{"two commits", []string{"verify", "a", "b"}, exitUsage},
		{"an unknown flag", []string{"verify", "--ledger-dsn", "postgres://x", "abc"}, exitUsage},
		{"no endpoints", []string{"verify", "abc"}, exitVerifyUnusable},
		{"no such commit", []string{"verify", "no-such-revision",
			"--fulcio-url", unreachableFulcio, "--rekor-url", unreachableRekor},
			exitVerifyUnusable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			t.Setenv("INNSEGL_FULCIO_URL", "")
			t.Setenv("INNSEGL_REKOR_URL", "")

			code := run(tc.args, &stdout, &stderr)

			if code != tc.want {
				t.Fatalf("exit = %d, want %d\nstdout:%s\nstderr:%s",
					code, tc.want, stdout.String(), stderr.String())
			}
		})
	}
}

// I5, as a property of the command line: there is no flag with which to hand
// this command a database, and its usage block says so.
func TestVerifyCommandHasNoDatabaseFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	run([]string{"verify", "--help"}, &stdout, &stderr)
	usage := stdout.String() + stderr.String()

	for _, forbidden := range []string{"dsn", "database", "ledger-dsn", "postgres"} {
		if strings.Contains(strings.ToLower(usage), "-"+forbidden) {
			t.Errorf("`innsegl verify --help` offers a %q flag; I5 says a verifier needs "+
				"no access to our database, and a flag for one is an invitation to depend "+
				"on it:\n%s", forbidden, usage)
		}
	}
	if !strings.Contains(usage, "never reads this system's ledger") {
		t.Errorf("the usage block does not state the I5 property:\n%s", usage)
	}
}

// The exit status is the verdict, and an unrecognised verdict is not success.
func TestVerdictExitMapsEveryStateToItsOwnStatus(t *testing.T) {
	cases := map[verify.Verdict]int{
		verify.VerdictVerified:          exitOK,
		verify.VerdictFailed:            exitVerifyFailed,
		verify.VerdictUnavailable:       exitVerifyUnavailable,
		verify.VerdictUnattributed:      exitVerifyUnattributed,
		verify.Verdict("something new"): exitVerifyUnusable,
	}
	seen := map[int]verify.Verdict{}
	for verdict, want := range cases {
		got := verdictExit(verdict)
		if got != want {
			t.Errorf("verdictExit(%q) = %d, want %d", verdict, got, want)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("%q and %q share exit status %d; doc 06 §4.1's states must stay "+
				"distinguishable by a script", verdict, other, got)
		}
		seen[got] = verdict
	}
}

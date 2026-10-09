// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

// ENF-011 (PROPOSED for doc 07) — `innsegl author` is how the operator sets
// a repository's mode; the hook only reads what it wrote. Setting operator
// mode reads the repository's own noreply address and reports it to the
// core, which pins it (#545); nothing is typed.

func runAuthorCLI(t *testing.T, home string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = runAuthor(t.Context(), args, &o, &e, home)
	return code, o.String(), e.String()
}

// isolateGit keeps git from reading the developer's own configuration: an
// operator's real address must never reach a test.
func isolateGit(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, "nonexistent-gitconfig"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
}

// recordReports replaces the call to the core, recording what it was sent
// and answering err.
func recordReports(t *testing.T, err error) *[][2]string {
	t.Helper()
	return recordReportsAnswering(t, client.PinNew, err)
}

// recordReportsAnswering is recordReports with the outcome the core gives.
func recordReportsAnswering(t *testing.T, outcome client.PinOutcome, err error) *[][2]string {
	t.Helper()
	var sent [][2]string
	previous := reportOperatorAuthor
	reportOperatorAuthor = func(_ context.Context, _ client.Paths, name, email string) (client.PinOutcome, error) {
		sent = append(sent, [2]string{name, email})
		if err != nil {
			return "", err
		}
		return outcome, nil
	}
	t.Cleanup(func() { reportOperatorAuthor = previous })
	stubCorePin(t, "", "", false, nil)
	return &sent
}

// stubCorePin replaces the read of the core's pin for this machine.
func stubCorePin(t *testing.T, name, email string, ok bool, err error) {
	t.Helper()
	previous := readOperatorAuthorPin
	readOperatorAuthorPin = func(context.Context, client.Paths) (string, string, bool, error) {
		return name, email, ok, err
	}
	t.Cleanup(func() { readOperatorAuthorPin = previous })
}

// writeCoreConfig enrols home with a fixture core, so the CLI can name this
// machine's installation.
func writeCoreConfig(t *testing.T, home, installation string) {
	t.Helper()
	p := client.ClientPaths(home)
	if err := os.MkdirAll(filepath.Dir(p.Core), 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"core_url":"https://core.invalid","installation_id":"` + installation + `"}`
	if err := os.WriteFile(p.Core, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resultLines is the lines that begin with the command's own prefix.
func resultLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "innsegl author: ") {
			lines = append(lines, l)
		}
	}
	return lines
}

const (
	enf014Installation = "0123456789abcdef0123456789abcdef"
	enf014Login        = "alpha-op"
	enf014Email        = "12345+alpha-op@users.noreply.github.com"
)

// ENF-014 (PROPOSED for doc 07) — `innsegl author repo <path> operator`
// always reports the effective identity (the typed override if set, else the
// repository's noreply pair) and always prints one result line, with an exit
// status per outcome (#545).
func TestENF014OperatorModePrintsOneResultLinePerOutcome(t *testing.T) {
	cases := []struct {
		desc     string
		outcome  client.PinOutcome
		err      error
		code     int
		want     string
		operator bool
	}{
		{"pinned now", client.PinNew, nil, exitOK, "pinned on the core for this machine: " + enf014Login + " <" + enf014Email + ">", true},
		{"already pinned", client.PinHeld, nil, exitOK, "already pinned on the core for this machine (same pair)", true},
		{"a different pair pinned", "", fmt.Errorf("%w: run on the core host", client.ErrOperatorAuthorPinned), exitAuthorRefused,
			"docker exec innsegl-api innsegl accounts author-reset " + enf014Installation, false},
		{"core unreachable", "", errors.New("dial tcp: connection refused"), exitAuthorUnreachable,
			"core unreachable: dial tcp: connection refused", false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			home := t.TempDir()
			isolateGit(t, home)
			writeCoreConfig(t, home, enf014Installation)
			repo, env := enf010Repo(t, home)
			ghRun(t, ghGitOrSkip(t), repo, env, "config", "user.email", enf014Email)
			sent := recordReportsAnswering(t, c.outcome, c.err)

			code, out, errOut := runAuthorCLI(t, home, "repo", repo, "operator")
			if code != c.code {
				t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, c.code, out, errOut)
			}
			lines := resultLines(out + errOut)
			if len(lines) != 1 || !strings.Contains(lines[0], c.want) {
				t.Fatalf("result lines %q, want one carrying %q", lines, c.want)
			}
			if len(*sent) != 1 || (*sent)[0] != [2]string{enf014Login, enf014Email} {
				t.Fatalf("the core was told %v", *sent)
			}
			commonDir, err := gitCommonDir(t.Context(), repo)
			if err != nil {
				t.Fatal(err)
			}
			a, err := client.ReadAuthors(client.ClientPaths(home))
			if err != nil || a.IsOperator(commonDir) != c.operator {
				t.Fatalf("operator mode = %v, want %v (%v)", a.IsOperator(commonDir), c.operator, err)
			}
		})
	}
}

// ENF-014 — a typed override is the identity reported: it is no longer a
// reason to skip the core.
func TestENF014ATypedOverrideIsReportedToo(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	writeCoreConfig(t, home, enf014Installation)
	repo, _ := enf010Repo(t, home) // no user.email at all
	sent := recordReportsAnswering(t, client.PinHeld, nil)
	if code, _, errOut := runAuthorCLI(t, home, "operator", "beta <67890+beta@users.noreply.github.com>"); code != exitOK {
		t.Fatalf("author operator: exit %d: %s", code, errOut)
	}
	code, out, errOut := runAuthorCLI(t, home, "repo", repo, "operator")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if len(*sent) != 1 || (*sent)[0] != [2]string{"beta", "67890+beta@users.noreply.github.com"} {
		t.Fatalf("the core was told %v, want the override", *sent)
	}
	if l := resultLines(out + errOut); len(l) != 1 || !strings.Contains(l[0], "already pinned") {
		t.Fatalf("result lines %q", l)
	}
}

// ENF-014 — an override the core would not pin (not a noreply address under
// its own login) is said plainly, and the core is not asked. The repository
// is still set: that override is the manual path, admitted only when the
// core's own configuration lists the pair.
func TestENF014AnOverrideTheCoreCannotPinIsSaidPlainly(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	writeCoreConfig(t, home, enf014Installation)
	repo, _ := enf010Repo(t, home)
	sent := recordReports(t, nil)
	if code, _, errOut := runAuthorCLI(t, home, "operator", enf010Operator); code != exitOK {
		t.Fatalf("author operator: exit %d: %s", code, errOut)
	}
	code, out, errOut := runAuthorCLI(t, home, "repo", repo, "operator")
	if code != exitAuthorNotPinnable {
		t.Fatalf("exit %d, want %d: %s", code, exitAuthorNotPinnable, errOut)
	}
	if len(*sent) != 0 {
		t.Fatalf("the core was asked to pin %v", *sent)
	}
	l := resultLines(out + errOut)
	if len(l) != 1 || !strings.Contains(l[0], "not pinned") || !strings.Contains(l[0], "INNSEGL_SIGN_AUTHOR_OPERATORS") {
		t.Fatalf("result lines %q", l)
	}
	commonDir, err := gitCommonDir(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if a, err := client.ReadAuthors(client.ClientPaths(home)); err != nil || !a.IsOperator(commonDir) {
		t.Fatalf("the override's repository is not in operator mode: %v", err)
	}
}

// ENF-014 — a repository with no noreply address and no override: one line,
// its own exit status, nothing reported, nothing set.
func TestENF014NoNoreplyAddressIsItsOwnOutcome(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	repo, _ := enf010Repo(t, home)
	sent := recordReports(t, nil)
	code, out, errOut := runAuthorCLI(t, home, "repo", repo, "operator")
	if code != exitAuthorNotPinnable || len(*sent) != 0 {
		t.Fatalf("exit %d (want %d), reports %v", code, exitAuthorNotPinnable, *sent)
	}
	if l := resultLines(out + errOut); len(l) != 1 || !strings.Contains(l[0], "noreply") {
		t.Fatalf("result lines %q", l)
	}
}

// ENF-015 (PROPOSED for doc 07) — `innsegl author` also shows what the core
// holds for this machine; a core it cannot reach is shown, not fatal (#545).
func TestENF015AuthorListsTheCoresPinForThisMachine(t *testing.T) {
	for _, c := range []struct {
		desc  string
		name  string
		email string
		ok    bool
		err   error
		want  string
	}{
		{"pinned", enf014Login, enf014Email, true, nil, enf014Login + " <" + enf014Email + ">"},
		{"none", "", "", false, nil, "none"},
		{"unreachable", "", "", false, errors.New("dial tcp: connection refused"), "core unreachable: dial tcp: connection refused"},
	} {
		t.Run(c.desc, func(t *testing.T) {
			home := t.TempDir()
			isolateGit(t, home)
			stubCorePin(t, c.name, c.email, c.ok, c.err)
			code, out, errOut := runAuthorCLI(t, home)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			var line string
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "pinned on the core") {
					line = l
				}
			}
			if !strings.Contains(line, c.want) {
				t.Fatalf("no core line carrying %q in:\n%s", c.want, out)
			}
			if !strings.Contains(out, "every other repository") {
				t.Fatalf("the local listing is missing:\n%s", out)
			}
		})
	}
}

func TestENF011AuthorCommandSetsARepositoryToOperatorMode(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	repo, env := enf010Repo(t, home)
	sent := recordReports(t, nil)

	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator"); code == exitOK ||
		!strings.Contains(errOut, "noreply") {
		t.Fatalf("operator mode with no noreply address: exit %d, stderr %q", code, errOut)
	}
	git := ghGitOrSkip(t)
	ghRun(t, git, repo, env, "config", "user.name", enf013PersonalName)
	ghRun(t, git, repo, env, "config", "user.email", "12345+alpha-op@users.noreply.github.com")
	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator"); code != exitOK {
		t.Fatalf("author repo operator: exit %d: %s", code, errOut)
	}
	if len(*sent) != 1 || (*sent)[0] != [2]string{"alpha-op", "12345+alpha-op@users.noreply.github.com"} {
		t.Fatalf("the core was told %v, want one report of the address's login and address", *sent)
	}
	commonDir, err := gitCommonDir(t.Context(), repo)
	if err != nil {
		t.Fatal(err)
	}
	a, err := client.ReadAuthors(client.ClientPaths(home))
	if err != nil {
		t.Fatal(err)
	}
	if !a.IsOperator(commonDir) {
		t.Fatalf("the repository is not in operator mode after `author repo %s operator`", repo)
	}
	code, out, _ := runAuthorCLI(t, home)
	if code != exitOK || !strings.Contains(out, commonDir) || !strings.Contains(out, "operator") {
		t.Fatalf("`innsegl author` does not list the repository: exit %d\n%s", code, out)
	}
	if strings.Contains(out, enf013PersonalName) {
		t.Fatalf("`innsegl author` prints user.name:\n%s", out)
	}
	if code, _, errOut := runAuthorCLI(t, home, "repo", repo, "agent"); code != exitOK {
		t.Fatalf("author repo agent: exit %d: %s", code, errOut)
	}
	if a, err = client.ReadAuthors(client.ClientPaths(home)); err != nil || len(a.Repos) != 0 {
		t.Fatalf("the repository is still listed after `author repo %s agent`: %v", repo, a.Repos)
	}
}

func TestENF011ACoreRefusalLeavesTheRepositoryInAgentMode(t *testing.T) {
	for desc, answer := range map[string]error{
		"pinned to another identity": fmt.Errorf("%w: run on the core host: innsegl accounts author-reset x", client.ErrOperatorAuthorPinned),
		"the core cannot be reached": errors.New("dial tcp: connection refused"),
	} {
		t.Run(desc, func(t *testing.T) {
			home := t.TempDir()
			isolateGit(t, home)
			repo, env := enf010Repo(t, home)
			ghRun(t, ghGitOrSkip(t), repo, env, "config", "user.email", "12345+alpha-op@users.noreply.github.com")
			recordReports(t, answer)

			code, _, errOut := runAuthorCLI(t, home, "repo", repo, "operator")
			if code == exitOK {
				t.Fatal("operator mode was set although the core did not pin the address")
			}
			if l := resultLines(errOut); len(l) != 1 || !strings.Contains(l[0], "agent mode") {
				t.Fatalf("stderr does not say the repository stays in agent mode: %q", errOut)
			}
			a, err := client.ReadAuthors(client.ClientPaths(home))
			if err != nil || len(a.Repos) != 0 {
				t.Fatalf("the repository was saved in operator mode: %v %v", a.Repos, err)
			}
		})
	}
}

func TestENF011AuthorCommandRefusesWhatIsNotARepositoryOrAnIdentity(t *testing.T) {
	home := t.TempDir()
	isolateGit(t, home)
	recordReports(t, nil)
	if code, _, _ := runAuthorCLI(t, home, "operator", "O'Brien <1+ob@users.noreply.github.com>"); code != exitUsage {
		t.Fatalf("an identity with a quote: exit %d, want %d", code, exitUsage)
	}
	if code, _, _ := runAuthorCLI(t, home, "operator", enf010Operator); code != exitOK {
		t.Fatal("author operator failed")
	}
	notRepo := filepath.Join(home, "plain")
	if err := os.MkdirAll(notRepo, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CEILING_DIRECTORIES", home)
	if code, _, _ := runAuthorCLI(t, home, "repo", notRepo, "operator"); code == exitOK {
		t.Fatal("a directory that is not a git repository was set to operator mode")
	}
	if code, _, _ := runAuthorCLI(t, home, "repo"); code != exitUsage {
		t.Fatalf("`author repo` with no path: exit %d, want %d", code, exitUsage)
	}
}

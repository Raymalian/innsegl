// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
)

// hookDecision runs the hook on one Bash command and returns its
// permission decision and reason ("" when it printed none).
func hookDecision(t *testing.T, cmd string) (decision, reason string) {
	t.Helper()
	code, stdout, _ := runHook(t, hookJSON(t, "Bash", cmd, "toolu_01ABCDEFghij0123", nil))
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if stdout == "" {
		return "", ""
	}
	var out struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
	return out.HookSpecificOutput.PermissionDecision, out.HookSpecificOutput.PermissionDecisionReason
}

// CMT-021 (#584): every way of turning signing off is refused, not only
// --no-gpg-sign on `git commit`. Before this, rebase and merge with
// --no-gpg-sign, commit-tree, signing configuration in GIT_CONFIG_* and
// `-c gpg.*` all passed the guard.
func TestCMT021GuardRefusesEveryWayOfTurningSigningOff(t *testing.T) {
	for _, cmd := range []string{
		"git rebase --no-gpg-sign main",
		"git merge --no-gpg-sign feature",
		"git cherry-pick --no-gpg-sign abc123",
		"git revert --no-gpg-sign HEAD",
		"git pull --no-gpg-sign origin main",
		"git am --no-gpg-sign < patch",
		"git commit-tree -p HEAD -m x 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		"c=$(git commit-tree HEAD^{tree} -m x) && git update-ref refs/heads/main $c",
		"git -C repo commit-tree -m x abc",
		"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=commit.gpgsign GIT_CONFIG_VALUE_0=false git commit -m x",
		"export GIT_CONFIG_COUNT=1; git commit -m x",
		"env GIT_CONFIG_PARAMETERS=\"'commit.gpgsign'='false'\" git commit -m x",
		"GIT_CONFIG_PARAMETERS= git rebase main",
		"git -c commit.gpgsign=false rebase main",
		"git -c commit.gpgSign=off merge feature",
		"git -c gpg.x509.program=/bin/true commit -m x",
		"git -c gpg.format=openpgp commit -m x",
		"git -c gpg.program=true rebase main",
		"git --config-env=commit.gpgsign=OFF commit -m x",
		"git --config-env gpg.x509.program=P commit -m x",
		"git config gpg.x509.program /bin/true",
		"git config --local gpg.format openpgp",
		"git config --global commit.gpgsign false",
		"git config --unset commit.gpgsign",
		"git config set commit.gpgsign false",
	} {
		t.Run(cmd, func(t *testing.T) {
			decision, reason := hookDecision(t, cmd)
			if decision != "deny" {
				t.Fatalf("decision %q, want deny", decision)
			}
			if !strings.Contains(reason, "signed") {
				t.Errorf("reason %q does not say commits must be signed", reason)
			}
		})
	}
}

// CMT-021: commands that keep signing on, or only read or mention it, run.
func TestCMT021GuardLeavesSigningThatStaysOnAlone(t *testing.T) {
	for _, cmd := range []string{
		"git rebase main",
		"git merge --no-ff feature",
		"git commit-tree -S -p HEAD -m x abc",
		"git commit-tree --gpg-sign -m x abc",
		"git config --get gpg.format",
		"git config --get-all commit.gpgsign",
		"git config --list",
		"git config user.email a@b.c",
		"echo $GIT_CONFIG_COUNT",
		"git commit -m 'explain git commit-tree and -c gpg.format=x in the docs'",
		"git log --format=%G? -1",
		"git -c user.name=x commit -m y",
		"grep -rn commit-tree .",
	} {
		t.Run(cmd, func(t *testing.T) {
			if decision, reason := hookDecision(t, cmd); decision == "deny" {
				t.Fatalf("refused: %s", reason)
			}
		})
	}
}

// withSigningOutage makes signingOutageNow answer o, ok for one test.
func withSigningOutage(t *testing.T, o signingOutage, ok bool) {
	t.Helper()
	restore := signingOutageNow
	signingOutageNow = func() (signingOutage, bool) { return o, ok }
	t.Cleanup(func() { signingOutageNow = restore })
}

// JRN-011 (#584): while signing is down, the refusal says so and says what
// to do instead of retrying with signing off. Only that one command is
// refused: every other command still runs, and so is still recorded.
func TestJRN011RefusalNamesASigningOutage(t *testing.T) {
	since := time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)
	withSigningOutage(t, signingOutage{Since: since, Reason: "the CA store token was revoked"}, true)

	decision, reason := hookDecision(t, "git rebase --no-gpg-sign main")
	if decision != "deny" {
		t.Fatalf("decision %q, want deny", decision)
	}
	for _, want := range []string{
		"signing is down since 2026-10-11T09:30:00Z",
		"the CA store token was revoked",
		"do not retry with signing off",
		"keep working and commit after repair",
	} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason does not contain %q:\n%s", want, reason)
		}
	}

	// The outage refuses nothing else: other commands run untouched, and a
	// plain commit is still passed on for signing (it waits on signing; it
	// is not refused here).
	if decision, _ := hookDecision(t, "ls -la"); decision != "" {
		t.Errorf("a command that does not commit was refused during an outage")
	}
	_, stdout, _ := runHook(t, hookJSON(t, "Bash", "git commit -m x", "toolu_01ABCDEFghij0123", nil))
	if strings.Contains(stdout, `"deny"`) || !strings.Contains(stdout, "gpg.x509.program") {
		t.Errorf("a plain commit during an outage was not passed on for signing: %s", stdout)
	}
	// The refusal stops one command, never the session.
	_, stdout, _ = runHook(t, hookJSON(t, "Bash", "git rebase --no-gpg-sign main", "toolu_01ABCDEFghij0123", nil))
	if strings.Contains(stdout, `"continue"`) || strings.Contains(stdout, `"stopReason"`) {
		t.Errorf("the refusal stops the session: %s", stdout)
	}
}

// JRN-011: with no outage known, the refusal names none.
func TestJRN011RefusalWithoutAnOutage(t *testing.T) {
	withSigningOutage(t, signingOutage{}, false)
	_, reason := hookDecision(t, "git rebase --no-gpg-sign main")
	if strings.Contains(reason, "down since") {
		t.Errorf("reason names an outage there is none of: %s", reason)
	}
	if !strings.Contains(reason, "do not retry with signing off") {
		t.Errorf("reason does not say not to retry with signing off: %s", reason)
	}
}

// JRN-011: the ref backstop's refusal carries the outage text too.
func TestJRN011BackstopRefusalNamesASigningOutage(t *testing.T) {
	got := unsignedRefusal("refs/heads/main", []string{"0123456789abcdef0123456789abcdef01234567"},
		signingOutage{Since: time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC), Reason: "probe failing"}, true)
	for _, want := range []string{
		"refs/heads/main", "0123456789ab", "not signed",
		"signing is down since 2026-10-11T09:30:00Z", "probe failing", "keep working and commit after repair",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal does not contain %q:\n%s", want, got)
		}
	}
}

// JRN-011 (#584, wired with #583): the refusal learns of the outage from
// this machine's client service, at the address core.json names. The
// package's TestMain keeps every other test from asking the developer's own
// service; this one points HOME at a stand-in.
func TestJRN011TheRefusalReadsTheOutageFromTheClientService(t *testing.T) {
	var mu sync.Mutex
	status := `{"signing":{"up":false,"detail":"FAILING since 2026-10-11T09:30:00Z — the CA store token was revoked",` +
		`"since":"2026-10-11T09:30:00Z","reason":"the CA store token was revoked"}}`
	svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != client.StatusPath {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if _, err := io.WriteString(w, status); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(svc.Close)
	home := t.TempDir()
	paths := client.ClientPaths(home)
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	core := `{"core_url":"https://core.invalid","installation_id":"inst-1","listen":"` +
		strings.TrimPrefix(svc.URL, "http://") + `"}`
	if err := os.WriteFile(paths.Core, []byte(core), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	o, down := signingOutageFromClient()
	if !down || !o.Since.Equal(time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)) || o.Reason != "the CA store token was revoked" {
		t.Fatalf("signingOutageFromClient = %+v %v", o, down)
	}

	restore := signingOutageNow
	signingOutageNow = signingOutageFromClient
	t.Cleanup(func() { signingOutageNow = restore })
	offSwitch := "git commit " + "--no-gpg" + "-sign -m x"
	_, reason := hookDecision(t, offSwitch)
	if !strings.Contains(reason, "signing is down since 2026-10-11T09:30:00Z (the CA store token was revoked)") {
		t.Fatalf("the refusal does not carry the probe's outage:\n%s", reason)
	}

	// Signing works: the refusal names no outage.
	mu.Lock()
	status = `{"signing":{"up":true,"detail":"a certificate was issued at 2026-10-11T09:35:00Z"}}`
	mu.Unlock()
	if _, reason := hookDecision(t, offSwitch); strings.Contains(reason, "down since") {
		t.Fatalf("an outage named while signing works:\n%s", reason)
	}
	// No HOME to read: nothing known.
	t.Setenv("HOME", "")
	if _, down := signingOutageFromClient(); down {
		t.Fatal("an outage with no home directory")
	}
}

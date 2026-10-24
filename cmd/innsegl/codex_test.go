// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
)

// OAI-025: the CLI starts a real child with the route/hook settings and
// preserves its exit status, rather than writing global configuration.
func TestOAI025CodexLauncherUsesPerInvocationConfiguration(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "codex")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.163.0'; exit 0; fi\nprintf '%s\\n' \"$@\"\nexit 7\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := runCodexProcess(binary, "http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", false, []string{"exec", "hello"}, strings.NewReader(""), &out, &errs)
	if code != 7 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	for _, want := range []string{"--no-daemon", "model_provider=\"innsegl\"", "/backend-api/codex", "hook session", "exec\nhello"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("child missing %q: %s", want, out.String())
		}
	}
	out.Reset()
	errs.Reset()
	code = runCodexProcess(binary, "http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", false, []string{"-c", "model_provider=other"}, strings.NewReader(""), &out, &errs)
	if code == 7 || out.Len() != 0 {
		t.Fatal("allowed overriding the capture route")
	}
}

// OAI-025: capture lifecycle statements must not install persistent signing hooks.
func TestOAI025CaptureSessionLeavesGitHooksUntouched(t *testing.T) {
	dir := t.TempDir()
	statedRunGit(t, dir, "init", "-q", "-b", "main")
	statedRunGit(t, dir, "remote", "add", "origin", "https://example.invalid/org/repo.git")
	statedRunGit(t, dir, "commit", "-q", "--allow-empty", "-m", "first")
	posts, post := capturePosts(nil)
	code := runHookSession(strings.NewReader(hookInputFor(dir)), &bytes.Buffer{}, &bytes.Buffer{}, env(map[string]string{"INNSEGL_CAPTURE_ONLY": "1"}), post)
	if code != exitOK || len(*posts) != 1 || (*posts)[0].body["repo"] == "" {
		t.Fatal("capture did not state repository")
	}
	for _, name := range []string{"prepare-commit-msg", "post-commit", "reference-transaction"} {
		if _, err := os.Stat(filepath.Join(dir, ".git", "hooks", name)); !os.IsNotExist(err) {
			t.Fatalf("capture installed %s: %v", name, err)
		}
	}
}

// OAI-025: an old installed hook must reject the explicit capture-only
// option rather than silently running the signing lifecycle.
func TestOAI025CaptureSessionOptionIsRecognised(t *testing.T) {
	var out, errs bytes.Buffer
	if code := hookCommand([]string{"session", "--capture-only"}, &out, &errs); code != exitOK {
		t.Fatalf("capture option exit=%d: %s", code, errs.String())
	}
}

// OAI-014: negotiated signing capability cannot bypass installed-hook trust.
func TestOAI014CodexLauncherValidatesHookBuild(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(`{"formats":["responses-http"],"signing":true,"signing_mode":"structured"}`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	if err := client.WriteCoreConfig(client.ClientPaths(home), client.CoreConfig{CoreURL: "https://example.invalid", InstallationID: "installation-test", Listen: strings.TrimPrefix(server.URL, "http://")}); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	called := false
	code := codexCommandWithHook([]string{"--sign-commits"}, &out, &errs, func() (string, error) {
		called = true
		return "", errors.New("installed hook is another build")
	})
	if !called || code != exitConnectFailed || !strings.Contains(errs.String(), "installed hook is another build") {
		t.Fatalf("hook trust bypassed: called=%v exit=%d stderr=%s", called, code, errs.String())
	}
}

// OAI-006: child launch hooks are installed only when the client/core
// capability negotiation enables linked threads.
func TestOAI006CodexLauncherEnablesLinkedThreadsWhenNegotiated(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "codex")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.163.0'; exit 0; fi\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := runCodexProcessSettings(binary, "http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", false, []string{"exec", "hello"}, strings.NewReader(""), &out, &errs, true, true)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	for _, want := range []string{"agents.enabled=true", "hooks.SubagentStart=", "hooks.SubagentStop=", "SubagentStart", "SubagentStop"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("negotiated child launch missing %q: %s", want, out.String())
		}
	}
}

func TestOAI006CodexLauncherKeepsChildrenDisabledWithoutNegotiation(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "codex")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'codex-cli 0.163.0'; exit 0; fi\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	code := runCodexProcessSettings(binary, "http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", false, nil, strings.NewReader(""), &out, &errs, false, false)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if strings.Contains(out.String(), "agents.enabled=true") || strings.Contains(out.String(), "hooks.SubagentStart=") {
		t.Fatalf("children enabled without negotiation: %s", out.String())
	}
}

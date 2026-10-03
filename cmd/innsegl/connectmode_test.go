// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

// RM-312: `innsegl connect` writes the route and its own hooks only;
// `--hardened` adds the lockdown; `--update` rewrites an enrolled machine's
// managed settings to the chosen mode without a token.

const userStatusLine = `{"statusLine": {"type": "command", "command": "/opt/example/statusline.sh"}}`

func (f *connectFixture) writeUserSettings(t *testing.T, text string) {
	t.Helper()
	dir := filepath.Join(f.home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func settingsJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readFile(t, path), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *connectFixture) enrol(t *testing.T, extra ...string) {
	t.Helper()
	args := append([]string{f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile, "--managed-settings", f.settings}, extra...)
	if code, stdout, stderr := f.connect(args...); code != exitOK {
		t.Fatalf("connect = %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestRM312ConnectHardenedWritesTheLockdownAndTheUsersStatusLine(t *testing.T) {
	f := newConnectFixture(t)
	f.writeUserSettings(t, userStatusLine)
	f.enrol(t, "--hardened")
	got := settingsJSON(t, f.settings)
	if got["allowManagedHooksOnly"] != true {
		t.Errorf("allowManagedHooksOnly = %v", got["allowManagedHooksOnly"])
	}
	sandbox, ok := got["sandbox"].(map[string]any)
	if !ok || sandbox["enabled"] != true || sandbox["enableWeakerNetworkIsolation"] != true ||
		!reflect.DeepEqual(sandbox["excludedCommands"], []any{"gh *"}) {
		t.Fatalf("sandbox = %v", got["sandbox"])
	}
	fsys, ok := sandbox["filesystem"].(map[string]any)
	if !ok {
		t.Fatalf("sandbox.filesystem = %v", sandbox["filesystem"])
	}
	if deny := fsys["denyRead"]; !reflect.DeepEqual(deny, []any{filepath.Join(f.home, ".innsegl")}) {
		t.Errorf("denyRead = %v", deny)
	}
	want := map[string]any{"type": "command", "command": "/opt/example/statusline.sh"}
	if !reflect.DeepEqual(got["statusLine"], want) {
		t.Errorf("statusLine = %v, want the user's own", got["statusLine"])
	}
}

func TestRM312ConnectUpdateMovesBetweenModesWithoutAToken(t *testing.T) {
	f := newConnectFixture(t)
	f.writeUserSettings(t, userStatusLine)
	operator := "{\n  \"model\": \"opus\",\n  \"sandbox\": {\n    \"filesystem\": {\n      \"denyRead\": [\n        \"/srv/private\"\n      ]\n    }\n  }\n}\n"
	if err := os.WriteFile(f.settings, []byte(operator), 0o644); err != nil {
		t.Fatal(err)
	}
	// What an earlier version left: the lockdown, written by default.
	f.enrol(t, "--hardened")
	enrolled, _ := f.core.Counts()
	f.calls = nil

	code, stdout, stderr := f.connect("--update", "--managed-settings", f.settings)
	if code != exitOK {
		t.Fatalf("--update = %d\n%s\n%s", code, stdout, stderr)
	}
	got := settingsJSON(t, f.settings)
	for _, key := range []string{"allowManagedHooksOnly", "permissions", "statusLine"} {
		if _, present := got[key]; present {
			t.Errorf("--update kept %q", key)
		}
	}
	if !reflect.DeepEqual(got["sandbox"], map[string]any{"filesystem": map[string]any{"denyRead": []any{"/srv/private"}}}) {
		t.Errorf("sandbox = %v, want the operator's own only", got["sandbox"])
	}
	if got["model"] != "opus" || got["env"] == nil || got["hooks"] == nil {
		t.Errorf("--update lost a key: %v", got)
	}
	if n, _ := f.core.Counts(); n != enrolled {
		t.Error("--update spent a token")
	}
	if len(f.calls) != 0 {
		t.Errorf("--update ran service commands: %v", f.calls)
	}

	if code, _, stderr := f.connect("--update", "--hardened", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("--update --hardened: %s", stderr)
	}
	if got := settingsJSON(t, f.settings); got["allowManagedHooksOnly"] != true || got["statusLine"] == nil {
		t.Errorf("--update --hardened did not lock down: %v", got)
	}

	if code, _, stderr := f.connect("--disconnect", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("disconnect: %s", stderr)
	}
	if got := readFile(t, f.settings); string(got) != operator {
		t.Fatalf("disconnect after --hardened left\n%s\nwant\n%s", got, operator)
	}
}

func TestRM312ConnectUpdateNeedsAnEnrolment(t *testing.T) {
	f := newConnectFixture(t)
	code, _, stderr := f.connect("--update", "--managed-settings", f.settings)
	if code == exitOK || !strings.Contains(stderr, "not connected") {
		t.Fatalf("--update with no enrolment = %d: %s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestRM312ConnectUpdatePrintsTheAdminCommand(t *testing.T) {
	f := newConnectFixture(t)
	f.enrol(t, "--no-service")
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := f.connect("--update", "--managed-settings", filepath.Join(blocker, "managed-settings.json"))
	if code == exitOK || !strings.Contains(stderr, "sudo install -m 0644") || !strings.Contains(stderr, "--update") {
		t.Fatalf("--update on a file it cannot write = %d: %s", code, stderr)
	}
}

func TestRM312ConnectHardenedIsRefusedWithPauseResumeDisconnect(t *testing.T) {
	f := newConnectFixture(t)
	for _, mode := range []string{"--pause", "--resume", "--disconnect"} {
		if code, _, stderr := f.connect(mode, "--hardened", "--managed-settings", f.settings); code != exitUsage || !strings.Contains(stderr, "--hardened") {
			t.Errorf("%s --hardened = %d: %s", mode, code, stderr)
		}
	}
}

// RM-329 (#500): the settings name the client's proxy CA, so connect makes
// sure it exists before writing them, on enrolment and on --update.
func TestRM329ConnectWritesTheProxyCABeforeTheSettingsNameIt(t *testing.T) {
	f := newConnectFixture(t)
	f.enrol(t)
	paths := client.ClientPaths(f.home)
	if _, err := os.Stat(paths.ProxyCA); err != nil {
		t.Fatalf("enrolment wrote no proxy CA: %v", err)
	}
	if err := os.Remove(paths.ProxyCA); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.ProxyCAKey); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.connect("--update", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("--update: %s", stderr)
	}
	if _, err := os.Stat(paths.ProxyCA); err != nil {
		t.Fatalf("--update wrote no proxy CA: %v", err)
	}
}

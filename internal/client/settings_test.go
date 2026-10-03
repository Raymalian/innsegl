// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testSettingsConfig() SettingsConfig {
	return SettingsConfig{
		HookBin:  "/opt/innsegl/bin/innsegl",
		LocalURL: "http://127.0.0.1:28195",
		ProxyCA:  "/opt/home-dev/.innsegl/client/proxy-ca.pem",
		LogDeny:  "/opt/home-dev/.innsegl",
		CAAllow:  "/opt/home-dev/.innsegl/ca",
	}
}

func fixedNow() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }

// goldenSettings is exactly what connect writes into an empty managed
// settings file for testSettingsConfig: the route and the hooks, and nothing
// that locks the machine down (RM-312).
const goldenSettings = `{
  "env": {
    "INNSEGL_CORE_URL": "http://127.0.0.1:28195",
    "HTTPS_PROXY": "http://127.0.0.1:28195",
    "https_proxy": "http://127.0.0.1:28195",
    "HTTP_PROXY": "http://127.0.0.1:28195",
    "http_proxy": "http://127.0.0.1:28195",
    "NO_PROXY": "127.0.0.1,localhost,::1",
    "no_proxy": "127.0.0.1,localhost,::1",
    "NODE_EXTRA_CA_CERTS": "/opt/home-dev/.innsegl/client/proxy-ca.pem",
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:28195"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook pre-tool-use"
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "SubagentStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ],
    "CwdChanged": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/opt/innsegl/bin/innsegl hook session"
          }
        ]
      }
    ]
  },
  "attribution": {
    "commit": ""
  }
}
`

// operatorSettings holds keys an operator wrote themselves, in an order and
// with values the installer must keep.
const operatorSettings = `{
  "model": "opus",
  "env": {
    "MY_VAR": "kept",
    "ANTHROPIC_BASE_URL": "https://old.example"
  },
  "hooks": {
    "PreToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "/opt/example/edit-hook.sh"}]}
    ]
  },
  "permissions": {"deny": ["Read(./secrets/**)"]},
  "sandbox": {"filesystem": {"denyRead": ["/srv/private"]}},
  "cleanupPeriodDays": 30,
  "note": "<keep> & é"
}
`

func TestENF009SettingsIntoAnEmptyFileMatchTheGolden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	var out bytes.Buffer
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &out); err != nil {
		t.Fatalf("InstallSettings: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenSettings {
		t.Fatalf("managed settings differ from the golden\n--- got\n%s\n--- want\n%s", got, goldenSettings)
	}
	if backups(t, path) != 0 {
		t.Fatal("a fresh file was backed up; there was nothing to back up")
	}
}

func TestENF009MergeKeepsOperatorKeysAndBacksUpOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(operatorSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &out); err != nil {
		t.Fatalf("InstallSettings: %v", err)
	}
	if backups(t, path) != 1 {
		t.Fatalf("want exactly one backup, got %d", backups(t, path))
	}
	backup, err := os.ReadFile(path + ".bak.20261001T120000Z")
	if err != nil || string(backup) != operatorSettings {
		t.Fatalf("the backup is not the original, byte for byte (err=%v)", err)
	}
	got := readJSON(t, path)
	for key, want := range map[string]any{
		"model":             "opus",
		"cleanupPeriodDays": json.Number("30"),
		"note":              "<keep> & é",
	} {
		if !reflect.DeepEqual(got[key], want) {
			t.Errorf("%s = %#v, want %#v", key, got[key], want)
		}
	}
	env := objAt(t, got, "env")
	// RM-329: a base URL routes model requests past the client; the
	// operator's own goes too, and is said.
	if _, has := env["ANTHROPIC_BASE_URL"]; env["MY_VAR"] != "kept" || has || env["HTTPS_PROXY"] != "http://127.0.0.1:28195" {
		t.Errorf("env = %v", env)
	}
	pre := listAt(t, objAt(t, got, "hooks"), "PreToolUse")
	if len(pre) != 2 || !strings.Contains(mustJSON(t, pre[0]), "/opt/example/edit-hook.sh") {
		t.Errorf("the operator's own PreToolUse hook did not survive first: %s", mustJSON(t, pre))
	}
	perms := objAt(t, got, "permissions")
	if !reflect.DeepEqual(perms, map[string]any{"deny": []any{"Read(./secrets/**)"}}) {
		t.Errorf("permissions = %v, want the operator's own only", perms)
	}
	deny := listAt(t, objAt(t, objAt(t, got, "sandbox"), "filesystem"), "denyRead")
	if !reflect.DeepEqual(deny, []any{"/srv/private"}) {
		t.Errorf("denyRead = %v, want the operator's own only", deny)
	}
	// The operator's key order stands: the first key is still theirs.
	text := readFile(t, path)
	if !strings.HasPrefix(string(text), "{\n  \"model\": \"opus\",\n  \"env\": {\n    \"MY_VAR\": \"kept\",") {
		t.Errorf("key order changed:\n%s", text)
	}
	if !strings.Contains(string(text), `"note": "<keep> & é"`) {
		t.Errorf("unrelated text was respelled:\n%s", text)
	}
}

func TestENF009SecondRunIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(operatorSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, path)
	later := func() time.Time { return fixedNow().Add(time.Hour) }
	var out bytes.Buffer
	if err := InstallSettings(path, testSettingsConfig(), later, &out); err != nil {
		t.Fatal(err)
	}
	second := readFile(t, path)
	if !bytes.Equal(first, second) {
		t.Fatal("a second run changed the file")
	}
	if backups(t, path) != 1 {
		t.Fatalf("a second run made another backup: %d", backups(t, path))
	}
	if !strings.Contains(out.String(), "already up to date") {
		t.Errorf("out = %q", out.String())
	}
}

func TestENF009RemoveTakesOnlyWhatInstallWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(operatorSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := testSettingsConfig()
	if err := InstallSettings(path, cfg, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := UninstallSettings(path, cfg, func() time.Time { return fixedNow().Add(time.Minute) }, &out); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, path)
	want := readJSONText(t, `{
	  "model": "opus",
	  "env": {"MY_VAR": "kept"},
	  "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "/opt/example/edit-hook.sh"}]}]},
	  "permissions": {"deny": ["Read(./secrets/**)"]},
	  "sandbox": {"filesystem": {"denyRead": ["/srv/private"]}},
	  "cleanupPeriodDays": 30,
	  "note": "<keep> & é"
	}`)
	// ANTHROPIC_BASE_URL was the operator's before install overwrote it; once
	// it holds what connect wrote it is connect's, so it goes.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after removal\n got %s\nwant %s", mustJSON(t, got), mustJSON(t, want))
	}

	// Into an empty file and out again leaves an empty object.
	path2 := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := InstallSettings(path2, cfg, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := UninstallSettings(path2, cfg, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if text := readFile(t, path2); string(text) != "{}\n" {
		t.Fatalf("install then remove left %q", text)
	}
}

func TestENF009RemoveLeavesAChangedValueAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	cfg := testSettingsConfig()
	if err := InstallSettings(path, cfg, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	text := readFile(t, path)
	edited := strings.Replace(string(text), `"OTEL_LOGS_EXPORTER": "otlp"`, `"OTEL_LOGS_EXPORTER": "console"`, 1)
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := UninstallSettings(path, cfg, fixedNow, &out); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, path)
	if objAt(t, got, "env")["OTEL_LOGS_EXPORTER"] != "console" {
		t.Fatalf("a value the operator changed was removed: %v", got)
	}
	if !strings.Contains(out.String(), "leaving it alone") {
		t.Errorf("out = %q, want a note that it was left alone", out.String())
	}
}

func TestENF009RefusesInvalidJSONAndChangesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("err = %v", err)
	}
	if text := readFile(t, path); string(text) != "{not json" {
		t.Fatal("an invalid file was changed")
	}
	if err := os.WriteFile(path, []byte(`["a list"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err == nil {
		t.Fatal("a file holding a list was accepted")
	}
}

func TestENF009NotWritablePrintsTheAdminCommand(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "managed-settings.json")
	err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{})
	var nw *NotWritableError
	if !errors.As(err, &nw) {
		t.Fatalf("err = %v, want a NotWritableError", err)
	}
	if !strings.Contains(nw.Command, "sudo mkdir -p") || !strings.Contains(nw.Command, "sudo install -m 0644") {
		t.Errorf("command = %q", nw.Command)
	}
	staged, rerr := os.ReadFile(nw.Staged)
	if rerr != nil || string(staged) != goldenSettings {
		t.Errorf("the staged file is not the settings to install (err=%v)", rerr)
	}
	_ = os.Remove(nw.Staged)
}

func TestENF009PauseAndResumeAreByteIdentical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(operatorSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, path)
	if err := Pause(path); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pause left the settings in place")
	}
	paused := readFile(t, path+".paused")
	if !bytes.Equal(before, paused) {
		t.Fatal("pause changed the bytes")
	}
	if err := Pause(path); err == nil {
		t.Fatal("pausing twice was accepted")
	}
	if err := Resume(path); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	after := readFile(t, path)
	if !bytes.Equal(before, after) {
		t.Fatal("resume did not restore the same bytes")
	}
	if err := Resume(path); err == nil || !strings.Contains(err.Error(), "nothing is paused") {
		t.Fatalf("resume with nothing paused: %v", err)
	}
}

func backups(t *testing.T, path string) int {
	t.Helper()
	m, err := filepath.Glob(path + ".bak.*")
	if err != nil {
		t.Fatal(err)
	}
	return len(m)
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return readJSONText(t, string(text))
}

func readJSONText(t *testing.T, text string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode %q: %v", text, err)
	}
	return m
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func objAt(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	o, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %#v", key, m[key])
	}
	return o
}

func listAt(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	l, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%s is not a list: %#v", key, m[key])
	}
	return l
}

// RM-329 (#500): a machine connected by an earlier version holds the
// base-URL route. --update moves it to the proxy: the base URL and the
// tool-search switch go, the proxy variables come.
func TestRM329UpdateMovesTheBaseURLRouteToTheProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	old := `{"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:28195", "ENABLE_TOOL_SEARCH": "true", "MY_VAR": "kept"}}` + "\n"
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	env := objAt(t, readJSON(t, path), "env")
	for _, gone := range []string{"ANTHROPIC_BASE_URL", "ENABLE_TOOL_SEARCH"} {
		if _, has := env[gone]; has {
			t.Errorf("%s survived the update", gone)
		}
	}
	for k, want := range map[string]string{
		"HTTPS_PROXY": "http://127.0.0.1:28195", "https_proxy": "http://127.0.0.1:28195",
		"NO_PROXY": "127.0.0.1,localhost,::1", "NODE_EXTRA_CA_CERTS": "/opt/home-dev/.innsegl/client/proxy-ca.pem",
		"MY_VAR": "kept",
	} {
		if env[k] != want {
			t.Errorf("%s = %v, want %q", k, env[k], want)
		}
	}
	// Removed again, the file holds the operator's own key only.
	if err := UninstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if env := objAt(t, readJSON(t, path), "env"); len(env) != 1 || env["MY_VAR"] != "kept" {
		t.Errorf("after removal env = %v", env)
	}
}

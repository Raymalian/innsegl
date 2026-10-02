// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// RM-312: by default the client writes the route and its own hooks only.
// The machine lockdown (allowManagedHooksOnly, the permissions flag, the
// sandbox) is opt-in, behind --hardened.

// goldenHardened is what connect --hardened writes into an empty managed
// settings file for testSettingsConfig, with the user's own statusLine
// copied in from userSettingsWithStatusLine.
const goldenHardened = `{
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:28195",
    "INNSEGL_CORE_URL": "http://127.0.0.1:28195",
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:28195",
    "ENABLE_TOOL_SEARCH": "true"
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
  },
  "allowManagedHooksOnly": true,
  "permissions": {
    "disableBypassPermissionsMode": "disable"
  },
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "failIfUnavailable": true,
    "excludedCommands": [
      "gh *"
    ],
    "enableWeakerNetworkIsolation": true,
    "filesystem": {
      "denyRead": [
        "/opt/home-dev/.innsegl"
      ],
      "allowRead": [
        "/opt/home-dev/.innsegl/ca"
      ]
    },
    "network": {
      "allowLocalBinding": true
    }
  },
  "statusLine": {
    "type": "command",
    "command": "/opt/home-dev/.claude/statusline.sh",
    "padding": 0
  }
}
`

// oldLockdown is what connect wrote before RM-312, measured on the
// operator's machine, with an operator's own sandbox path, permission rule
// and statusLine beside it.
const oldLockdown = `{
  "model": "opus",
  "env": {
    "ANTHROPIC_BASE_URL": "http://127.0.0.1:28195",
    "INNSEGL_CORE_URL": "http://127.0.0.1:28195",
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "http/json",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:28195",
    "ENABLE_TOOL_SEARCH": "true"
  },
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/innsegl/bin/innsegl hook pre-tool-use"}]}
    ],
    "SessionStart": [{"hooks": [{"type": "command", "command": "/opt/innsegl/bin/innsegl hook session"}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/opt/innsegl/bin/innsegl hook session"}]}],
    "SubagentStart": [{"hooks": [{"type": "command", "command": "/opt/innsegl/bin/innsegl hook session"}]}],
    "CwdChanged": [{"hooks": [{"type": "command", "command": "/opt/innsegl/bin/innsegl hook session"}]}]
  },
  "allowManagedHooksOnly": true,
  "attribution": {"commit": ""},
  "permissions": {"deny": ["Read(./secrets/**)"], "disableBypassPermissionsMode": "disable"},
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "failIfUnavailable": true,
    "filesystem": {
      "denyRead": ["/srv/private", "/opt/home-dev/.innsegl"],
      "allowRead": ["/opt/home-dev/.innsegl/ca"]
    },
    "network": {"allowLocalBinding": true}
  },
  "statusLine": {"type": "command", "command": "/opt/operator/managed-status.sh"}
}
`

const userSettingsWithStatusLine = `{
  "theme": "dark",
  "statusLine": {
    "type": "command",
    "command": "/opt/home-dev/.claude/statusline.sh",
    "padding": 0
  }
}
`

func hardenedConfig(t *testing.T, userSettings string) SettingsConfig {
	t.Helper()
	cfg := testSettingsConfig()
	cfg.Hardened = true
	if userSettings != "" {
		path := filepath.Join(t.TempDir(), "settings.json")
		if err := os.WriteFile(path, []byte(userSettings), 0o644); err != nil {
			t.Fatal(err)
		}
		line, err := ReadStatusLine(path)
		if err != nil {
			t.Fatalf("ReadStatusLine: %v", err)
		}
		cfg.StatusLine = line
	}
	return cfg
}

func TestRM312DefaultWritesNoLockdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := InstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, path)
	for _, key := range []string{"sandbox", "allowManagedHooksOnly", "permissions", "statusLine"} {
		if _, present := got[key]; present {
			t.Errorf("the default settings hold %q: %s", key, readFile(t, path))
		}
	}
	keys := []string{}
	for k := range got {
		keys = append(keys, k)
	}
	if len(keys) != 3 {
		t.Errorf("top-level keys = %v, want env, hooks, attribution", keys)
	}
}

func TestRM312HardenedMatchesTheGoldenAndCopiesTheStatusLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := InstallSettings(path, hardenedConfig(t, userSettingsWithStatusLine), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); string(got) != goldenHardened {
		t.Fatalf("hardened settings differ from the golden\n--- got\n%s\n--- want\n%s", got, goldenHardened)
	}
	// A second run changes nothing.
	var out bytes.Buffer
	if err := InstallSettings(path, hardenedConfig(t, userSettingsWithStatusLine), fixedNow, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already up to date") {
		t.Errorf("a second hardened run changed the file: %s", out.String())
	}
}

func TestRM312HardenedWithoutAUserStatusLineWritesNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := InstallSettings(path, hardenedConfig(t, `{"theme": "dark"}`), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, present := readJSON(t, path)["statusLine"]; present {
		t.Fatal("a statusLine was written although the user has none")
	}
	if line, err := ReadStatusLine(filepath.Join(t.TempDir(), "absent.json")); err != nil || line != nil {
		t.Fatalf("an absent user settings file = %v, %v; want nil, nil", line, err)
	}
}

func TestRM312HardenedKeepsAnOperatorsOwnManagedStatusLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	own := `{"statusLine": {"type": "command", "command": "/opt/operator/managed-status.sh"}}` + "\n"
	if err := os.WriteFile(path, []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := InstallSettings(path, hardenedConfig(t, userSettingsWithStatusLine), fixedNow, &out); err != nil {
		t.Fatal(err)
	}
	line := objAt(t, readJSON(t, path), "statusLine")
	if line["command"] != "/opt/operator/managed-status.sh" {
		t.Fatalf("the operator's own managed statusLine was replaced: %v", line)
	}
	if !strings.Contains(out.String(), "statusLine") {
		t.Errorf("out = %q, want a note that the statusLine was left alone", out.String())
	}
}

func TestRM312UpdateFromTheOldLockdownRemovesOnlyTheLockdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(oldLockdown), 0o644); err != nil {
		t.Fatal(err)
	}
	// The user's own statusLine differs from the managed one, so the
	// managed one is the operator's, not a copy innsegl made: it stays.
	cfg := testSettingsConfig()
	user := hardenedConfig(t, userSettingsWithStatusLine)
	cfg.StatusLine = user.StatusLine
	if err := InstallSettings(path, cfg, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	got := readJSON(t, path)
	want := readJSONText(t, goldenSettings)
	want["model"] = "opus"
	want["permissions"] = map[string]any{"deny": []any{"Read(./secrets/**)"}}
	want["sandbox"] = map[string]any{"filesystem": map[string]any{"denyRead": []any{"/srv/private"}}}
	want["statusLine"] = map[string]any{"type": "command", "command": "/opt/operator/managed-status.sh"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after update\n got %s\nwant %s", mustJSON(t, got), mustJSON(t, want))
	}
	if backups(t, path) != 1 {
		t.Errorf("want one backup of the old file, got %d", backups(t, path))
	}
}

func TestRM312UpdateFromHardenedToDefaultRemovesTheStatusLineCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	hard := hardenedConfig(t, userSettingsWithStatusLine)
	if err := InstallSettings(path, hard, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	soft := hard
	soft.Hardened = false
	if err := InstallSettings(path, soft, fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); string(got) != goldenSettings {
		t.Fatalf("hardened then default\n--- got\n%s\n--- want\n%s", got, goldenSettings)
	}
}

func TestRM312DisconnectAfterEachModeLeavesNoInnseglKey(t *testing.T) {
	for _, mode := range []string{"default", "hardened"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed-settings.json")
			if err := os.WriteFile(path, []byte(operatorSettings), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg := hardenedConfig(t, userSettingsWithStatusLine)
			cfg.Hardened = mode == "hardened"
			if err := InstallSettings(path, cfg, fixedNow, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if err := UninstallSettings(path, cfg, fixedNow, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			want := readJSONText(t, operatorSettings)
			// ANTHROPIC_BASE_URL held connect's value, so it went with it.
			delete(objAt(t, want, "env"), "ANTHROPIC_BASE_URL")
			if got := readJSON(t, path); !reflect.DeepEqual(got, want) {
				t.Fatalf("after disconnect\n got %s\nwant %s", mustJSON(t, got), mustJSON(t, want))
			}

			empty := filepath.Join(t.TempDir(), "managed-settings.json")
			if err := InstallSettings(empty, cfg, fixedNow, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if err := UninstallSettings(empty, cfg, fixedNow, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			if text := readFile(t, empty); string(text) != "{}\n" {
				t.Fatalf("install then remove left %q", text)
			}
		})
	}
}

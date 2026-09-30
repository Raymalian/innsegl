// SPDX-License-Identifier: Apache-2.0

package api

import (
	"os"
	"path/filepath"
	"testing"
)

// AUTH-002: enrolment is refused unless the managed-settings file this
// deployment's harness loaded can be read as denying the container-runtime
// socket, per ADR-0062's "enrolment stays locked" section. CheckSocketDenial
// is the fact the enrolment endpoint reads at the moment of every request —
// never cached, never assumed from a prior check.

func writeManagedSettings(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "managed-settings.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("writing fixture managed settings: %v", err)
	}
	return path
}

func TestCheckSocketDenial_DeniedWhenSandboxBlocksTheSocket(t *testing.T) {
	path := writeManagedSettings(t, `{
		"sandbox": {
			"enabled": true,
			"allowUnsandboxedCommands": false,
			"network": {"allowLocalBinding": true}
		}
	}`)
	got, err := CheckSocketDenial(path)
	if err != nil {
		t.Fatalf("CheckSocketDenial: %v", err)
	}
	if !got.Denied {
		t.Fatalf("Denied = false, want true; reason: %s", got.Reason)
	}
}

func TestCheckSocketDenial_NotDeniedWhenFileIsAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	got, err := CheckSocketDenial(path)
	if err != nil {
		t.Fatalf("CheckSocketDenial: %v", err)
	}
	if got.Denied {
		t.Fatalf("Denied = true for an absent file, want false")
	}
	if got.Reason == "" {
		t.Fatal("an absent file must give a reason an operator can act on")
	}
}

func TestCheckSocketDenial_NotDeniedWhenSandboxIsOff(t *testing.T) {
	path := writeManagedSettings(t, `{"sandbox": {"enabled": false, "allowUnsandboxedCommands": false}}`)
	got, err := CheckSocketDenial(path)
	if err != nil {
		t.Fatalf("CheckSocketDenial: %v", err)
	}
	if got.Denied {
		t.Fatal("Denied = true with sandbox.enabled false, want false")
	}
}

func TestCheckSocketDenial_NotDeniedWhenUnsandboxedCommandsAreAllowed(t *testing.T) {
	path := writeManagedSettings(t, `{"sandbox": {"enabled": true, "allowUnsandboxedCommands": true}}`)
	got, err := CheckSocketDenial(path)
	if err != nil {
		t.Fatalf("CheckSocketDenial: %v", err)
	}
	if got.Denied {
		t.Fatal("Denied = true with allowUnsandboxedCommands true, want false")
	}
}

func TestCheckSocketDenial_NotDeniedWhenUnixSocketsAreExplicitlyAllowed(t *testing.T) {
	for _, key := range []string{"allowUnixSockets", "allowAllUnixSockets"} {
		path := writeManagedSettings(t, `{
			"sandbox": {
				"enabled": true,
				"allowUnsandboxedCommands": false,
				"network": {"`+key+`": true}
			}
		}`)
		got, err := CheckSocketDenial(path)
		if err != nil {
			t.Fatalf("CheckSocketDenial(%s): %v", key, err)
		}
		if got.Denied {
			t.Fatalf("Denied = true with sandbox.network.%s present, want false", key)
		}
	}
}

func TestCheckSocketDenial_NotDeniedOnMalformedJSON(t *testing.T) {
	path := writeManagedSettings(t, `{not json`)
	got, err := CheckSocketDenial(path)
	if err != nil {
		t.Fatalf("CheckSocketDenial: %v", err)
	}
	if got.Denied {
		t.Fatal("Denied = true for malformed JSON, want false (fail closed)")
	}
}

func TestCheckSocketDenial_NotDeniedWithNoSandboxStanza(t *testing.T) {
	path := writeManagedSettings(t, `{"env": {}}`)
	got, err := CheckSocketDenial(path)
	if err != nil {
		t.Fatalf("CheckSocketDenial: %v", err)
	}
	if got.Denied {
		t.Fatal("Denied = true with no sandbox stanza, want false")
	}
}

func TestDefaultManagedSettingsPath_PerOS(t *testing.T) {
	if got := DefaultManagedSettingsPath("darwin"); got != "/Library/Application Support/ClaudeCode/managed-settings.json" {
		t.Fatalf("darwin path = %q", got)
	}
	if got := DefaultManagedSettingsPath("linux"); got != "/etc/claude-code/managed-settings.json" {
		t.Fatalf("linux path = %q", got)
	}
}

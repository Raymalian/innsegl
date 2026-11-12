// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// OAI-020/025, CLI-036: ordinary launches get the same managed route and
// lifecycle as explicit launches; updates preserve the administrator's text.
func TestOAI025CodexManagedInstallUpdateRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed_config.toml")
	original := "# administrator settings\nmodel = 'example-model'\n[tools]\nweb_search = true\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := CodexManagedConfig{LocalURL: "http://127.0.0.1:28195", HookBin: "/opt/innsegl/bin/innsegl"}
	now := func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }
	if err := InstallCodexSettings(path, cfg, now, io.Discard); err != nil {
		t.Fatal(err)
	}
	if active, err := CodexManagedActive(path); err != nil || !active {
		t.Fatalf("installed block inactive: %v", err)
	}
	first := readFile(t, path)
	for _, want := range []string{original, "model_provider=\"innsegl\"", "hooks.SessionStart=", "hooks.UserPromptSubmit=", "hooks.SubagentStart=", "hooks.SessionEnd=", "agents.enabled=true", "/backend-api/codex", "otel.exporter="} {
		if !bytes.Contains(first, []byte(want)) {
			t.Errorf("missing %q", want)
		}
	}
	if err := InstallCodexSettings(path, cfg, now, io.Discard); err != nil {
		t.Fatal(err)
	}
	second := readFile(t, path)
	if !bytes.Equal(first, second) {
		t.Fatal("repeat setup changed bytes")
	}
	if err := PauseCodexSettings(path, true, now, io.Discard); err != nil {
		t.Fatal(err)
	}
	if active, err := CodexManagedActive(path); err != nil || active {
		t.Fatalf("paused block active: %v", err)
	}
	if got := readFile(t, path); !bytes.Contains(got, []byte(original)) {
		t.Fatal("pause removed administrator settings")
	}
	if err := PauseCodexSettings(path, false, now, io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); !bytes.Equal(got, first) {
		t.Fatal("resume changed managed mode or administrator settings")
	}
	cfg.LocalURL = "http://127.0.0.1:28495"
	cfg.API, cfg.Signing = true, true
	if err := InstallCodexSettings(path, cfg, now, io.Discard); err != nil {
		t.Fatal(err)
	}
	updated := readFile(t, path)
	if bytes.Contains(updated, []byte(":28195")) || !bytes.Contains(updated, []byte(":28495/v1")) || !bytes.Contains(updated, []byte("pre-tool-use --codex")) {
		t.Fatal("update left stale routing or signing")
	}
	api, signing, err := CodexManagedMode(path)
	if err != nil || !api || !signing {
		t.Fatalf("mode not retained: %v %v %v", api, signing, err)
	}
	if err := UninstallCodexSettings(path, now, io.Discard); err != nil {
		t.Fatal(err)
	}
	removed := readFile(t, path)
	if string(removed) != original {
		t.Fatalf("uninstall changed administrator text: %q", removed)
	}
}

// OAI-025: invalid TOML, ambiguous ownership and overlapping administrator
// configuration cannot be silently overwritten by enrollment or recovery.
func TestOAI025CodexManagedRefusesAmbiguousConfiguration(t *testing.T) {
	for _, original := range []string{"model = [", "model_provider = 'other'\n", "# BEGIN INNSEGL CODEX\n", "# END INNSEGL CODEX\n", "[hooks]\nSessionStart = []\n"} {
		t.Run(strings.ReplaceAll(original, "\n", "_"), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "managed_config.toml")
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := CodexManagedConfig{LocalURL: "http://127.0.0.1:28195", HookBin: "/opt/innsegl/bin/innsegl"}
			if err := InstallCodexSettings(path, cfg, time.Now, io.Discard); err == nil {
				t.Fatal("accepted ambiguous configuration")
			}
			got := readFile(t, path)
			if string(got) != original {
				t.Fatal("modified refused file")
			}
		})
	}
}

// CLI-036: preflight stages exactly the desired managed TOML through the
// existing hash-checked administrator install, before enrollment is consumed.
func TestCLI036CodexManagedPreflightStagesWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed_config.toml")
	if err := os.WriteFile(path, []byte("# existing\n"), 0400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0600); err != nil {
			t.Error(err)
		}
	})
	cfg := CodexManagedConfig{LocalURL: "http://127.0.0.1:28195", HookBin: "/opt/innsegl/bin/innsegl"}
	err := CheckCodexSettingsWritable(path, cfg, true)
	if err == nil {
		t.Fatal("read-only target accepted")
	}
	got := readFile(t, path)
	if string(got) != "# existing\n" {
		t.Fatal("preflight wrote the target")
	}
}

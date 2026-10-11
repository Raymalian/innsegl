// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// staleHookSettings is a managed settings file an older connect left
// behind, as measured: duplicate entries naming an innsegl binary that no
// longer exists (~/go/bin/innsegl), one at a quoted path, one on an event
// connect no longer writes, beside the operator's own hooks, one of which
// shares a group with a stale entry.
const staleHookSettings = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/home-dev/go/bin/innsegl hook pre-tool-use"}]},
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/home-dev/go/bin/innsegl hook pre-tool-use"}]},
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-hook"},
                                    {"type": "command", "command": "/opt/home-dev/go/bin/innsegl hook pre-tool-use"}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "'/opt/home-dev/My Tools/innsegl' hook session"}]},
      {"hooks": [{"type": "command", "command": "/opt/other/innsegl-helper hook session"}]}
    ],
    "Stop": [
      {"hooks": [{"type": "command", "command": "/opt/home-dev/go/bin/innsegl hook session"}]}
    ]
  }
}
`

// staleForeign are the hooks in staleHookSettings that are not innsegl's.
var staleForeign = []string{"/usr/local/bin/lint-hook", "/opt/other/innsegl-helper hook session"}

// innseglCommands lists every hook command in the settings whose program
// is an innsegl binary, by event.
func innseglCommands(t *testing.T, m map[string]any) map[string][]string {
	t.Helper()
	got := map[string][]string{}
	if _, ok := m["hooks"]; !ok {
		return got
	}
	for event := range objAt(t, m, "hooks") {
		for _, g := range listAt(t, objAt(t, m, "hooks"), event) {
			group, ok := g.(map[string]any)
			if !ok {
				t.Fatalf("hooks.%s holds a group that is not an object: %#v", event, g)
			}
			for _, h := range listAt(t, group, "hooks") {
				hook, ok := h.(map[string]any)
				if !ok {
					t.Fatalf("hooks.%s holds a hook that is not an object: %#v", event, h)
				}
				if cmd, ok := hook["command"].(string); ok && isInnseglHookCommand(cmd) {
					got[event] = append(got[event], cmd)
				}
			}
		}
	}
	return got
}

func checkForeignHooksKept(t *testing.T, m map[string]any) {
	t.Helper()
	all := mustJSON(t, m["hooks"])
	for _, foreign := range staleForeign {
		if !strings.Contains(all, foreign) {
			t.Errorf("the operator's hook %q was removed: %s", foreign, all)
		}
	}
}

// CLI-034 (#595): connect replaces every innsegl hook entry it did not just
// write, wherever it points, and keeps every hook that is not innsegl's.
func TestCLI034ConnectReplacesStaleInnseglHookEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(staleHookSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := testSettingsConfig()
	var out bytes.Buffer
	if err := InstallSettings(path, cfg, fixedNow, &out); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, path)
	want := map[string][]string{
		"PreToolUse":  {cfg.preToolUseCommand()},
		"PostToolUse": {cfg.postToolUseCommand()},
	}
	for _, e := range sessionHookEvents {
		want[e] = []string{cfg.sessionCommand()}
	}
	if got := innseglCommands(t, m); !reflect.DeepEqual(got, want) {
		t.Errorf("innsegl hook entries = %v\nwant %v", got, want)
	}
	checkForeignHooksKept(t, m)
	if _, ok := objAt(t, m, "hooks")["Stop"]; ok {
		t.Errorf("an event left empty by the removal was kept: %s", mustJSON(t, m["hooks"]))
	}
	for _, said := range []string{"/opt/home-dev/go/bin/innsegl hook pre-tool-use", "'/opt/home-dev/My Tools/innsegl' hook session"} {
		if !strings.Contains(out.String(), said) {
			t.Errorf("connect did not say it removed %q:\n%s", said, out.String())
		}
	}
	out.Reset()
	if err := InstallSettings(path, cfg, fixedNow, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "already up to date") {
		t.Errorf("a second run changed the file:\n%s", out.String())
	}
}

// CLI-035 (#595): disconnect removes every innsegl hook entry, not only the
// ones naming the current binary, and keeps every other hook.
func TestCLI035DisconnectRemovesAllInnseglHookEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, []byte(staleHookSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UninstallSettings(path, testSettingsConfig(), fixedNow, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, path)
	if got := innseglCommands(t, m); len(got) != 0 {
		t.Errorf("innsegl hook entries left after disconnect: %v", got)
	}
	checkForeignHooksKept(t, m)
}

// CLI-036 (#595): the printed administrator command installs the staged
// file only while it still has the hash it had when staged. It runs here
// without its leading sudo, into a temporary destination.
func TestCLI036AdminInstallRefusesAStagedFileChangedAfterStaging(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	if got := sha256CheckCommand("linux"); got != "sha256sum -c -" {
		t.Errorf("linux checker = %q", got)
	}
	if got := sha256CheckCommand("darwin"); got != "shasum -a 256 -c -" {
		t.Errorf("darwin checker = %q", got)
	}
	run := func(tamper bool) (dest string, out []byte, err error) {
		dir := t.TempDir()
		blocker := filepath.Join(dir, "not-a-dir")
		if werr := os.WriteFile(blocker, nil, 0o644); werr != nil {
			t.Fatal(werr)
		}
		ierr := InstallSettings(filepath.Join(blocker, "managed-settings.json"), testSettingsConfig(), fixedNow, &bytes.Buffer{})
		var nw *NotWritableError
		if !errors.As(ierr, &nw) {
			t.Fatalf("err = %v, want a NotWritableError", ierr)
		}
		if !strings.HasPrefix(nw.Command, "sudo sh -c ") || strings.Count(nw.Command, "sudo") != 1 {
			t.Fatalf("command = %q, want a single sudo sh -c", nw.Command)
		}
		if tamper {
			if werr := os.WriteFile(nw.Staged, []byte(`{"hooks": {}}`+"\n"), 0o600); werr != nil {
				t.Fatal(werr)
			}
		}
		target := filepath.Join(dir, "etc")
		cmd := strings.ReplaceAll(strings.TrimPrefix(nw.Command, "sudo "), blocker, target)
		// #nosec G204 -- the command under test, against temporary paths.
		out, err = exec.CommandContext(t.Context(), "sh", "-c", cmd).CombinedOutput()
		return filepath.Join(target, "managed-settings.json"), out, err
	}

	dest, out, err := run(false)
	if err != nil {
		t.Fatalf("an untouched staged file was refused: %v\n%s", err, out)
	}
	if got := readFile(t, dest); string(got) != goldenSettings {
		t.Errorf("installed = %q", got)
	}
	if fi, serr := os.Stat(dest); serr != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("installed file: %v (%v), want mode 0644", fi, serr)
	}

	dest, out, err = run(true)
	if err == nil {
		t.Fatalf("a staged file changed after staging was installed:\n%s", out)
	}
	if _, serr := os.Stat(dest); !errors.Is(serr, fs.ErrNotExist) {
		t.Errorf("the refused file reached the destination (stat: %v)", serr)
	}
}

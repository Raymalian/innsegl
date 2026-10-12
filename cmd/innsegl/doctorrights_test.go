// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age/plugin"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

// ---------------------------------------------------------------------------
// CLI-037, CLI-038, CLI-039 (PROPOSED for doc 07's TC-CLI, #596) — doctor
// checks the rights innsegl holds on this machine: every innsegl hook in the
// managed settings, the client service and the git hooks run this binary,
// from a path the user cannot write (CLI-037); every command doctor runs is
// on its allow-list, git and the age plugin included (CLI-038); and the one
// change it makes on its own is tightening the modes of innsegl's own files
// (CLI-039).
// ---------------------------------------------------------------------------

// otherUID is a user who owns nothing the tests create: what the user can
// write is then decided by the mode bits alone.
func otherUID() int { return os.Getuid() + 100000 }

// rightsRoot is a resolved temporary directory: on macOS t.TempDir sits
// behind the /var symlink.
func rightsRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// fakeInnsegl writes an executable at dir/innsegl, with every directory on
// the way 0755.
func fakeInnsegl(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "innsegl")
	// Each one a different build: its own bytes.
	if err := os.WriteFile(p, []byte("#!/bin/sh\n# "+dir+"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// hookEntry is one command in one event of the managed settings.
type hookEntry struct{ event, command string }

// writeManagedSettings writes the managed settings with these hook
// commands, one group each.
func writeManagedSettings(t *testing.T, path string, entries []hookEntry) []byte {
	t.Helper()
	hooks := map[string][]any{}
	for _, e := range entries {
		hooks[e.event] = append(hooks[e.event], map[string]any{
			"hooks": []any{map[string]any{"type": "command", "command": e.command}}})
	}
	b, err := json.MarshalIndent(map[string]any{"env": map[string]string{"X": "y"}, "hooks": hooks}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

// allInnseglHooks is every hook connect installs, each naming bin.
func allInnseglHooks(bin string) []hookEntry {
	out := []hookEntry{{"PreToolUse", bin + " hook pre-tool-use"}, {"PostToolUse", bin + " hook post-tool-use"}}
	for _, ev := range doctorSessionEvents {
		out = append(out, hookEntry{ev, bin + " hook session"})
	}
	return out
}

// CLI-037 — a hook naming another binary, a binary that is gone, an event
// with no innsegl hook and an event with two are each a finding with the
// command that repairs them; another program's hook is not innsegl's
// business; the settings are only read.
func TestCLI037ManagedSettingsHooksNameThisBinary(t *testing.T) {
	root := rightsRoot(t)
	self := fakeInnsegl(t, filepath.Join(root, "bin"))
	other := fakeInnsegl(t, filepath.Join(root, "other"))
	gone := filepath.Join(root, "gone", "innsegl")
	var entries []hookEntry
	for _, e := range allInnseglHooks(self) {
		switch e.event {
		case "PreToolUse":
			entries = append(entries, hookEntry{e.event, other + " hook pre-tool-use"},
				hookEntry{e.event, "/usr/bin/true some-other-tool"})
		case "PostToolUse":
			entries = append(entries, hookEntry{e.event, gone + " hook post-tool-use"})
		case "UserPromptSubmit":
		case "SessionStart":
			entries = append(entries, e, e)
		default:
			entries = append(entries, e)
		}
	}
	settings := filepath.Join(root, "managed-settings.json")
	before := writeManagedSettings(t, settings, entries)

	d := newDoctorRun(t, healthyDoctorCore())
	d.self, d.settings, d.uid = self, settings, otherUID()
	_, out := d.run(t)
	for _, want := range []string{
		"managed settings: FOREIGN", other,
		"managed settings: MISSING", gone,
		"UserPromptSubmit",
		"managed settings: DUPLICATE", "SessionStart",
		"innsegl connect --update",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/usr/bin/true") {
		t.Errorf("another program's hook was reported:\n%s", out)
	}
	if after, err := os.ReadFile(settings); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("doctor changed the managed settings (%v)", err)
	}
	d.assertSafe(t)
}

// CLI-037 — the same settings naming this binary at a path no one else can
// write is "ok"; a binary the user owns, or one group- or world-writable,
// or in a directory that is, is WRITABLE.
func TestCLI037AHookBinaryTheUserCanWriteIsFlagged(t *testing.T) {
	root := rightsRoot(t)
	self := fakeInnsegl(t, filepath.Join(root, "bin"))
	settings := filepath.Join(root, "managed-settings.json")
	writeManagedSettings(t, settings, allInnseglHooks(self))

	d := newDoctorRun(t, healthyDoctorCore())
	d.self, d.settings, d.uid = self, settings, otherUID()
	_, out := d.run(t)
	if !strings.Contains(out, "managed settings: ok") || strings.Contains(out, "WRITABLE") {
		t.Fatalf("a binary only an administrator can write:\n%s", out)
	}

	for name, setup := range map[string]func(){
		"owned by the user": func() { d.uid = os.Getuid() },
		"world-writable":    func() { chmod(t, self, 0o757) },
		"directory writable": func() {
			chmod(t, filepath.Dir(self), 0o777)
		},
	} {
		t.Run(name, func(t *testing.T) {
			chmod(t, self, 0o755)
			chmod(t, filepath.Dir(self), 0o755)
			d.uid = otherUID()
			setup()
			_, out := d.run(t)
			if !strings.Contains(out, "managed settings: WRITABLE") || !strings.Contains(out, self) {
				t.Fatalf("a hook binary %s:\n%s", name, out)
			}
			// #599: the repair is the installed copy, then connect.
			if !strings.Contains(out, "make install-release") ||
				strings.Index(out, "make install-release") > strings.Index(out, "innsegl connect --update") {
				t.Fatalf("the repair does not name make install-release, then innsegl connect --update:\n%s", out)
			}
		})
	}
	chmod(t, filepath.Dir(self), 0o755)
}

func chmod(t *testing.T, p string, m os.FileMode) {
	t.Helper()
	if err := os.Chmod(p, m); err != nil {
		t.Fatal(err)
	}
}

// CLI-037 — the client service's definition and a repository's git hooks
// naming another binary are FOREIGN, each with its repair; naming this one
// is ok.
func TestCLI037TheServiceAndGitHooksRunThisBinary(t *testing.T) {
	root := rightsRoot(t)
	self := fakeInnsegl(t, filepath.Join(root, "bin"))
	other := fakeInnsegl(t, filepath.Join(root, "other"))
	settings := filepath.Join(root, "managed-settings.json")
	writeManagedSettings(t, settings, allInnseglHooks(self))
	repo := gitInitRepo(t)
	writeHooks := func(bin string) {
		for _, h := range managedHooks {
			p := filepath.Join(repo, ".git", "hooks", h.name)
			if err := os.WriteFile(p, []byte(h.script(bin, p+linkPreviousSuffix)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}

	d := newDoctorRun(t, healthyDoctorCore())
	d.self, d.settings, d.uid = self, settings, otherUID()
	plist := client.Service{GOOS: "darwin", Home: d.f.home}.Path()
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(client.RenderPlist(other, "/tmp/x.log", "")), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHooks(other)
	_, out := d.run(t, "--repo", repo)
	for _, want := range []string{"service binary: FOREIGN", other, "innsegl connect --update",
		"hooks: FOREIGN", "innsegl link " + repo} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	if err := os.WriteFile(plist, []byte(client.RenderPlist(self, "/tmp/x.log", "")), 0o644); err != nil {
		t.Fatal(err)
	}
	writeHooks(self)
	_, out = d.run(t, "--repo", repo)
	if !strings.Contains(out, "service binary: ok") || !strings.Contains(out, "hooks: ok") ||
		strings.Contains(out, "FOREIGN") {
		t.Fatalf("the service and hooks running this binary:\n%s", out)
	}

	// Linux: the systemd unit names the binary.
	unit := client.Service{GOOS: "linux", Home: d.f.home}.Path()
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte(client.RenderUnit(other, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	deps := d.deps(t)
	deps.goos = "linux"
	var buf strings.Builder
	runDoctor(t.Context(), []string{"--wait", "1s"}, &buf, &buf, deps)
	if !strings.Contains(buf.String(), "service binary: FOREIGN") || !strings.Contains(buf.String(), other) {
		t.Fatalf("a systemd unit naming another binary:\n%s", buf.String())
	}
}

// CLI-038 — the allow-list: the client restart, git's version, the two
// rev-parse reads per hook, and the age plugins' identity protocol. Any
// other git call, plugin or protocol is refused.
func TestCLI038TheAllowListNamesEveryCommandDoctorRuns(t *testing.T) {
	allowed := [][]string{
		{"launchctl", "kickstart", "-k", "gui/501/" + client.LaunchdLabel},
		{"git", "--version"},
		{"git", "-C", "/r", "rev-parse", "--path-format=absolute", "--git-common-dir"},
		{"age-plugin-se", "--age-plugin=identity-v1"},
		{"age-plugin-yubikey", "--age-plugin=identity-v1"},
	}
	for _, h := range managedHooks {
		allowed = append(allowed, []string{"git", "-C", "/r", "rev-parse", "--git-path", "hooks/" + h.name})
	}
	for _, argv := range allowed {
		if !doctorCommandAllowed("darwin", 501, argv) {
			t.Errorf("%q is not allowed", argv)
		}
	}
	if !doctorCommandAllowed("linux", 501, []string{"systemctl", "--user", "restart", client.SystemdUnit}) {
		t.Error("the Linux restart is not allowed")
	}
	for _, argv := range [][]string{
		{"git", "-C", "/r", "config", "core.hooksPath", "/x"},
		{"git", "-C", "", "rev-parse", "--path-format=absolute", "--git-common-dir"},
		{"git", "-C", "/r", "rev-parse", "--git-path", "hooks/pre-push"},
		{"git", "--version", "--exec-path=/x"},
		{"git", "-c", "core.fsmonitor=/x", "--version"},
		{"age-plugin-foo", "--age-plugin=identity-v1"},
		{"age-plugin-se", "--age-plugin=recipient-v1"},
		{"/tmp/age-plugin-se", "--age-plugin=identity-v1"},
		{"systemctl", "--user", "restart", client.SystemdUnit},
	} {
		if doctorCommandAllowed("darwin", 501, argv) {
			t.Errorf("%q is allowed", argv)
		}
	}
	for _, argv := range allowed {
		if argv[0] == "launchctl" {
			if doctorReadOnly(argv) {
				t.Errorf("the restart %q counts as read-only", argv)
			}
		} else if !doctorReadOnly(argv) {
			t.Errorf("%q is not read-only", argv)
		}
	}
}

// tripwire puts a program of each name first on PATH that records being
// run. Doctor reaches programs only through its runner, so none of them
// may ever run.
func tripwire(t *testing.T, names ...string) (record string) {
	t.Helper()
	dir := t.TempDir()
	record = filepath.Join(t.TempDir(), "ran")
	for _, n := range names {
		script := "#!/bin/sh\necho \"" + n + " $*\" >> '" + record + "'\nexit 1\n"
		if err := os.WriteFile(filepath.Join(dir, n), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return record
}

// CLI-038 — a run that restarts the client service, checks a linked
// repository and the host's git, and is handed an identity naming a plugin
// off the list: every call reaches the fake runner and is on the list, the
// plugin is refused before it runs, and nothing on PATH is executed behind
// the runner's back.
func TestCLI038DoctorExecsNothingOffItsList(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	root := rightsRoot(t)
	self := fakeInnsegl(t, filepath.Join(root, "bin"))
	settings := filepath.Join(root, "managed-settings.json")
	writeManagedSettings(t, settings, allInnseglHooks(self))
	repo := gitInitRepo(t)
	for _, h := range managedHooks {
		p := filepath.Join(repo, ".git", "hooks", h.name)
		if err = os.WriteFile(p, []byte(h.script(self, p+linkPreviousSuffix)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	identity := filepath.Join(root, "identity.txt")
	if err = os.WriteFile(identity, []byte(plugin.EncodeIdentity("foo", []byte{1, 2, 3})+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	core := &doctorCore{custody: cacustody.Status{Initialized: true, Sealed: true,
		Reason: "the store is sealed; the operator's machine unlocks it"}, material: []byte("sealed"),
		probeAt: time.Now().Add(-time.Minute), probeWhy: "Fulcio answered HTTP 500", spireUp: true}
	f := newConnectFixture(t)
	svc := httptest.NewUnstartedServer(nil)
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings, "--no-service", "--listen", svc.Listener.Addr().String()); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	s, err := client.NewServer(client.ClientPaths(f.home), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	svc.Config.Handler = s.Handler()
	t.Cleanup(svc.Close)
	core.mount(t, f)
	d := &doctorRun{f: f, git: gitBin, self: self, settings: settings, identity: identity}
	d.onRun = func(argv []string) {
		if argv[0] == "launchctl" {
			svc.Start()
		}
	}

	ran := tripwire(t, "git", "launchctl", "systemctl", "docker", "age-plugin-se", "age-plugin-foo", "sh")
	_, out := d.run(t, "--repo", repo)

	if b, rerr := os.ReadFile(ran); rerr == nil {
		t.Fatalf("doctor ran programs behind its runner:\n%s\n%s", b, out)
	}
	if !strings.Contains(out, "age-plugin-foo") || !strings.Contains(out, "not on innsegl doctor's allow-list") {
		t.Errorf("a plugin off the list was not refused:\n%s", out)
	}
	if core.unlockedBody() != nil {
		t.Error("the store was unlocked through a plugin off the list")
	}
	d.assertSafe(t)
	for _, want := range [][]string{
		{"launchctl", "kickstart", "-k", "gui/501/" + client.LaunchdLabel},
		{"git", "--version"},
		{"git", "-C", repo, "rev-parse", "--path-format=absolute", "--git-common-dir"},
		{"git", "-C", repo, "rev-parse", "--git-path", "hooks/prepare-commit-msg"},
	} {
		if !slices.ContainsFunc(d.calls, func(c []string) bool { return slices.Equal(c, want) }) {
			t.Errorf("the runner never saw %q; it saw %q", want, d.calls)
		}
	}
}

// CLI-039 — the mode doctor sets is the old one less group and other bits:
// never a bit added.
func TestCLI039TighteningNeverAddsABit(t *testing.T) {
	for m := fs.FileMode(0); m <= 0o777; m++ {
		n := tightenedMode(m)
		if n&^m != 0 || n&0o077 != 0 || n&0o700 != m&0o700 {
			t.Fatalf("tightenedMode(%04o) = %04o", m, n)
		}
	}
}

// CLI-039 — innsegl's own key files and folders lose group and other
// access; a file already tighter keeps its mode; a public certificate, a
// symlink's target and a file outside ~/.innsegl are not touched. A second
// run finds nothing to do.
func TestCLI039DoctorOnlyTightensInnseglsOwnFiles(t *testing.T) {
	d := newDoctorRun(t, healthyDoctorCore())
	d.uid = os.Getuid()
	p := client.ClientPaths(d.f.home)
	outside := filepath.Join(d.f.home, "notes.txt")
	write := func(path string, m os.FileMode) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), m); err != nil {
			t.Fatal(err)
		}
		chmod(t, path, m)
	}
	write(outside, 0o644)
	write(p.Authors, 0o400)
	write(p.TrustIdentity, 0o644)
	backup := filepath.Join(p.TrustBackups, "trust-1.age")
	write(backup, 0o644)
	chmod(t, p.Key, 0o644)
	chmod(t, p.Cert, 0o644)
	chmod(t, p.Dir, 0o755)
	chmod(t, p.TrustBackups, 0o755)
	chmod(t, filepath.Dir(p.TrustIdentity), 0o755)
	if err := os.Remove(p.ProxyCAKey); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p.ProxyCAKey); err != nil {
		t.Fatal(err)
	}

	_, out := d.run(t)
	if !strings.Contains(out, "modes: tightened") {
		t.Errorf("no tightening reported:\n%s", out)
	}
	for path, want := range map[string]os.FileMode{
		p.Key: 0o600, p.Dir: 0o700, p.TrustIdentity: 0o600, filepath.Dir(p.TrustIdentity): 0o700,
		p.TrustBackups: 0o700, backup: 0o600,
		p.Authors: 0o400, p.Cert: 0o644, outside: 0o644,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %04o, want %04o", path, fi.Mode().Perm(), want)
		}
	}
	_, out = d.run(t)
	if !strings.Contains(out, "modes: ok") {
		t.Errorf("a second run tightened again:\n%s", out)
	}
}

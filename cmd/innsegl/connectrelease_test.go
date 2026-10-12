// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

// CLI-041 and CLI-042 (PROPOSED for doc 07, #599). Hooks run on every agent
// prompt and tool call, and the client service and scheduled jobs run with
// nobody watching. A binary any agent can rebuild must not be what they run:
// connect names only a copy the user cannot change (`make install-release`
// puts it in client.ReleaseDir), and refuses a binary the user can change.
//
// Nothing here writes outside temporary folders: the "installed copy" is a
// file in t.TempDir(), and which paths count as unchangeable is the
// fixture's writable stand-in.

// selfBuild writes a stand-in for this build in a folder of the test's own,
// so the real check finds it changeable, and makes binPath answer it.
func selfBuild(t *testing.T, f *connectFixture, content string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "innsegl")
	if err := os.WriteFile(bin, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	f.deps.binPath = func() (string, error) { return bin, nil }
	// The user the real check asks about is the one running the test, not
	// the fixture's 501, so it holds on any machine and in a container.
	f.deps.uid = os.Getuid()
	return bin
}

// releaseCopy writes the installed copy at a temporary path and has the
// fixture treat it as root's when rootOwned, and every other path by the
// real check.
func releaseCopy(t *testing.T, f *connectFixture, content string, rootOwned bool) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(dir, "libexec", "innsegl", "innsegl")
	if err := os.MkdirAll(filepath.Dir(release), 0o755); err != nil {
		t.Fatal(err)
	}
	if content != "" {
		if err := os.WriteFile(release, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.deps.release = release
	actual := f.deps.realWritable()
	f.deps.writable = func(p string) string {
		if rootOwned && p == release {
			return ""
		}
		return actual(p)
	}
	return release
}

func TestCLI041ConnectRefusesABinaryTheUserCanChange(t *testing.T) {
	f := newConnectFixture(t)
	self := selfBuild(t, f, "build-1")
	releaseCopy(t, f, "", true) // nothing installed
	code, stdout, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings)
	if code != exitConnectFailed {
		t.Fatalf("connect with a changeable binary = %d, want %d\n%s\n%s", code, exitConnectFailed, stdout, stderr)
	}
	for _, want := range []string{self, "you own", "make install-release", "Nothing was changed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, stderr)
		}
	}
	f.assertNothingWritten(t)
}

func TestCLI041ConnectRefusesAnInstalledCopyOfAnotherBuild(t *testing.T) {
	f := newConnectFixture(t)
	selfBuild(t, f, "build-2")
	release := releaseCopy(t, f, "build-1", true)
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings)
	if code != exitConnectFailed || !strings.Contains(stderr, release) || !strings.Contains(stderr, "another build") ||
		!strings.Contains(stderr, "make install-release") {
		t.Fatalf("connect with a stale installed copy = %d:\n%s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestCLI041ConnectRefusesAnInstalledCopyTheUserCanChange(t *testing.T) {
	f := newConnectFixture(t)
	selfBuild(t, f, "build-1")
	release := releaseCopy(t, f, "build-1", false)
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings)
	if code != exitConnectFailed || !strings.Contains(stderr, release) || !strings.Contains(stderr, "you own") {
		t.Fatalf("connect with a changeable installed copy = %d:\n%s", code, stderr)
	}
	f.assertNothingWritten(t)
}

func TestCLI041UpdateRefusesABinaryTheUserCanChange(t *testing.T) {
	f := newConnectFixture(t)
	f.enrol(t)
	before := string(readFile(t, f.settings))
	selfBuild(t, f, "build-1")
	releaseCopy(t, f, "", true)
	code, _, stderr := f.connect("--update", "--managed-settings", f.settings)
	if code != exitConnectFailed || !strings.Contains(stderr, "make install-release") {
		t.Fatalf("--update with a changeable binary = %d:\n%s", code, stderr)
	}
	if string(readFile(t, f.settings)) != before {
		t.Error("a refused --update changed the managed settings")
	}
}

// The installed copy of this very build is what the hooks and the service
// name, though connect itself ran from the checkout.
func TestCLI041ConnectNamesTheInstalledCopyOfThisBuild(t *testing.T) {
	f := newConnectFixture(t)
	self := selfBuild(t, f, "build-1")
	release := releaseCopy(t, f, "build-1", true)
	f.enrol(t)
	settings := string(readFile(t, f.settings))
	if !strings.Contains(settings, release+" hook session") || !strings.Contains(settings, release+" hook pre-tool-use") {
		t.Errorf("the hooks do not run the installed copy %s:\n%s", release, settings)
	}
	if strings.Contains(settings, self) || strings.Contains(plistOf(t, f), self) {
		t.Errorf("the checkout build %s is named", self)
	}
	if !strings.Contains(plistOf(t, f), "<string>"+release+"</string>") {
		t.Errorf("the client service does not start the installed copy:\n%s", plistOf(t, f))
	}
}

// Disconnecting removes what connect wrote; it runs nothing later, so it is
// never refused for the binary it runs from.
func TestCLI041DisconnectIsNotRefusedForAChangeableBinary(t *testing.T) {
	f := newConnectFixture(t)
	f.enrol(t)
	selfBuild(t, f, "build-1")
	releaseCopy(t, f, "", true)
	if code, _, stderr := f.connect("--disconnect", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("--disconnect = %d:\n%s", code, stderr)
	}
}

// CLI-042: a client service that still starts another binary (the checkout
// build an earlier connect named) is moved onto the installed copy by
// `connect --update`, without --service.
func TestCLI042UpdateMovesTheServiceOntoTheInstalledCopy(t *testing.T) {
	f := newConnectFixture(t)
	f.enrol(t)
	if !strings.Contains(plistOf(t, f), "<string>"+connectTestBin+"</string>") {
		t.Fatalf("setup: the service does not start %s", connectTestBin)
	}
	selfBuild(t, f, "build-1")
	release := releaseCopy(t, f, "build-1", true)
	f.calls = nil
	code, stdout, stderr := f.connect("--update", "--managed-settings", f.settings)
	if code != exitOK {
		t.Fatalf("--update = %d\n%s\n%s", code, stdout, stderr)
	}
	if plist := plistOf(t, f); !strings.Contains(plist, "<string>"+release+"</string>") || strings.Contains(plist, connectTestBin) {
		t.Fatalf("the service was not moved onto %s:\n%s", release, plist)
	}
	if len(f.calls) == 0 {
		t.Error("the moved service was not restarted")
	}
}

func TestCLI042LinuxUnitStartsTheInstalledCopy(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.goos = "linux"
	selfBuild(t, f, "build-1")
	release := releaseCopy(t, f, "build-1", true)
	f.enrol(t)
	unit := string(readFile(t, filepath.Join(f.home, ".config", "systemd", "user", client.SystemdUnit)))
	if !strings.Contains(unit, `ExecStart="`+release+`" client serve`) {
		t.Fatalf("the unit does not start the installed copy:\n%s", unit)
	}
}

// The host backup timer innsegl dropped (#237) still runs a script from a
// checkout where it was installed. connect names it and the command that
// removes it, and removes nothing itself.
func TestCLI042ConnectNamesTheLeftoverBackupJob(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			f := newConnectFixture(t)
			f.deps.goos = goos
			f.enrol(t)
			job, _, ok := f.deps.service().LeftoverBackupJob()
			if ok {
				t.Fatalf("a job reported before one exists: %s", job)
			}
			if err := os.MkdirAll(filepath.Dir(job), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(job, []byte("checkout/scripts/backup-ledger.sh\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, remove, ok := f.deps.service().LeftoverBackupJob()
			if !ok || !strings.Contains(remove, job) {
				t.Fatalf("LeftoverBackupJob = %q, %v", remove, ok)
			}
			code, _, stderr := f.connect("--update", "--managed-settings", f.settings)
			if code != exitOK || !strings.Contains(stderr, job) || !strings.Contains(stderr, remove) {
				t.Fatalf("--update = %d; the leftover job and its removal are not named:\n%s", code, stderr)
			}
			if _, err := os.Stat(job); err != nil {
				t.Errorf("connect removed the job itself: %v", err)
			}
		})
	}
}

// Settings of the caller's own (--managed-settings) with no service run
// nothing on their own: no session loads them and nothing starts. There a
// binary the user can change is named, as the two-machine test (OPS-174)
// runs it. The system managed settings, or a service, require the
// installed copy.
func TestCLI041OwnSettingsWithoutAServiceTakeThisBinary(t *testing.T) {
	f := newConnectFixture(t)
	self := selfBuild(t, f, "build-1")
	releaseCopy(t, f, "", true)
	f.enrol(t, "--no-service")
	if settings := string(readFile(t, f.settings)); !strings.Contains(settings, self+" hook session") {
		t.Fatalf("the hooks do not name this binary:\n%s", settings)
	}
	for _, c := range []struct {
		settings string
		service  bool
		want     hookBinaryUse
	}{
		{f.settings, false, preferInstalled},
		{f.settings, true, requireInstalled},
		{defaultManagedSettingsPath("darwin"), false, requireInstalled},
	} {
		if got := f.deps.unattended(connectFlags{settings: c.settings}, c.service); got != c.want {
			t.Errorf("unattended(%s, service %v) = %v, want %v", c.settings, c.service, got, c.want)
		}
	}
}

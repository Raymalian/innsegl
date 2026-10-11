// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// CLI-025 (PROPOSED for doc 07, #592) — the client service unlocks the CA
// store on its own (ADR-0076) with the operator's identity file, and a plugin
// identity in it runs age-plugin-<name>, found on the service's PATH. A
// LaunchAgent or a systemd --user unit that sets no PATH gets the service
// manager's default, which does not hold the usual plugin directories
// (measured on the operator's Mac: launchd's is /usr/bin:/bin:/usr/sbin:/sbin,
// and the plugin is installed outside it). So the plugin's directory, as
// connect resolves it, is written into the service definition: only when the
// default would miss it, after the system directories, never before them.

func writeIdentityFile(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func lookIn(dirs map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if d, ok := dirs[name]; ok {
			return filepath.Join(d, name), nil
		}
		return "", exec.ErrNotFound
	}
}

// pluginFile writes an executable stand-in for age-plugin-<name> in a fresh
// 0755 directory and answers the directory.
func pluginFile(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "plugins", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-"+name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestCLI025ThePinnedPluginDirectoryIsAddedToTheServicePATH(t *testing.T) {
	id := writeIdentityFile(t, "# created: today", plugin.EncodeIdentity("se", []byte("handle")))
	dir := pluginFile(t, "se")
	pins, problems, err := PinPlugins(id, lookIn(map[string]string{"age-plugin-se": dir}))
	if err != nil || len(problems) != 0 || len(pins) != 1 {
		t.Fatalf("PinPlugins = %+v, %v, %v", pins, problems, err)
	}
	if pins[0].Path != filepath.Join(dir, "age-plugin-se") || len(pins[0].SHA256) != 64 {
		t.Fatalf("pin = %+v", pins[0])
	}
	if got, want := ServicePATH("darwin", pins), DefaultServicePATH("darwin")+":"+dir; got != want {
		t.Fatalf("darwin PATH = %q, want %q", got, want)
	}
	if got, want := ServicePATH("linux", pins), DefaultServicePATH("linux")+":"+dir; got != want {
		t.Fatalf("linux PATH = %q, want %q", got, want)
	}
}

// CLI-046 (#598): a plugin anyone but its owner could replace is not pinned
// at connect, and the reason is named.
func TestCLI046ConnectDoesNotPinAWritablePlugin(t *testing.T) {
	id := writeIdentityFile(t, plugin.EncodeIdentity("se", []byte("h")))
	dir := pluginFile(t, "se")
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	pins, problems, err := PinPlugins(id, lookIn(map[string]string{"age-plugin-se": dir}))
	if err != nil || len(pins) != 0 || len(problems) != 1 || !strings.Contains(problems[0], "writable") ||
		!strings.Contains(problems[0], "innsegl connect --update") {
		t.Fatalf("PinPlugins = %+v, %v, %v; want the writable directory named", pins, problems, err)
	}
}

func TestCLI025NoPATHWhenTheDefaultFindsEveryPlugin(t *testing.T) {
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{
		"no identity file": filepath.Join(t.TempDir(), "absent.txt"),
		"an X25519 key":    writeIdentityFile(t, x.String()),
	} {
		pins, problems, err := PinPlugins(id, lookIn(nil))
		if err != nil || len(pins) != 0 || len(problems) != 0 || ServicePATH("darwin", pins) != "" {
			t.Errorf("%s: PinPlugins = %+v, %v, %v; want nothing pinned and no PATH", name, pins, problems, err)
		}
	}
	if got := ServicePATH("darwin", []trustbackup.PluginPin{{Name: "yubikey", Path: "/usr/bin/age-plugin-yubikey"}}); got != "" {
		t.Errorf("a plugin in /usr/bin: PATH = %q; want none", got)
	}
}

func TestCLI025APluginNotFoundIsNamed(t *testing.T) {
	id := writeIdentityFile(t, plugin.EncodeIdentity("se", []byte("h")))
	pins, problems, err := PinPlugins(id, lookIn(nil))
	if err != nil || len(pins) != 0 || len(problems) != 1 || !strings.Contains(problems[0], "age-plugin-se") {
		t.Fatalf("PinPlugins = %+v, %v, %v; want age-plugin-se named", pins, problems, err)
	}
	if _, _, err := PinPlugins(writeIdentityFile(t, "AGE-PLUGIN-SE-1QQQ"), lookIn(nil)); err == nil {
		t.Fatal("a broken identity line was accepted")
	}
}

func TestCLI025ThePlistAndTheUnitCarryThePATH(t *testing.T) {
	path := "/usr/bin:/bin:/opt/a & b/bin"
	plist := RenderPlist("/opt/innsegl/innsegl", "/tmp/innsegl-client.log", path)
	want := "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>PATH</key>\n" +
		"    <string>/usr/bin:/bin:/opt/a &amp; b/bin</string>\n  </dict>\n"
	if !strings.Contains(plist, want) {
		t.Fatalf("the plist does not carry PATH:\n%s", plist)
	}
	unit := RenderUnit("/opt/innsegl/innsegl", `/usr/bin:/opt/100%"x"/bin`)
	if !strings.Contains(unit, "\nEnvironment=\"PATH=/usr/bin:/opt/100%%\\\"x\\\"/bin\"\n") {
		t.Fatalf("the unit does not carry PATH, quoted:\n%s", unit)
	}
	if strings.Contains(RenderPlist("/b", "/l", ""), "EnvironmentVariables") ||
		strings.Contains(RenderUnit("/b", ""), "Environment=") {
		t.Fatal("an empty PATH was written")
	}
}

func TestCLI025InstallWritesTheServicePATH(t *testing.T) {
	home := t.TempDir()
	svc := Service{GOOS: "linux", Home: home, UID: 1000, Run: (&recorder{}).run, PATH: "/usr/bin:/opt/p/bin"}
	if err := svc.Install("/opt/innsegl/bin/innsegl"); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(svc.Path())
	if err != nil || !strings.Contains(string(text), `Environment="PATH=/usr/bin:/opt/p/bin"`) {
		t.Fatalf("the unit has no PATH (err=%v):\n%s", err, text)
	}
}

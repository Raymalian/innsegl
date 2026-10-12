// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/plugin"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// CLI-025 (PROPOSED for doc 07, #592) — `innsegl connect --update --service`
// resolves the plugin the operator's identity file names, as this shell finds
// it, and writes its directory into the client service's PATH, so the
// service's own CA unlock (ADR-0076) can run it. The user's real service is
// never touched: the fixture records service-manager calls.
//
// #598: that resolution is a pin. The plugin's absolute path and SHA-256 are
// recorded in the client folder, and the service's PATH names the pinned
// file's own directory.

// installPlugin writes an executable stand-in for age-plugin-se in a fresh
// 0755 directory and points connect's lookup at it. It answers the
// directory, symlinks resolved.
func installPlugin(t *testing.T, f *connectFixture) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "age-plugin-se"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.deps.lookPath = func(name string) (string, error) {
		if name == "age-plugin-se" {
			return filepath.Join(resolved, name), nil
		}
		return exec.LookPath(name)
	}
	return resolved
}

func connectWithPluginIdentity(t *testing.T) *connectFixture {
	t.Helper()
	f := newConnectFixture(t)
	if code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings); code != exitOK {
		t.Fatalf("connect: %s", stderr)
	}
	idFile := client.ClientPaths(f.home).TrustIdentity
	if err := os.MkdirAll(filepath.Dir(idFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idFile, []byte(plugin.EncodeIdentity("se", []byte("h"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func plistOf(t *testing.T, f *connectFixture) string {
	t.Helper()
	return string(readFile(t, filepath.Join(f.home, "Library", "LaunchAgents", "dev.innsegl.client.plist")))
}

func TestCLI025ConnectWritesThePluginDirectoryIntoTheService(t *testing.T) {
	f := connectWithPluginIdentity(t)
	dir := installPlugin(t, f)
	code, stdout, stderr := f.connect("--update", "--service", "--managed-settings", f.settings)
	if code != exitOK {
		t.Fatalf("--update --service = %d\n%s\n%s", code, stdout, stderr)
	}
	want := "<string>" + client.DefaultServicePATH("darwin") + ":" + dir + "</string>"
	if !strings.Contains(plistOf(t, f), want) {
		t.Fatalf("the service definition has no PATH to the plugin:\n%s", plistOf(t, f))
	}
	pins, err := trustbackup.ReadPluginPins(client.PluginPinsFile(client.ClientPaths(f.home)))
	if err != nil || len(pins) != 1 || pins[0].Path != filepath.Join(dir, "age-plugin-se") || len(pins[0].SHA256) != 64 {
		t.Fatalf("pins = %+v, %v", pins, err)
	}
}

// CLI-047 (#598): `innsegl connect --update` is the repair for a refused
// plugin. An upgrade that moves the plugin rewrites and restarts the
// installed service on its own, so its PATH follows the new pin.
func TestCLI047UpdatePinsAMovedPluginAndRewritesTheService(t *testing.T) {
	f := connectWithPluginIdentity(t)
	installPlugin(t, f)
	if code, _, stderr := f.connect("--update", "--service", "--managed-settings", f.settings); code != exitOK {
		t.Fatalf("--update --service: %s", stderr)
	}
	moved := installPlugin(t, f)
	f.calls = nil
	code, stdout, stderr := f.connect("--update", "--managed-settings", f.settings)
	if code != exitOK {
		t.Fatalf("--update = %d\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(plistOf(t, f), ":"+moved+"</string>") || len(f.calls) == 0 {
		t.Fatalf("the service was not rewritten for the moved plugin (calls %v):\n%s", f.calls, plistOf(t, f))
	}
	f.calls = nil
	if code, _, stderr := f.connect("--update", "--managed-settings", f.settings); code != exitOK || len(f.calls) != 0 {
		t.Fatalf("an unchanged pin restarted the service (exit %d, calls %v): %s", code, f.calls, stderr)
	}
}

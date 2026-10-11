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
)

// CLI-025 (PROPOSED for doc 07, #592) — `innsegl connect --update --service`
// resolves the plugin the operator's identity file names, as this shell finds
// it, and writes its directory into the client service's PATH, so the
// service's own CA unlock (ADR-0076) can run it. The user's real service is
// never touched: the fixture records service-manager calls.
func TestCLI025ConnectWritesThePluginDirectoryIntoTheService(t *testing.T) {
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
	f.deps.lookPath = func(name string) (string, error) {
		if name == "age-plugin-se" {
			return "/opt/plugins/bin/age-plugin-se", nil
		}
		return exec.LookPath(name)
	}
	code, stdout, stderr := f.connect("--update", "--service", "--managed-settings", f.settings)
	if code != exitOK {
		t.Fatalf("--update --service = %d\n%s\n%s", code, stdout, stderr)
	}
	plist := string(readFile(t, filepath.Join(f.home, "Library", "LaunchAgents", "dev.innsegl.client.plist")))
	want := "<string>" + client.DefaultServicePATH("darwin") + ":/opt/plugins/bin</string>"
	if !strings.Contains(plist, want) {
		t.Fatalf("the service definition has no PATH to the plugin:\n%s", plist)
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// BAK-031 (PROPOSED for doc 07, #592) — an age plugin's own prompt ("touch
// your key") reaches the terminal of the interactive command that runs it:
// doctor, ca-custody unlock and the trust-backup drill. Before, every prompt
// was discarded, and a hardware key that waits for a touch looked hung.
//
// The plugin here is this test binary itself, run under the name
// age-plugin-innseglfake: it speaks the age plugin protocol, shows one
// message, and opens nothing. No hardware is needed, so it runs on Linux CI.

const fakePluginName = "innseglfake"

const fakePluginMessage = "touch your key"

// runAsFakeAgePlugin serves the plugin protocol when this binary was started
// as the fake plugin; TestMain calls it first.
func runAsFakeAgePlugin() (int, bool) {
	if filepath.Base(os.Args[0]) != "age-plugin-"+fakePluginName {
		return 0, false
	}
	p, err := plugin.New(fakePluginName)
	if err != nil {
		return 1, true
	}
	fs := flag.NewFlagSet(fakePluginName, flag.ContinueOnError)
	p.RegisterFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1, true
	}
	p.HandleIdentity(func([]byte) (age.Identity, error) { return promptingIdentity{p}, nil })
	return p.Main(), true
}

type promptingIdentity struct{ p *plugin.Plugin }

func (i promptingIdentity) Unwrap([]*age.Stanza) ([]byte, error) {
	if err := i.p.DisplayMessage(fakePluginMessage); err != nil {
		return nil, err
	}
	return nil, age.ErrIncorrectIdentity
}

func TestBAK031APluginPromptReachesTheTerminal(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A copy, not a link: the pin checks the file it resolves to and that
	// file's directory, and the build cache's modes depend on the umask.
	src, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "age-plugin-"+fakePluginName), src, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// #598: the plugin runs only as connect pinned it.
	home := t.TempDir()
	t.Setenv("HOME", home)
	pin, err := trustbackup.PinPlugin(fakePluginName, nil)
	if err != nil {
		t.Fatal(err)
	}
	paths := client.ClientPaths(home)
	if err = os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err = trustbackup.WritePluginPins(client.PluginPinsFile(paths), []trustbackup.PluginPin{pin}); err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err = os.WriteFile(idFile, []byte(plugin.EncodeIdentity(fakePluginName, []byte("handle"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, other.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, "material"); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	var terminal bytes.Buffer
	ids, err := operatorIdentities(idFile, &terminal)()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(&sealed, ids...); err == nil {
		t.Fatal("the fake plugin opened a file it holds no key for")
	}
	if !strings.Contains(terminal.String(), fakePluginName+" plugin: "+fakePluginMessage) {
		t.Fatalf("the plugin's prompt did not reach the terminal; it shows %q", terminal.String())
	}
}

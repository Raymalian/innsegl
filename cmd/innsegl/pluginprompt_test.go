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
	dir := t.TempDir()
	if err := os.Symlink(self, filepath.Join(dir, "age-plugin-"+fakePluginName)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(idFile, []byte(plugin.EncodeIdentity(fakePluginName, []byte("handle"))+"\n"), 0o600); err != nil {
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

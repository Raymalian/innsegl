// SPDX-License-Identifier: Apache-2.0

package trustbackup

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

// CLI-046, CLI-047 (PROPOSED for doc 07, #598) — the age plugin an identity
// file names is resolved once, at `innsegl connect`, to an absolute path and
// its SHA-256. Every later use (the CLI's unlock, the client service's unlock,
// the trust-backup drill) runs that plugin only while it is still that file,
// in a place only its owner or root can write. Otherwise it is refused, with
// the repair named, before the plugin starts.
//
// The plugin is this test binary, copied under the name
// age-plugin-innseglpin: it speaks the age plugin protocol and opens a file
// with the X25519 key its identity line carries. No hardware is needed, so
// it runs on Linux CI.

const pinPluginName = "innseglpin"

func TestMain(m *testing.M) {
	if filepath.Base(os.Args[0]) == "age-plugin-"+pinPluginName {
		os.Exit(runFakePlugin())
	}
	os.Exit(m.Run())
}

// runFakePlugin is the fake plugin: its identity data is an X25519 key.
func runFakePlugin() int {
	p, err := plugin.New(pinPluginName)
	if err != nil {
		return 1
	}
	fs := flag.NewFlagSet(pinPluginName, flag.ContinueOnError)
	p.RegisterFlags(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return age.ParseX25519Identity(string(data))
	})
	return p.Main()
}

// fakePlugin installs the fake plugin in a fresh directory, puts that
// directory first on PATH, and answers the plugin's path and an identity
// file whose one line is a plugin identity for key.
func fakePlugin(t *testing.T, key *age.X25519Identity) (bin, idFile string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bin")
	if err = os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(dir, "age-plugin-"+pinPluginName)
	if err = os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	idFile = filepath.Join(t.TempDir(), "identity.txt")
	line := plugin.EncodeIdentity(pinPluginName, []byte(key.String()))
	if err = os.WriteFile(idFile, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bin, idFile
}

// pinNow pins the fake plugin as connect would, into a pin file.
func pinNow(t *testing.T) string {
	t.Helper()
	pin, err := PinPlugin(pinPluginName, nil)
	if err != nil {
		t.Fatalf("PinPlugin: %v", err)
	}
	pins := filepath.Join(t.TempDir(), "age-plugins.json")
	if err = WritePluginPins(pins, []PluginPin{pin}); err != nil {
		t.Fatal(err)
	}
	return pins
}

func sealTo(t *testing.T, key *age.X25519Identity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, key.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, "material"); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(sealed []byte, ids []age.Identity) error {
	r, err := age.Decrypt(bytes.NewReader(sealed), ids...)
	if err != nil {
		return err
	}
	_, err = io.ReadAll(r)
	return err
}

func wantRefused(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: the plugin was run", what)
	}
	if !strings.Contains(err.Error(), "innsegl connect --update") {
		t.Fatalf("%s: the refusal names no repair: %v", what, err)
	}
}

func TestPinnedPluginOpensAFile(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	bin, idFile := fakePlugin(t, key)
	pins := pinNow(t)
	got, err := ReadPluginPins(pins)
	if err != nil || len(got) != 1 {
		t.Fatalf("ReadPluginPins = %+v, %v", got, err)
	}
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != pinPluginName || got[0].Path != resolved || len(got[0].SHA256) != 64 {
		t.Fatalf("pin = %+v; want %s at %s with its sha256", got[0], pinPluginName, resolved)
	}
	ids, err := LoadIdentities(idFile, nil, pins)
	if err != nil {
		t.Fatal(err)
	}
	if err = open(sealTo(t, key), ids); err != nil {
		t.Fatalf("the pinned plugin did not open the file: %v", err)
	}
}

func TestCLI046AWritablePluginOrDirectoryIsRefused(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]func(bin string) string{
		"directory": filepath.Dir,
		"plugin":    func(bin string) string { return bin },
	} {
		t.Run(name, func(t *testing.T) {
			bin, idFile := fakePlugin(t, key)
			pins := pinNow(t)
			ids, err := LoadIdentities(idFile, nil, pins)
			if err != nil {
				t.Fatal(err)
			}
			sealed := sealTo(t, key)
			if err = os.Chmod(target(bin), 0o777); err != nil {
				t.Fatal(err)
			}
			_, err = LoadIdentities(idFile, nil, pins)
			wantRefused(t, err, "load with a writable "+name)
			if !strings.Contains(err.Error(), "writable") {
				t.Fatalf("the refusal does not say why: %v", err)
			}
			// Loaded before the change, used after it: checked again at use.
			wantRefused(t, open(sealed, ids), "unwrap with a writable "+name)
			// Connect will not pin it either.
			if _, err = PinPlugin(pinPluginName, nil); err == nil || !strings.Contains(err.Error(), "writable") {
				t.Fatalf("PinPlugin pinned a writable %s: %v", name, err)
			}
		})
	}
}

func TestCLI047AChangedOrUnpinnedPluginIsRefused(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("hash", func(t *testing.T) {
		bin, idFile := fakePlugin(t, key)
		pins := pinNow(t)
		ids, err := LoadIdentities(idFile, nil, pins)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(bin, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.WriteString("wrapper"); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		_, err = LoadIdentities(idFile, nil, pins)
		wantRefused(t, err, "load after a change")
		if !strings.Contains(err.Error(), "changed") {
			t.Fatalf("the refusal does not say why: %v", err)
		}
		wantRefused(t, open(sealTo(t, key), ids), "unwrap after a change")
	})

	t.Run("another plugin first on PATH", func(t *testing.T) {
		_, idFile := fakePlugin(t, key)
		pins := pinNow(t)
		fakePlugin(t, key) // an identical copy, earlier on PATH
		_, err := LoadIdentities(idFile, nil, pins)
		wantRefused(t, err, "load with another copy first on PATH")
	})

	t.Run("never pinned", func(t *testing.T) {
		_, idFile := fakePlugin(t, key)
		for _, pins := range []string{"", filepath.Join(t.TempDir(), "absent.json")} {
			_, err := LoadIdentities(idFile, nil, pins)
			wantRefused(t, err, "load with no pin")
		}
	})
}

func TestAnX25519IdentityNeedsNoPin(t *testing.T) {
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "identity.txt")
	if err = os.WriteFile(p, []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ids, err := LoadIdentities(p, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = open(sealTo(t, key), ids); err != nil {
		t.Fatal(err)
	}
}

func TestPluginPinsFileIsRefusedWhenBroken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "age-plugins.json")
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPluginPins(p); err == nil {
		t.Fatal("a broken pin file was read")
	}
	if _, err := PinPlugin(pinPluginName, func(string) (string, error) { return "", os.ErrNotExist }); err == nil {
		t.Fatal("a plugin not found was pinned")
	}
}

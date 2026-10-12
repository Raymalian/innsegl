// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// CLI-040: the state directory is private to the operator. Directories are
// 0700 and files 0600; looser modes are tightened when the client starts;
// nothing is ever loosened.
func TestCLI040StateIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	home := t.TempDir()
	root := filepath.Join(home, ".innsegl")
	p := ClientPaths(home)
	dirs := []string{root, p.Dir, p.Outbox, p.TrustBackups, filepath.Join(root, "ca"), filepath.Join(root, "backups")}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	loose := map[string]os.FileMode{
		p.Cert: 0o644,
		filepath.Join(p.TrustBackups, "bundle.age"): 0o644,
		filepath.Join(root, "backups", "dump.sql"):  0o644,
		filepath.Join(root, "ca", "root.pem"):       0o644,
		filepath.Join(p.Outbox, "entry.json"):       0o640,
		p.Key:                                       0o400, // tighter already: must stay
	}
	for f, m := range loose {
		if err := os.WriteFile(f, []byte("x"), m); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f, m); err != nil {
			t.Fatal(err)
		}
	}
	core := []byte(`{"core_url":"https://c","installation_id":"i"}`)
	if err := os.WriteFile(p.Core, core, 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.Core, 0o664); err != nil {
		t.Fatal(err)
	}
	loose[p.Core] = 0o664

	if _, err := ReadCoreConfig(p); err != nil {
		t.Fatal(err)
	}

	for _, d := range dirs {
		if got := modeOf(t, d); got != 0o700 {
			t.Errorf("dir %s: mode %o, want 700", d, got)
		}
	}
	for f, m := range loose {
		want := os.FileMode(0o600)
		if m == 0o400 {
			want = 0o400
		}
		if got := modeOf(t, f); got != want {
			t.Errorf("file %s: mode %o, want %o", f, got, want)
		}
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

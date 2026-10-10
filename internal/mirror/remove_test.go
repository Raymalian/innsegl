// SPDX-License-Identifier: Apache-2.0

package mirror

import (
	"os"
	"path/filepath"
	"testing"
)

// LED-046's mirror half (operator decision 6): erasing a repository removes
// its mirror, and only its mirror.
func TestLED046RemoveDeletesOneRepositorysMirror(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"example.test/acme/gone", "example.test/acme/kept"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(r)+".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if removed, err := s.Remove("example.test/acme/gone"); err != nil || !removed {
		t.Fatalf("Remove = %v, %v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(root, "example.test/acme/gone.git")); !os.IsNotExist(err) {
		t.Error("the erased repository's mirror is still there")
	}
	if _, err := os.Stat(filepath.Join(root, "example.test/acme/kept.git")); err != nil {
		t.Error("another repository's mirror went with it")
	}
	if removed, err := s.Remove("example.test/acme/gone"); err != nil || removed {
		t.Errorf("a second Remove = %v, %v; want false, nil", removed, err)
	}
	if _, err := s.Remove("../../etc"); err == nil {
		t.Error("a path that is not a repository was accepted")
	}
}

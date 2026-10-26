// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFilesTransactionRestoresEveryOldFileWhenACommitFails(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	cert := filepath.Join(dir, "cert.pem")
	marker := filepath.Join(dir, "credential-refused")
	for path, body := range map[string]string{key: "old key", cert: "old cert", marker: "old refusal"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	call := 0
	failed := false
	renamer := func(old, newName string) error {
		call++
		if newName == cert && !failed {
			failed = true
			return errors.New("simulated disk rename failure")
		}
		return os.Rename(old, newName)
	}
	files := []fileChange{
		{path: key, data: []byte("new key"), mode: 0o600},
		{path: cert, data: []byte("new cert"), mode: 0o600},
		{path: marker, remove: true},
	}
	if err := writeFilesTransaction(files, renamer); err == nil {
		t.Fatal("writeFilesTransaction succeeded despite the injected commit failure")
	}
	if call < 3 {
		t.Fatalf("transaction made %d rename calls, want failed commit and rollback", call)
	}
	for path, want := range map[string]string{key: "old key", cert: "old cert", marker: "old refusal"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v; want restored %q", filepath.Base(path), got, err, want)
		}
	}
}

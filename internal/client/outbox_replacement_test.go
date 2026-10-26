// SPDX-License-Identifier: Apache-2.0

package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveOutboxForReplacementPreservesItemsAndDoesNotOverwriteArchive(t *testing.T) {
	p := ClientPaths(t.TempDir())
	if err := os.MkdirAll(p.Outbox, 0o700); err != nil {
		t.Fatal(err)
	}
	item := filepath.Join(p.Outbox, "00000000000000000001.exchange")
	if err := os.WriteFile(item, []byte("old signed exchange"), 0o600); err != nil {
		t.Fatal(err)
	}

	archive, err := ArchiveOutboxForReplacement(p, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if archive == "" {
		t.Fatal("archive path is empty")
	}
	if got, err := os.ReadFile(filepath.Join(archive, filepath.Base(item))); err != nil || string(got) != "old signed exchange" {
		t.Fatalf("archived item = %q, %v", got, err)
	}
	if _, err := os.Stat(p.Outbox); !os.IsNotExist(err) {
		t.Fatalf("active outbox still exists after archival: %v", err)
	}
	if err := RestoreOutboxAfterFailedReplacement(p, archive); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(item); err != nil || string(got) != "old signed exchange" {
		t.Fatalf("restored item = %q, %v", got, err)
	}

	if _, err := ArchiveOutboxForReplacement(p, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p.Outbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ArchiveOutboxForReplacement(p, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("second replacement overwrote an existing recovery archive")
	}
}

func TestArchivedOutboxCanBeListedAndExportedWithoutChangingTheArchive(t *testing.T) {
	p := ClientPaths(t.TempDir())
	const installationID = "0123456789abcdef0123456789abcdef"
	if err := os.MkdirAll(p.Outbox, 0o700); err != nil {
		t.Fatal(err)
	}
	item := filepath.Join(p.Outbox, "00000000000000000001.exchange")
	if err := os.WriteFile(item, []byte(`{"entry":"signed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := ArchiveOutboxForReplacement(p, installationID)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := ListArchivedOutboxes(p)
	if err != nil || len(listed) != 1 {
		t.Fatalf("ListArchivedOutboxes = %+v, %v", listed, err)
	}
	if listed[0].InstallationID != installationID || listed[0].Items != 1 || listed[0].Bytes == 0 {
		t.Fatalf("archive summary = %+v", listed[0])
	}
	destination := filepath.Join(t.TempDir(), "export")
	if err := ExportArchivedOutbox(p, installationID, destination); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, filepath.Base(item))); err != nil || string(got) != `{"entry":"signed"}` {
		t.Fatalf("exported entry = %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(archive, filepath.Base(item))); err != nil || string(got) != `{"entry":"signed"}` {
		t.Fatalf("source archive changed during export: %q, %v", got, err)
	}
	if err := ExportArchivedOutbox(p, installationID, destination); err == nil {
		t.Fatal("export overwrote an existing destination")
	}
}

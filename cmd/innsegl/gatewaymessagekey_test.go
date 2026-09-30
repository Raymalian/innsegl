// SPDX-License-Identifier: Apache-2.0

package main

// gatewaymessagekey_test.go — E19 (#395-#397): writeMessageKeyFile, the
// function that restates RM-237's own derived agent-message key to a file
// the run page's query API reads and verifies with, never mints with — see
// writeMessageKeyFile's own doc comment in gateway.go for why 0400 is
// enough (innsegl-mcp and innsegl-api run as the identical uid:gid in
// every deployment this project ships).

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteMessageKeyFileWritesOwnerReadOnly(t *testing.T) {
	dir := t.TempDir()
	if err := writeMessageKeyFile(dir, "gateway-v1", "deadbeef"); err != nil {
		t.Fatalf("writeMessageKeyFile: %v", err)
	}

	path := filepath.Join(dir, "gateway-v1")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	if string(got) != "deadbeef" {
		t.Errorf("content = %q, want %q", got, "deadbeef")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat(%s): %v", path, err)
		}
		if mode := info.Mode().Perm(); mode != 0o400 {
			t.Errorf("file mode = %o, want 0400 (owner-read only, no group or world bits)", mode)
		}
		dirInfo, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("Stat(%s): %v", dir, err)
		}
		if dirMode := dirInfo.Mode().Perm(); dirMode&0o077 != 0 {
			t.Errorf("directory mode = %o, want no group or world bits set", dirMode)
		}
	}
}

func TestWriteMessageKeyFileCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist", "yet")
	if err := writeMessageKeyFile(dir, "gateway-v1", "deadbeef"); err != nil {
		t.Fatalf("writeMessageKeyFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "gateway-v1")); err != nil {
		t.Fatalf("the key file was not created under the new directory: %v", err)
	}
}

func TestWriteMessageKeyFileIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := writeMessageKeyFile(dir, "gateway-v1", "deadbeef"); err != nil {
			t.Fatalf("write #%d: %v", i+1, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "gateway-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "deadbeef" {
		t.Errorf("content = %q, want %q", got, "deadbeef")
	}
}

func TestWriteMessageKeyFileRefusesAConflictingKeyUnderTheSameID(t *testing.T) {
	dir := t.TempDir()
	if err := writeMessageKeyFile(dir, "gateway-v1", "deadbeef"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	err := writeMessageKeyFile(dir, "gateway-v1", "different-key-entirely")
	if err == nil {
		t.Fatal("a different key claiming the same id should be refused, never silently overwritten")
	}

	got, rerr := os.ReadFile(filepath.Join(dir, "gateway-v1"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != "deadbeef" {
		t.Errorf("content after the refused write = %q, want the ORIGINAL %q untouched", got, "deadbeef")
	}
}

func TestWriteMessageKeyFileTwoDifferentKeyIDsCoexist(t *testing.T) {
	dir := t.TempDir()
	if err := writeMessageKeyFile(dir, "gateway-v1", "key-one"); err != nil {
		t.Fatal(err)
	}
	if err := writeMessageKeyFile(dir, "gateway-v2", "key-two"); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"gateway-v1": "key-one", "gateway-v2": "key-two"} {
		got, err := os.ReadFile(filepath.Join(dir, id))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", id, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", id, got, want)
		}
	}
}

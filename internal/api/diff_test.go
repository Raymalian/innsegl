// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// Unit coverage for diff.go's pure parser and its own output bound, neither
// of which need Postgres or a real git process.

func TestBoundedWriterStopsAtTheBound(t *testing.T) {
	var buf bytes.Buffer
	cancelled := false
	w := &boundedWriter{buf: &buf, max: 10, cancel: func() { cancelled = true }}

	n, err := w.Write([]byte("12345"))
	if err != nil || n != 5 {
		t.Fatalf("first write: n=%d err=%v, want 5, nil", n, err)
	}
	if cancelled {
		t.Error("cancel should not fire before the bound is reached")
	}

	// This write crosses the bound mid-write: only the room left is kept.
	n, err = w.Write([]byte("1234567890"))
	if err == nil {
		t.Fatal("a write crossing the bound should answer an error")
	}
	if n != 10 {
		t.Errorf("n = %d, want len(p) (10) even though only part was kept", n)
	}
	if buf.Len() != 10 {
		t.Errorf("buf.Len() = %d, want 10 (5 + 5 room)", buf.Len())
	}
	if !w.truncated || !cancelled {
		t.Errorf("truncated=%v cancelled=%v, want both true", w.truncated, cancelled)
	}

	// Once truncated, any further write is refused outright.
	n, err = w.Write([]byte("x"))
	if err == nil || n != 0 {
		t.Errorf("write after truncation: n=%d err=%v, want 0, an error", n, err)
	}
}

func TestAtoiOrAndAtoiOr1(t *testing.T) {
	if got := atoiOr("42", -1); got != 42 {
		t.Errorf("atoiOr(42) = %d, want 42", got)
	}
	if got := atoiOr("not a number", -1); got != -1 {
		t.Errorf("atoiOr(garbage) = %d, want the default -1", got)
	}
	if got := atoiOr1(""); got != 1 {
		t.Errorf("atoiOr1(\"\") = %d, want 1 — git omits the count when it is 1", got)
	}
	if got := atoiOr1("5"); got != 5 {
		t.Errorf("atoiOr1(5) = %d, want 5", got)
	}
	if got := atoiOr1("garbage"); got != 1 {
		t.Errorf("atoiOr1(garbage) = %d, want the default 1", got)
	}
}

func TestParseDiffTreePatchBinaryFile(t *testing.T) {
	patch := "diff --git a/blob.bin b/blob.bin\n" +
		"new file mode 100644\n" +
		"index 0000000..abc1234\n" +
		"Binary files /dev/null and b/blob.bin differ\n"
	diff := parseDiffTreePatch([]byte(patch), false)
	if len(diff.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(diff.Files))
	}
	f := diff.Files[0]
	if !f.Binary || f.Status != "A" || len(f.Hunks) != 0 {
		t.Errorf("file = %+v, want Binary=true Status=A no hunks", f)
	}
}

func TestParseDiffTreePatchRenameWithContentChange(t *testing.T) {
	patch := "diff --git a/old.txt b/new.txt\n" +
		"similarity index 80%\n" +
		"rename from old.txt\n" +
		"rename to new.txt\n" +
		"index 1111111..2222222 100644\n" +
		"--- a/old.txt\n" +
		"+++ b/new.txt\n" +
		"@@ -1,2 +1,2 @@\n" +
		" context line\n" +
		"-old line\n" +
		"+new line\n"
	diff := parseDiffTreePatch([]byte(patch), false)
	if len(diff.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(diff.Files))
	}
	f := diff.Files[0]
	if f.Status != "R" || f.OldPath != "old.txt" || f.Path != "new.txt" {
		t.Errorf("file = %+v, want Status=R OldPath=old.txt Path=new.txt", f)
	}
	if len(f.Hunks) != 1 || len(f.Hunks[0].Lines) != 3 {
		t.Fatalf("hunks = %+v, want one hunk with 3 lines", f.Hunks)
	}
	kinds := []string{f.Hunks[0].Lines[0].Kind, f.Hunks[0].Lines[1].Kind, f.Hunks[0].Lines[2].Kind}
	if kinds[0] != "context" || kinds[1] != "del" || kinds[2] != "add" {
		t.Errorf("line kinds = %v, want [context del add]", kinds)
	}
}

func TestParseDiffTreePatchDeletedFile(t *testing.T) {
	patch := "diff --git a/gone.txt b/gone.txt\n" +
		"deleted file mode 100644\n" +
		"index 1111111..0000000\n" +
		"--- a/gone.txt\n" +
		"+++ /dev/null\n" +
		"@@ -1 +0,0 @@\n" +
		"-the only line\n"
	diff := parseDiffTreePatch([]byte(patch), false)
	if len(diff.Files) != 1 || diff.Files[0].Status != "D" {
		t.Fatalf("files = %+v, want one Status=D", diff.Files)
	}
}

func TestParseDiffTreePatchOutputTruncationMarksTheLastFile(t *testing.T) {
	patch := "diff --git a/a.txt b/a.txt\n" +
		"@@ -1 +1 @@\n" +
		"-a\n" +
		"+b\n"
	diff := parseDiffTreePatch([]byte(patch), true)
	if len(diff.Files) != 1 || !diff.Files[0].Truncated {
		t.Errorf("files = %+v, want the one file marked Truncated", diff.Files)
	}
}

func TestParseDiffTreePatchHunkCapMarksTheFileTruncated(t *testing.T) {
	var b strings.Builder
	b.WriteString("diff --git a/many.txt b/many.txt\n")
	for i := 0; i < maxHunksPerFile+5; i++ {
		b.WriteString("@@ -" + strconv.Itoa(i+1) + " +" + strconv.Itoa(i+1) + " @@\n")
		b.WriteString("-x\n+y\n")
	}
	diff := parseDiffTreePatch([]byte(b.String()), false)
	if len(diff.Files) != 1 {
		t.Fatalf("got %d files, want 1", len(diff.Files))
	}
	if !diff.Files[0].Truncated {
		t.Error("a file with more hunks than the cap should read Truncated")
	}
	if len(diff.Files[0].Hunks) != maxHunksPerFile {
		t.Errorf("got %d hunks, want the cap of %d", len(diff.Files[0].Hunks), maxHunksPerFile)
	}
}

func TestParseDiffTreePatchNoFilesIsAnEmptySlice(t *testing.T) {
	diff := parseDiffTreePatch([]byte(""), false)
	if diff.Files == nil {
		t.Error("Files should be an empty slice, never nil")
	}
	if len(diff.Files) != 0 {
		t.Errorf("got %d files, want 0", len(diff.Files))
	}
}

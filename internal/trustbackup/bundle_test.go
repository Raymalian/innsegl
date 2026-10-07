// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

var testNow = time.Date(2026, 10, 7, 16, 52, 0, 0, time.UTC)

func testIdentity(t *testing.T) (*age.X25519Identity, []age.Recipient) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id, []age.Recipient{id.Recipient()}
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// fixtureSources is one of each kind of item: a volume, a single file, a
// command's output and a value.
func fixtureSources(t *testing.T) []Source {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "pki", "ca.crt"), "CERT", 0o644)
	writeFile(t, filepath.Join(dir, "pki", "ca.key"), "KEY", 0o600)
	writeFile(t, filepath.Join(dir, "pki", "sub", "nested"), "N", 0o600)
	writeFile(t, filepath.Join(dir, "secret"), "SECRET", 0o400)
	return []Source{
		PathSource("fulcio-pki", filepath.Join(dir, "pki")),
		PathSource("identity-secret", filepath.Join(dir, "secret")),
		StreamSource("trillian-db", "trillian.sql", func(w io.Writer) error {
			_, err := io.WriteString(w, "line1\nline2\n")
			return err
		}),
		ValueSource("fulcio-ca-password", "password", []byte("pw")),
	}
}

func TestABundleRoundTripsEveryItemWithItsChecksum(t *testing.T) {
	id, rs := testIdentity(t)
	var buf bytes.Buffer
	m, err := WriteBundle(&buf, rs, fixtureSources(t), testNow)
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	if m.Format != Format || !m.CreatedAt.Equal(testNow) || len(m.Items) != 4 {
		t.Fatalf("manifest = %+v", m)
	}
	want := map[string]string{
		"fulcio-pki/ca.crt":           sum("CERT"),
		"fulcio-pki/ca.key":           sum("KEY"),
		"fulcio-pki/sub/nested":       sum("N"),
		"identity-secret/secret":      sum("SECRET"),
		"trillian-db/trillian.sql":    sum("line1\nline2\n"),
		"fulcio-ca-password/password": sum("pw"),
	}
	got := map[string]string{}
	for _, it := range m.Items {
		for _, f := range it.Files {
			got[it.Name+"/"+f.Path] = f.SHA256
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: sha256 %q, want %q", k, got[k], v)
		}
	}
	if strings.Contains(buf.String(), "SECRET") || strings.Contains(buf.String(), "KEY") {
		t.Fatal("the bundle carries plaintext")
	}

	out := t.TempDir()
	read, err := ReadBundle(bytes.NewReader(buf.Bytes()), []age.Identity{id}, out)
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if read.Files() != 6 || read.Bytes() != int64(len("CERTKEYNSECRETline1\nline2\npw")) {
		t.Fatalf("read %d files, %d bytes", read.Files(), read.Bytes())
	}
	b, err := os.ReadFile(filepath.Join(out, "fulcio-pki", "ca.key"))
	if err != nil || string(b) != "KEY" {
		t.Fatalf("extracted ca.key = %q, %v", b, err)
	}
	if fi := must(os.Stat(filepath.Join(out, "fulcio-pki", "ca.key")))(t); fi.Mode().Perm() != 0o600 {
		t.Fatalf("extracted mode %v, want 0600", fi.Mode().Perm())
	}
	// Verify only: nothing written.
	if _, err := ReadBundle(bytes.NewReader(buf.Bytes()), []age.Identity{id}, ""); err != nil {
		t.Fatalf("ReadBundle verify-only: %v", err)
	}
}

// A stream is written in parts, never held whole, and comes back as one
// file.
func TestALargeCommandOutputIsSplitAndJoined(t *testing.T) {
	old := partSize
	partSize = 4
	t.Cleanup(func() { partSize = old })
	id, rs := testIdentity(t)
	var buf bytes.Buffer
	m, err := WriteBundle(&buf, rs, []Source{
		StreamSource("db", "dump.sql", func(w io.Writer) error {
			for _, c := range []string{"01", "2345678", "9"} {
				if _, err := io.WriteString(w, c); err != nil {
					return err
				}
			}
			return nil
		}),
	}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if f := m.Items[0].Files[0]; f.Parts != 3 || f.Size != 10 || f.SHA256 != sum("0123456789") {
		t.Fatalf("file = %+v", f)
	}
	out := t.TempDir()
	if _, err := ReadBundle(&buf, []age.Identity{id}, out); err != nil {
		t.Fatal(err)
	}
	b := must(os.ReadFile(filepath.Join(out, "db", "dump.sql")))(t)
	if string(b) != "0123456789" {
		t.Fatalf("joined = %q", b)
	}
}

func TestWriteBundleRefusesWhatItCannotBackUp(t *testing.T) {
	_, rs := testIdentity(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), "x", 0o600)
	if err := os.Symlink(filepath.Join(dir, "f"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	unreadable := filepath.Join(t.TempDir(), "locked")
	writeFile(t, filepath.Join(unreadable, "k"), "x", 0o600)
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreMode(t, unreadable) })

	cases := map[string]struct {
		rs   []age.Recipient
		srcs []Source
	}{
		"no recipients":     {nil, []Source{ValueSource("a", "a", []byte("x"))}},
		"no sources":        {rs, nil},
		"a bad item name":   {rs, []Source{ValueSource("../a", "a", []byte("x"))}},
		"a bad file name":   {rs, []Source{ValueSource("a", "../a", []byte("x"))}},
		"a duplicate item":  {rs, []Source{ValueSource("a", "a", []byte("x")), ValueSource("a", "b", []byte("x"))}},
		"a missing path":    {rs, []Source{PathSource("a", filepath.Join(dir, "nope"))}},
		"a symlink":         {rs, []Source{PathSource("a", dir)}},
		"an empty dir":      {rs, []Source{PathSource("a", t.TempDir())}},
		"a socket-like":     {rs, []Source{PathSource("a", os.DevNull)}},
		"an unreadable dir": {rs, []Source{PathSource("a", unreadable)}},
		"an empty value":    {rs, []Source{ValueSource("a", "a", nil)}},
		"a failing stream": {rs, []Source{StreamSource("a", "a.sql", func(w io.Writer) error {
			if _, err := io.WriteString(w, "partial"); err != nil {
				return err
			}
			return errors.New("boom")
		})}},
		"an empty stream": {rs, []Source{StreamSource("a", "a.sql", func(io.Writer) error { return nil })}},
		"no producer":     {rs, []Source{StreamSource("a", "a.sql", nil)}},
	}
	if os.Geteuid() == 0 {
		delete(cases, "an unreadable dir") // root reads through 0000
	}
	for name, c := range cases {
		if _, err := WriteBundle(io.Discard, c.rs, c.srcs, testNow); err == nil {
			t.Errorf("%s: WriteBundle succeeded, want a refusal", name)
		}
	}
	// The failing stream's refusal carries its error.
	_, err := WriteBundle(io.Discard, rs, cases["a failing stream"].srcs, testNow)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failing stream error = %v, want its error", err)
	}
}

func TestWriteBundleRefusesAFileOverTheLimit(t *testing.T) {
	old := maxFileSize
	maxFileSize = 3
	t.Cleanup(func() { maxFileSize = old })
	_, rs := testIdentity(t)
	p := filepath.Join(t.TempDir(), "big")
	writeFile(t, p, "four", 0o600)
	if _, err := WriteBundle(io.Discard, rs, []Source{PathSource("a", p)}, testNow); err == nil {
		t.Fatal("a file over the limit was taken")
	}
}

func TestWriteBundleReportsAWriteFailure(t *testing.T) {
	_, rs := testIdentity(t)
	var full bytes.Buffer
	if _, err := WriteBundle(&full, rs, fixtureSources(t), testNow); err != nil {
		t.Fatal(err)
	}
	// The header, and the final chunk age writes only on Close.
	for _, n := range []int{0, 10, full.Len() - 1} {
		if _, err := WriteBundle(&byteFailWriter{n: n}, rs, fixtureSources(t), testNow); err == nil {
			t.Fatalf("failing at byte %d: WriteBundle succeeded on a failing writer", n)
		}
	}
}

func TestWriteBundleRefusesAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file; this case needs an unprivileged user")
	}
	_, rs := testIdentity(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "k"), "x", 0o000)
	if _, err := WriteBundle(io.Discard, rs, []Source{PathSource("a", dir)}, testNow); err == nil {
		t.Fatal("an unreadable key file was skipped silently")
	}
}

// A bundle damaged in the middle of a file fails while that file is read,
// and an extraction that would overwrite a file is refused.
func TestReadBundleRefusesADamagedChunkAndAnOverwrite(t *testing.T) {
	id, rs := testIdentity(t)
	big := bytes.Repeat([]byte("k"), 200<<10)
	var buf bytes.Buffer
	if _, err := WriteBundle(&buf, rs, []Source{ValueSource("a", "f", big)}, testNow); err != nil {
		t.Fatal(err)
	}
	damaged := bytes.Clone(buf.Bytes())
	damaged[len(damaged)/2] ^= 0xff
	if _, err := ReadBundle(bytes.NewReader(damaged), []age.Identity{id}, ""); err == nil {
		t.Fatal("a damaged chunk was accepted")
	}
	out := t.TempDir()
	writeFile(t, filepath.Join(out, "a", "f"), "already here", 0o600)
	if _, err := ReadBundle(bytes.NewReader(buf.Bytes()), []age.Identity{id}, out); err == nil {
		t.Fatal("extraction overwrote an existing file")
	}
}

// plainBundle encrypts a hand-made tar stream, so every refusal ReadBundle
// makes can be reached.
func plainBundle(t *testing.T, rs []age.Recipient, build func(tw *tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(w)
	build(tw)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func addEntry(t *testing.T, tw *tar.Writer, name, body string) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(tw, body); err != nil {
		t.Fatal(err)
	}
}

func manifestJSON(t *testing.T, m Manifest) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func goodManifest(body string) Manifest {
	return Manifest{Format: Format, CreatedAt: testNow, Items: []Item{{Name: "a",
		Files: []File{{Path: "f", Mode: 0o600, Size: int64(len(body)), SHA256: sum(body)}}}}}
}

func TestReadBundleRefusesATamperedOrIncompleteBundle(t *testing.T) {
	id, rs := testIdentity(t)
	other, _ := testIdentity(t)
	cases := map[string]func(tw *tar.Writer){
		"no manifest": func(tw *tar.Writer) { addEntry(t, tw, "a/f", "x") },
		"a checksum mismatch": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f", "y")
			addEntry(t, tw, ManifestPath, manifestJSON(t, goodManifest("x")))
		},
		"a file the manifest lacks": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, "a/g", "x")
			addEntry(t, tw, ManifestPath, manifestJSON(t, goodManifest("x")))
		},
		"a file the bundle lacks": func(tw *tar.Writer) {
			addEntry(t, tw, ManifestPath, manifestJSON(t, goodManifest("x")))
		},
		"an entry after the manifest": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, ManifestPath, manifestJSON(t, goodManifest("x")))
			addEntry(t, tw, "a/g", "x")
		},
		"an unreadable manifest": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, ManifestPath, "{")
		},
		"a foreign format": func(tw *tar.Writer) {
			m := goodManifest("x")
			m.Format = "other/9"
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, ManifestPath, manifestJSON(t, m))
		},
		"an escaping path": func(tw *tar.Writer) {
			addEntry(t, tw, "../evil", "x")
		},
		"an absolute path": func(tw *tar.Writer) {
			addEntry(t, tw, "/evil", "x")
		},
		"a top-level file": func(tw *tar.Writer) {
			addEntry(t, tw, "evil", "x")
		},
		"a symlink entry": func(tw *tar.Writer) {
			if err := tw.WriteHeader(&tar.Header{Name: "a/l", Typeflag: tar.TypeSymlink, Linkname: "/etc"}); err != nil {
				t.Fatal(err)
			}
		},
		"a part numbered zero": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f.part-000000", "x")
		},
		"a directory where a file goes": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, "a/f/g", "x")
		},
		"parts out of order": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f"+partSuffix(2), "x")
		},
		"a part beside a whole file": func(tw *tar.Writer) {
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, "a/f"+partSuffix(1), "x")
		},
		"a size mismatch": func(tw *tar.Writer) {
			m := goodManifest("x")
			m.Items[0].Files[0].Size = 9
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, ManifestPath, manifestJSON(t, m))
		},
		"a parts mismatch": func(tw *tar.Writer) {
			m := goodManifest("x")
			m.Items[0].Files[0].Parts = 2
			addEntry(t, tw, "a/f", "x")
			addEntry(t, tw, ManifestPath, manifestJSON(t, m))
		},
	}
	for name, build := range cases {
		data := plainBundle(t, rs, build)
		if _, err := ReadBundle(bytes.NewReader(data), []age.Identity{id}, ""); err == nil {
			t.Errorf("%s: ReadBundle accepted it", name)
		}
		if _, err := ReadBundle(bytes.NewReader(data), []age.Identity{id}, t.TempDir()); err == nil {
			t.Errorf("%s (extracting): ReadBundle accepted it", name)
		}
	}
	good := plainBundle(t, rs, func(tw *tar.Writer) {
		addEntry(t, tw, "a/f", "x")
		addEntry(t, tw, ManifestPath, manifestJSON(t, goodManifest("x")))
	})
	if _, err := ReadBundle(bytes.NewReader(good), []age.Identity{other}, ""); err == nil {
		t.Error("ReadBundle opened a bundle with the wrong identity")
	}
	if _, err := ReadBundle(bytes.NewReader(good[:len(good)-5]), []age.Identity{id}, ""); err == nil {
		t.Error("ReadBundle accepted a truncated bundle")
	}
	if _, err := ReadBundle(bytes.NewReader(good), []age.Identity{id}, ""); err != nil {
		t.Errorf("the control bundle was refused: %v", err)
	}
	// An extraction target that cannot be written is a refusal too.
	blocked := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocked, "x", 0o600)
	if _, err := ReadBundle(bytes.NewReader(good), []age.Identity{id}, blocked); err == nil {
		t.Error("ReadBundle extracted into a file")
	}
}

// byteFailWriter fails once n bytes have been written.
type byteFailWriter struct{ n int }

func (f *byteFailWriter) Write(p []byte) (int, error) {
	if len(p) > f.n {
		k := f.n
		f.n = 0
		return k, errors.New("disk full")
	}
	f.n -= len(p)
	return len(p), nil
}

// Every write the tar stream makes can fail, and each failure is an error,
// never a short bundle reported as good.
func TestWriteTarReportsAFailureAtEveryOffset(t *testing.T) {
	old := partSize
	partSize = 3
	t.Cleanup(func() { partSize = old })
	var full bytes.Buffer
	if _, err := writeTar(&full, fixtureSources(t), testNow); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < full.Len(); n += 97 {
		if _, err := writeTar(&byteFailWriter{n: n}, fixtureSources(t), testNow); err == nil {
			t.Fatalf("failing at byte %d of %d: writeTar succeeded", n, full.Len())
		}
	}
	// The last block boundary too: only the end-of-archive write fails.
	if _, err := writeTar(&byteFailWriter{n: full.Len() - 1}, fixtureSources(t), testNow); err == nil {
		t.Fatal("failing at the last byte: writeTar succeeded")
	}
}

// must answers v, and ends the test on err: must(f())(t).
func must[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// restoreMode gives a directory a test locked back to its owner, so the
// test's cleanup can remove it.
func restoreMode(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Error(err)
	}
}

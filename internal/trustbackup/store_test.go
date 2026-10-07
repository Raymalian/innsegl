// SPDX-License-Identifier: Apache-2.0

package trustbackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func clockFrom(start time.Time) func() time.Time {
	t := start
	return func() time.Time {
		now := t
		t = t.Add(time.Hour)
		return now
	}
}

func TestCreateKeepsTheNewestNAndChecksumsEach(t *testing.T) {
	id, rs := testIdentity(t)
	dir := filepath.Join(t.TempDir(), "backups")
	s := &Store{Dir: dir, Keep: 2, Now: clockFrom(testNow)}
	var last Entry
	for i := 0; i < 3; i++ {
		e, m, err := s.Create(rs, []Source{ValueSource("a", "f", []byte("x"))})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if len(m.Items) != 1 {
			t.Fatalf("manifest %+v", m)
		}
		last = e
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != last.Name || !list[0].CreatedAt.After(list[1].CreatedAt) {
		t.Fatalf("list = %+v, want the newest two, newest first", list)
	}
	if list[0].Name != "trust-backup-20261007T185200Z.tar.age" {
		t.Fatalf("name = %q", list[0].Name)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v, %v", fi.Mode().Perm(), err)
	}
	f, e, err := s.Open(last.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := must(io.ReadAll(f))(t)
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != e.SHA256 || int64(len(b)) != e.Size {
		t.Fatal("the recorded checksum is not the bundle's")
	}
	if fi := must(f.Stat())(t); fi.Mode().Perm() != 0o600 {
		t.Fatalf("bundle mode %v", fi.Mode().Perm())
	}
	if _, err := ReadBundle(bytes.NewReader(b), []age.Identity{id}, ""); err != nil {
		t.Fatalf("the stored bundle does not open: %v", err)
	}
	// Nothing but the two bundles and their checksums is left behind.
	names := must(os.ReadDir(dir))(t)
	if len(names) != 4 {
		t.Fatalf("dir holds %d entries, want 4", len(names))
	}
}

func TestCreateLeavesNothingWhenTheBundleFails(t *testing.T) {
	_, rs := testIdentity(t)
	dir := t.TempDir()
	s := &Store{Dir: dir, Keep: 3, Now: clockFrom(testNow)}
	if _, _, err := s.Create(rs, []Source{PathSource("a", "/nonexistent")}); err == nil {
		t.Fatal("Create succeeded")
	}
	names := must(os.ReadDir(dir))(t)
	if len(names) != 0 {
		t.Fatalf("a failed run left %d files", len(names))
	}
	if _, _, err := s.Create(nil, []Source{ValueSource("a", "f", []byte("x"))}); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("no recipients: %v", err)
	}
}

func TestCreateRefusesToOverwriteABundle(t *testing.T) {
	_, rs := testIdentity(t)
	s := &Store{Dir: t.TempDir(), Keep: 3, Now: func() time.Time { return testNow }}
	src := []Source{ValueSource("a", "f", []byte("x"))}
	if _, _, err := s.Create(rs, src); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(rs, src); err == nil {
		t.Fatal("a second bundle in the same second overwrote the first")
	}
}

func TestCreateFailsOnAnUnwritableDir(t *testing.T) {
	_, rs := testIdentity(t)
	blocked := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocked, "x", 0o600)
	s := &Store{Dir: filepath.Join(blocked, "sub"), Keep: 1, Now: clockFrom(testNow)}
	if _, _, err := s.Create(rs, []Source{ValueSource("a", "f", []byte("x"))}); err == nil {
		t.Fatal("Create wrote under a file")
	}
}

func TestPutVerifiesTheOuterChecksum(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "local")
	s := &Store{Dir: dir, Keep: 2}
	name := "trust-backup-20261007T165200Z.tar.age"
	body := "ciphertext"
	if _, err := s.Put(name, strings.NewReader(body), sum("other")); err == nil {
		t.Fatal("Put took a body whose checksum does not match")
	}
	if names := must(os.ReadDir(dir))(t); len(names) != 0 {
		t.Fatalf("a refused Put left %d files", len(names))
	}
	e, err := s.Put(name, strings.NewReader(body), sum(body))
	if err != nil {
		t.Fatal(err)
	}
	if e.SHA256 != sum(body) || e.Size != int64(len(body)) || !e.CreatedAt.Equal(testNow) {
		t.Fatalf("entry = %+v", e)
	}
	// The same bundle again is a no-op, not an error.
	if _, err := s.Put(name, strings.NewReader(body), sum(body)); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	for _, bad := range []string{"../x", "trust-backup-x.tar.age", "", "trust-backup-20261007T165200Z.tar.age/../../x"} {
		if _, err := s.Put(bad, strings.NewReader(body), sum(body)); err == nil {
			t.Errorf("Put took the name %q", bad)
		}
	}
	if _, err := s.Put(name, strings.NewReader(body), "nothex"); err == nil {
		t.Error("Put took a malformed checksum")
	}
	if _, err := s.Put("trust-backup-20261008T165200Z.tar.age", iotestErrReader{}, sum(body)); err == nil {
		t.Error("Put succeeded on a failing reader")
	}
}

type iotestErrReader struct{}

func (iotestErrReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestListIgnoresWhatIsNotACompleteBundle(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, Keep: 5}
	// No checksum beside it: an interrupted write.
	writeFile(t, filepath.Join(dir, "trust-backup-20261007T165200Z.tar.age"), "x", 0o600)
	// A checksum that does not parse.
	writeFile(t, filepath.Join(dir, "trust-backup-20261006T165200Z.tar.age"), "x", 0o600)
	writeFile(t, filepath.Join(dir, "trust-backup-20261006T165200Z.tar.age.sha256"), "zz", 0o600)
	writeFile(t, filepath.Join(dir, "unrelated"), "x", 0o600)
	writeFile(t, filepath.Join(dir, ".tmp-123"), "x", 0o600)
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("list = %+v", list)
	}
	if _, _, err := s.Open("trust-backup-20261007T165200Z.tar.age"); err == nil {
		t.Fatal("Open served a bundle with no checksum")
	}
	if _, _, err := s.Open("../etc/passwd"); err == nil {
		t.Fatal("Open served a path outside the store")
	}
	missing := &Store{Dir: filepath.Join(dir, "absent")}
	if l, err := missing.List(); err != nil || len(l) != 0 {
		t.Fatalf("a missing dir lists %v, %v; want empty", l, err)
	}
	if _, err := s.Latest(); !errors.Is(err, ErrNoBundle) {
		t.Fatalf("Latest on an empty store = %v", err)
	}
}

func TestStatusRoundTrips(t *testing.T) {
	s := &Store{Dir: filepath.Join(t.TempDir(), "d")}
	if _, err := s.ReadStatus(); err == nil {
		t.Fatal("ReadStatus on nothing succeeded")
	}
	want := Status{LastAttempt: testNow, LastSuccess: testNow, Latest: "n", Error: "e"}
	if err := s.WriteStatus(want); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadStatus()
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	writeFile(t, filepath.Join(s.Dir, StatusFileName), "{", 0o600)
	if _, err := s.ReadStatus(); err == nil {
		t.Fatal("ReadStatus took a broken file")
	}
	blocked := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocked, "x", 0o600)
	if err := (&Store{Dir: blocked}).WriteStatus(want); err == nil {
		t.Fatal("WriteStatus wrote under a file")
	}
}

// A bundle is published whole or not at all: when its checksum file cannot
// be written, the bundle is removed too, and a rename that fails leaves
// nothing behind.
func TestPutPublishesWholeOrNothing(t *testing.T) {
	body := "ciphertext"
	name := "trust-backup-20261007T165200Z.tar.age"

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, name+".sha256", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: dir, Keep: 2}
	if _, err := s.Put(name, strings.NewReader(body), sum(body)); err == nil {
		t.Fatal("Put succeeded with no checksum file")
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the bundle was left without its checksum: %v", err)
	}

	dir2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir2, name, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	s2 := &Store{Dir: dir2, Keep: 2}
	if _, err := s2.Put(name, strings.NewReader(body), sum(body)); err == nil {
		t.Fatal("Put renamed over a directory")
	}
	des := must(os.ReadDir(dir2))(t)
	if len(des) != 1 {
		t.Fatalf("a failed Put left %d entries", len(des))
	}
}

func TestLatestAndOpenAnswerTheNewest(t *testing.T) {
	_, rs := testIdentity(t)
	s := &Store{Dir: t.TempDir(), Keep: 3, Now: clockFrom(testNow)}
	for i := 0; i < 2; i++ {
		if _, _, err := s.Create(rs, []Source{ValueSource("a", "f", []byte("x"))}); err != nil {
			t.Fatal(err)
		}
	}
	e, err := s.Latest()
	if err != nil || e.Name != "trust-backup-20261007T175200Z.tar.age" {
		t.Fatalf("Latest = %+v, %v", e, err)
	}
	if err := os.Chmod(filepath.Join(s.Dir, e.Name), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, _, err := s.Open(e.Name); err == nil {
			t.Fatal("Open succeeded on an unreadable bundle")
		}
	}
	if err := os.Chmod(s.Dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { restoreMode(t, s.Dir) })
	if os.Geteuid() != 0 {
		if _, err := s.Latest(); err == nil {
			t.Fatal("Latest succeeded on an unreadable directory")
		}
	}
}

// The core writes as root to read every key volume, and serves the bundles
// as uid 1000: every file and the directory are handed to the owner given.
func TestCreateHandsEveryFileToItsOwner(t *testing.T) {
	_, rs := testIdentity(t)
	me := &Owner{UID: os.Getuid(), GID: os.Getgid()}
	s := &Store{Dir: filepath.Join(t.TempDir(), "d"), Keep: 2, Now: clockFrom(testNow), Owner: me}
	if _, _, err := s.Create(rs, []Source{ValueSource("a", "f", []byte("x"))}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteStatus(Status{Latest: "x"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(s.Dir); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("dir mode %v, %v; want 0750 for the owner's group", fi.Mode().Perm(), err)
	}
	if os.Geteuid() == 0 {
		return
	}
	// An owner this process may not give files to is a failure, not a
	// bundle the core cannot read.
	other := &Store{Dir: filepath.Join(t.TempDir(), "d"), Keep: 2, Now: clockFrom(testNow), Owner: &Owner{UID: 0, GID: 0}}
	if _, _, err := other.Create(rs, []Source{ValueSource("a", "f", []byte("x"))}); err == nil {
		t.Fatal("Create succeeded handing files to root")
	}
	des := must(os.ReadDir(other.Dir))(t)
	for _, d := range des {
		if strings.HasSuffix(d.Name(), ".tar.age") {
			t.Fatalf("a bundle was left that its reader may not open: %s", d.Name())
		}
	}
	if err := other.WriteStatus(Status{}); err == nil {
		t.Fatal("WriteStatus succeeded handing the file to root")
	}
}

func TestParseOwner(t *testing.T) {
	if o, err := ParseOwner("1000:1001"); err != nil || o.UID != 1000 || o.GID != 1001 {
		t.Fatalf("ParseOwner = %+v, %v", o, err)
	}
	for _, bad := range []string{"", "1000", "a:b", "1000:", "-1:0"} {
		if _, err := ParseOwner(bad); err == nil {
			t.Errorf("ParseOwner(%q) accepted", bad)
		}
	}
}

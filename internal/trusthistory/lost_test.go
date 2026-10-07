// SPDX-License-Identifier: Apache-2.0

package trusthistory

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	akiA = "3A0C7D69AA674E40CDAC318BDE6FA82D98A3E15A"
	akiC = "75D25436DC9703A9109CCD98C15989FB6B4024EC"
)

// A lost root is known by its key id alone: the certificate is gone, which is
// the whole reason it is lost. The id is the Authority Key Identifier its
// certificates carry, normalised to lower case.
func TestALostRootIsRecordedByItsKeyIDAlone(t *testing.T) {
	h := New()
	lost := day1
	added, err := h.RecordLost(akiA, lost, "the trust volumes were recreated")
	if err != nil || !added {
		t.Fatalf("RecordLost = %v, %v", added, err)
	}
	if again, rerr := h.RecordLost("3a0c7d69aa674e40cdac318bde6fa82d98a3e15a", lost, "x"); rerr != nil || again {
		t.Errorf("recording the same lost root twice = %v, %v", again, rerr)
	}
	e, ok := h.LostRoot([]byte{0x3a, 0x0c, 0x7d, 0x69, 0xaa, 0x67, 0x4e, 0x40, 0xcd, 0xac, 0x31, 0x8b,
		0xde, 0x6f, 0xa8, 0x2d, 0x98, 0xa3, 0xe1, 0x5a})
	if !ok || e.Reason == "" || e.LostAt == nil || !e.LostAt.Equal(lost) {
		t.Errorf("LostRoot = %+v, %v", e, ok)
	}
	if _, ok := h.LostRoot([]byte{1, 2, 3}); ok {
		t.Error("LostRoot matched an id it does not hold")
	}
	if _, ok := h.LostRoot(nil); ok {
		t.Error("LostRoot matched a certificate with no Authority Key Identifier")
	}
	// A lost root has no beginning in the record, and does not move it.
	if !h.Began().IsZero() {
		t.Errorf("Began = %s with only a lost root", h.Began())
	}

	path := filepath.Join(t.TempDir(), FileName)
	if err = Save(path, h); err != nil {
		t.Fatalf("Save: %v", err)
	}
	back, err := Load(path)
	if err != nil || len(back.OfKind(KindLostRoot)) != 1 {
		t.Fatalf("Load = %+v, %v", back, err)
	}
	// Its date and reason are as append-only as anything else.
	moved := lost.Add(time.Hour)
	back.Entries[0].LostAt = &moved
	if err := Save(path, back); !errors.Is(err, ErrRewrite) {
		t.Errorf("moving lost_at: %v, want ErrRewrite", err)
	}
}

func TestALostRootEntryIsRefusedWhenMalformed(t *testing.T) {
	h := New()
	for name, c := range map[string]struct {
		id     string
		reason string
		at     time.Time
	}{
		"not hex":   {"zz", "r", day1},
		"too short": {"3a0c", "r", day1},
		"no reason": {akiA, "", day1},
		"no date":   {akiA, "r", time.Time{}},
	} {
		if _, err := h.RecordLost(c.id, c.at, c.reason); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	bad := []string{
		`{"version":1,"entries":[{"kind":"lost_root","key_id":"3a0c7d69aa674e40cdac318bde6fa82d98a3e15a","public_pem":"x","first_used":"0001-01-01T00:00:00Z","lost_at":"2026-09-16T00:00:00Z","reason":"r"}]}`,
		`{"version":1,"entries":[{"kind":"fulcio_root","key_id":"aa","public_pem":"","first_used":"2026-09-16T00:00:00Z","lost_at":"2026-09-16T00:00:00Z"}]}`,
	}
	for _, raw := range bad {
		if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%s) = %v, want ErrInvalid", raw, err)
		}
	}
}

// The operator's seed: imported once, idempotent, strict.
func TestTheLostRootsSeedIsImported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LostRootsFileName)
	if _, err := LoadLostRoots(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an absent seed = %v, want os.ErrNotExist", err)
	}
	body := `{"version":1,"lost_roots":[
	 {"key_id":"` + akiA + `","lost_at":"2026-09-16T00:00:00Z","reason":"used until 2026-09-16"},
	 {"key_id":"` + akiC + `","lost_at":"2026-09-16T23:59:59Z","reason":"used on 2026-09-16 only"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	seed, err := LoadLostRoots(path)
	if err != nil || len(seed) != 2 {
		t.Fatalf("LoadLostRoots = %+v, %v", seed, err)
	}
	for _, raw := range []string{"{", `{"version":2,"lost_roots":[]}`, `{"version":1,"lost_roots":[],"x":1}`, `{"version":1,"lost_roots":[]} {}`} {
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadLostRoots(path); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("LoadLostRoots(%s) = %v", raw, err)
		}
	}
}

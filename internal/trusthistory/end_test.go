// SPDX-License-Identifier: Apache-2.0

package trusthistory

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A rotation ends the outgoing root (#533): retired when it simply stops
// issuing, revoked when its key may have been exposed. End is the one way the
// rotation script sets either, so its refusals are what keep a mistyped
// rotation from writing a date the append-only file can never take back.

func endFixture(t *testing.T) (*History, string) {
	t.Helper()
	h := New()
	root := caPEM(t, "A", day1, ten)
	if _, err := h.Record(KindFulcioRoot, root, day1); err != nil {
		t.Fatal(err)
	}
	return h, spkiID(t, root)
}

func TestEndRetiresARootAtTheGivenTimeWithItsReason(t *testing.T) {
	h, id := endFixture(t)
	at := day1.AddDate(0, 3, 0)
	if err := h.End(KindFulcioRoot, id, EndRetire, at, "planned rotation"); err != nil {
		t.Fatal(err)
	}
	e, _ := h.Lookup(KindFulcioRoot, id)
	if e.RetiredAt == nil || !e.RetiredAt.Equal(at) || e.RetiredReason != "planned rotation" {
		t.Fatalf("retired_at %v reason %q; want %v, planned rotation", e.RetiredAt, e.RetiredReason, at)
	}
	if e.RevokedAt != nil {
		t.Fatalf("a retirement set revoked_at %v", e.RevokedAt)
	}
	// What the verifier then does with it: before stays, after is refused.
	if err := e.AcceptsAt(at.Add(-time.Minute), 0); err != nil {
		t.Errorf("an entry logged before the retirement: %v", err)
	}
	if err := e.AcceptsAt(at.Add(time.Minute), 0); err == nil {
		t.Error("an entry logged after the retirement was accepted")
	}
}

func TestEndRevokesARootAndRetiresItTooWithNoSkew(t *testing.T) {
	h, id := endFixture(t)
	at := day1.AddDate(0, 3, 0)
	if err := h.End(KindFulcioRoot, id, EndRevoke, at, "key may be exposed"); err != nil {
		t.Fatal(err)
	}
	e, _ := h.Lookup(KindFulcioRoot, id)
	if e.RevokedAt == nil || !e.RevokedAt.Equal(at) {
		t.Fatalf("revoked_at %v, want %v", e.RevokedAt, at)
	}
	if e.RetiredAt == nil || !e.RetiredAt.Equal(at) || e.RetiredReason != "key may be exposed" {
		t.Fatalf("a revoked root must also stop issuing: retired_at %v reason %q", e.RetiredAt, e.RetiredReason)
	}
	if err := e.AcceptsAt(at.Add(time.Second), time.Hour); err == nil {
		t.Error("a revoked root accepted an entry inside the skew bound")
	}
}

// A root already retired may still be revoked later, when an exposure is
// found after the fact. Its retirement and reason stay as they were.
func TestEndRevokesARootThatWasAlreadyRetired(t *testing.T) {
	h, id := endFixture(t)
	retired := day1.AddDate(0, 3, 0)
	if err := h.End(KindFulcioRoot, id, EndRetire, retired, "planned rotation"); err != nil {
		t.Fatal(err)
	}
	revoked := retired.AddDate(0, 1, 0)
	if err := h.End(KindFulcioRoot, id, EndRevoke, revoked, "found exposed"); err != nil {
		t.Fatal(err)
	}
	e, _ := h.Lookup(KindFulcioRoot, id)
	if !e.RetiredAt.Equal(retired) || e.RetiredReason != "planned rotation" || !e.RevokedAt.Equal(revoked) {
		t.Fatalf("got retired %v (%q) revoked %v", e.RetiredAt, e.RetiredReason, e.RevokedAt)
	}
}

func TestEndRefusesWhatItCannotDoSafely(t *testing.T) {
	at := day1.AddDate(0, 3, 0)
	const lostID = "abcdef0123456789abcdef0123456789abcdef01"
	cases := []struct {
		name string
		do   func(h *History, id string) error
		want error
	}{
		{"an unknown mode", func(h *History, id string) error {
			return h.End(KindFulcioRoot, id, EndMode("forget"), at, "r")
		}, ErrInvalid},
		{"no reason", func(h *History, id string) error {
			return h.End(KindFulcioRoot, id, EndRetire, at, "  ")
		}, ErrInvalid},
		{"no time", func(h *History, id string) error {
			return h.End(KindFulcioRoot, id, EndRetire, time.Time{}, "r")
		}, ErrInvalid},
		{"a lost root", func(h *History, _ string) error {
			if _, err := h.RecordLost(lostID, day1, "gone"); err != nil {
				return err
			}
			return h.End(KindLostRoot, lostID, EndRetire, at, "r")
		}, ErrInvalid},
		{"an entry the history does not hold", func(h *History, _ string) error {
			return h.End(KindFulcioRoot, "00", EndRetire, at, "r")
		}, ErrNotFound},
		{"a date before the root was first used", func(h *History, id string) error {
			return h.End(KindFulcioRoot, id, EndRetire, day1.Add(-time.Hour), "r")
		}, ErrInvalid},
		{"retiring twice", func(h *History, id string) error {
			if err := h.End(KindFulcioRoot, id, EndRetire, at, "r"); err != nil {
				return err
			}
			return h.End(KindFulcioRoot, id, EndRetire, at.Add(time.Hour), "r")
		}, ErrRewrite},
		{"revoking twice", func(h *History, id string) error {
			if err := h.End(KindFulcioRoot, id, EndRevoke, at, "r"); err != nil {
				return err
			}
			return h.End(KindFulcioRoot, id, EndRevoke, at.Add(time.Hour), "r")
		}, ErrRewrite},
		{"retiring a revoked root", func(h *History, id string) error {
			if err := h.End(KindFulcioRoot, id, EndRevoke, at, "r"); err != nil {
				return err
			}
			return h.End(KindFulcioRoot, id, EndRetire, at.Add(time.Hour), "r")
		}, ErrRewrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, id := endFixture(t)
			if err := tc.do(h, id); !errors.Is(err, tc.want) {
				t.Fatalf("End = %v, want %v", err, tc.want)
			}
		})
	}
}

// A refused End leaves the entry exactly as it was, so a second attempt sees
// the same history the first one did.
func TestARefusedEndChangesNothing(t *testing.T) {
	h, id := endFixture(t)
	at := day1.AddDate(0, 3, 0)
	if err := h.End(KindFulcioRoot, id, EndRetire, at, "first"); err != nil {
		t.Fatal(err)
	}
	if err := h.End(KindFulcioRoot, id, EndRetire, at.Add(time.Hour), "second"); !errors.Is(err, ErrRewrite) {
		t.Fatalf("End = %v, want ErrRewrite", err)
	}
	e, _ := h.Lookup(KindFulcioRoot, id)
	if !e.RetiredAt.Equal(at) || e.RetiredReason != "first" {
		t.Fatalf("after a refused End: retired %v (%q)", e.RetiredAt, e.RetiredReason)
	}
}

// The reason a root was retired is part of the record. Save allows it to be
// written where it was empty, and never changed after.
func TestSaveRefusesToChangeARetirementReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	h, id := endFixture(t)
	if err := h.End(KindFulcioRoot, id, EndRetire, day1.AddDate(0, 3, 0), "planned rotation"); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, h); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	c.Entries[0].RetiredReason = "something else"
	if err := Save(path, c); !errors.Is(err, ErrRewrite) {
		t.Fatalf("Save = %v, want ErrRewrite", err)
	}
	c.Entries[0].RetiredReason = ""
	if err := Save(path, c); !errors.Is(err, ErrRewrite) {
		t.Fatalf("removing the reason: Save = %v, want ErrRewrite", err)
	}
}

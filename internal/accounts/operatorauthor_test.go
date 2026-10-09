// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"testing"
)

// GH-008 (PROPOSED for doc 07) — an installation's operator author is pinned
// on first use (#545).
//
// The operator's own machine reports who it pushes as, read from git, so no
// one types it. The first report pins it; the same report again changes
// nothing; a different one is refused until an operator resets the pin on
// the core. Only a GitHub noreply address is pinned automatically: it is the
// address GitHub attaches to the account, and the one a deploy host matches.
func newInstallation(t *testing.T) (*Store, string) {
	t.Helper()
	_, s, a := setup(t)
	tok, meta, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"github.com/acme/app"}})
	if err != nil {
		t.Fatal(err)
	}
	en, err := s.ConsumeEnrolmentToken(tctx(t), tok)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := s.CreateInstallation(tctx(t), InstallationParams{
		AccountID: en.AccountID, CreatedBy: en.CreatedBy, Name: "laptop", Kind: en.Kind, Repos: en.Repos, TokenID: meta.TokenID})
	if err != nil {
		t.Fatal(err)
	}
	return s, inst.ID
}

const (
	fixtureName  = "alpha"
	fixtureEmail = "12345+alpha@users.noreply.github.com"
)

func TestGH008TheFirstReportPinsTheOperatorAuthor(t *testing.T) {
	s, id := newInstallation(t)
	if _, _, ok, err := s.OperatorAuthor(tctx(t), id); err != nil || ok {
		t.Fatalf("a new installation has a pinned author (ok=%v, err=%v)", ok, err)
	}
	if _, err := s.PinOperatorAuthor(tctx(t), id, fixtureName, fixtureEmail); err != nil {
		t.Fatalf("first report: %v", err)
	}
	name, email, ok, err := s.OperatorAuthor(tctx(t), id)
	if err != nil || !ok || name != fixtureName || email != fixtureEmail {
		t.Fatalf("OperatorAuthor = %q %q %v %v", name, email, ok, err)
	}
	if _, err := s.PinOperatorAuthor(tctx(t), id, fixtureName, fixtureEmail); err != nil {
		t.Fatalf("the same report again: %v", err)
	}
}

func TestGH008ADifferentReportIsRefusedUntilReset(t *testing.T) {
	s, id := newInstallation(t)
	if _, err := s.PinOperatorAuthor(tctx(t), id, fixtureName, fixtureEmail); err != nil {
		t.Fatal(err)
	}
	for _, other := range [][2]string{
		{"beta", "67890+beta@users.noreply.github.com"},
		{"alpha", "99999+alpha@users.noreply.github.com"},
	} {
		if _, err := s.PinOperatorAuthor(tctx(t), id, other[0], other[1]); !errors.Is(err, ErrAuthorPinned) {
			t.Errorf("a different pair %q <%s>: err = %v, want ErrAuthorPinned", other[0], other[1], err)
		}
	}
	if err := s.ResetOperatorAuthor(tctx(t), id, ""); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, err := s.PinOperatorAuthor(tctx(t), id, "beta", "67890+beta@users.noreply.github.com"); err != nil {
		t.Fatalf("a report after the reset: %v", err)
	}
}

func TestGH008OnlyANoreplyAddressIsPinned(t *testing.T) {
	s, id := newInstallation(t)
	for _, email := range []string{"alpha@example.com", "agent@innsegl.invalid", "alpha@users.noreply.github.com", ""} {
		if _, err := s.PinOperatorAuthor(tctx(t), id, fixtureName, email); !errors.Is(err, ErrInvalid) {
			t.Errorf("PinOperatorAuthor(%q): err = %v, want ErrInvalid", email, err)
		}
	}
	// The name is the address's login, never a person's name.
	for _, name := range []string{"", "Personal Fixture Name", "beta"} {
		if _, err := s.PinOperatorAuthor(tctx(t), id, name, fixtureEmail); !errors.Is(err, ErrInvalid) {
			t.Errorf("name %q, not the address's login: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, _, ok, err := s.OperatorAuthor(tctx(t), id); err != nil || ok {
		t.Fatalf("a refused report pinned something (ok=%v, err=%v)", ok, err)
	}
}

func TestGH008AnUnknownOrRevokedInstallationPinsNothing(t *testing.T) {
	s, id := newInstallation(t)
	if _, err := s.PinOperatorAuthor(tctx(t), "0123456789abcdef0123456789abcdef", fixtureName, fixtureEmail); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown installation: err = %v, want ErrNotFound", err)
	}
	if err := s.SetInstallationStatus(tctx(t), id, StatusRevoked, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PinOperatorAuthor(tctx(t), id, fixtureName, fixtureEmail); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked installation: err = %v, want ErrRevoked", err)
	}
}

// GH-011 (PROPOSED for doc 07) — a report says whether it pinned the pair
// now or found that same pair already pinned, so the operator's machine can
// print which (#545). A different pair is still ErrAuthorPinned.
func TestGH011APinSaysWhetherItIsNewOrAlreadyHeld(t *testing.T) {
	s, id := newInstallation(t)
	created, err := s.PinOperatorAuthor(tctx(t), id, fixtureName, fixtureEmail)
	if err != nil || !created {
		t.Fatalf("first report: created=%v err=%v, want created", created, err)
	}
	created, err = s.PinOperatorAuthor(tctx(t), id, fixtureName, fixtureEmail)
	if err != nil || created {
		t.Fatalf("the same report again: created=%v err=%v, want already held", created, err)
	}
	created, err = s.PinOperatorAuthor(tctx(t), id, "beta", "67890+beta@users.noreply.github.com")
	if !errors.Is(err, ErrAuthorPinned) || created {
		t.Fatalf("a different report: created=%v err=%v, want ErrAuthorPinned", created, err)
	}
}

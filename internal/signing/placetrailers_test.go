// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"strings"
	"testing"
)

// TestPlaceTrailersNeedsNoAuthor pins the whole reason this function exists:
// unlike CommitMessage, it renders with no AuthorEmail and no AuthorPolicy at
// all — ADR-0059 decision 2's caller (prepare-commit-msg) has no author to
// give it, because the commit object does not exist yet.
func TestPlaceTrailersNeedsNoAuthor(t *testing.T) {
	got, err := PlaceTrailers(refClaim, "subject\n\nbody.\n")
	if err != nil {
		t.Fatalf("PlaceTrailers: %v", err)
	}
	want := "subject\n\nbody.\n\nAgent-Identity: " + refClaim.Identity + "\n" +
		"Agent-Run: " + refClaim.Run + "\n" +
		"Agent-Task: " + refClaim.Task + "\n"
	if got != want {
		t.Errorf("PlaceTrailers =\n%q\nwant\n%q", got, want)
	}
}

// TestPlaceTrailersAgreesWithCommitMessageOnPlacement pins that PlaceTrailers
// is not a second implementation: for every (message, claim) CommitMessage
// admits, PlaceTrailers produces byte-identical output once the author gate
// is subtracted, because both call the same unexported prepareMessage.
func TestPlaceTrailersAgreesWithCommitMessageOnPlacement(t *testing.T) {
	cases := []string{
		"subject\n\nbody.\n",
		"subject",
		"subject\n\nbody.\n\nRefs: R\n",
		"subject\n\nbody.\n\nSigned-off-by: dev <dev@example.com>\n",
	}
	for _, in := range cases {
		want, err := CommitMessage(refPolicy, Commit{Message: in, AuthorEmail: operator, Claim: refClaim})
		if err != nil {
			t.Fatalf("CommitMessage(%q): %v", in, err)
		}
		got, err := PlaceTrailers(refClaim, in)
		if err != nil {
			t.Fatalf("PlaceTrailers(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("PlaceTrailers(%q) = %q, want %q (CommitMessage's own answer)", in, got, want)
		}
	}
}

// TestPlaceTrailersRefusesWhatCommitMessageRefuses pins that the placement
// refusals — the dangerous, git-pinned half of ADR-0028 — are reused rather
// than reimplemented: every shape CommitMessage refuses on grounds other than
// the author, PlaceTrailers refuses identically.
func TestPlaceTrailersRefusesWhatCommitMessageRefuses(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrMessage},
		{"a bare --- divider", "subject\n\nalpha\n---\nomega\n", ErrMessage},
		{"last paragraph mixes trailers and prose", "subject\n\nRefs: R\nprose line\n", ErrMessage},
		{"the message already claims Agent-Run", "subject\n\nbody.\n\nAgent-Run: run-9\n", ErrTrailerAlreadyPresent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlaceTrailers(refClaim, tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("PlaceTrailers(%q) error = %v, want %v", tc.in, err, tc.want)
			}
			if got != "" {
				t.Errorf("PlaceTrailers refused but returned %q", got)
			}
		})
	}
}

// TestPlaceTrailersRefusesAnIncoherentClaim pins that Claim.Trailers' own
// gate (ADR-0018 §6 consistency) is still reached with no author involved.
func TestPlaceTrailersRefusesAnIncoherentClaim(t *testing.T) {
	bad := Claim{Identity: refClaim.Identity, Run: "run-43", Task: refClaim.Task}
	got, err := PlaceTrailers(bad, "subject\n\nbody.\n")
	if !errors.Is(err, ErrClaim) {
		t.Fatalf("PlaceTrailers error = %v, want ErrClaim", err)
	}
	if got != "" {
		t.Errorf("PlaceTrailers refused but returned %q", got)
	}
}

// TestPlaceTrailersRendersAnAuthorNothingWouldAdmit is the point of this
// file: an author policy that admits NOTHING (the zero value; see
// AuthorPolicy's own comment) would refuse every commit through
// CommitMessage, and PlaceTrailers still succeeds, because it never asks.
func TestPlaceTrailersRendersAnAuthorNothingWouldAdmit(t *testing.T) {
	// Sanity: the zero-value policy really does refuse this author.
	if _, err := CommitMessage(AuthorPolicy{}, Commit{
		Message: "subject\n\nbody.\n", AuthorEmail: operator, Claim: refClaim,
	}); err == nil {
		t.Fatal("test setup: the zero-value AuthorPolicy admitted an author; it should admit none")
	}
	got, err := PlaceTrailers(refClaim, "subject\n\nbody.\n")
	if err != nil {
		t.Fatalf("PlaceTrailers: %v", err)
	}
	if !strings.HasSuffix(got, "Agent-Task: "+refClaim.Task+"\n") {
		t.Errorf("PlaceTrailers did not place the trailers: %q", got)
	}
}

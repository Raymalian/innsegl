// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"strings"
	"testing"
)

// SIG-012 — the display name beside an admitted address.
//
// # The id, and why it is not SIG-009
//
// RM-159 asks for SIG-009. SIG-009, SIG-010 and SIG-011 were already taken, in
// code, by internal/signing/sigstoreretry_test.go — three uncatalogued cases
// about Rekor retry jitter. This is the fourth such collision this project has
// found (SPI-008, LED-012, GH-004 were the others), and the reason is always
// the same: an id is claimed from doc 07, which does not know about a test that
// never got a catalog row. scripts/test-ids.sh reports exactly this. So the id
// here is the next one free in BOTH places.
//
// # What this pins
//
// The I6 author gate admitted a commit by ADDRESS ALONE. AuthorPolicy.Operators
// was a list of addresses and CheckAuthor took an email; the display name beside
// the address is free text in the commit object and was compared to nothing.
//
// Measured on this repository on 2026-09-18: an operator's real name is the
// author and the committer of four merge commits on origin/main. The CI gate
// was green throughout, because the address was on the list. Removing them now
// would re-hash 58 commits and orphan 33 signatures — the record is append-only
// on purpose, so this is a hole that can only be prevented, never repaired.
//
// So an Operator is now a PAIR. The address says which entry applies; the name
// pinned to it says which display name that address may carry.
//
// # The names in here are invented
//
// No fixture below is a real person. That is also the proof the gate works by
// allowlist rather than by having been told about anybody: it refuses "Someone
// Else" without ever having heard of them, and it would refuse a real name the
// same way.

const (
	pinnedAddress = "12345+alpha@users.noreply.github.com"
	pinnedName    = "Fixture Alpha"
	otherAddress  = "67890+beta@users.noreply.github.com"
	otherName     = "Fixture Beta"
)

// pinnedPolicy is two listed operators, each with its own pinned name, plus the
// unlinked category and one installed bot. Every branch of CheckIdentity is
// reachable from it.
var pinnedPolicy = AuthorPolicy{
	Operators: []Operator{
		{Address: pinnedAddress, Name: pinnedName},
		{Address: otherAddress, Name: otherName},
	},
	AllowUnlinked: true,
	InstalledBots: []string{"49699333+dependabot[bot]@users.noreply.github.com"},
}

// TestSIG012APinnedNameIsRequiredOnAListedOperatorsAddress is the case the leak
// would have failed: the address is admitted, the name is not the pinned one.
func TestSIG012APinnedNameIsRequiredOnAListedOperatorsAddress(t *testing.T) {
	if err := pinnedPolicy.CheckIdentity(pinnedName, pinnedAddress); err != nil {
		t.Fatalf("CheckIdentity(<pinned name>, %q) = %v, want admitted", pinnedAddress, err)
	}

	err := pinnedPolicy.CheckIdentity("Someone Else", pinnedAddress)
	if err == nil {
		t.Fatal("a display name that is not the one pinned to this address was ADMITTED; " +
			"this is the leak RM-159 exists to stop")
	}
	if !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Errorf("error = %v, want it to wrap ErrAuthorNotAdmitted so every existing "+
			"caller classifies it the way it classifies an address refusal", err)
	}
	if !errors.Is(err, ErrNameNotPinned) {
		t.Errorf("error = %v, want it to wrap ErrNameNotPinned", err)
	}
}

// TestSIG012TheRefusalDoesNotEchoTheName is the property that makes this safe
// to run in CI at all.
//
// The refusal lands in a log of a PUBLIC repository. Printing the name there
// publishes exactly what the gate just stopped — the gate would become the leak.
// So the message says the role, the address (which is a listed operator's, and
// already in the tracked policy) and nothing else.
func TestSIG012TheRefusalDoesNotEchoTheName(t *testing.T) {
	for _, name := range []string{"Someone Else", "A Real Person", otherName} {
		err := pinnedPolicy.CheckIdentity(name, pinnedAddress)
		if err == nil {
			t.Fatalf("CheckIdentity(%q, %q) was admitted", name, pinnedAddress)
		}
		if strings.Contains(err.Error(), name) {
			t.Errorf("the refusal for %q PUBLISHED the name it refused: %q", name, err.Error())
		}
	}

	// And the same for an operator with nothing pinned to it: the refusal is
	// about the configuration, not about the person who tripped over it.
	unpinned := AuthorPolicy{Operators: []Operator{{Address: pinnedAddress}}}
	err := unpinned.CheckIdentity("Someone Else", pinnedAddress)
	if err == nil {
		t.Fatal("a listed operator with NO pinned name admitted a display name; a gate " +
			"whose configuration is missing must refuse, not pass")
	}
	if strings.Contains(err.Error(), "Someone Else") {
		t.Errorf("the refusal published the name it refused: %q", err.Error())
	}
}

// TestSIG012TheNameIsCheckedExactly pins the comparison. A display name is not
// a domain: it is bytes a person typed, and case, spacing and Unicode are all
// part of the identity GitHub renders. Folding any of it would admit a name
// that reads as somebody else's.
func TestSIG012TheNameIsCheckedExactly(t *testing.T) {
	for _, near := range []string{
		"fixture alpha",
		"FIXTURE ALPHA",
		"Fixture  Alpha",
		" Fixture Alpha",
		"Fixture Alpha ",
		"Fixture Alphа", // Cyrillic а
		"",
	} {
		if err := pinnedPolicy.CheckIdentity(near, pinnedAddress); err == nil {
			t.Errorf("CheckIdentity(%q, %q) was admitted; only the exact pinned name is",
				near, pinnedAddress)
		}
	}
}

// TestSIG012APinnedNameIsPinnedToOneAddress: the name admitted on one listed
// operator's address is not admitted on another's. Otherwise two operators
// would be one allowlist and the pin would say nothing.
func TestSIG012APinnedNameIsPinnedToOneAddress(t *testing.T) {
	if err := pinnedPolicy.CheckIdentity(pinnedName, otherAddress); err == nil {
		t.Errorf("a name pinned to %q was admitted on %q", pinnedAddress, otherAddress)
	}
	if err := pinnedPolicy.CheckIdentity(otherName, otherAddress); err != nil {
		t.Errorf("the other operator's own pinned name was refused: %v", err)
	}
}

// TestSIG012AnAddressTheGateRefusesIsStillRefused: the name half never widens
// the address half. CheckIdentity asks CheckAuthor first and stops there.
func TestSIG012AnAddressTheGateRefusesIsStillRefused(t *testing.T) {
	for _, addr := range []string{
		"9999+stranger@users.noreply.github.com",
		"agent@innsegl.dev",
		"noreply@github.com",
		"not-an-address",
		"",
	} {
		if err := pinnedPolicy.CheckIdentity(pinnedName, addr); err == nil {
			t.Errorf("CheckIdentity(<pinned name>, %q) was admitted", addr)
		}
	}
	if err := (AuthorPolicy{}).CheckIdentity(pinnedName, pinnedAddress); err == nil {
		t.Error("the zero-value policy admitted an identity; its whole point is that it " +
			"admits nothing (ADR-0028 §7)")
	}

	// A permitted name that pins no address states nothing about who may
	// author a commit, so the address half steps over it rather than treating
	// it as a listed operator. It is in the same list only so that one parser
	// and one file serve both halves of the gate.
	nameOnly := AuthorPolicy{Operators: []Operator{{Name: "Innsegl"}}}
	if err := nameOnly.CheckIdentity("Innsegl", pinnedAddress); err == nil {
		t.Error("a policy holding only a bare display name admitted an address; a name " +
			"with no address admits no address")
	}
	if err := nameOnly.CheckAuthor(pinnedAddress); err == nil {
		t.Error("CheckAuthor admitted an address on the strength of a bare display name")
	}
}

// TestSIG012AnUnpinnableAddressCarriesNoPin.
//
// The pin exists because a listed operator's address CAN be attached to a
// GitHub account — that is what made the leak possible. Neither of the other
// two admitted categories can be:
//
//   - AllowUnlinked admits only the reserved, undelegatable names of RFC 2606
//     and RFC 6761. No mailbox in them can receive a verification message, so
//     no account can hold one, so no display name beside one can become a
//     contributor. The agent local part is minted per run and cannot be
//     enumerated in a policy in the first place.
//   - An installed bot is admitted by exact address and its display name is
//     GitHub's, not a person's.
//
// Refusing a name on those would refuse every agent commit this deployment
// makes, for a risk that does not exist there. It is scripts/no-personal-
// identity.sh — which runs on a developer's machine, where the name is free
// text in a git config — that holds the stricter line on those addresses.
func TestSIG012AnUnpinnableAddressCarriesNoPin(t *testing.T) {
	for _, addr := range []string{
		"agent@innsegl.invalid",
		"run-7f3a@innsegl.invalid",
		"agent@example.com",
		"49699333+dependabot[bot]@users.noreply.github.com",
	} {
		if err := pinnedPolicy.CheckIdentity("Innsegl", addr); err != nil {
			t.Errorf("CheckIdentity(%q, %q) = %v, want admitted", "Innsegl", addr, err)
		}
	}
}

// TestSIG012CheckAuthorStillAnswersTheAddressQuestionAlone.
//
// CheckAuthor is what sign_commit and the CI gate call, and both hold only an
// address: a commit record read back with `git log --format=%ae` has no name in
// it, and internal/mcp is not this issue's to change. Its answer must therefore
// be exactly what it was — the pin is an ADDITION reached through CheckIdentity,
// never a silent narrowing of the call everything already makes.
func TestSIG012CheckAuthorStillAnswersTheAddressQuestionAlone(t *testing.T) {
	if err := pinnedPolicy.CheckAuthor(pinnedAddress); err != nil {
		t.Errorf("CheckAuthor(%q) = %v, want admitted", pinnedAddress, err)
	}
	if err := pinnedPolicy.CheckAuthor("agent@innsegl.invalid"); err != nil {
		t.Errorf("CheckAuthor of an unlinked address = %v, want admitted", err)
	}
	if err := pinnedPolicy.CheckAuthor("9999+stranger@users.noreply.github.com"); err == nil {
		t.Error("CheckAuthor admitted an address that is not a listed operator")
	}
}

// TestSIG012AnUnreadableOperatorEntryAdmitsNothing keeps ADR-0028's fail-closed
// reading of a malformed policy, through both entry points. A typo in a policy
// with no cryptographic backstop must be loud.
func TestSIG012AnUnreadableOperatorEntryAdmitsNothing(t *testing.T) {
	broken := AuthorPolicy{
		Operators:     []Operator{{Address: "not-an-address", Name: "Fixture Alpha"}},
		AllowUnlinked: true,
	}
	if err := broken.CheckAuthor("agent@innsegl.invalid"); !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Errorf("CheckAuthor = %v, want ErrAuthorNotAdmitted", err)
	}
	if err := broken.CheckIdentity("Innsegl", "agent@innsegl.invalid"); !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Errorf("CheckIdentity = %v, want ErrAuthorNotAdmitted", err)
	}

	// The same for the installed-bot list, which had the same rule written and
	// no case driving it. A bot entry is an exact address or it is a typo, and
	// a typo must not quietly shrink the list to the entries that happened to
	// parse.
	badBot := AuthorPolicy{InstalledBots: []string{"not-an-address"}, AllowUnlinked: true}
	if err := badBot.CheckAuthor("agent@innsegl.invalid"); !errors.Is(err, ErrAuthorNotAdmitted) {
		t.Errorf("CheckAuthor with an unreadable installed bot = %v, want ErrAuthorNotAdmitted", err)
	}
}

// TestSIG012ParseOperatorReadsGitsOwnIdentitySyntax.
//
// One parser, used by every source that can state a pinned pair: the
// -sign-author-operators flag, $INNSEGL_SIGN_AUTHOR_OPERATORS, and the
// untracked permitted-name list scripts/no-personal-identity.sh reads. The
// syntax is `Name <address>` because that is what git itself writes in a commit
// object's author line, so an operator configuring this is copying a string
// they can read straight out of `git log`.
func TestSIG012ParseOperatorReadsGitsOwnIdentitySyntax(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Operator
	}{
		{"Fixture Alpha <12345+alpha@users.noreply.github.com>", Operator{pinnedAddress, pinnedName}},
		{"  Fixture Alpha   <12345+alpha@users.noreply.github.com>  ", Operator{pinnedAddress, pinnedName}},
		// A bare address is an operator with nothing pinned. It is the form
		// every existing configuration uses and it still parses — but
		// CheckIdentity refuses it, so it is a loud half-configuration rather
		// than a silent pass.
		{"12345+alpha@users.noreply.github.com", Operator{Address: pinnedAddress}},
		// A bare name pins nothing and names no address. It is what the
		// permitted-name list holds for the agent identities, whose local part
		// is minted per run; CheckAuthor skips it.
		{"Innsegl", Operator{Name: "Innsegl"}},
		{"dependabot[bot]", Operator{Name: "dependabot[bot]"}},
	} {
		got, err := ParseOperator(tc.in)
		if err != nil {
			t.Errorf("ParseOperator(%q) = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseOperator(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{
		"<12345+alpha@users.noreply.github.com>", // an address with no name pins nothing
		"Fixture Alpha a@b>",                     // closes what it never opened
		"Fixture Alpha <>",
		"Fixture Alpha <a@b> trailing",
		"Fixture <a@b> <c@d>",
		"",
		"   ",
	} {
		if got, err := ParseOperator(bad); err == nil {
			t.Errorf("ParseOperator(%q) = %+v, want an error", bad, got)
		}
	}
}

// TestSIG012ParseOperatorsIgnoresCommentsAndBlanks. The permitted-name list is
// edited by a human and carries its own reasoning; a `#` line is a note, not an
// identity.
func TestSIG012ParseOperatorsIgnoresCommentsAndBlanks(t *testing.T) {
	got, err := ParseOperators([]string{
		"# Display names this repository permits.",
		"",
		"   ",
		"Innsegl",
		"Fixture Alpha <12345+alpha@users.noreply.github.com>   # the operator",
		"#Innsegl Demo Agent",
	})
	if err != nil {
		t.Fatalf("ParseOperators: %v", err)
	}
	want := []Operator{{Name: "Innsegl"}, {Address: pinnedAddress, Name: pinnedName}}
	if len(got) != len(want) {
		t.Fatalf("ParseOperators returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	if _, err := ParseOperators([]string{"Innsegl", "Fixture Alpha <>"}); err == nil {
		t.Error("ParseOperators accepted an unreadable entry; a policy that cannot be " +
			"read must admit nothing rather than silently narrow")
	}
}

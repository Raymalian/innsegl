// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"fmt"
	"strings"
)

// The display-name half of the I6 author gate.
//
// # Why an address was not enough
//
// A commit object's author line is `Name <address>`. The gate read the address
// and nothing else: AuthorPolicy.Operators was a list of addresses, CheckAuthor
// took an email, and the display name beside it was free text compared to
// nothing.
//
// Measured on this repository on 2026-09-18: an operator's real name is the
// author AND the committer of four merge commits on origin/main. The CI gate
// was green throughout, because the address was on the list. Removing those
// commits now would re-hash 58 commits and orphan 33 signatures whose Rekor
// entries are bound to the SHAs the rewrite would destroy. The record is
// append-only on purpose, so a name that reaches it is published permanently.
// This is a hole that can be prevented and never repaired.
//
// # One rule, one place
//
// This file owns the rule. scripts/no-personal-identity.sh is the same rule at
// the one moment Go cannot reach — before the commit object exists, on a
// developer's machine, where the display name is free text in a git config. It
// cannot call into this package: it is POSIX sh precisely so it runs wherever
// git runs, including an Alpine container with no bash and no Go toolchain.
//
// So it CONSUMES this rule rather than restating it. The syntax a pinned pair
// is written in (`Name <address>`), the file it is written in, and the
// fail-closed reading of a missing file are defined here and parsed by
// ParseOperator; doc 07 GH-005 drives the same identities through both halves
// and requires the same verdict, so the two cannot drift apart.
//
// # Where the names live
//
// NOT IN A TRACKED FILE, and that is not a preference. An allowlist is safe to
// publish as a MECHANISM; a person's display name is not, whatever else is true
// about it. A deployment states its pinned pairs through configuration that
// never enters the repository:
//
//	-sign-author-operators, or $INNSEGL_SIGN_AUTHOR_OPERATORS
//
// and this repository's own commit-time gate reads them from an untracked file:
//
//	$INNSEGL_ALLOWED_NAMES_FILE, or .innsegl/allowed-names
//
// A policy with no pinned name admits no identity. Losing the configuration is
// exactly when a gate is most trusted and least able to judge.

// Operator is one identity this deployment attributes commits to.
//
// Both fields are optional, and the three combinations mean three things:
//
//	Address and Name   a PINNED PAIR. That address admits that display name
//	                   and no other; that display name is admitted on that
//	                   address and no other.
//	Address only       an operator with nothing pinned. CheckAuthor admits the
//	                   address, exactly as it always has; CheckIdentity REFUSES
//	                   it, because a pin that was never stated cannot be
//	                   satisfied. A half-configured policy fails loudly rather
//	                   than quietly reverting to the hole.
//	Name only          a display name that pins no address — what the agent and
//	                   bot identities need, since an agent's local part is
//	                   minted per run and cannot be enumerated. It states
//	                   nothing about who may author a commit, so the address
//	                   half skips it; it is here so that one parser and one
//	                   file serve both halves of the gate.
type Operator struct {
	// Address is the exact commit author address, compared with a
	// case-sensitive local part and a case-folded domain — the comparison
	// CheckAuthor has always used.
	Address string

	// Name is the display name pinned to Address, compared BYTE-EXACTLY. A
	// display name is not a domain: it is what a person typed, and case,
	// spacing and Unicode are all part of the identity GitHub renders beside
	// the commit. Folding any of it would admit a name that reads as somebody
	// else's.
	Name string
}

// ErrNameNotPinned is the display-name half of the I6 gate refusing. It always
// accompanies ErrAuthorNotAdmitted, so a caller that classifies author
// refusals keeps classifying this one — the address was admitted and the
// identity was not, which is the same decision with a finer reason.
var ErrNameNotPinned = errors.New(
	"commit author display name is not the name pinned to this address (I6)")

// CheckIdentity reports whether the policy admits the pair (name, email) as a
// commit author, and refuses with ErrAuthorNotAdmitted if it does not.
//
// It is the whole of the gate: the address half first — the same CheckAuthor
// every existing caller makes — then the name.
//
// # The refusal never echoes the name
//
// This runs in CI, and a CI log is as public as the repository it runs on.
// Printing the offending display name there would publish exactly what the gate
// stopped, turning the gate into the leak. The message says the role and the
// address; the address is a listed operator's and is already in the tracked
// policy, so it publishes nothing new.
//
// # Which addresses carry a pin
//
// Only a listed operator's. The pin exists because such an address CAN be
// attached to a GitHub account — that is what made the leak possible. The other
// two admitted categories cannot be:
//
//   - AllowUnlinked admits only the reserved, undelegatable names of RFC 2606
//     and RFC 6761. No mailbox in them can receive a verification message, so
//     no account can hold one, so no display name beside one can become a
//     contributor.
//   - An installed bot is admitted by exact address and its display name is
//     GitHub's own, not a person's.
//
// Pinning a name on those would refuse every agent commit a deployment makes,
// against a risk that does not exist there. scripts/no-personal-identity.sh
// does hold a stricter line on them, because on a developer's machine the name
// is free text and the permitted set is small enough to enumerate. That
// difference is a decision, recorded here and asserted by GH-005, not a drift.
func (p AuthorPolicy) CheckIdentity(name, email string) error {
	return p.admit(email, name, true)
}

// admitName is the name half, asked of the operator entry whose address
// matched. It is reached only from AuthorPolicy.admit, and only once that walk
// has admitted the address — an address the gate refuses never gets this far,
// so the name can never widen what the address allows.
func (op Operator) admitName(name, email string) error {
	if op.Name == "" {
		return fmt.Errorf("%w (%w): %q is a listed operator with NO display name "+
			"pinned to it, so the name beside it cannot be checked. State the pair as "+
			"`Name <%s>`; a pin that was never stated is not a pin that passes",
			ErrAuthorNotAdmitted, ErrNameNotPinned, email, email)
	}
	if op.Name == name {
		return nil
	}
	// DELIBERATELY NAMELESS. Neither the offending name nor the pinned one is
	// printed: this text reaches a public log.
	return fmt.Errorf("%w (%w): the display name on %q is not the one pinned to it. "+
		"The pinned set is deliberately not in this repository — a name in a tracked "+
		"file is a published name — so compare it against the configured list",
		ErrAuthorNotAdmitted, ErrNameNotPinned, email)
}

// ParseOperator reads one configured identity.
//
// The syntax is git's own, because an operator writing one is copying a string
// they can read straight out of `git log`:
//
//	Fixture Alpha <12345+alpha@users.noreply.github.com>   a pinned pair
//	12345+alpha@users.noreply.github.com                   an address, no pin
//	Fixture Alpha                                          a name, no address
//
// A trailing `#` comment is stripped and surrounding space is trimmed. An empty
// line is not an entry and is an error here; ParseOperators drops them instead.
//
// AN UNREADABLE ENTRY IS AN ERROR, never a skipped one. ADR-0028 §7 settled the
// direction: a typo in a policy with no cryptographic backstop must be loud, or
// it becomes a silently narrower allowlist that nobody notices until the day it
// matters.
func ParseOperator(line string) (Operator, error) {
	bad := func(why string) (Operator, error) {
		// The line is echoed only when it holds no address, because an entry
		// that failed to parse as `Name <address>` may be half a name.
		return Operator{}, fmt.Errorf("%w: an identity entry %s", ErrAuthorNotAdmitted, why)
	}

	s := strings.TrimSpace(stripComment(line))
	if s == "" {
		return bad("is empty")
	}

	open := strings.IndexByte(s, '<')
	if open < 0 {
		if strings.ContainsAny(s, ">@") {
			if strings.ContainsRune(s, '>') {
				return bad("closes an address it never opened")
			}
			// A bare address: an operator with nothing pinned to it.
			return Operator{Address: s}, nil
		}
		// A bare display name.
		return Operator{Name: s}, nil
	}

	if !strings.HasSuffix(s, ">") {
		return bad("has text after the address; the whole entry is `Name <address>`")
	}
	inner := s[open+1 : len(s)-1]
	if inner == "" || strings.ContainsAny(inner, "<>") {
		return bad("does not hold exactly one address between < and >")
	}
	name := strings.TrimSpace(s[:open])
	if name == "" {
		return bad("pins an address to no name at all, which pins nothing")
	}
	return Operator{Address: inner, Name: name}, nil
}

// ParseOperators reads a whole configured list — the lines of the untracked
// permitted-name file, or the comma-separated value of
// -sign-author-operators. Blank lines and whole-line `#` comments are dropped;
// anything else that will not parse is an error, for ParseOperator's reason.
func ParseOperators(lines []string) ([]Operator, error) {
	var out []Operator
	for i, line := range lines {
		if strings.TrimSpace(stripComment(line)) == "" {
			continue
		}
		op, err := ParseOperator(line)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i+1, err)
		}
		out = append(out, op)
	}
	return out, nil
}

// stripComment removes a `#` comment. A display name cannot contain `#`
// without being unreadable in the file that holds it, so the whole-line and
// trailing forms are the same rule.
func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

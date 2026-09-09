// SPDX-License-Identifier: Apache-2.0

package signing

import "testing"

// GH-004 (proposed for doc 07; doc 07 is not modified here).
//
// An INSTALLED BOT is admitted by name. A CODING AGENT never is.
//
// # The distinction, which is the whole of this
//
// I6 exists so that an agent writing code in this repository cannot become a
// GitHub identity: "agent identity lives only in trailers + signature". The
// actors that threaten it are the ones that produce code — Claude Code, Copilot
// and their kin. If one of those is ever attributed as an author, "who wrote
// this" has two answers, one cryptographic and one social, and they can
// disagree. The whole design exists so there is exactly one.
//
// A dependency bot is not that. It raises a version number in a manifest under
// a policy the operator set, and it authors nothing anyone would attribute to a
// human or to an agent of this system.
//
// So the policy gains a category with a narrow rule: an installed bot is
// admitted only by exact address, listed deliberately, and the listing is not a
// pattern. `AllowUnlinked` cannot help here — a
// `@users.noreply.github.com` address is precisely how GitHub attaches a commit
// to an account, which is why that flag refuses it.
func TestGH004AnInstalledBotIsAdmittedByNameAndACodingAgentIsNot(t *testing.T) {
	p := AuthorPolicy{
		Operators:     []string{"66436734+KodyMike@users.noreply.github.com"},
		InstalledBots: []string{"49699333+dependabot[bot]@users.noreply.github.com"},
		AllowUnlinked: true,
	}

	if err := p.CheckAuthor("49699333+dependabot[bot]@users.noreply.github.com"); err != nil {
		t.Errorf("the listed bot was refused: %v", err)
	}
	if err := p.CheckAuthor("66436734+KodyMike@users.noreply.github.com"); err != nil {
		t.Errorf("the operator was refused: %v", err)
	}
	if err := p.CheckAuthor("agent@innsegl.invalid"); err != nil {
		t.Errorf("an unlinked agent address was refused: %v", err)
	}

	// EXACT ADDRESSES ONLY. A pattern over "[bot]" or over the noreply domain
	// would admit every bot GitHub ever installs, including one that writes
	// code. The list is a decision per actor, taken once, in writing.
	for _, bad := range []string{
		"1+claude[bot]@users.noreply.github.com",
		"2+copilot[bot]@users.noreply.github.com",
		"3+dependabot[bot]@users.noreply.github.com", // right name, wrong account
		"dependabot@github.com",
		"49699333+dependabot@users.noreply.github.com", // no [bot]
	} {
		if err := p.CheckAuthor(bad); err == nil {
			t.Errorf("CheckAuthor(%q) was admitted; only the exact listed addresses are, "+
				"and a coding agent must never be listed at all", bad)
		}
	}

	// And an empty list admits nothing, so the category cannot widen a policy
	// that did not ask for it.
	none := AuthorPolicy{Operators: p.Operators, AllowUnlinked: true}
	if err := none.CheckAuthor("49699333+dependabot[bot]@users.noreply.github.com"); err == nil {
		t.Error("a policy listing no installed bots admitted one")
	}
}

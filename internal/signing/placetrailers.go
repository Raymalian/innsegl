// SPDX-License-Identifier: Apache-2.0

package signing

import "strings"

// PlaceTrailers is CommitMessage's placement half, exported without its
// author gate — RM-240 (#385), ADR-0059 decision 2.
//
// prepare-commit-msg asks the core for a run's trailers before the commit
// object git will build from this message exists, so there is no author line
// yet for CheckAuthor to admit or refuse; decision 4's own gate 3 checks the
// author later, against the payload signing actually receives. Building a
// Commit{AuthorEmail: ...} here, with no real address to put in it, would be
// answering a question this call is not being asked.
//
// The placement logic itself is NOT a second implementation: this calls the
// exact prepareMessage ADR-0028 built and SIG-006's differential pins against
// real git, so a message this function accepts or refuses agrees with
// CommitMessage's own answer for the identical (message, claim) pair. Not
// duplicated here: this is CommitMessage's own trailer-writing loop, copied
// rather than factored into a shared helper only because CommitMessage
// itself is untouched by this file — the loop is eight lines of
// concatenation, not a decision, and prepareMessage is where every decision
// lives.
func PlaceTrailers(claim Claim, message string) (string, error) {
	trailers, err := claim.Trailers()
	if err != nil {
		return "", err
	}
	body, join, err := prepareMessage(message)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString(body)
	if !join {
		// The trailer block opens its own paragraph. Git only reads a group
		// of lines as trailers when a blank line precedes it.
		b.WriteString("\n")
	}
	for _, t := range trailers {
		b.WriteString(t.String())
		b.WriteString("\n")
	}
	return b.String(), nil
}

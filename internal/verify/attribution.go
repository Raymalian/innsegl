// SPDX-License-Identifier: Apache-2.0

package verify

import "context"

// ADR-0047's answer, reachable on its own.
//
// # Why this exists as a separate door
//
// Verify runs three cryptographic checks and, alongside them, the content check
// ADR-0047 added. After a rebase only the second can be answered at all: the
// rewrite destroys the signature, so Fulcio and Rekor have nothing to say about
// the object, while the ledger still holds what the CHANGE was.
//
// The component that serves verdicts to strangers — internal/api's Prover — is
// structurally forbidden a ledger, and deliberately: proof.go's third invariant,
// IP §6.11's "never downgrades to database-only 'trust us' answers", and API-006
// which plants a `commit_recorded`, removes both upstreams and requires the
// answer to still be "unavailable". That constraint is right and is not being
// loosened here.
//
// So the content answer needs its own door rather than a ledger handle inside
// the Prover's. A caller that HAS a ledger asks this; a caller that does not
// keeps getting exactly the three checks it got before. The two answers stay
// separately labelled all the way to the screen, which is what doc 06 P2 asks
// for: never present what you do not know.
//
// # What this is NOT
//
// It is not verification and must never be rendered as it. A patch-id match
// plus a trailer is the ledger's record of who made a change, not a signature
// over it: both halves are forgeable by a compromised MCP (IP §6.10), which is
// exactly why ADR-0047 gave this its own verdict rather than folding it into
// `verified`.

// ContentConfig is what the content check needs and nothing else. There is no
// Fulcio URL, no Rekor URL and no clock here, because none of the three checks
// runs on this path.
type ContentConfig struct {
	// GitPath is the git binary; empty means a PATH lookup.
	GitPath string
	// Source is the ledger. Nil is a supported state and answers
	// "unavailable" — never "failed", which would report a finding the check
	// did not make.
	Source ContentSource
}

// AttributeContent asks whether a signed run produced this change.
//
// runID is the run the commit CLAIMS, read from its `Agent-Run` trailer by the
// caller (verify.ReadClaim). It is passed in rather than parsed here because
// the caller has already read the commit object to find it, and reading it
// twice would let the two reads disagree.
//
// It never returns an error: every way this can fail to reach an answer is one
// of ContentAttribution's own results, with the reason in Detail. An error
// return would give a caller a fourth state to render that doc 06 §4.2 has no
// badge for.
func AttributeContent(
	ctx context.Context, cfg ContentConfig, repo, sha, runID string,
) ContentAttribution {
	return checkContent(ctx, contentInput{
		gitPath: cfg.GitPath,
		repo:    repo,
		sha:     sha,
		runID:   runID,
	}, cfg.Source)
}

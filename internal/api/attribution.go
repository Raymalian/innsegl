// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/verify"
)

// ADR-0047's answer, served beside the proof rather than inside it.
//
// # Why this is not a field on /proof
//
// The Prover holds no ledger and must keep holding none: proof.go's third
// invariant, IP §6.11's "never downgrades to database-only 'trust us' answers",
// and API-006, which plants a `commit_recorded` for the commit under test,
// removes both upstreams, and requires the answer to still be "unavailable".
// Giving the Prover a pool so it could fill in a content field would delete that
// guarantee for every caller, to fix one verdict.
//
// So the content question gets its own endpoint. /proof stays exactly what it
// was — three cryptographic checks over Fulcio and Rekor, reproducible by
// anyone, ledger-free — and this answers the different question ADR-0047 asks:
// which run recorded this CHANGE. The dashboard calls both and shows them as two
// distinct answers, which doc 06 P2 requires anyway: never present what you do
// not know, and these are not known the same way.
//
// # What a caller must not do with it
//
// This is not verification. A patch-id match plus an `Agent-Run` trailer is the
// ledger's record of authorship, not a signature over the object; both halves
// are forgeable by a compromised MCP (IP §6.10). ADR-0047 gave it its own
// verdict for that reason, and doc 06 §4.2's fourth badge is where it belongs.
// Rendering it as `verified` would be the exact downgrade §6.11 forbids.

// Attribution is the response body of GET /api/v1/attribution/{commit_sha}.
type Attribution struct {
	// Commit is the commit asked about, resolved to a full SHA.
	Commit string `json:"commit"`
	// Repo is the repository it was resolved in.
	Repo string `json:"repo"`
	// Claimed is the run named by the commit's `Agent-Run` trailer, empty when
	// it carries none.
	Claimed string `json:"claimed_run,omitempty"`
	// Content is the check's answer, verbatim from internal/verify. Nothing
	// here computes or adjusts a verdict.
	Content verify.ContentAttribution `json:"content"`
}

// contentSource adapts the query pool to internal/verify's interface.
//
// The two ContentRecord types are deliberately separate — internal/ledger says
// why: internal/verify holds no database and must keep holding none, so it
// declares the interface it needs and the ledger satisfies it. This is the
// three lines where those two meet.
type contentSource struct{ store *Store }

func (c contentSource) RunsForPatchID(
	ctx context.Context, patchID string,
) ([]verify.ContentRecord, error) {
	records, err := ledger.RunsForPatchID(ctx, c.store.pool, patchID)
	if err != nil {
		return nil, err
	}
	out := make([]verify.ContentRecord, 0, len(records))
	for _, r := range records {
		out = append(out, verify.ContentRecord{
			RunID:     r.RunID,
			PatchID:   r.PatchID,
			CommitSHA: r.CommitSHA,
			EventID:   r.EventID,
		})
	}
	return out, nil
}

// handleAttribution answers about one commit in one repository.
//
// An unreachable ledger is an "unavailable" Content result inside a 200, for
// handleProof's reason: "we could not check" is an answer this API is obliged
// to give in full, not an HTTP error a client renders as a broken page.
func (s *Server) handleAttribution(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	sha := r.PathValue("commit_sha")

	path, ok := s.prover.RepoPath(repo)
	if !ok {
		writeProblem(w, fmt.Errorf("%w: this deployment serves no repository called %q",
			ErrNotFound, repo))
		return
	}

	full, message, err := s.prover.CommitMessage(r.Context(), path, sha)
	if err != nil {
		writeProblem(w, fmt.Errorf("%w: %s is not a commit in %s", ErrNotFound, sha, repo))
		return
	}
	claim, cerr := verify.ReadClaim(message)
	if cerr != nil {
		// A malformed trailer block is not a missing one, and the content
		// check's own "claims no run" answer says the right thing about both.
		claim = verify.Claim{}
	}

	writeJSON(w, http.StatusOK, Attribution{
		Commit:  full,
		Repo:    repo,
		Claimed: claim.Run,
		Content: verify.AttributeContent(r.Context(),
			verify.ContentConfig{GitPath: s.prover.GitPath(), Source: contentSource{store: s.store}},
			path, full, claim.Run),
	})
}

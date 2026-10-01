// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
)

// maxCommitTrailersBodyBytes bounds the POST body: a commit message this
// large is already absurd, and the bound exists so a malformed or hostile
// request cannot exhaust memory before json.Unmarshal ever sees it.
const maxCommitTrailersBodyBytes = 1 << 20

// committrailers.go — RM-240 (#385), ADR-0059 decision 2: the core's answer
// to prepare-commit-msg's own request for a run's trailers.
//
// # What is, and is not, checked here
//
// The author gate is NOT here. ADR-0028's CheckAuthor runs at signing
// (decision 4's third gate), against the payload's actual author and
// committer lines — bytes that do not exist yet when a message is merely
// being drafted, before the commit object git will build from it has even
// been formed. This endpoint answers exactly one question: does the tool
// call this message is being drafted for authorise a commit
// (commitpath.Resolve, ADR-0059 decision 4's first gate), and can the run it
// names claim trailers (claimFor, internal/mcp.CommitClaimForRun). Nothing
// else is asked, and nothing else is refused.
//
// commitTrailersHandler is not mounted by this file — cmd/innsegl/gateway.go
// wires it onto commitpath.TrailersPath after this wave, the same
// deliberate split gateway.go's own doc comment on sessionEndHandler
// describes for that endpoint.
func commitTrailersHandler(res commitpath.Resolver, claimFor func(ctx context.Context, runID string) (signing.Claim, error), now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "innsegl: commit trailers: only POST is accepted", http.StatusMethodNotAllowed)
			return
		}

		raw, err := io.ReadAll(io.LimitReader(r.Body, maxCommitTrailersBodyBytes+1))
		if err != nil {
			http.Error(w, "innsegl: commit trailers: the request body could not be read",
				http.StatusBadRequest)
			return
		}
		if len(raw) > maxCommitTrailersBodyBytes {
			http.Error(w, "innsegl: commit trailers: the request body is too large",
				http.StatusBadRequest)
			return
		}
		var req commitpath.TrailersRequest
		if uerr := json.Unmarshal(raw, &req); uerr != nil {
			http.Error(w, "innsegl: commit trailers: the request body is not the expected JSON shape",
				http.StatusBadRequest)
			return
		}

		// Gate 1 (ADR-0059 decision 4's first, asked here too): the tool call
		// this message is being drafted for really was relayed, is a `git
		// commit`, and is still inside its window.
		call, err := commitpath.Resolve(commitpath.ResolverFrom(r.Context(), res), req.ToolUseID, now())
		if err != nil {
			writeCommitPathError(w, err)
			return
		}

		// Gate 2: the run that call belongs to can claim trailers at all
		// (internal/mcp.CommitClaimForRun — active, not retired, not lapsed).
		claim, err := claimFor(r.Context(), call.RunID)
		if err != nil {
			writeCommitPathError(w, err)
			return
		}

		trailers, err := claim.Trailers()
		if err != nil {
			writeCommitPathError(w, err)
			return
		}

		// --amend and a harness retry re-present a message that already
		// carries this run's own three trailers, verbatim: placing them again
		// would either duplicate the paragraph or, since ADR-0028's own
		// render already refuses any message that spells one of the three
		// protected keys a second time, be refused outright
		// (signing.ErrTrailerAlreadyPresent). An exact match on all three is
		// answered with the message unchanged, which is what "already
		// claimed" means; anything else — a partial or mismatched trailer —
		// falls through to the render below and is refused by it.
		message := req.Message
		if !commitTrailersAlreadyClaimed(message, trailers) {
			message, err = signing.PlaceTrailers(claim, req.Message)
			if err != nil {
				writeCommitPathError(w, err)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		discardEncodeError(json.NewEncoder(w).Encode(commitpath.TrailersResponse{Message: message}))
	})
}

// discardEncodeError is writeCommitTrailersError's write discard, named for
// the identical reason internal/gateway's discardWriteError is (proxy.go):
// visible and explained, never a bare `_ =`. A caller that has already gone
// leaves nothing here to report the failure to.
func discardEncodeError(error) {}

// commitTrailersAlreadyClaimed reports whether every trailer claim would add
// is already present in message, as a whole line, verbatim. It does not
// reimplement ADR-0028's placement classifier — it does not need to: it asks
// only whether this EXACT prior render is already there, which is the one
// question --amend and a retry ask.
func commitTrailersAlreadyClaimed(message string, trailers []signing.Trailer) bool {
	lines := strings.Split(message, "\n")
	for _, t := range trailers {
		want := t.String()
		found := false
		for _, line := range lines {
			if line == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return len(trailers) > 0
}

// writeCommitPathError classifies err through the same taxonomy
// internal/mcp already uses (mcp.Classify) and answers 403 for a settled
// refusal — a gate this run cannot pass, or a claim it cannot make — and 500
// for anything IP §4 marked retryable, which here means an outage this
// endpoint cannot itself repair. commitpath.Resolve's own errors and
// signing.PlaceTrailers's are plain errors, not *mcp.Error; mcp.Classify's
// documented fallback for an error it cannot name is INVARIANT_VIOLATION,
// not retryable — exactly a settled refusal, the same reading ADR-0028 §8
// gives its own package's failures.
func writeCommitPathError(w http.ResponseWriter, err error) {
	status := http.StatusForbidden
	if mcp.Classify(err).Retryable {
		status = http.StatusInternalServerError
	}
	writeCommitTrailersError(w, status, err.Error())
}

// commitTrailersErrorBody mirrors internal/gateway's own writeGatewayError
// wire shape ({"error": "..."}) — duplicated rather than imported because
// that function is unexported and this endpoint is a different loopback
// surface (ADR-0059 decision 2), not internal/gateway's proxy.
type commitTrailersErrorBody struct {
	Error string `json:"error"`
}

func writeCommitTrailersError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, err := json.Marshal(commitTrailersErrorBody{Error: msg})
	if err != nil {
		// json.Marshal on a struct holding one string field cannot fail; this
		// is defensive rather than reachable, and still writes SOMETHING
		// naming innsegl rather than leaving the body empty.
		body = []byte(`{"error":"innsegl: commit trailers: the request was refused and the reason could not be encoded"}`)
	}
	discardWriteError(w.Write(body))
}

// discardWriteError mirrors internal/gateway's own discard of the identical
// shape (proxy.go's discardWriteError) — a write failure here means the
// caller has already gone, and there is nothing left to tell it.
func discardWriteError(int, error) {}

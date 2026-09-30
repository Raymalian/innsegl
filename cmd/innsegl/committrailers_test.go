// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
)

// ---------------------------------------------------------------------------
// Test doubles.
// ---------------------------------------------------------------------------

// ctResolver is commitpath.Resolver, held in memory. It answers only what
// the test put in it, exactly the shape commitpath_test.go's own doubles use
// for Resolve (internal/commitpath).
type ctResolver struct {
	calls map[string]commitpath.RelayedCall
}

func newCTResolver() *ctResolver { return &ctResolver{calls: map[string]commitpath.RelayedCall{}} }

func (r *ctResolver) LookupPending(toolUseID string) (commitpath.RelayedCall, bool) {
	c, ok := r.calls[toolUseID]
	return c, ok
}

const (
	ctToolUseID = "toolu_0123456789abcdef"
	ctRunID     = "run-42"
	ctIdentity  = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"
)

// ctRelay files a relayed `git commit` Bash call, observed at `at`, under
// ctToolUseID — commitpath.Resolve's own gate (internal/commitpath).
func (r *ctResolver) relay(runID string, at time.Time) {
	r.calls[ctToolUseID] = commitpath.RelayedCall{
		RunID:      runID,
		Tool:       "Bash",
		Input:      json.RawMessage(`{"command":"git commit -m \"fix: thing\""}`),
		ObservedAt: at,
	}
}

// ctClaim is a fixed, renderable claim for ctRunID.
var ctClaim = signing.Claim{Identity: ctIdentity, Run: ctRunID, Task: "JIRA-118"}

func ctClaimFor(claim signing.Claim, err error) func(context.Context, string) (signing.Claim, error) {
	return func(_ context.Context, runID string) (signing.Claim, error) {
		if err != nil {
			return signing.Claim{}, err
		}
		if runID != claim.Run {
			return signing.Claim{}, errors.New("test double: unexpected run id")
		}
		return claim, nil
	}
}

func ctNow(at time.Time) func() time.Time { return func() time.Time { return at } }

// ctDo POSTs body (or, if body is a string, its bytes verbatim) to the
// handler and returns the recorded response.
func ctDo(t *testing.T, h http.Handler, method string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "/_gateway/commit-trailers", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func ctReqJSON(t *testing.T, toolUseID, message string) []byte {
	t.Helper()
	b, err := json.Marshal(commitpath.TrailersRequest{ToolUseID: toolUseID, Message: message})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return b
}

func ctErrorBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not {\"error\": ...}: %v (%q)", err, rec.Body.String())
	}
	if body.Error == "" {
		t.Fatalf("response body carries no error: %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	return body.Error
}

// ---------------------------------------------------------------------------
// Method and body framing.
// ---------------------------------------------------------------------------

func TestCommitTrailersHandlerRejectsNonPOST(t *testing.T) {
	h := commitTrailersHandler(newCTResolver(), ctClaimFor(ctClaim, nil), ctNow(time.Now()))
	rec := ctDo(t, h, http.MethodGet, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestCommitTrailersHandlerRejectsOversizedBody(t *testing.T) {
	h := commitTrailersHandler(newCTResolver(), ctClaimFor(ctClaim, nil), ctNow(time.Now()))
	huge := ctReqJSON(t, ctToolUseID, strings.Repeat("x", maxCommitTrailersBodyBytes+1))
	rec := ctDo(t, h, http.MethodPost, huge)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestCommitTrailersHandlerRejectsMalformedJSON(t *testing.T) {
	h := commitTrailersHandler(newCTResolver(), ctClaimFor(ctClaim, nil), ctNow(time.Now()))
	rec := ctDo(t, h, http.MethodPost, []byte("{not json"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// ---------------------------------------------------------------------------
// The two gates: the relayed tool call, then the claim.
// ---------------------------------------------------------------------------

func TestCommitTrailersHandlerRefusesAnUnresolvedToolCall(t *testing.T) {
	now := time.Now()
	// The resolver holds nothing for ctToolUseID: commitpath.Resolve refuses
	// with "no relayed tool call ... is running" before claimFor is ever
	// asked.
	called := false
	claimFor := func(context.Context, string) (signing.Claim, error) {
		called = true
		return signing.Claim{}, nil
	}
	h := commitTrailersHandler(newCTResolver(), claimFor, ctNow(now))
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, ctToolUseID, "subject\n\nbody.\n"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	ctErrorBody(t, rec)
	if called {
		t.Error("claimFor was called even though the tool call did not resolve")
	}
}

func TestCommitTrailersHandlerRefusesAnEmptyToolUseID(t *testing.T) {
	h := commitTrailersHandler(newCTResolver(), ctClaimFor(ctClaim, nil), ctNow(time.Now()))
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, "", "subject\n\nbody.\n"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := ctErrorBody(t, rec); !strings.Contains(got, commitpath.EnvToolUseID) {
		t.Errorf("refusal %q does not name %s", got, commitpath.EnvToolUseID)
	}
}

func TestCommitTrailersHandlerRefusesAClaimTheRunCannotMake(t *testing.T) {
	now := time.Now()
	res := newCTResolver()
	res.relay(ctRunID, now)
	refusal := mcp.Errorf(mcp.ClassRunAlreadyRetired, ctRunID, "run %q was retired", ctRunID)
	h := commitTrailersHandler(res, ctClaimFor(signing.Claim{}, refusal), ctNow(now))
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, ctToolUseID, "subject\n\nbody.\n"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	ctErrorBody(t, rec)
}

func TestCommitTrailersHandlerReturns500ForARetryableFailure(t *testing.T) {
	now := time.Now()
	res := newCTResolver()
	res.relay(ctRunID, now)
	outage := mcp.Errorf(mcp.ClassLedgerUnavailable, ctRunID, "the ledger is unreachable")
	h := commitTrailersHandler(res, ctClaimFor(signing.Claim{}, outage), ctNow(now))
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, ctToolUseID, "subject\n\nbody.\n"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestCommitTrailersHandlerRefusesAMessageShapeADR0028Refuses(t *testing.T) {
	now := time.Now()
	res := newCTResolver()
	res.relay(ctRunID, now)
	h := commitTrailersHandler(res, ctClaimFor(ctClaim, nil), ctNow(now))
	// A bare "---" divider: ADR-0028 refuses it outright (ErrMessage).
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, ctToolUseID, "subject\n\nalpha\n---\nomega\n"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	ctErrorBody(t, rec)
}

// ---------------------------------------------------------------------------
// The success path, and its idempotency.
// ---------------------------------------------------------------------------

func TestCommitTrailersHandlerPlacesTheThreeTrailers(t *testing.T) {
	now := time.Now()
	res := newCTResolver()
	res.relay(ctRunID, now)
	h := commitTrailersHandler(res, ctClaimFor(ctClaim, nil), ctNow(now))
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, ctToolUseID, "subject\n\nbody.\n"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	var resp commitpath.TrailersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want, err := signing.PlaceTrailers(ctClaim, "subject\n\nbody.\n")
	if err != nil {
		t.Fatalf("signing.PlaceTrailers: %v", err)
	}
	if resp.Message != want {
		t.Errorf("message =\n%q\nwant\n%q", resp.Message, want)
	}
	for _, line := range []string{
		"Agent-Identity: " + ctClaim.Identity,
		"Agent-Run: " + ctClaim.Run,
		"Agent-Task: " + ctClaim.Task,
	} {
		if !strings.Contains(resp.Message, line) {
			t.Errorf("message does not carry %q:\n%s", line, resp.Message)
		}
	}
	if !strings.HasPrefix(resp.Message, "subject\n\nbody.\n") {
		t.Errorf("the rest of the message changed:\n%s", resp.Message)
	}
}

// TestCommitTrailersHandlerDoesNotDuplicateTrailersAlreadyPresent is
// ADR-0059 decision 2's own idempotency requirement: --amend and a harness
// retry re-present a message that already carries this run's exact three
// trailers, and calling ADR-0028's render on it again would refuse outright
// (signing.ErrTrailerAlreadyPresent) rather than silently doubling them. The
// handler must recognise the exact match and hand the message back
// unchanged.
func TestCommitTrailersHandlerDoesNotDuplicateTrailersAlreadyPresent(t *testing.T) {
	now := time.Now()
	res := newCTResolver()
	res.relay(ctRunID, now)
	h := commitTrailersHandler(res, ctClaimFor(ctClaim, nil), ctNow(now))

	already := "subject\n\nbody.\n\n" +
		"Agent-Identity: " + ctClaim.Identity + "\n" +
		"Agent-Run: " + ctClaim.Run + "\n" +
		"Agent-Task: " + ctClaim.Task + "\n"
	rec := ctDo(t, h, http.MethodPost, ctReqJSON(t, ctToolUseID, already))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %q", rec.Code, rec.Body.String())
	}
	var resp commitpath.TrailersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Message != already {
		t.Errorf("message =\n%q\nwant it unchanged:\n%q", resp.Message, already)
	}
	if n := strings.Count(resp.Message, "Agent-Run: "); n != 1 {
		t.Errorf("Agent-Run appears %d times, want 1:\n%s", n, resp.Message)
	}
}

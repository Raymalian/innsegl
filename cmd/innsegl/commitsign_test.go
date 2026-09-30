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

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mcp"
)

// RM-241 (#386): the HTTP surface ADR-0059 decision 4's `SignPath` answers.
// commitSignHandler is a thin, testable wrapper: everything it does is
// translate one HTTP request into one call of the injected `sign` function
// and its answer back into a response. It is deliberately not mounted in
// gateway.go — the supervisor wires it after the wave (ADR-0059 decision 3's
// own client is a separate, not-yet-built piece).

// csErrorBody mirrors internal/gateway's own gatewayErrorBody shape
// ({"error": "..."}), which this handler is required to match rather than
// import — cmd/innsegl does not depend on internal/gateway for this.
type csErrorBody struct {
	Error string `json:"error"`
}

func decodeCSError(t *testing.T, body []byte) csErrorBody {
	t.Helper()
	var out csErrorBody
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response body is not {\"error\": ...}: %v\nbody: %s", err, body)
	}
	if out.Error == "" {
		t.Fatalf("response body carries no error message: %s", body)
	}
	return out
}

func doCommitSign(t *testing.T, h http.Handler, method string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, commitpath.SignPath, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Method and body shape.
// ---------------------------------------------------------------------------

func TestCommitSignHandlerRefusesANonPOSTMethod(t *testing.T) {
	h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
		t.Fatal("sign was called; the method should have been refused first")
		return commitpath.SignResponse{}, nil
	})
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := doCommitSign(t, h, method, nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
		}
		decodeCSError(t, rec.Body.Bytes())
	}
}

func TestCommitSignHandlerRefusesAMalformedBody(t *testing.T) {
	h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
		t.Fatal("sign was called; malformed JSON should have been refused first")
		return commitpath.SignResponse{}, nil
	})
	cases := [][]byte{
		nil,
		[]byte(""),
		[]byte("not json"),
		[]byte(`{"tool_use_id": `), // truncated
		[]byte(`["an array, not an object"]`),
	}
	for _, body := range cases {
		rec := doCommitSign(t, h, http.MethodPost, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want %d", body, rec.Code, http.StatusBadRequest)
		}
		decodeCSError(t, rec.Body.Bytes())
	}
}

func TestCommitSignHandlerRefusesAnOversizedBody(t *testing.T) {
	h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
		t.Fatal("sign was called; an oversized body should have been refused first")
		return commitpath.SignResponse{}, nil
	})
	huge, err := json.Marshal(commitpath.SignRequest{
		ToolUseID: "toolu_01oversized00000000000000000",
		Payload:   bytes.Repeat([]byte("a"), maxCommitSignRequestBytes+1),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	rec := doCommitSign(t, h, http.MethodPost, huge)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	decodeCSError(t, rec.Body.Bytes())
}

// ---------------------------------------------------------------------------
// The happy path — sign succeeds, its answer is handed back as 200 JSON.
// ---------------------------------------------------------------------------

func TestCommitSignHandlerReturns200AndTheSignResponseOnSuccess(t *testing.T) {
	var gotReq commitpath.SignRequest
	h := commitSignHandler(func(_ context.Context, req commitpath.SignRequest) (commitpath.SignResponse, error) {
		gotReq = req
		return commitpath.SignResponse{
			Signature: []byte("-----BEGIN SIGNED MESSAGE-----\nfake\n-----END SIGNED MESSAGE-----\n"),
			Status:    []byte("[GNUPG:] SIG_CREATED X\n"),
		}, nil
	})

	sent := commitpath.SignRequest{
		ToolUseID: "toolu_01happypath0000000000000000",
		Args:      []string{"--status-fd=2", "-bsau", "Name <a@example.invalid>"},
		Payload:   []byte("tree deadbeef\n\nmsg\n"),
	}
	body, err := json.Marshal(sent)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	rec := doCommitSign(t, h, http.MethodPost, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var out commitpath.SignResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decoding the response: %v\nbody: %s", err, rec.Body.String())
	}
	if !bytes.Contains(out.Signature, []byte("BEGIN SIGNED MESSAGE")) {
		t.Errorf("Signature = %q, want it to carry the signature sign() returned", out.Signature)
	}
	if !bytes.Contains(out.Status, []byte("SIG_CREATED")) {
		t.Errorf("Status = %q, want it to carry the status sign() returned", out.Status)
	}
	if gotReq.ToolUseID != sent.ToolUseID {
		t.Errorf("sign() was called with ToolUseID %q, want %q", gotReq.ToolUseID, sent.ToolUseID)
	}
	if !bytes.Equal(gotReq.Payload, sent.Payload) {
		t.Errorf("sign() was called with Payload %q, want %q", gotReq.Payload, sent.Payload)
	}
}

// ---------------------------------------------------------------------------
// Error mapping: a refusal (non-retryable *mcp.Error) is 403; a dependency
// outage (retryable *mcp.Error) is 503; anything sign() returns that is not
// even a classified error is 500.
// ---------------------------------------------------------------------------

func TestCommitSignHandlerMapsARefusalTo403(t *testing.T) {
	h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
		return commitpath.SignResponse{}, mcp.Errorf(mcp.ClassInvariantViolation, "",
			"the payload's trailers do not match this run's claim")
	})
	rec := doCommitSign(t, h, http.MethodPost, mustJSON(t, commitpath.SignRequest{ToolUseID: "toolu_01x000000000000000000000000"}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	got := decodeCSError(t, rec.Body.Bytes())
	if !strings.Contains(got.Error, "trailers do not match") {
		t.Errorf("error message = %q, want it to name the reason sign() gave", got.Error)
	}
}

func TestCommitSignHandlerMapsADependencyOutageTo503(t *testing.T) {
	h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
		return commitpath.SignResponse{}, mcp.Errorf(mcp.ClassSigningUnavailable, "",
			"Fulcio could not be reached")
	})
	rec := doCommitSign(t, h, http.MethodPost, mustJSON(t, commitpath.SignRequest{ToolUseID: "toolu_01x000000000000000000000000"}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	got := decodeCSError(t, rec.Body.Bytes())
	if !strings.Contains(got.Error, "Fulcio") {
		t.Errorf("error message = %q, want it to name the reason sign() gave", got.Error)
	}
}

func TestCommitSignHandlerMapsAnUnclassifiedErrorTo500(t *testing.T) {
	h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
		return commitpath.SignResponse{}, errors.New("some entirely unexpected failure")
	})
	rec := doCommitSign(t, h, http.MethodPost, mustJSON(t, commitpath.SignRequest{ToolUseID: "toolu_01x000000000000000000000000"}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	decodeCSError(t, rec.Body.Bytes())
}

// Every one of the *mcp.Error classes that is retryable (a dependency
// outage) maps to 503, and every one that is not maps to 403 — the same
// classification IP §4 already gives every other MCP caller, read here
// through .Retryable rather than reimplemented case by case.
func TestCommitSignHandlerMapsEveryErrorClassByItsOwnRetryability(t *testing.T) {
	for _, class := range mcp.Classes() {
		t.Run(string(class), func(t *testing.T) {
			h := commitSignHandler(func(context.Context, commitpath.SignRequest) (commitpath.SignResponse, error) {
				return commitpath.SignResponse{}, mcp.Errorf(class, "", "case for %s", class)
			})
			rec := doCommitSign(t, h, http.MethodPost, mustJSON(t, commitpath.SignRequest{ToolUseID: "toolu_01x000000000000000000000000"}))
			want := http.StatusForbidden
			if class.Retryable() {
				want = http.StatusServiceUnavailable
			}
			if rec.Code != want {
				t.Errorf("class %s (retryable=%v): status = %d, want %d",
					class, class.Retryable(), rec.Code, want)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

// ---------------------------------------------------------------------------
// A nil sign dependency is a wiring defect, not a panic.
// ---------------------------------------------------------------------------

func TestCommitSignHandlerRefusesRatherThanPanicsWithNoSignFunction(t *testing.T) {
	h := commitSignHandler(nil)
	rec := doCommitSign(t, h, http.MethodPost, mustJSON(t, commitpath.SignRequest{ToolUseID: "toolu_01x000000000000000000000000"}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	decodeCSError(t, rec.Body.Bytes())
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/mcp"
)

// commitsign.go — RM-241 (#386): the HTTP surface ADR-0059's `SignPath`
// answers, over the SAME loopback listener `innsegl gateway` already serves
// on (commitpath.SignPath, commitpath.DefaultCoreURL).
//
// # This is git's own contract, not a new one
//
// ADR-0059 decision 3: the program git invokes as `gpg.x509.program` is a
// thin client that reads the payload git hands it, attaches the tool call
// identifier the PreToolUse hook injected, and asks the core to sign it. This
// file is the core's other end of that one HTTP call — nothing more. It does
// no gating and no signing itself: `sign` is `mcp.SignPayloadForGateway`
// (internal/mcp/signpayload.go) in production, taken as a plain function
// value so this file can be tested against anything with the same shape and
// so this file never needs to know what internal/mcp's package state holds.
//
// # Deliberately not mounted here
//
// commitSignHandler is built and returned; nothing in this file registers it
// on any mux. ADR-0059 decision 4's gates depend on internal/mcp's
// commit-sign path being CONFIGURED (ConfigureSignPayload, on top of
// sign_commit's own ConfigureSignCommit) — wiring that belongs to the
// supervisor that assembles a deployment's full set of dependencies, after
// this wave, exactly as the task that added this file specifies. Mounting an
// unconfigured handler here would make `serve -also gateway` fail closed in
// a way nothing in THIS package's own tests could catch.
func commitSignHandler(
	sign func(ctx context.Context, req commitpath.SignRequest) (commitpath.SignResponse, error),
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeCommitSignError(w, http.StatusMethodNotAllowed,
				"innsegl commit-sign: only POST is accepted")
			return
		}
		if sign == nil {
			// A wiring defect — the supervisor bound this handler without
			// configuring what it calls — is a 500, not a panic that takes
			// the whole listener down with it.
			writeCommitSignError(w, http.StatusInternalServerError,
				"innsegl commit-sign: not configured")
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxCommitSignRequestBytes+1))
		if err != nil {
			writeCommitSignError(w, http.StatusBadRequest,
				"innsegl commit-sign: reading the request body: "+err.Error())
			return
		}
		if len(body) > maxCommitSignRequestBytes {
			writeCommitSignError(w, http.StatusBadRequest,
				"innsegl commit-sign: the request body is over the size this endpoint accepts")
			return
		}

		var req commitpath.SignRequest
		if jerr := json.Unmarshal(body, &req); jerr != nil {
			writeCommitSignError(w, http.StatusBadRequest,
				"innsegl commit-sign: the request body is not the expected JSON shape: "+jerr.Error())
			return
		}

		resp, serr := sign(r.Context(), req)
		if serr != nil {
			status, msg := commitSignErrorResponse(serr)
			writeCommitSignError(w, status, msg)
			return
		}

		out, merr := json.Marshal(resp)
		if merr != nil {
			// json.Marshal on two []byte fields cannot fail; defensive
			// rather than reachable, on writeGatewayError's own reasoning
			// (internal/gateway/proxy.go).
			writeCommitSignError(w, http.StatusInternalServerError,
				"innsegl commit-sign: the answer could not be encoded")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		discardCommitSignWriteError(w.Write(out))
	})
}

// commitSignErrorResponse maps whatever sign returned to an HTTP status and a
// message: a classified *mcp.Error carries its own IP §4 retryable flag,
// which is exactly the distinction this endpoint needs and nothing this file
// re-derives — retryable means a dependency outage (503, "try again"),
// not retryable means a refusal (403, the request itself will never
// succeed). Anything sign returns that is not even a classified error —
// a defect in whatever `sign` actually is, since production's own
// SignPayloadForGateway classifies everything it returns — is a 500: this
// file does not know what it is and does not guess.
func commitSignErrorResponse(err error) (status int, message string) {
	var classified *mcp.Error
	if errors.As(err, &classified) {
		if classified.Retryable {
			return http.StatusServiceUnavailable, classified.Message
		}
		return http.StatusForbidden, classified.Message
	}
	return http.StatusInternalServerError, "innsegl commit-sign: " + err.Error()
}

// maxCommitSignRequestBytes bounds the request body. A signable commit
// payload is a handful of header lines plus a message under sign_commit's
// own MaxSignCommitMessageBytes (64KiB); 256KiB is generous headroom for
// several parents and a large message while staying far below anything an
// oversized request could turn into a resource-exhaustion vector.
const maxCommitSignRequestBytes = 256 << 10

// commitSignErrorBody mirrors internal/gateway's own gatewayErrorBody
// ({"error": "..."}, proxy.go) — matched rather than imported, since
// cmd/innsegl has no other reason to depend on internal/gateway from this
// file, and the two endpoints share nothing beyond this one shape.
type commitSignErrorBody struct {
	Error string `json:"error"`
}

func writeCommitSignError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, err := json.Marshal(commitSignErrorBody{Error: msg})
	if err != nil {
		// json.Marshal on a struct holding one string field cannot fail;
		// defensive rather than reachable (writeGatewayError's own
		// reasoning, internal/gateway/proxy.go).
		body = []byte(`{"error":"innsegl commit-sign: the error could not be encoded"}`)
	}
	discardCommitSignWriteError(w.Write(body))
}

// discardCommitSignWriteError is writeCommitSignError's named discard, for
// the identical reason internal/gateway's discardWriteError exists: a write
// failure here means the caller has already gone, and there is nothing left
// to tell it.
func discardCommitSignWriteError(int, error) {}

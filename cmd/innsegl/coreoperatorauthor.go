// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/mcp"
)

// The operator author an enrolled machine reports (#545, GH-010).
//
// A repository set to operator mode authors agent commits as the operator,
// read from that repository's git config on the operator's machine. The
// machine reports the pair here over its own certificate, and the core pins
// it on first use for that installation (accounts.PinOperatorAuthor). Gate 3
// of the commit-sign path then admits it for that installation's commits
// (mcp.admitsAuthor, GH-009). A different report is refused: an agent on the
// machine can reach its git config, not the pin on the core.

// coreOperatorAuthorPath is client.OperatorAuthorPath, on the core's side.
const coreOperatorAuthorPath = client.OperatorAuthorPath

// operatorAuthorReport is the body a machine sends.
type operatorAuthorReport = client.OperatorAuthorReport

// operatorAuthorPinner is the store the route pins into and reads from.
type operatorAuthorPinner interface {
	PinOperatorAuthor(ctx context.Context, installationID, name, email string) (created bool, err error)
	OperatorAuthor(ctx context.Context, installationID string) (name, email string, ok bool, err error)
}

// operatorAuthorHandler pins the reported pair for the calling installation
// (POST), or answers the pair pinned for it (GET, GH-011). Only the caller's
// own installation is ever read. Neither the name nor the address is logged.
func operatorAuthorHandler(store operatorAuthorPinner, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			writeCoreError(w, http.StatusMethodNotAllowed, "innsegl core: operator author: only GET and POST are accepted")
			return
		}
		id, ok := gateway.InstallationFromContext(r.Context())
		if !ok || id == "" {
			gateway.WriteClientRefusal(w)
			return
		}
		if r.Method == http.MethodGet {
			name, email, pinned, err := store.OperatorAuthor(r.Context(), id)
			if err != nil {
				log.warn("operator author: reading", "installation_id", id, "err", err)
				writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: operator author is unavailable; retry")
				return
			}
			writeCoreJSON(w, http.StatusOK, client.OperatorAuthorPin{Pinned: pinned, Name: name, Email: email})
			return
		}
		var report operatorAuthorReport
		if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&report); err != nil {
			writeCoreError(w, http.StatusBadRequest, "innsegl core: operator author: the body is not a report")
			return
		}
		created, err := store.PinOperatorAuthor(r.Context(), id, report.Name, report.Email)
		switch {
		case err == nil:
			result := client.PinHeld
			if created {
				result = client.PinNew
			}
			writeCoreJSON(w, http.StatusOK, client.OperatorAuthorPinResult{Pinned: true, Result: result})
		case errors.Is(err, accounts.ErrAuthorPinned):
			writeCoreError(w, http.StatusConflict, "innsegl core: this machine's operator author is already "+
				"pinned to a different identity. To pin another, run on the core host: "+
				"docker exec innsegl-api innsegl accounts author-reset "+id)
		case errors.Is(err, accounts.ErrInvalid):
			writeCoreError(w, http.StatusBadRequest, "innsegl core: operator author: "+err.Error())
		case errors.Is(err, accounts.ErrNotFound), errors.Is(err, accounts.ErrRevoked):
			gateway.WriteClientRefusal(w)
		default:
			log.warn("operator author: pinning", "installation_id", id, "err", err)
			writeCoreError(w, http.StatusServiceUnavailable, "innsegl core: operator author is unavailable; retry")
		}
	}
}

// operatorAuthors is the pin source gate 3 reads, on a hosted core; nil on a
// single-host core, which has no installations.
func operatorAuthors(h *hostedCore) mcp.OperatorAuthors {
	if h == nil || h.writer == nil {
		return nil
	}
	return h.writer
}

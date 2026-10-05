// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"innsegl.dev/innsegl/internal/ledger"
)

// Resolving alerts from the dashboard (RM-330, #506, ADR-0044's 2026-10-03
// amendment).
//
// Two calls, as every ceremony in this package is:
//
//	POST /api/v1/alert-resolutions/begin   {event_ids, reason}
//	     -> a WebAuthn request challenge for the signed-in user's passkeys
//	POST /api/v1/alert-resolutions/finish  {ceremony_id, credential}
//	     -> the resolutions, written only if the assertion verifies
//
// A signed-in session is not enough. Resolving an alert is a statement made
// in a person's name, so it takes a fresh passkey ceremony, with user
// verification, against that user's own passkeys — the same bar adding a
// passkey to the account already sets. The request is stored with the
// ceremony, not sent again on finish, so the passkey confirms exactly the
// alerts and the reason that began it.
//
// The write goes through the resolver credential (resolver.go), never the
// read-only pool and never the auth writer. With no resolver configured both
// routes answer 503 and point at `innsegl resolve-alert`, which still works.

// resolutionRoutePrefix is the prefix ServeHTTP hands to serveResolutions.
const resolutionRoutePrefix = "/api/v1/alert-resolutions"

// ceremonyKindResolveAlerts is migration 0013's ceremony kind.
const ceremonyKindResolveAlerts = "resolve_alerts"

// maxResolutionReasonBytes mirrors migration 0003's CHECK on reason.
const maxResolutionReasonBytes = 2048

// Auth events this surface records: who confirmed which resolution.
const (
	AuthEventAlertsResolved          = "alerts_resolved"
	AuthEventAlertResolutionRefused  = "alert_resolution_refused"
	resolutionDisabledMessage        = "resolving an alert needs the resolver role configured on the API, and this deployment has none"
	resolutionNeedsPasskeyMessage    = "resolving an alert is confirmed with a passkey, and this account has none; add one on the account page first"
	resolutionCeremonyExpiredMessage = "this confirmation has expired or was already used; start over"
)

// ResolveRequest is the body of POST /api/v1/alert-resolutions/begin.
type ResolveRequest struct {
	EventIDs []string `json:"event_ids"`
	Reason   string   `json:"reason"`
}

// Resolution is one written resolution, as the finish call answers it.
type Resolution struct {
	EventID    string    `json:"event_id"`
	ResolvedBy string    `json:"resolved_by"`
	ResolvedAt time.Time `json:"resolved_at"`
	Reason     string    `json:"reason"`
}

// ResolveResult is the body of a successful finish.
type ResolveResult struct {
	Resolutions []Resolution `json:"resolutions"`
}

// pendingResolution is what a resolve_alerts ceremony stores: go-webauthn's
// own SessionData, round-tripped unmodified, and the request it confirms.
type pendingResolution struct {
	Session  webauthn.SessionData `json:"session"`
	EventIDs []string             `json:"event_ids"`
	Reason   string               `json:"reason"`
}

func (s *Server) newResolutionMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/alert-resolutions/begin", s.handleResolveBegin)
	mux.HandleFunc("POST /api/v1/alert-resolutions/finish", s.handleResolveFinish)
	return mux
}

// serveResolutions guards every request under resolutionRoutePrefix: POST
// only, same origin, a session, and a resolver to write with.
func (s *Server) serveResolutions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	case http.MethodOptions:
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, codeBadRequest, r.Method+" is not a method "+
			"the alert-resolution surface accepts")
		return
	}
	sess, ok := s.sameOriginSession(w, r)
	if !ok {
		return
	}
	if s.resolver == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, resolutionDisabledMessage)
		return
	}
	ctx := withAccountSession(r.Context(), sess)
	s.resolutionMux.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) handleResolveBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req ResolveRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > maxResolutionReasonBytes {
		writeError(w, http.StatusBadRequest, codeBadRequest, "reason must be 1-2048 bytes")
		return
	}
	// Refuse what could never be written before anyone is asked for a
	// passkey: unknown, not an alert, or already resolved.
	if err := s.resolver.alerts.CheckOpen(ctx, req.EventIDs); err != nil {
		writeResolutionError(w, err)
		return
	}

	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	if len(user.credentials) == 0 {
		writeError(w, http.StatusForbidden, codeForbidden, resolutionNeedsPasskeyMessage)
		return
	}
	assertion, sessionData, err := s.webAuthn.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the "+
			"confirmation ceremony: "+err.Error())
		return
	}
	body, err := json.Marshal(pendingResolution{Session: *sessionData, EventIDs: req.EventIDs, Reason: reason})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	ceremonyID, err := s.authStore.SaveCeremony(ctx, ceremonyKindResolveAlerts, body, userID, "", authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, loginCeremonyResponse{CeremonyID: ceremonyID, CredentialAssertion: assertion})
}

func (s *Server) handleResolveFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req finishRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}

	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, ceremonyKindResolveAlerts)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, resolutionCeremonyExpiredMessage)
		return
	}
	if ceremony.PendingUserID != userID {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "this confirmation does not "+
			"belong to the signed-in user")
		return
	}
	var pending pendingResolution
	if jerr := json.Unmarshal(ceremony.SessionData, &pending); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return
	}

	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	cred, err := s.webAuthn.FinishLogin(user, pending.Session, credentialHTTPRequest(req.Credential))
	if err != nil {
		s.recordAuth(ctx, AuthEventAlertResolutionRefused, userID, "the passkey did not verify: "+err.Error())
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "the passkey did not confirm "+
			"this resolution: "+err.Error())
		return
	}
	if uerr := s.authStore.UpdatePasskey(ctx, *cred); uerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not update the passkey")
		return
	}

	written, err := s.resolver.alerts.ResolveAlerts(ctx, pending.EventIDs, user.displayName, pending.Reason)
	if err != nil {
		writeResolutionError(w, err)
		return
	}
	s.recordAuth(ctx, AuthEventAlertsResolved, userID, strings.Join(pending.EventIDs, " "))

	out := ResolveResult{Resolutions: make([]Resolution, len(written))}
	for i, res := range written {
		out.Resolutions[i] = Resolution{
			EventID: res.EventID, ResolvedBy: res.ResolvedBy, ResolvedAt: res.ResolvedAt, Reason: res.Reason,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// writeResolutionError maps the ledger's named refusals to their statuses.
// Anything else is the ledger not answering, which says nothing about the
// alerts named.
func writeResolutionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ledger.ErrAlertAlreadyResolved):
		writeError(w, http.StatusConflict, codeConflict, err.Error())
	case errors.Is(err, ledger.ErrAlertNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, err.Error())
	case errors.Is(err, ledger.ErrNotAnAlert), errors.Is(err, ledger.ErrBadResolution):
		writeError(w, http.StatusBadRequest, codeBadRequest, err.Error())
	default:
		writeError(w, http.StatusServiceUnavailable, codeUnavailable,
			"the ledger did not take the resolution; nothing was written")
	}
}

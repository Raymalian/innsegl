// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The sign-in surface (RM-260/RM-261, ADR-0062). Everything in this file is
// mounted at authRoutePrefix by NewServer, and it is the ONE place in this
// package a non-GET method is ever answered — see server.go's ServeHTTP for
// why that carve-out is drawn exactly there and nowhere else.
//
// Every ceremony is two calls, begin then finish, with go-webauthn's own
// SessionData held server-side between them (AuthStore's webauthn_ceremonies
// table) rather than trusted back from the client: a ceremony id names it,
// is single-use (LoadAndConsumeCeremony deletes on read), and expires on its
// own short clock (authCeremonyTTL) independent of anything the client says.

// authRoutePrefix is the one path prefix ServeHTTP hands to authMux instead
// of the read-only mux, and the one prefix the method guard and the
// deny-by-default session gate both skip.
const authRoutePrefix = "/api/v1/auth/"

// authCeremonyTTL bounds how long a begun-but-not-finished ceremony may be
// completed. Short, because nothing about a passkey ceremony should still be
// pending minutes later, and a short bound narrows the window AUTH-004's
// replay case has to land in.
const authCeremonyTTL = 5 * time.Minute

// defaultSessionLifetime is applied when ServerConfig.SessionLifetime is
// zero. ADR-0062 leaves the exact number to #409 to measure and tune; this
// is a starting point for a console an operator opens once or twice a day,
// not a value the ADR fixes.
const defaultSessionLifetime = 12 * time.Hour

// sessionCookieName is the one cookie this surface ever sets.
const sessionCookieName = "innsegl_session"

// maxAuthRequestBodyBytes bounds every request this file parses. A WebAuthn
// ceremony body is a few kilobytes at most; this is generous headroom, not a
// bound chosen to just barely fit one.
const maxAuthRequestBodyBytes = 64 << 10 // 64 KiB

// authMux wires the sign-in surface's own routes. Built once by NewServer.
func (s *Server) newAuthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/auth/session", s.handleAuthSession)
	mux.HandleFunc("GET /api/v1/auth/setup", s.handleAuthSetup)
	mux.HandleFunc("POST /api/v1/auth/enrol/begin", s.handleEnrolBegin)
	mux.HandleFunc("POST /api/v1/auth/enrol/finish", s.handleEnrolFinish)
	mux.HandleFunc("POST /api/v1/auth/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/v1/auth/login/finish", s.handleLoginFinish)
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/v1/auth/recover", s.handleRecover)
	// #481: an invited person with no account yet, holding the link.
	mux.HandleFunc("POST /api/v1/auth/invitation", s.handleInvitationPreview)
	mux.HandleFunc("POST /api/v1/auth/invitation/begin", s.handleInvitationBegin)
	mux.HandleFunc("POST /api/v1/auth/invitation/finish", s.handleInvitationFinish)
	return mux
}

// serveAuth is what ServeHTTP calls for every request under authRoutePrefix.
// It enforces the one thing every route here shares — same-origin — before
// any of them runs, and refuses any method the sub-mux itself would 404 on
// with the same 405 the read-only surface gives (belt and braces: the
// sub-mux already only registers GET and POST on the paths above).
func (s *Server) serveAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodOptions {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, codeBadRequest, r.Method+" is not a method "+
			"the sign-in surface accepts")
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// AUTH-004: a request from another origin is refused before it reaches a
	// handler. WebAuthn's own ceremony verification already refuses an
	// assertion or attestation collected at the wrong origin (the library
	// checks CollectedClientData.Origin against RPOrigins); this check
	// refuses the REQUEST itself, which also covers /logout and
	// /auth/session, neither of which carries a WebAuthn ceremony for the
	// library to check. A same-origin fetch always sets Origin on a POST in
	// every browser this dashboard is documented to run in, so requiring it
	// present costs nothing a legitimate client was not already sending.
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.webAuthnConfig.RPOrigin {
		writeError(w, http.StatusForbidden, codeForbidden,
			"this request's Origin does not match the dashboard's own origin")
		return
	}
	s.authMux.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// GET /api/v1/auth/session — "am I signed in"
// ---------------------------------------------------------------------------

// SessionStatus answers GET /api/v1/auth/session. Organisations are the
// signed-in person's live memberships (AUTH-005, #480), read on every
// request: the dashboard's organisation switcher reads them here, and a
// removal shows on the next request.
type SessionStatus struct {
	Authenticated bool                  `json:"authenticated"`
	DisplayName   string                `json:"display_name,omitempty"`
	Organisations []SessionOrganisation `json:"organisations,omitempty"`
}

// SessionOrganisation is one membership as the session reports it.
type SessionOrganisation struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Operator bool   `json:"operator"`
}

func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := s.sessionFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusOK, SessionStatus{Authenticated: false})
		return
	}
	u, err := s.authStore.UserByID(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusOK, SessionStatus{Authenticated: false})
		return
	}
	out := SessionStatus{Authenticated: true, DisplayName: u.DisplayName, Organisations: []SessionOrganisation{}}
	if s.orgs != nil {
		ms, merr := s.orgs.Memberships(r.Context(), userID)
		if merr != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
			return
		}
		for _, m := range ms {
			out.Organisations = append(out.Organisations,
				SessionOrganisation{ID: m.AccountID, Name: m.Name, Role: m.Role, Operator: m.Operator})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// GET /api/v1/auth/setup — "does an account still need creating" (#445)
// ---------------------------------------------------------------------------

// handleAuthSetup answers the setup link's own status check: `make start`
// and install.sh print a setup link only while this says Needed, and the
// setup page itself asks this before showing "create your account" so a
// stale or reused link says so rather than silently re-running first-user
// enrolment. No session: it is the one question a person with no account yet
// must be able to ask.
func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	open, err := s.authStore.EnrolmentOpen(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not check enrolment state")
		return
	}
	writeJSON(w, http.StatusOK, SetupStatus{Needed: open})
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/enrol/begin
// ---------------------------------------------------------------------------

type enrolBeginRequest struct {
	DisplayName string `json:"display_name"`
	Code        string `json:"code"`
}

type ceremonyResponse struct {
	CeremonyID string `json:"ceremony_id"`
	*protocol.CredentialCreation
}

type loginCeremonyResponse struct {
	CeremonyID string `json:"ceremony_id"`
	*protocol.CredentialAssertion
}

func (s *Server) handleEnrolBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req enrolBeginRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	open, err := s.authStore.EnrolmentOpen(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not check enrolment state")
		return
	}
	if !open {
		s.recordAuth(ctx, AuthEventEnrolmentRefused, "", "a user with a passkey already exists")
		writeError(w, http.StatusForbidden, codeForbidden, "this deployment already has a "+
			"signed-in user; enrolment is only for the first one (ADR-0062). Sign in instead.")
		return
	}

	if req.DisplayName == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, "display_name is required")
		return
	}

	if cerr := s.authStore.ConsumeEnrolmentCode(ctx, req.Code); cerr != nil {
		s.recordAuth(ctx, AuthEventEnrolmentRefused, "", "the one-time code was not admissible")
		writeError(w, http.StatusForbidden, codeForbidden, "that one-time code is not usable: "+
			"it may be wrong, already used, or expired. Mint a new one with "+
			"`innsegl admin-credential enrol-code`.")
		return
	}

	userID, err := NewUserID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}
	user := dbUser{id: userID, displayName: req.DisplayName}
	creation, sessionData, err := s.webAuthn.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(registrationSelection),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the "+
			"registration ceremony: "+err.Error())
		return
	}
	body, err := json.Marshal(sessionData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	ceremonyID, err := s.authStore.SaveCeremony(ctx, "register", body, userID, req.DisplayName, authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, ceremonyResponse{CeremonyID: ceremonyID, CredentialCreation: creation})
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/enrol/finish
// ---------------------------------------------------------------------------

type finishRequest struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) handleEnrolFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req finishRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}

	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, "register")
	if err != nil {
		s.recordAuth(ctx, AuthEventEnrolmentRefused, "", "no matching enrolment ceremony")
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "this enrolment ceremony has "+
			"expired or was already completed; start over")
		return
	}
	var sessionData webauthn.SessionData
	if jerr := json.Unmarshal(ceremony.SessionData, &sessionData); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return
	}

	user := dbUser{id: ceremony.PendingUserID, displayName: ceremony.PendingDisplayName}
	cred, err := s.webAuthn.FinishRegistration(user, sessionData, credentialHTTPRequest(req.Credential))
	if err != nil {
		s.recordAuth(ctx, AuthEventEnrolmentRefused, "", "the registration ceremony did not verify: "+err.Error())
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "the passkey could not be "+
			"registered: "+err.Error())
		return
	}

	if cerr := s.authStore.CreateUser(ctx, ceremony.PendingUserID, ceremony.PendingDisplayName); cerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not create the user")
		return
	}
	if _, aerr := s.authStore.AddPasskey(ctx, ceremony.PendingUserID, defaultFirstPasskeyName, *cred); aerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the passkey")
		return
	}
	// ADR-0062 amendment (#445): "Ten single-use codes are shown once when
	// the account is created." First enrolment is the one moment this
	// account has no recovery codes yet, so minting here is MintRecoveryCodes'
	// ordinary "replace whatever exists" behaviour, not a special case of it.
	codes, merr := s.authStore.MintRecoveryCodes(ctx, ceremony.PendingUserID)
	if merr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not mint recovery codes")
		return
	}
	s.recordAuth(ctx, AuthEventEnrolmentCompleted, ceremony.PendingUserID,
		"attestation format: "+cred.AttestationFormat)
	// The first user owns the deployment's own organisation, so the account
	// page has one to connect machines from. A failure here does not undo
	// the account: the API founds it again when it next starts.
	if s.orgs != nil {
		if _, ferr := s.orgs.FoundOperator(ctx); ferr != nil {
			s.recordAuth(ctx, AuthEventEnrolmentCompleted, ceremony.PendingUserID,
				"the operator organisation was not created: "+ferr.Error())
		}
	}

	if serr := s.startSession(w, r, ceremony.PendingUserID, credentialIDString(cred.ID)); serr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not create a session")
		return
	}
	writeJSON(w, http.StatusOK, EnrolFinished{
		Authenticated: true, DisplayName: ceremony.PendingDisplayName, RecoveryCodes: codes,
	})
}

// defaultFirstPasskeyName is what first-user enrolment names the one
// passkey it adds: the setup page (ADR-0062 amendment) asks for an account
// name, never a passkey name, so this is a placeholder a person can rename
// from the account page like any other.
const defaultFirstPasskeyName = "Primary passkey"

// ---------------------------------------------------------------------------
// POST /api/v1/auth/login/begin — discoverable (usernameless) login
// ---------------------------------------------------------------------------

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assertion, sessionData, err := s.webAuthn.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the "+
			"sign-in ceremony: "+err.Error())
		return
	}
	body, err := json.Marshal(sessionData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	ceremonyID, err := s.authStore.SaveCeremony(ctx, "login", body, "", "", authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, loginCeremonyResponse{CeremonyID: ceremonyID, CredentialAssertion: assertion})
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/login/finish
// ---------------------------------------------------------------------------

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req finishRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}

	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, "login")
	if err != nil {
		s.recordAuth(ctx, AuthEventSignInRefused, "", "no matching sign-in ceremony")
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "this sign-in ceremony has "+
			"expired or was already completed; start over")
		return
	}
	var sessionData webauthn.SessionData
	if jerr := json.Unmarshal(ceremony.SessionData, &sessionData); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return
	}

	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, lerr := loadUser(ctx, s.authStore, string(userHandle))
		if lerr != nil {
			return nil, lerr
		}
		return u, nil
	}

	user, cred, err := s.webAuthn.FinishPasskeyLogin(handler, sessionData, credentialHTTPRequest(req.Credential))
	if err != nil {
		s.recordAuth(ctx, AuthEventSignInRefused, "", "the sign-in ceremony did not verify: "+err.Error())
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "sign-in failed: "+err.Error())
		return
	}
	if uerr := s.authStore.UpdatePasskey(ctx, *cred); uerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not update the passkey")
		return
	}

	userID := string(user.WebAuthnID())
	s.recordAuth(ctx, AuthEventSignInSucceeded, userID, "")
	s.issueSession(w, r, userID, credentialIDString(cred.ID), user.WebAuthnDisplayName())
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/logout
// ---------------------------------------------------------------------------

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := s.cookieToken(r)
	userID, _, _ := s.sessionFromRequest(r)
	if err := s.authStore.RevokeSession(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not sign out")
		return
	}
	s.recordAuth(r.Context(), AuthEventSignOut, userID, "")
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, struct{}{})
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/recover (#445) — a one-time way back in with no passkey
// ---------------------------------------------------------------------------

// handleRecover is ADR-0062 amendment's recovery door: a signed-in session
// with no passkey behind it at all, good for reaching the account page and
// adding one. No session required to call it — that is the whole point, the
// same "AUTH-002's ceremony has no session yet" reasoning enrol/begin
// already holds to.
func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req RecoverRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}

	userID, remaining, err := s.authStore.ConsumeRecoveryCode(ctx, req.Code)
	if err != nil {
		s.recordAuth(ctx, AuthEventSignInRefused, "", "a recovery code was not admissible")
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "that recovery code is not "+
			"usable: it may be wrong or already used")
		return
	}
	u, uerr := s.authStore.UserByID(ctx, userID)
	if uerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	// No passkey_id: a recovery-code session names no passkey (ADR-0062
	// amendment, Account.passkeys[].current's own doc comment).
	if serr := s.startSession(w, r, userID, ""); serr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not create a session")
		return
	}
	s.recordAuth(ctx, AuthEventSignInSucceeded, userID, "recovery code")
	writeJSON(w, http.StatusOK, RecoverResult{
		Authenticated: true, DisplayName: u.DisplayName, Remaining: remaining,
	})
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// decodeAuthRequest reads and decodes a bounded JSON body, writing its own
// error response and returning false on any failure.
func decodeAuthRequest(w http.ResponseWriter, r *http.Request, into any) bool {
	limited := io.LimitReader(r.Body, maxAuthRequestBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, "the request body could not be read")
		return false
	}
	if len(body) > maxAuthRequestBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, codeBadRequest, "the request body is too large")
		return false
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	if jerr := json.Unmarshal(body, into); jerr != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, "the request body is not valid JSON")
		return false
	}
	return true
}

// credentialHTTPRequest wraps a raw client credential response as the
// *http.Request go-webauthn's Finish* functions read their body from — the
// same technique the library's own tests use (see
// TestFinishRegistration_Success in its webauthn package).
func credentialHTTPRequest(body []byte) *http.Request {
	return &http.Request{Body: io.NopCloser(bytes.NewReader(body))}
}

// startSession mints a session for userID — carrying passkeyID when one
// signed in this session into being, empty for a recovery-code session — and
// sets the cookie, writing NO body: handleEnrolFinish and handleRecover each
// have their own response shape to write afterwards, which is the one thing
// that differs between every caller of CreateSession (#445). issueSession
// below is the one shared shape, login/finish's own.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID, passkeyID string) error {
	token, expiresAt, err := s.authStore.CreateSession(r.Context(), userID, passkeyID, s.sessionLifetime)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, token, expiresAt)
	return nil
}

// issueSession is startSession plus the ordinary SessionStatus body
// login/finish answers with.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, userID, passkeyID, displayName string) {
	if err := s.startSession(w, r, userID, passkeyID); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not create a session")
		return
	}
	writeJSON(w, http.StatusOK, SessionStatus{Authenticated: true, DisplayName: displayName})
}

// setSessionCookie sets the one cookie this surface issues. ADR-0062: the
// cookie is HttpOnly, SameSite=Strict, Secure where the origin is https, and
// bounded — every one of those is set here and nowhere else in this package.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	//nolint:gosec // G124: Secure is conditional on the origin's own scheme
	// (ADR-0062: "Secure where the origin is https"), not omitted — an
	// http://localhost deployment whose cookie forced Secure would never
	// have that cookie sent back at all.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.webAuthnConfig.RPOrigin, "https://"),
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

// clearSessionCookie tells the browser to forget the cookie — belt as well
// as braces alongside the server-side revoke, which is the half that
// actually matters (ADR-0062: "not merely instructs the browser to forget
// the cookie").
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	//nolint:gosec // G124: Secure is conditional on the origin's own scheme, same reason as setSessionCookie.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(s.webAuthnConfig.RPOrigin, "https://"),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// cookieToken reads the raw session cookie, or "" if there is none.
func (s *Server) cookieToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// sessionFromRequest is the one question the deny-by-default gate asks of
// every non-allow-listed request: does this request carry a live session?
// passkeyID is the passkey (if any) that session was issued for — #445's
// account surface uses it to answer Account.passkeys[].current; nothing
// before #445 needed it and every such caller discards it.
func (s *Server) sessionFromRequest(r *http.Request) (userID, passkeyID string, ok bool) {
	token := s.cookieToken(r)
	if token == "" {
		return "", "", false
	}
	userID, passkeyID, ok, err := s.authStore.VerifySession(r.Context(), token)
	if err != nil || !ok {
		return "", "", false
	}
	return userID, passkeyID, true
}

// recordAuth writes an auth event and swallows a failure to do so — see
// AuthStore.RecordAuthEvent's own comment for why a recording failure never
// blocks the ceremony it describes. discardError (readonly.go) rather than a
// blank assignment: errcheck runs with check-blank, so a discard has to be
// visible and named.
func (s *Server) recordAuth(ctx context.Context, eventType, userID, detail string) {
	discardError(s.authStore.RecordAuthEvent(ctx, eventType, userID, detail))
}

// codeForbidden, codeUnauthorized and codeConflict extend server.go's
// error-code vocabulary for the sign-in surface and (#445) the account
// surface accounthandlers.go mounts beside it.
const (
	codeForbidden    = "forbidden"
	codeUnauthorized = "unauthorized"
	codeConflict     = "conflict"
)

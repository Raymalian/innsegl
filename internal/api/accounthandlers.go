// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

// The account surface (#445, ADR-0062's 2026-10-01 amendment): a signed-in
// user's own profile, the passkeys they manage, and their recovery codes.
// Mounted at accountRoutePrefix by NewServer, parallel to authhandlers.go's
// sign-in surface — but where that surface is mostly PUBLIC (no session),
// every route here requires one: there is no account to look at without
// being signed into it.

// accountRoutePrefix is the prefix ServeHTTP hands to accountMux instead of
// the read-only mux — the account surface's own carve-out, alongside
// authRoutePrefix's.
const accountRoutePrefix = "/api/v1/account"

// newAccountMux wires the account surface's own routes. Built once by
// NewServer.
func (s *Server) newAccountMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/account", s.handleGetAccount)
	mux.HandleFunc("PATCH /api/v1/account", s.handlePatchAccount)
	mux.HandleFunc("POST /api/v1/account/passkeys/begin", s.handlePasskeyBegin)
	mux.HandleFunc("POST /api/v1/account/passkeys/finish", s.handlePasskeyFinish)
	mux.HandleFunc("PATCH /api/v1/account/passkeys/{id}", s.handlePasskeyRename)
	mux.HandleFunc("DELETE /api/v1/account/passkeys/{id}", s.handlePasskeyDelete)
	mux.HandleFunc("POST /api/v1/account/recovery-codes", s.handleRecoveryCodesRegenerate)
	return mux
}

// serveAccount is what ServeHTTP calls for every request under
// accountRoutePrefix: the method guard, the SAME same-origin check
// serveAuth's own mutating routes enforce (#445: "Mutating auth routes
// already check Origin — new ones must too" — applied here to every method,
// matching serveAuth's own unconditional check), and — the one rule that
// differs from serveAuth — a session, required on every route, because
// there is no public one here.
func (s *Server) serveAccount(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST, PATCH, DELETE, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, codeBadRequest, r.Method+" is not a method "+
			"the account surface accepts")
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, HEAD, POST, PATCH, DELETE, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sess, ok := s.sameOriginSession(w, r)
	if !ok {
		return
	}
	// Verified once, here, and carried on the request's own context — every
	// handler below reads it with accountSessionFrom rather than asking
	// sessionFromRequest a second time, which would either have to re-trust
	// an answer already known or re-run the same query for no new
	// information (the request has not changed between the two calls).
	s.accountMux.ServeHTTP(w, r.WithContext(withAccountSession(r.Context(), sess)))
}

// sameOriginSession is the check every signed-in mutating surface shares
// (#445's account routes, RM-330's alert resolutions): the request's Origin,
// when it carries one, is the dashboard's own, and the request carries a live
// session. It writes the refusal itself and returns false on either failure.
func (s *Server) sameOriginSession(w http.ResponseWriter, r *http.Request) (accountSession, bool) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.webAuthnConfig.RPOrigin {
		writeError(w, http.StatusForbidden, codeForbidden,
			"this request's Origin does not match the dashboard's own origin")
		return accountSession{}, false
	}
	userID, passkeyID, ok := s.sessionFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, codeUnauthorized,
			"sign in required (ADR-0062): this dashboard and its read API answer "+
				"nothing without an operator session")
		return accountSession{}, false
	}
	return accountSession{userID: userID, passkeyID: passkeyID}, true
}

// withAccountSession carries a verified session on a request's context, for
// accountSessionFrom to read.
func withAccountSession(ctx context.Context, sess accountSession) context.Context {
	return context.WithValue(ctx, accountSessionContextKey{}, sess)
}

// accountSession is what serveAccount already verified about the caller:
// which user, and which passkey (if any — empty for a recovery-code
// session) issued the session they are using.
type accountSession struct {
	userID    string
	passkeyID string
}

// accountSessionContextKey is unexported, so only this file can set or read
// the value it keys — a request that reaches one of this file's handlers
// without going through serveAccount first (there is no such path: every
// handler below is only ever registered on accountMux, which only
// serveAccount ever dispatches to) would read the zero value, an empty
// userID, rather than panic.
type accountSessionContextKey struct{}

// accountSessionFrom reads what serveAccount verified. Every handler in this
// file calls it exactly once.
func accountSessionFrom(r *http.Request) accountSession {
	if sess, ok := r.Context().Value(accountSessionContextKey{}).(accountSession); ok {
		return sess
	}
	return accountSession{}
}

// ---------------------------------------------------------------------------
// GET /api/v1/account, PATCH /api/v1/account
// ---------------------------------------------------------------------------

// accountFor assembles Account for a signed-in user — shared by
// handleGetAccount and handlePatchAccount so the two cannot answer a
// different shape for the same user. currentPasskeyID is the requesting
// session's own passkey_id (sessionFromRequest's second return), empty for
// a recovery-code session.
func (s *Server) accountFor(ctx context.Context, userID, currentPasskeyID string) (Account, error) {
	u, err := s.authStore.UserByID(ctx, userID)
	if err != nil {
		return Account{}, err
	}
	rows, err := s.authStore.AccountPasskeys(ctx, userID)
	if err != nil {
		return Account{}, err
	}
	remaining, err := s.authStore.RecoveryCodesRemaining(ctx, userID)
	if err != nil {
		return Account{}, err
	}

	passkeys := make([]AccountPasskey, len(rows))
	for i, row := range rows {
		passkeys[i] = AccountPasskey{
			ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt,
			LastUsedAt: row.LastUsedAt, Current: currentPasskeyID != "" && row.ID == currentPasskeyID,
		}
	}
	return Account{
		UserID: u.UserID, DisplayName: u.DisplayName, CreatedAt: u.CreatedAt,
		Passkeys: passkeys, RecoveryCodesRemaining: remaining,
	}, nil
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	sess := accountSessionFrom(r)
	acc, err := s.accountFor(r.Context(), sess.userID, sess.passkeyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

func (s *Server) handlePatchAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := accountSessionFrom(r)
	var req AccountUpdate
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.DisplayName)
	if name == "" || len(name) > 64 {
		writeError(w, http.StatusBadRequest, codeBadRequest, "display_name must be 1-64 characters")
		return
	}
	if err := s.authStore.UpdateDisplayName(ctx, sess.userID, name); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not update the account")
		return
	}
	acc, err := s.accountFor(ctx, sess.userID, sess.passkeyID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	writeJSON(w, http.StatusOK, acc)
}

// ---------------------------------------------------------------------------
// POST /api/v1/account/passkeys/begin, .../finish
// ---------------------------------------------------------------------------

func (s *Server) handlePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req PasskeyBeginRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		writeError(w, http.StatusBadRequest, codeBadRequest, "name must be 1-64 characters")
		return
	}

	u, err := s.authStore.UserByID(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	existing, err := s.authStore.PasskeysByUser(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not list existing passkeys")
		return
	}

	user := dbUser{id: userID, displayName: u.DisplayName, credentials: existing}
	creation, sessionData, err := s.webAuthn.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(registrationSelection),
		// A passkey already on this account must not be offered again by
		// the platform's own "use an existing passkey" prompt.
		webauthn.WithExclusions(webauthn.Credentials(existing).CredentialDescriptors()),
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
	// pending_user_id/pending_display_name are reused for a DIFFERENT
	// purpose than 'register' puts them to — see migration 0009's own
	// comment: here they carry the ALREADY-signed-in user (never a new one)
	// and the NAME this new passkey is being given.
	ceremonyID, err := s.authStore.SaveCeremony(ctx, "add_passkey", body, userID, name, authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, ceremonyResponse{CeremonyID: ceremonyID, CredentialCreation: creation})
}

func (s *Server) handlePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req finishRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}

	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, "add_passkey")
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "this ceremony has expired "+
			"or was already completed; start over")
		return
	}
	if ceremony.PendingUserID != userID {
		// Defends against a ceremony begun by one session and finished by
		// another — same-origin and the session cookie already make this
		// unreachable in the browser, but the ceremony id alone does not
		// prove who is presenting it.
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "this ceremony does not "+
			"belong to the signed-in user")
		return
	}
	var sessionData webauthn.SessionData
	if jerr := json.Unmarshal(ceremony.SessionData, &sessionData); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return
	}

	u, err := s.authStore.UserByID(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	existing, err := s.authStore.PasskeysByUser(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not list existing passkeys")
		return
	}
	user := dbUser{id: userID, displayName: u.DisplayName, credentials: existing}

	cred, err := s.webAuthn.FinishRegistration(user, sessionData, credentialHTTPRequest(req.Credential))
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "the passkey could not be "+
			"registered: "+err.Error())
		return
	}
	name := ceremony.PendingDisplayName
	createdAt, aerr := s.authStore.AddPasskey(ctx, userID, name, *cred)
	if aerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the passkey")
		return
	}
	s.recordAuth(ctx, AuthEventPasskeyAdded, userID, "attestation format: "+cred.AttestationFormat)

	// Current is always false here: THIS session signed in with whatever
	// passkey (or recovery code) it already holds, never with the one it
	// just finished adding (AccountPasskey's own doc comment).
	writeJSON(w, http.StatusOK, AccountPasskey{
		ID: credentialIDString(cred.ID), Name: name, CreatedAt: createdAt, LastUsedAt: nil, Current: false,
	})
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/account/passkeys/{id}, DELETE /api/v1/account/passkeys/{id}
// ---------------------------------------------------------------------------

func (s *Server) handlePasskeyRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := accountSessionFrom(r)
	var req PasskeyRename
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		writeError(w, http.StatusBadRequest, codeBadRequest, "name must be 1-64 characters")
		return
	}

	row, err := s.authStore.RenamePasskey(ctx, sess.userID, r.PathValue("id"), name)
	if err != nil {
		if errors.Is(err, ErrPasskeyNotFound) {
			writeError(w, http.StatusNotFound, codeNotFound, "no such passkey")
			return
		}
		writeError(w, http.StatusInternalServerError, codeInternal, "could not rename the passkey")
		return
	}
	writeJSON(w, http.StatusOK, AccountPasskey{
		ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt, LastUsedAt: row.LastUsedAt,
		Current: sess.passkeyID != "" && row.ID == sess.passkeyID,
	})
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	id := r.PathValue("id")
	if err := s.authStore.DeletePasskey(ctx, userID, id); err != nil {
		switch {
		case errors.Is(err, ErrLastPasskey):
			writeError(w, http.StatusConflict, codeConflict, "this is the only passkey on the "+
				"account; add another one before removing this one")
		case errors.Is(err, ErrPasskeyNotFound):
			writeError(w, http.StatusNotFound, codeNotFound, "no such passkey")
		default:
			writeError(w, http.StatusInternalServerError, codeInternal, "could not remove the passkey")
		}
		return
	}
	s.recordAuth(ctx, AuthEventPasskeyRemoved, userID, "")
	writeJSON(w, http.StatusOK, struct{}{})
}

// ---------------------------------------------------------------------------
// POST /api/v1/account/recovery-codes
// ---------------------------------------------------------------------------

func (s *Server) handleRecoveryCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	codes, err := s.authStore.MintRecoveryCodes(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not mint recovery codes")
		return
	}
	s.recordAuth(ctx, AuthEventRecoveryCodesRegenerated, userID, "")
	writeJSON(w, http.StatusOK, RecoveryCodes{Codes: codes})
}

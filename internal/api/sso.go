// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Signing in with an organisation's identity provider (#485, E30).
//
// Sign-in surface (no session):
//
//	POST /api/v1/auth/sso/begin       {sign_in_name} -> {redirect_url}
//	GET  /api/v1/auth/sso/callback    the provider sends the browser back here
//
// Account surface (signed in):
//
//	GET    /api/v1/account/sso?organisation_id=ID   the organisation's sign-in
//	POST   /api/v1/account/sso/configure/begin|finish   owner, fresh passkey
//	POST   /api/v1/account/sso/remove/begin|finish      owner, fresh passkey
//	POST   /api/v1/account/sso/link       {organisation_id or sign_in_name} -> {redirect_url}
//	DELETE /api/v1/account/sign-ins/{id}  unlink one of your own
//
// A sign-in joins an EXISTING person. The provider's identity (issuer and
// subject, nothing else) must first be linked from the account page by a
// person signed in some other way; linking makes them a member of the
// organisation if they never were one. Signing in through an organisation
// whose owner removed you is refused; an invitation brings you back.
//
// One sign-in in flight is a ceremony of kind 'sso' (migration 0019): its id
// is the OAuth state, loading it deletes it (single use), it expires on its
// own clock, and it holds the nonce, the PKCE verifier and the hash of a
// cookie set on the browser that began it. The callback refuses a browser
// without that cookie. The session a sign-in opens is the same cookie a
// passkey gets, naming the connection so the owner's changes can end it.
//
// Nothing the provider sends reaches an auth event, an audit row or a
// response beyond the issuer and subject held in oidc_identities.

const (
	ssoCallbackPath = "/api/v1/auth/sso/callback"
	ssoCookieName   = "innsegl_sso"
	ceremonyKindSSO = "sso"

	ceremonyKindConfigureSSO = "configure_sso"
	ceremonyKindRemoveSSO    = "remove_sso"

	// AuthEventSSOConfigured and AuthEventSSORemoved are the owner's two
	// changes; sign-ins and refusals are signin_succeeded and
	// signin_refused, detailed "organisation sign-in: ...".
	AuthEventSSOConfigured = "sso_configured"
	AuthEventSSORemoved    = "sso_removed"
	AuthEventSSOLinked     = "sso_linked"
	AuthEventSSOUnlinked   = "sso_unlinked"
)

// ssoFlightTTL bounds a sign-in between begin and the provider sending the
// browser back: long enough to type a password and pass a second factor.
const ssoFlightTTL = 10 * time.Minute

// Where the callback sends the browser on a refusal: the sign-in page, or
// the account page for a link, with ?sso=<reason>. The dashboard words it.
const (
	ssoReasonExpired  = "expired"  // no such state, spent, or past its bound
	ssoReasonBrowser  = "browser"  // not the browser that began it
	ssoReasonDenied   = "denied"   // the provider answered with an error
	ssoReasonChanged  = "changed"  // the owner changed the connection mid-flight
	ssoReasonProvider = "provider" // the provider could not be used
	ssoReasonRefused  = "refused"  // the ID token was refused
	ssoReasonUnknown  = "unknown"  // no account holds this identity
	ssoReasonRemoved  = "removed"  // the organisation removed this person
	ssoReasonTaken    = "taken"    // another account holds this identity
	ssoReasonInternal = "internal"
)

// SSOSignInRequest is POST /api/v1/auth/sso/begin's body.
type SSOSignInRequest struct {
	SignInName string `json:"sign_in_name"`
}

// SSOLinkRequest is POST /api/v1/account/sso/link's body: the organisation
// by id (a member's own) or by its sign-in name (a person joining through
// it). The name wins when both are given.
type SSOLinkRequest struct {
	OrganisationID string `json:"organisation_id"`
	SignInName     string `json:"sign_in_name"`
}

// SSOBegin answers begin and link: where to send the browser.
type SSOBegin struct {
	RedirectURL string `json:"redirect_url"`
}

// SSOConfigureRequest is POST /api/v1/account/sso/configure/begin's body.
type SSOConfigureRequest struct {
	OrganisationID string `json:"organisation_id"`
	SSOConnectionParams
}

// AccountSSO answers GET /api/v1/account/sso and configure/finish. Issuer,
// client id and the redirect URI are the owner's to see; a member sees
// whether the organisation has a sign-in and its name. The secret never
// leaves the server: HasClientSecret says whether one is held.
type AccountSSO struct {
	OrganisationID  string     `json:"organisation_id"`
	Configured      bool       `json:"configured"`
	SignInName      string     `json:"sign_in_name,omitempty"`
	Issuer          string     `json:"issuer,omitempty"`
	ClientID        string     `json:"client_id,omitempty"`
	HasClientSecret bool       `json:"has_client_secret"`
	RedirectURI     string     `json:"redirect_uri,omitempty"`
	CanManage       bool       `json:"can_manage"`
	UpdatedAt       *time.Time `json:"updated_at,omitempty"`
}

// AccountSignIn is one identity linked to the account, by the organisation
// whose sign-in linked it.
type AccountSignIn struct {
	ID           int64      `json:"id"`
	Organisation string     `json:"organisation"`
	SignInName   string     `json:"sign_in_name"`
	LinkedAt     time.Time  `json:"linked_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
}

// ssoFlight is what an 'sso' ceremony holds between begin and callback.
type ssoFlight struct {
	ConnectionID string `json:"connection_id"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	Nonce        string `json:"nonce"`
	Verifier     string `json:"verifier"`
	BindingHash  string `json:"binding_hash"`
}

const (
	ssoNotConfiguredMessage = "no organisation sign-in is set up under that name"
	ssoOwnerMessage         = "only the organisation's owner sets up or removes its sign-in"
	ssoProviderMessage      = "the identity provider could not be used: "
)

func (s *Server) registerSSOAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/sso/begin", s.handleSSOBegin)
	mux.HandleFunc("GET "+ssoCallbackPath, s.handleSSOCallback)
}

func (s *Server) registerSSOAccountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/account/sso", s.withOrgs(s.handleAccountSSO))
	mux.HandleFunc("POST /api/v1/account/sso/configure/begin", s.withOrgs(s.handleSSOConfigureBegin))
	mux.HandleFunc("POST /api/v1/account/sso/configure/finish", s.withOrgs(s.handleSSOConfigureFinish))
	mux.HandleFunc("POST /api/v1/account/sso/remove/begin", s.withOrgs(s.handleSSORemoveBegin))
	mux.HandleFunc("POST /api/v1/account/sso/remove/finish", s.withOrgs(s.handleSSORemoveFinish))
	mux.HandleFunc("POST /api/v1/account/sso/link", s.withOrgs(s.handleSSOLink))
	mux.HandleFunc("DELETE /api/v1/account/sign-ins/{id}", s.handleSSOUnlink)
}

// ssoRedirectURI is the one callback the provider is told, exactly.
func (s *Server) ssoRedirectURI() string {
	return strings.TrimRight(s.webAuthnConfig.RPOrigin, "/") + ssoCallbackPath
}

// ---------------------------------------------------------------------------
// Beginning a sign-in or a link
// ---------------------------------------------------------------------------

func (s *Server) handleSSOBegin(w http.ResponseWriter, r *http.Request) {
	if s.orgs == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, orgsUnavailableMessage)
		return
	}
	var req SSOSignInRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	c, err := s.orgs.SSOConnectionByName(r.Context(), req.SignInName)
	if err != nil {
		writeSSOLookupError(w, err)
		return
	}
	s.beginSSO(w, r, c, "")
}

// handleSSOLink begins a sign-in that links the provider's identity to the
// signed-in person. Membership is not required: linking is how a person the
// organisation's provider vouches for joins it.
func (s *Server) handleSSOLink(w http.ResponseWriter, r *http.Request) {
	var req SSOLinkRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	var (
		c   SSOConnection
		err error
	)
	if strings.TrimSpace(req.SignInName) != "" {
		c, err = s.orgs.SSOConnectionByName(r.Context(), req.SignInName)
	} else {
		c, err = s.orgs.SSOConnection(r.Context(), req.OrganisationID)
	}
	if err != nil {
		writeSSOLookupError(w, err)
		return
	}
	s.beginSSO(w, r, c, accountSessionFrom(r).userID)
}

func writeSSOLookupError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrSSONotConfigured) {
		writeError(w, http.StatusNotFound, codeNotFound, ssoNotConfiguredMessage)
		return
	}
	writeError(w, http.StatusInternalServerError, codeInternal, "could not read the organisation's sign-in")
}

// beginSSO reads the provider's discovery, records the flight, sets the
// browser's binding cookie and answers the authorization URL. linkUser is
// empty for a sign-in.
func (s *Server) beginSSO(w http.ResponseWriter, r *http.Request, c SSOConnection, linkUser string) {
	ctx := r.Context()
	meta, err := discoverOIDC(ctx, s.ssoHTTPClient, c.Issuer)
	if err != nil {
		writeError(w, http.StatusBadGateway, codeUnavailable, ssoProviderMessage+"its discovery document did not load")
		return
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}
	nonce, err := newRandomID(16)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}
	binding, err := newRandomID(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}
	body, err := json.Marshal(ssoFlight{ConnectionID: c.ID, Issuer: c.Issuer, ClientID: c.ClientID,
		Nonce: nonce, Verifier: verifier, BindingHash: hashToken(binding)})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the sign-in")
		return
	}
	state, err := s.authStore.SaveCeremony(ctx, ceremonyKindSSO, body, linkUser, "", ssoFlightTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the sign-in")
		return
	}
	//nolint:gosec // G124: Secure follows the origin's scheme, as the session cookie's does.
	http.SetCookie(w, &http.Cookie{
		Name: ssoCookieName, Value: binding, Path: ssoCallbackPath, HttpOnly: true,
		Secure: strings.HasPrefix(s.webAuthnConfig.RPOrigin, "https://"),
		// Lax, not Strict: the provider sends the browser back with a
		// top-level navigation from its own site, which a Strict cookie
		// would not ride on.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ssoFlightTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, SSOBegin{
		RedirectURL: meta.authorizationURL(c.ClientID, s.ssoRedirectURI(), state, nonce, challenge),
	})
}

// ---------------------------------------------------------------------------
// The callback
// ---------------------------------------------------------------------------

func (s *Server) clearSSOCookie(w http.ResponseWriter) {
	//nolint:gosec // G124: as beginSSO's.
	http.SetCookie(w, &http.Cookie{Name: ssoCookieName, Value: "", Path: ssoCallbackPath, HttpOnly: true,
		Secure: strings.HasPrefix(s.webAuthnConfig.RPOrigin, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// ssoLanding is where the browser goes: the sign-in page, or the account
// page for a link, with the reason on a refusal.
func ssoLanding(link bool, reason string) string {
	base := "/"
	if link {
		base = "/account"
	}
	if reason == "" {
		if link {
			return "/account?notice=sso-linked"
		}
		return "/"
	}
	return base + "?sso=" + reason
}

func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	refuse := func(link bool, userID, connectionID, reason string) {
		s.recordAuth(ctx, AuthEventSignInRefused, userID,
			"organisation sign-in: "+reason+connectionDetail(connectionID))
		http.Redirect(w, r, ssoLanding(link, reason), http.StatusSeeOther)
	}
	if s.orgs == nil {
		refuse(false, "", "", ssoReasonInternal)
		return
	}
	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, q.Get("state"), ceremonyKindSSO)
	if err != nil {
		refuse(false, "", "", ssoReasonExpired)
		return
	}
	s.clearSSOCookie(w)
	link := ceremony.PendingUserID != ""
	var f ssoFlight
	if jerr := json.Unmarshal(ceremony.SessionData, &f); jerr != nil {
		refuse(link, ceremony.PendingUserID, "", ssoReasonInternal)
		return
	}
	cookie, cerr := r.Cookie(ssoCookieName)
	if cerr != nil || subtle.ConstantTimeCompare([]byte(hashToken(cookie.Value)), []byte(f.BindingHash)) != 1 {
		refuse(link, ceremony.PendingUserID, f.ConnectionID, ssoReasonBrowser)
		return
	}
	if q.Get("error") != "" {
		refuse(link, ceremony.PendingUserID, f.ConnectionID, ssoReasonDenied)
		return
	}
	c, err := s.orgs.SSOConnectionByID(ctx, f.ConnectionID)
	if err != nil || c.Issuer != f.Issuer || c.ClientID != f.ClientID {
		refuse(link, ceremony.PendingUserID, f.ConnectionID, ssoReasonChanged)
		return
	}
	id, reason := s.ssoIdentity(ctx, c, f, q.Get("code"))
	if reason != "" {
		refuse(link, ceremony.PendingUserID, c.ID, reason)
		return
	}
	if link {
		if reason := s.linkSSO(ctx, c, id, ceremony.PendingUserID); reason != "" {
			refuse(true, ceremony.PendingUserID, c.ID, reason)
			return
		}
		s.recordAuth(ctx, AuthEventSSOLinked, ceremony.PendingUserID, "organisation sign-in linked"+connectionDetail(c.ID))
		http.Redirect(w, r, ssoLanding(true, ""), http.StatusSeeOther)
		return
	}

	userID, err := s.authStore.UserByOIDCIdentity(ctx, id.Issuer, id.Subject)
	if errors.Is(err, ErrIdentityNotFound) {
		refuse(false, "", c.ID, ssoReasonUnknown)
		return
	}
	if err != nil {
		refuse(false, "", c.ID, ssoReasonInternal)
		return
	}
	if _, _, err = s.orgs.JoinThroughSSO(ctx, c.ID, userID); err != nil {
		reason := ssoReasonInternal
		if errors.Is(err, ErrRemovedMember) {
			reason = ssoReasonRemoved
		}
		refuse(false, userID, c.ID, reason)
		return
	}
	token, expiresAt, err := s.authStore.CreateSSOSession(ctx, userID, c.ID, s.sessionLifetime)
	if err != nil {
		refuse(false, userID, c.ID, ssoReasonInternal)
		return
	}
	s.setSessionCookie(w, token, expiresAt)
	s.recordAuth(ctx, AuthEventSignInSucceeded, userID, "organisation sign-in"+connectionDetail(c.ID))
	http.Redirect(w, r, ssoLanding(false, ""), http.StatusSeeOther)
}

func connectionDetail(id string) string {
	if id == "" {
		return ""
	}
	return ", connection " + id
}

// ssoIdentity exchanges the code and verifies the ID token, answering the
// identity or the reason it was refused.
func (s *Server) ssoIdentity(ctx context.Context, c SSOConnection, f ssoFlight, code string) (oidcIdentity, string) {
	meta, err := discoverOIDC(ctx, s.ssoHTTPClient, c.Issuer)
	if err != nil {
		return oidcIdentity{}, ssoReasonProvider
	}
	raw, err := exchangeCode(ctx, s.ssoHTTPClient, meta, c.ClientID, c.ClientSecret, code, f.Verifier, s.ssoRedirectURI())
	if errors.Is(err, errIDTokenRefused) {
		return oidcIdentity{}, ssoReasonRefused
	}
	if err != nil {
		return oidcIdentity{}, ssoReasonProvider
	}
	id, err := verifyIDToken(ctx, s.ssoHTTPClient, meta, raw, c.ClientID, f.Nonce, time.Now())
	if errors.Is(err, errIDTokenRefused) {
		return oidcIdentity{}, ssoReasonRefused
	}
	if err != nil {
		return oidcIdentity{}, ssoReasonProvider
	}
	return id, ""
}

// linkSSO links the identity to userID and joins them to the organisation.
// A refused join undoes the link.
func (s *Server) linkSSO(ctx context.Context, c SSOConnection, id oidcIdentity, userID string) string {
	err := s.authStore.LinkOIDCIdentity(ctx, id.Issuer, id.Subject, userID, c.ID)
	if errors.Is(err, ErrIdentityLinkedElsewhere) {
		return ssoReasonTaken
	}
	if err != nil {
		return ssoReasonInternal
	}
	if _, _, err = s.orgs.JoinThroughSSO(ctx, c.ID, userID); err != nil {
		discardError(s.authStore.unlinkOIDCIdentityBySubject(ctx, userID, id.Issuer, id.Subject))
		if errors.Is(err, ErrRemovedMember) {
			return ssoReasonRemoved
		}
		return ssoReasonInternal
	}
	return ""
}

// ---------------------------------------------------------------------------
// The owner's settings
// ---------------------------------------------------------------------------

func (s *Server) accountSSOView(c SSOConnection, role string) AccountSSO {
	out := AccountSSO{OrganisationID: c.AccountID, Configured: c.ID != "", SignInName: c.SignInName,
		CanManage: roleMay(role, PrivilegeManageSSO)}
	if out.CanManage {
		out.RedirectURI = s.ssoRedirectURI()
		if out.Configured {
			out.Issuer, out.ClientID, out.HasClientSecret = c.Issuer, c.ClientID, c.ClientSecret != ""
			at := c.UpdatedAt.UTC()
			out.UpdatedAt = &at
		}
	}
	return out
}

func (s *Server) handleAccountSSO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountID := r.URL.Query().Get("organisation_id")
	m, ok := s.membership(ctx, w, accountSessionFrom(r).userID, accountID)
	if !ok {
		return
	}
	c, err := s.orgs.SSOConnection(ctx, accountID)
	if err != nil && !errors.Is(err, ErrSSONotConfigured) {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the organisation's sign-in")
		return
	}
	c.AccountID = accountID
	writeJSON(w, http.StatusOK, s.accountSSOView(c, m.Role))
}

// mayManageSSO answers whether userID owns accountID, writing the refusal
// when not.
func (s *Server) mayManageSSO(ctx context.Context, w http.ResponseWriter, userID, accountID string) bool {
	m, ok := s.membership(ctx, w, userID, accountID)
	if !ok {
		return false
	}
	if !roleMay(m.Role, PrivilegeManageSSO) {
		writeError(w, http.StatusForbidden, codeForbidden, ssoOwnerMessage)
		return false
	}
	return true
}

func (s *Server) handleSSOConfigureBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req SSOConfigureRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if !s.mayManageSSO(ctx, w, userID, req.OrganisationID) {
		return
	}
	req.Issuer, req.ClientID = strings.TrimSpace(req.Issuer), strings.TrimSpace(req.ClientID)
	req.SignInName = strings.ToLower(strings.TrimSpace(req.SignInName))
	if req.SignInName == "" || req.ClientID == "" {
		writeError(w, http.StatusBadRequest, codeBadRequest, "a sign-in name, an issuer and a client id are required")
		return
	}
	if err := validIssuerURL(req.Issuer); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, "the issuer must be an https URL with no user, query or fragment")
		return
	}
	// The provider is asked before the passkey prompt, so a typo in the
	// issuer costs no ceremony.
	if _, err := discoverOIDC(ctx, s.ssoHTTPClient, req.Issuer); err != nil {
		writeError(w, http.StatusBadGateway, codeUnavailable, ssoProviderMessage+"its discovery document did not "+
			"load, or names another issuer")
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindConfigureSSO, userID, req)
}

func (s *Server) handleSSOConfigureFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req SSOConfigureRequest
	if !s.finishConfirmation(w, r, ceremonyKindConfigureSSO, userID, &req) {
		return
	}
	c, err := s.orgs.SetSSOConnection(ctx, req.OrganisationID, req.SSOConnectionParams, userID)
	if err != nil {
		writeSSOChangeError(w, err)
		return
	}
	s.recordAuth(ctx, AuthEventSSOConfigured, userID, "organisation "+req.OrganisationID+connectionDetail(c.ID))
	writeJSON(w, http.StatusOK, s.accountSSOView(c, roleOwner))
}

func (s *Server) handleSSORemoveBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MemberRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if !s.mayManageSSO(ctx, w, userID, req.OrganisationID) {
		return
	}
	if _, err := s.orgs.SSOConnection(ctx, req.OrganisationID); err != nil {
		writeSSOLookupError(w, err)
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindRemoveSSO, userID, MemberRequest{OrganisationID: req.OrganisationID})
}

// SSORemoved answers .../sso/remove/finish.
type SSORemoved struct {
	SessionsRevoked int `json:"sessions_revoked"`
}

func (s *Server) handleSSORemoveFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MemberRequest
	if !s.finishConfirmation(w, r, ceremonyKindRemoveSSO, userID, &req) {
		return
	}
	n, err := s.orgs.RemoveSSOConnection(ctx, req.OrganisationID, userID)
	if err != nil {
		writeSSOChangeError(w, err)
		return
	}
	s.recordAuth(ctx, AuthEventSSORemoved, userID, "organisation "+req.OrganisationID+
		", sessions revoked "+strconv.Itoa(n))
	writeJSON(w, http.StatusOK, SSORemoved{SessionsRevoked: n})
}

func writeSSOChangeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrOrgForbidden):
		writeError(w, http.StatusForbidden, codeForbidden, ssoOwnerMessage)
	case errors.Is(err, ErrSSONameTaken):
		writeError(w, http.StatusConflict, codeConflict, "another organisation uses that sign-in name; choose another")
	case errors.Is(err, ErrOrgInvalid):
		writeError(w, http.StatusBadRequest, codeBadRequest, "the sign-in name is 2 to 63 lowercase letters, digits "+
			"and hyphens; the issuer an https URL; the client id 1 to 512 bytes")
	case errors.Is(err, ErrSSONotConfigured):
		writeError(w, http.StatusNotFound, codeNotFound, ssoNotConfiguredMessage)
	default:
		writeError(w, http.StatusInternalServerError, codeInternal, "could not change the organisation's sign-in")
	}
}

// ---------------------------------------------------------------------------
// A person's own linked identities
// ---------------------------------------------------------------------------

func (s *Server) accountSignIns(ctx context.Context, userID string) ([]AccountSignIn, error) {
	rows, err := s.authStore.OIDCIdentities(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]AccountSignIn, len(rows))
	for i, row := range rows {
		out[i] = AccountSignIn{ID: row.ID, Organisation: row.Organisation, SignInName: row.SignInName,
			LinkedAt: row.LinkedAt.UTC(), LastUsedAt: row.LastUsedAt}
	}
	return out, nil
}

func (s *Server) handleSSOUnlink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		err = s.authStore.UnlinkOIDCIdentity(ctx, userID, id)
	}
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) || errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange) {
			writeError(w, http.StatusNotFound, codeNotFound, "no such sign-in on your account")
			return
		}
		writeError(w, http.StatusInternalServerError, codeInternal, "could not remove the sign-in")
		return
	}
	s.recordAuth(ctx, AuthEventSSOUnlinked, userID, "identity "+strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, struct{}{})
}

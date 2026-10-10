// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Members, roles and invitations (RM-301 #480, RM-302 #481). The dashboard's
// pages for these are the next change; these are the routes they call.
//
// Signed in (account surface):
//
//	GET  /api/v1/account/members?organisation_id=ID   members, and invitations to a manager
//	POST /api/v1/account/invitations/begin|finish     {organisation_id, role} -> the link, once
//	POST /api/v1/account/members/role/begin|finish    {organisation_id, user_id, role}
//	POST /api/v1/account/members/remove/begin|finish  {organisation_id, user_id}
//	POST /api/v1/account/invitations/accept           {code}: join with this account
//
// No session (sign-in surface), for a person with no account yet:
//
//	POST /api/v1/auth/invitation                      {code} -> what it invites to
//	POST /api/v1/auth/invitation/begin|finish         a new passkey, the user and the membership
//
// Inviting, changing a role and removing a member each take a fresh passkey
// ceremony of their own kind (migration 0017), as connecting and revoking a
// machine do. The role is checked at begin, so a refusal costs no passkey
// prompt, and by the spine again at finish with this user as the actor
// (api.RoleMay, the one table). An invitation names no email: the link is
// the invitation, and its code rides in the URL's fragment, which a browser
// never sends to a server.

// Ceremony kinds, migration 0017's.
const (
	ceremonyKindInvite          = "invite_member"
	ceremonyKindChangeRole      = "change_member_role"
	ceremonyKindRemoveMember    = "remove_member"
	ceremonyKindRegisterInvited = "register_invited"
)

// Auth events these routes record. A code never reaches one.
const (
	AuthEventInvitationCreated  = "invitation_created"
	AuthEventInvitationAccepted = "invitation_accepted"
	AuthEventInvitationRefused  = "invitation_refused"
	AuthEventMemberRoleChanged  = "member_role_changed"
	AuthEventMemberRemoved      = "member_removed"
)

const (
	invitationInvalidMessage = "that invitation link is not usable: it may be wrong, already used, " +
		"withdrawn or expired. Ask for a new one."
	memberNotFoundMessage  = "no such member of that organisation"
	membersNeedRoleMessage = "changing the members of an organisation needs its owner or an admin, and " +
		"the owner role needs an owner"
	lastOwnerMessage     = "an organisation keeps at least one owner; make someone else an owner first"
	alreadyMemberMessage = "you are already a member of that organisation"
	invitePath           = "/invite#"
)

// AccountMembers answers GET /api/v1/account/members. Invitations are listed
// to an owner or admin only, and empty otherwise.
type AccountMembers struct {
	Members     []AccountMember     `json:"members"`
	Invitations []AccountInvitation `json:"invitations"`
	CanManage   bool                `json:"can_manage"`
}

// AccountMember is one live member. You marks the signed-in person.
type AccountMember struct {
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Since       time.Time `json:"since"`
	You         bool      `json:"you"`
}

// AccountInvitation is one invitation, without its code.
type AccountInvitation struct {
	ID         int64     `json:"id"`
	Role       string    `json:"role"`
	State      string    `json:"state"`
	CreatedBy  string    `json:"created_by"`
	AcceptedBy string    `json:"accepted_by"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// InvitationRequest is POST /api/v1/account/invitations/begin's body.
type InvitationRequest struct {
	OrganisationID string `json:"organisation_id"`
	Role           string `json:"role"`
}

// InvitationLink answers .../invitations/finish: the link, shown once.
type InvitationLink struct {
	Link           string    `json:"link"`
	OrganisationID string    `json:"organisation_id"`
	Role           string    `json:"role"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// MemberRoleRequest is POST /api/v1/account/members/role/begin's body.
type MemberRoleRequest struct {
	OrganisationID string `json:"organisation_id"`
	UserID         string `json:"user_id"`
	Role           string `json:"role"`
}

// MemberRequest is POST /api/v1/account/members/remove/begin's body.
type MemberRequest struct {
	OrganisationID string `json:"organisation_id"`
	UserID         string `json:"user_id"`
}

// MemberRemoved answers .../members/remove/finish.
type MemberRemoved struct {
	SessionsRevoked   int      `json:"sessions_revoked"`
	SuspendedMachines []string `json:"suspended_machines"`
}

// InvitationCode is the body that carries a code.
type InvitationCode struct {
	Code string `json:"code"`
}

// InvitationPreview answers POST /api/v1/auth/invitation.
type InvitationPreview struct {
	OrganisationID string    `json:"organisation_id"`
	Organisation   string    `json:"organisation"`
	Role           string    `json:"role"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// InvitationBegin is POST /api/v1/auth/invitation/begin's body.
type InvitationBegin struct {
	Code        string `json:"code"`
	DisplayName string `json:"display_name"`
}

// InvitationJoined answers POST /api/v1/auth/invitation/finish: the
// session it opened, the new account's recovery codes (shown once) and the
// organisation joined.
type InvitationJoined struct {
	Authenticated bool                `json:"authenticated"`
	DisplayName   string              `json:"display_name"`
	RecoveryCodes []string            `json:"recovery_codes"`
	Organisation  AccountOrganisation `json:"organisation"`
}

func (s *Server) registerMemberRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/account/members", s.withOrgs(s.handleMembers))
	mux.HandleFunc("POST /api/v1/account/invitations/begin", s.withOrgs(s.handleInviteBegin))
	mux.HandleFunc("POST /api/v1/account/invitations/finish", s.withOrgs(s.handleInviteFinish))
	mux.HandleFunc("POST /api/v1/account/members/role/begin", s.withOrgs(s.handleRoleBegin))
	mux.HandleFunc("POST /api/v1/account/members/role/finish", s.withOrgs(s.handleRoleFinish))
	mux.HandleFunc("POST /api/v1/account/members/remove/begin", s.withOrgs(s.handleRemoveBegin))
	mux.HandleFunc("POST /api/v1/account/members/remove/finish", s.withOrgs(s.handleRemoveFinish))
	mux.HandleFunc("POST /api/v1/account/invitations/accept", s.withOrgs(s.handleInvitationAccept))
}

func accountOrganisation(m OrgMembership) AccountOrganisation {
	return AccountOrganisation{ID: m.AccountID, Name: m.Name, Role: m.Role, Operator: m.Operator,
		Privileges: rolePrivileges(m.Role)}
}

// memberAction is the privilege a change touching roles needs: the owner's
// own when the owner role is given or taken.
func memberAction(roles ...string) string {
	if slices.Contains(roles, roleOwner) {
		return PrivilegeManageOwners
	}
	return PrivilegeManageMembers
}

func validRole(role string) bool { return role == roleOwner || role == roleAdmin || role == roleMember }

// membership answers the user's live membership of accountID, writing 403
// when there is none.
func (s *Server) membership(ctx context.Context, w http.ResponseWriter, userID, accountID string) (OrgMembership, bool) {
	orgs, _, err := s.membershipIndex(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return OrgMembership{}, false
	}
	m, ok := orgs[accountID]
	if !ok {
		writeError(w, http.StatusForbidden, codeForbidden, orgsNotMemberMessage)
		return OrgMembership{}, false
	}
	return m, true
}

// mayChangeMembers answers whether userID may take action in accountID,
// writing the refusal when not.
func (s *Server) mayChangeMembers(ctx context.Context, w http.ResponseWriter, userID, accountID, action string) bool {
	m, ok := s.membership(ctx, w, userID, accountID)
	if !ok {
		return false
	}
	if !roleMay(m.Role, action) {
		writeError(w, http.StatusForbidden, codeForbidden, membersNeedRoleMessage)
		return false
	}
	return true
}

// targetRole answers a member's current role, writing 404 when they are not
// a live member.
func (s *Server) targetRole(ctx context.Context, w http.ResponseWriter, accountID, userID string) (string, bool) {
	ms, err := s.orgs.Members(ctx, accountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the members")
		return "", false
	}
	i := slices.IndexFunc(ms, func(m OrgMember) bool { return m.UserID == userID })
	if i < 0 {
		writeError(w, http.StatusNotFound, codeNotFound, memberNotFoundMessage)
		return "", false
	}
	return ms[i].Role, true
}

// writeMemberError maps the spine's refusals of a member change.
func writeMemberError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, ErrOrgForbidden):
		writeError(w, http.StatusForbidden, codeForbidden, membersNeedRoleMessage)
	case errors.Is(err, ErrLastOwner):
		writeError(w, http.StatusConflict, codeConflict, lastOwnerMessage)
	case errors.Is(err, ErrOrgNotFound):
		writeError(w, http.StatusNotFound, codeNotFound, memberNotFoundMessage)
	case errors.Is(err, ErrAlreadyMember):
		writeError(w, http.StatusConflict, codeConflict, alreadyMemberMessage)
	case errors.Is(err, ErrInvitationInvalid):
		writeError(w, http.StatusNotFound, codeNotFound, invitationInvalidMessage)
	default:
		writeError(w, http.StatusInternalServerError, codeInternal, "could not "+what)
	}
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	accountID := r.URL.Query().Get("organisation_id")
	m, ok := s.membership(ctx, w, userID, accountID)
	if !ok {
		return
	}
	ms, err := s.orgs.Members(ctx, accountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the members")
		return
	}
	out := AccountMembers{Members: make([]AccountMember, len(ms)), Invitations: []AccountInvitation{},
		CanManage: roleMay(m.Role, PrivilegeManageMembers)}
	for i, x := range ms {
		out.Members[i] = AccountMember{UserID: x.UserID, DisplayName: x.DisplayName, Role: x.Role,
			Since: x.Since.UTC(), You: x.UserID == userID}
	}
	if out.CanManage {
		invs, ierr := s.orgs.Invitations(ctx, accountID)
		if ierr != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "could not load the invitations")
			return
		}
		for _, i := range invs {
			out.Invitations = append(out.Invitations, AccountInvitation{ID: i.ID, Role: i.Role, State: i.State,
				CreatedBy: i.CreatedBy, AcceptedBy: i.AcceptedBy, ExpiresAt: i.ExpiresAt.UTC()})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleInviteBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req InvitationRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusBadRequest, codeBadRequest, "role must be owner, admin or member")
		return
	}
	if !s.mayChangeMembers(ctx, w, userID, req.OrganisationID, memberAction(req.Role)) {
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindInvite, userID, req)
}

func (s *Server) handleInviteFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req InvitationRequest
	if !s.finishConfirmation(w, r, ceremonyKindInvite, userID, &req) {
		return
	}
	code, inv, err := s.orgs.CreateInvitation(ctx, req.OrganisationID, req.Role, userID)
	if err != nil {
		writeMemberError(w, err, "create the invitation")
		return
	}
	s.recordAuth(ctx, AuthEventInvitationCreated, userID,
		"organisation "+req.OrganisationID+", role "+req.Role+", invitation "+strconv.FormatInt(inv.ID, 10))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, InvitationLink{
		Link:           strings.TrimRight(s.webAuthnConfig.RPOrigin, "/") + invitePath + code,
		OrganisationID: req.OrganisationID, Role: inv.Role, ExpiresAt: inv.ExpiresAt.UTC(),
	})
}

func (s *Server) handleRoleBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MemberRoleRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if !validRole(req.Role) {
		writeError(w, http.StatusBadRequest, codeBadRequest, "role must be owner, admin or member")
		return
	}
	if _, ok := s.membership(ctx, w, userID, req.OrganisationID); !ok {
		return
	}
	current, ok := s.targetRole(ctx, w, req.OrganisationID, req.UserID)
	if !ok || !s.mayChangeMembers(ctx, w, userID, req.OrganisationID, memberAction(current, req.Role)) {
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindChangeRole, userID, req)
}

func (s *Server) handleRoleFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MemberRoleRequest
	if !s.finishConfirmation(w, r, ceremonyKindChangeRole, userID, &req) {
		return
	}
	if err := s.orgs.SetRole(ctx, req.OrganisationID, req.UserID, req.Role, userID); err != nil {
		writeMemberError(w, err, "change the role")
		return
	}
	s.recordAuth(ctx, AuthEventMemberRoleChanged, userID,
		"organisation "+req.OrganisationID+", member "+req.UserID+", role "+req.Role)
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleRemoveBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MemberRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	if _, ok := s.membership(ctx, w, userID, req.OrganisationID); !ok {
		return
	}
	current, ok := s.targetRole(ctx, w, req.OrganisationID, req.UserID)
	if !ok || !s.mayChangeMembers(ctx, w, userID, req.OrganisationID, memberAction(current)) {
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindRemoveMember, userID, req)
}

func (s *Server) handleRemoveFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MemberRequest
	if !s.finishConfirmation(w, r, ceremonyKindRemoveMember, userID, &req) {
		return
	}
	removal, err := s.orgs.RemoveMember(ctx, req.OrganisationID, req.UserID, userID)
	if err != nil {
		writeMemberError(w, err, "remove the member")
		return
	}
	s.recordAuth(ctx, AuthEventMemberRemoved, userID, "organisation "+req.OrganisationID+", member "+req.UserID+
		", sessions revoked "+strconv.Itoa(removal.SessionsRevoked)+", machines suspended "+
		strconv.Itoa(len(removal.Suspended)))
	out := MemberRemoved{SessionsRevoked: removal.SessionsRevoked, SuspendedMachines: removal.Suspended}
	if out.SuspendedMachines == nil {
		out.SuspendedMachines = []string{}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleInvitationAccept joins the signed-in person to the organisation the
// code invites to.
func (s *Server) handleInvitationAccept(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req InvitationCode
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	m, err := s.orgs.AcceptInvitation(ctx, req.Code, userID)
	if err != nil {
		if errors.Is(err, ErrInvitationInvalid) {
			s.recordAuth(ctx, AuthEventInvitationRefused, userID, "the link was not usable")
		}
		writeMemberError(w, err, "accept the invitation")
		return
	}
	s.recordAuth(ctx, AuthEventInvitationAccepted, userID, "organisation "+m.AccountID+", role "+m.Role)
	writeJSON(w, http.StatusOK, accountOrganisation(m))
}

// ---------------------------------------------------------------------------
// A new person, with no session yet
// ---------------------------------------------------------------------------

// invitedCeremony is what a register_invited ceremony stores: go-webauthn's
// SessionData only. The code is sent again with finish, so no live code is
// held at rest beside the ceremony.
type invitedCeremony struct {
	Session webauthn.SessionData `json:"session"`
}

// invitationFinish is POST /api/v1/auth/invitation/finish's body.
type invitationFinish struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
	Code       string          `json:"code"`
}

func (s *Server) handleInvitationPreview(w http.ResponseWriter, r *http.Request) {
	if s.orgs == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, orgsUnavailableMessage)
		return
	}
	var req InvitationCode
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	p, err := s.orgs.PeekInvitation(r.Context(), req.Code)
	if err != nil {
		writeMemberError(w, err, "read the invitation")
		return
	}
	writeJSON(w, http.StatusOK, InvitationPreview{OrganisationID: p.AccountID, Organisation: p.AccountName,
		Role: p.Role, ExpiresAt: p.ExpiresAt.UTC()})
}

func (s *Server) handleInvitationBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.orgs == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, orgsUnavailableMessage)
		return
	}
	var req InvitationBegin
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.DisplayName == "" || len(req.DisplayName) > 256 {
		writeError(w, http.StatusBadRequest, codeBadRequest, "display_name is required, at most 256 bytes")
		return
	}
	if _, err := s.orgs.PeekInvitation(ctx, req.Code); err != nil {
		if errors.Is(err, ErrInvitationInvalid) {
			s.recordAuth(ctx, AuthEventInvitationRefused, "", "the link was not usable")
		}
		writeMemberError(w, err, "read the invitation")
		return
	}
	userID, err := NewUserID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "no randomness available")
		return
	}
	creation, sessionData, err := s.webAuthn.BeginRegistration(dbUser{id: userID, displayName: req.DisplayName},
		webauthn.WithAuthenticatorSelection(registrationSelection))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the registration ceremony: "+err.Error())
		return
	}
	body, err := json.Marshal(invitedCeremony{Session: *sessionData})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	ceremonyID, err := s.authStore.SaveCeremony(ctx, ceremonyKindRegisterInvited, body, userID, req.DisplayName, authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, ceremonyResponse{CeremonyID: ceremonyID, CredentialCreation: creation})
}

func (s *Server) handleInvitationFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.orgs == nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable, orgsUnavailableMessage)
		return
	}
	var req invitationFinish
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, ceremonyKindRegisterInvited)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, confirmExpiredMessage)
		return
	}
	var pending invitedCeremony
	if jerr := json.Unmarshal(ceremony.SessionData, &pending); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return
	}
	user := dbUser{id: ceremony.PendingUserID, displayName: ceremony.PendingDisplayName}
	cred, err := s.webAuthn.FinishRegistration(user, pending.Session, credentialHTTPRequest(req.Credential))
	if err != nil {
		s.recordAuth(ctx, AuthEventInvitationRefused, "", "the registration ceremony did not verify: "+err.Error())
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "the passkey could not be registered: "+err.Error())
		return
	}
	// The user, their passkey and the membership commit together, or none
	// of them does: a link spent concurrently leaves no user behind.
	m, err := s.orgs.AcceptInvitationAsNewUser(ctx, req.Code, func(q Querier) (string, error) {
		if cerr := createUserIn(ctx, q, user.id, user.displayName); cerr != nil {
			return "", cerr
		}
		_, aerr := addPasskeyIn(ctx, q, user.id, defaultFirstPasskeyName, *cred)
		return user.id, aerr
	})
	if err != nil {
		if errors.Is(err, ErrInvitationInvalid) {
			s.recordAuth(ctx, AuthEventInvitationRefused, "", "the link was not usable")
		}
		writeMemberError(w, err, "accept the invitation")
		return
	}
	codes, err := s.authStore.MintRecoveryCodes(ctx, user.id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not mint recovery codes")
		return
	}
	s.recordAuth(ctx, AuthEventInvitationAccepted, user.id, "organisation "+m.AccountID+", role "+m.Role+
		", new account, attestation format: "+cred.AttestationFormat)
	if serr := s.startSession(w, r, user.id, credentialIDString(cred.ID)); serr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not create a session")
		return
	}
	writeJSON(w, http.StatusOK, InvitationJoined{Authenticated: true, DisplayName: user.displayName,
		RecoveryCodes: codes, Organisation: accountOrganisation(m)})
}

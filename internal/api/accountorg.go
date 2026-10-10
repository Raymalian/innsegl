// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// The account page's organisation routes (RM-333, #511, ADR-0062's
// 2026-10-03 amendment):
//
//	GET  /api/v1/account/machines                    the organisations' machines
//	POST /api/v1/account/machines/revoke/begin       {machine_id} -> passkey challenge
//	POST /api/v1/account/machines/revoke/finish      -> the revoked machine
//	POST /api/v1/account/enrolment-tokens/begin      {organisation_id, kind, repos} -> challenge
//	POST /api/v1/account/enrolment-tokens/finish     -> the token, once
//	GET  /api/v1/account/sessions                    this user's live sign-ins
//	POST /api/v1/account/sessions/sign-out-others    end every other sign-in
//	GET  /api/v1/account/repositories                the organisations' repositories
//	GET  /api/v1/account/agents                      agent types and runs on their machines
//
// Minting a token admits a machine and revoking one shuts it out, so each
// takes a fresh passkey ceremony of its own kind (migration 0014), with user
// verification, and the owner or admin role in the machine's organisation —
// checked at begin and again at finish, because a role can change in
// between. The request is held with the ceremony, so the passkey confirms
// exactly what began it, as alert resolution does (alertresolutions.go).

// Ceremony kinds, migration 0014's.
const (
	ceremonyKindMintToken     = "mint_enrolment_token" //nolint:gosec // a ceremony kind, not a credential
	ceremonyKindRevokeMachine = "revoke_installation"
	// Migration 0018's (#471).
	ceremonyKindSuspendMachine = "suspend_installation"
	ceremonyKindResumeMachine  = "resume_installation"
)

// Auth events these routes record. The token itself never reaches one.
const (
	AuthEventEnrolmentTokenMinted   = "enrolment_token_minted" //nolint:gosec // an event name, not a credential
	AuthEventMachineRevoked         = "machine_revoked"
	AuthEventMachineSuspended       = "machine_suspended"
	AuthEventMachineResumed         = "machine_resumed"
	AuthEventConfirmationRefused    = "confirmation_refused"
	AuthEventOtherSessionsSignedOut = "other_sessions_signed_out"
)

const (
	orgsUnavailableMessage = "this deployment has no accounts store, so organisations, machines and " +
		"repositories cannot be shown; run `innsegl accounts` on the core host"
	orgsNeedsRoleMessage = "revoking a machine someone else connected needs the owner or an admin of its " +
		"organisation; ask one of them"
	orgsNotMemberMessage       = "you are not a member of that organisation"
	confirmNeedsPasskey        = "this is confirmed with a passkey, and this account has none; add one first"
	confirmExpiredMessage      = "this confirmation has expired or was already used; start over"
	machineNotFoundMessage     = "no such machine in your organisations"
	machineRevokedMessage      = "that machine is already revoked"
	machineNotActiveMessage    = "only an active machine can be suspended"
	machineNotSuspendedMessage = "only a suspended machine can be resumed"
	organisationsLoadMessage   = "could not load your organisations"
)

func (s *Server) registerOrganisationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/account/machines", s.withOrgs(s.handleMachines))
	mux.HandleFunc("POST /api/v1/account/machines/revoke/begin", s.withOrgs(s.handleRevokeBegin))
	mux.HandleFunc("POST /api/v1/account/machines/revoke/finish", s.withOrgs(s.handleRevokeFinish))
	mux.HandleFunc("POST /api/v1/account/machines/suspend/begin", s.withOrgs(s.machineStatusBegin(suspendChange)))
	mux.HandleFunc("POST /api/v1/account/machines/suspend/finish", s.withOrgs(s.machineStatusFinish(suspendChange)))
	mux.HandleFunc("POST /api/v1/account/machines/resume/begin", s.withOrgs(s.machineStatusBegin(resumeChange)))
	mux.HandleFunc("POST /api/v1/account/machines/resume/finish", s.withOrgs(s.machineStatusFinish(resumeChange)))
	mux.HandleFunc("POST /api/v1/account/enrolment-tokens/begin", s.withOrgs(s.handleMintBegin))
	mux.HandleFunc("POST /api/v1/account/enrolment-tokens/finish", s.withOrgs(s.handleMintFinish))
	mux.HandleFunc("GET /api/v1/account/repositories", s.withOrgs(s.handleAccountRepositories))
	mux.HandleFunc("GET /api/v1/account/agents", s.withOrgs(s.handleAccountAgents))
	s.registerMemberRoutes(mux)
	mux.HandleFunc("GET /api/v1/account/sessions", s.handleSessions)
	mux.HandleFunc("POST /api/v1/account/sessions/sign-out-others", s.handleSignOutOthers)
}

// withOrgs answers 503 when the deployment holds no accounts spine.
func (s *Server) withOrgs(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.orgs == nil {
			writeError(w, http.StatusServiceUnavailable, codeUnavailable, orgsUnavailableMessage)
			return
		}
		h(w, r)
	}
}

// organisationsOf answers the user's organisations for Account. No spine is
// no organisations, not an error.
func (s *Server) organisationsOf(ctx context.Context, userID string) ([]AccountOrganisation, error) {
	out := []AccountOrganisation{}
	if s.orgs == nil {
		return out, nil
	}
	ms, err := s.orgs.Memberships(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		out = append(out, AccountOrganisation{
			ID: m.AccountID, Name: m.Name, Role: m.Role, Operator: m.Operator,
			Privileges: rolePrivileges(m.Role),
		})
	}
	return out, nil
}

// membershipIndex is the user's memberships by organisation id, and the ids
// in order.
func (s *Server) membershipIndex(ctx context.Context, userID string) (map[string]OrgMembership, []string, error) {
	ms, err := s.orgs.Memberships(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]OrgMembership, len(ms))
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		byID[m.AccountID] = m
		ids = append(ids, m.AccountID)
	}
	return byID, ids, nil
}

func accountMachine(m OrgMachine, org OrgMembership, userID string, lastRun map[string]time.Time) AccountMachine {
	out := AccountMachine{
		ID: m.ID, OrganisationID: m.AccountID, Organisation: org.Name, Name: m.Name, Kind: m.Kind,
		Status: m.Status, Repos: m.Repos, EnrolledAt: m.CreatedAt.UTC(), LastRenewedAt: m.LastRenewedAt,
		RevokedAt: m.RevokedAt, CanManage: roleMay(org.Role, PrivilegeRevokeMachine) || (userID != "" && m.CreatedBy == userID),
	}
	if out.Repos == nil {
		out.Repos = []string{}
	}
	if at, ok := lastRun[m.ID]; ok {
		out.LastRunAt = &at
	}
	return out
}

func (s *Server) handleMachines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgs, ids, err := s.membershipIndex(ctx, accountSessionFrom(r).userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return
	}
	machines, err := s.orgs.Machines(ctx, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the machines")
		return
	}
	machineIDs := make([]string, len(machines))
	for i, m := range machines {
		machineIDs[i] = m.ID
	}
	lastRun, err := s.store.MachineLastRun(ctx, machineIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the machines' activity")
		return
	}
	out := AccountMachines{Machines: make([]AccountMachine, len(machines)), CAFingerprint: s.coreCAFingerprint()}
	for i, m := range machines {
		out.Machines[i] = accountMachine(m, orgs[m.AccountID], accountSessionFrom(r).userID, lastRun)
	}
	writeJSON(w, http.StatusOK, out)
}

// findMachine answers one of the user's organisations' machines, with the
// membership it is under. ok is false (and the refusal written) when it is
// not one of theirs or the spine failed.
func (s *Server) findMachine(ctx context.Context, w http.ResponseWriter, userID, machineID string) (OrgMachine, OrgMembership, bool) {
	orgs, ids, err := s.membershipIndex(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return OrgMachine{}, OrgMembership{}, false
	}
	machines, err := s.orgs.Machines(ctx, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the machines")
		return OrgMachine{}, OrgMembership{}, false
	}
	i := slices.IndexFunc(machines, func(m OrgMachine) bool { return m.ID == machineID })
	if i < 0 {
		writeError(w, http.StatusNotFound, codeNotFound, machineNotFoundMessage)
		return OrgMachine{}, OrgMembership{}, false
	}
	return machines[i], orgs[machines[i].AccountID], true
}

// mayManage answers whether userID may connect or revoke machines in
// organisation accountID, writing the refusal when not.
func (s *Server) mayManage(ctx context.Context, w http.ResponseWriter, userID, accountID, action string) bool {
	orgs, _, err := s.membershipIndex(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return false
	}
	m, ok := orgs[accountID]
	if !ok {
		writeError(w, http.StatusForbidden, codeForbidden, orgsNotMemberMessage)
		return false
	}
	if !roleMay(m.Role, action) {
		writeError(w, http.StatusForbidden, codeForbidden, orgsNeedsRoleMessage)
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// The passkey confirmation both changes share
// ---------------------------------------------------------------------------

// pendingConfirmation is what a mint or revoke ceremony stores: go-webauthn's
// own SessionData, round-tripped unmodified, and the request it confirms.
type pendingConfirmation struct {
	Session webauthn.SessionData `json:"session"`
	Request json.RawMessage      `json:"request"`
}

// beginConfirmation asks the user's own passkeys for a fresh assertion and
// stores request with the challenge.
func (s *Server) beginConfirmation(ctx context.Context, w http.ResponseWriter, kind, userID string, request any) {
	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return
	}
	if len(user.credentials) == 0 {
		writeError(w, http.StatusForbidden, codeForbidden, confirmNeedsPasskey)
		return
	}
	assertion, sessionData, err := s.webAuthn.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not begin the "+
			"confirmation ceremony: "+err.Error())
		return
	}
	req, err := json.Marshal(request)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	body, err := json.Marshal(pendingConfirmation{Session: *sessionData, Request: req})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	ceremonyID, err := s.authStore.SaveCeremony(ctx, kind, body, userID, "", authCeremonyTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not save the ceremony")
		return
	}
	writeJSON(w, http.StatusOK, loginCeremonyResponse{CeremonyID: ceremonyID, CredentialAssertion: assertion})
}

// finishConfirmation consumes a ceremony of kind, verifies the assertion
// against the user's own passkeys, and decodes the confirmed request into
// request. It writes the refusal itself and returns false on any failure.
func (s *Server) finishConfirmation(w http.ResponseWriter, r *http.Request, kind, userID string, request any) bool {
	ctx := r.Context()
	var req finishRequest
	if !decodeAuthRequest(w, r, &req) {
		return false
	}
	ceremony, err := s.authStore.LoadAndConsumeCeremony(ctx, req.CeremonyID, kind)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, confirmExpiredMessage)
		return false
	}
	if ceremony.PendingUserID != userID {
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "this confirmation does not "+
			"belong to the signed-in user")
		return false
	}
	var pending pendingConfirmation
	if jerr := json.Unmarshal(ceremony.SessionData, &pending); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return false
	}
	if jerr := json.Unmarshal(pending.Request, request); jerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the saved ceremony")
		return false
	}
	user, err := loadUser(ctx, s.authStore, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the account")
		return false
	}
	cred, err := s.webAuthn.FinishLogin(user, pending.Session, credentialHTTPRequest(req.Credential))
	if err != nil {
		s.recordAuth(ctx, AuthEventConfirmationRefused, userID, kind+": the passkey did not verify: "+err.Error())
		writeError(w, http.StatusUnauthorized, codeUnauthorized, "the passkey did not confirm this: "+err.Error())
		return false
	}
	if uerr := s.authStore.UpdatePasskey(ctx, *cred); uerr != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not update the passkey")
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Revoke a machine
// ---------------------------------------------------------------------------

func (s *Server) handleRevokeBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MachineRevokeRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	m, _, ok := s.findMachine(ctx, w, userID, req.MachineID)
	if !ok {
		return
	}
	if m.CreatedBy != userID && !s.mayManage(ctx, w, userID, m.AccountID, PrivilegeRevokeMachine) {
		return
	}
	if m.Status == "revoked" {
		writeError(w, http.StatusConflict, codeConflict, machineRevokedMessage)
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindRevokeMachine, userID, req)
}

func (s *Server) handleRevokeFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req MachineRevokeRequest
	if !s.finishConfirmation(w, r, ceremonyKindRevokeMachine, userID, &req) {
		return
	}
	m, _, ok := s.findMachine(ctx, w, userID, req.MachineID)
	if !ok {
		return
	}
	if m.CreatedBy != userID && !s.mayManage(ctx, w, userID, m.AccountID, PrivilegeRevokeMachine) {
		return
	}
	if err := s.orgs.RevokeMachine(ctx, m.ID, userID); err != nil {
		switch {
		case errors.Is(err, ErrMachineRevoked):
			writeError(w, http.StatusConflict, codeConflict, machineRevokedMessage)
		case errors.Is(err, ErrMachineNotFound):
			writeError(w, http.StatusNotFound, codeNotFound, machineNotFoundMessage)
		default:
			writeError(w, http.StatusInternalServerError, codeInternal, "could not revoke the machine")
		}
		return
	}
	s.recordAuth(ctx, AuthEventMachineRevoked, userID, m.ID)
	m, org, ok := s.findMachine(ctx, w, userID, m.ID)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, accountMachine(m, org, userID, nil))
}

// ---------------------------------------------------------------------------
// Suspend and resume a machine (#471)
// ---------------------------------------------------------------------------

// statusChange is suspending or resuming: the status a machine must hold
// first, the ceremony kind, and the change itself.
type statusChange struct {
	from, kind, event, refusal string
	apply                      func(o Organisations) func(ctx context.Context, id, actor string) error
}

var (
	suspendChange = statusChange{
		from: "active", kind: ceremonyKindSuspendMachine, event: AuthEventMachineSuspended,
		refusal: machineNotActiveMessage,
		apply:   func(o Organisations) func(context.Context, string, string) error { return o.SuspendMachine },
	}
	resumeChange = statusChange{
		from: "suspended", kind: ceremonyKindResumeMachine, event: AuthEventMachineResumed,
		refusal: machineNotSuspendedMessage,
		apply:   func(o Organisations) func(context.Context, string, string) error { return o.ResumeMachine },
	}
)

// machineForStatusChange finds the machine and checks who may change it
// (the revoke rule) and that it holds the status the change starts from.
func (s *Server) machineForStatusChange(ctx context.Context, w http.ResponseWriter, userID, machineID string, c statusChange) (OrgMachine, bool) {
	m, _, ok := s.findMachine(ctx, w, userID, machineID)
	if !ok {
		return OrgMachine{}, false
	}
	if m.CreatedBy != userID && !s.mayManage(ctx, w, userID, m.AccountID, PrivilegeRevokeMachine) {
		return OrgMachine{}, false
	}
	switch m.Status {
	case c.from:
		return m, true
	case "revoked":
		writeError(w, http.StatusConflict, codeConflict, machineRevokedMessage)
	default:
		writeError(w, http.StatusConflict, codeConflict, c.refusal)
	}
	return OrgMachine{}, false
}

func (s *Server) machineStatusBegin(c statusChange) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := accountSessionFrom(r).userID
		var req MachineRevokeRequest
		if !decodeAuthRequest(w, r, &req) {
			return
		}
		if _, ok := s.machineForStatusChange(ctx, w, userID, req.MachineID, c); !ok {
			return
		}
		s.beginConfirmation(ctx, w, c.kind, userID, req)
	}
}

func (s *Server) machineStatusFinish(c statusChange) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		userID := accountSessionFrom(r).userID
		var req MachineRevokeRequest
		if !s.finishConfirmation(w, r, c.kind, userID, &req) {
			return
		}
		m, ok := s.machineForStatusChange(ctx, w, userID, req.MachineID, c)
		if !ok {
			return
		}
		if err := c.apply(s.orgs)(ctx, m.ID, userID); err != nil {
			switch {
			case errors.Is(err, ErrMachineRevoked):
				writeError(w, http.StatusConflict, codeConflict, machineRevokedMessage)
			case errors.Is(err, ErrMachineNotFound):
				writeError(w, http.StatusNotFound, codeNotFound, machineNotFoundMessage)
			default:
				writeError(w, http.StatusInternalServerError, codeInternal, "could not change the machine")
			}
			return
		}
		s.recordAuth(ctx, c.event, userID, m.ID)
		m, org, ok := s.findMachine(ctx, w, userID, m.ID)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, accountMachine(m, org, userID, nil))
	}
}

// ---------------------------------------------------------------------------
// Connect a machine: mint an enrolment token
// ---------------------------------------------------------------------------

func (s *Server) handleMintBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req EnrolmentTokenRequest
	if !decodeAuthRequest(w, r, &req) {
		return
	}
	switch req.Kind {
	case "":
		req.Kind = "workstation"
	case "workstation", "service":
	default:
		writeError(w, http.StatusBadRequest, codeBadRequest, "kind must be workstation or service")
		return
	}
	if len(req.Repos) == 0 {
		req.Repos = []string{"*"}
	}
	if !s.mayManage(ctx, w, userID, req.OrganisationID, PrivilegeConnectMachine) {
		return
	}
	s.beginConfirmation(ctx, w, ceremonyKindMintToken, userID, req)
}

func (s *Server) handleMintFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	var req EnrolmentTokenRequest
	if !s.finishConfirmation(w, r, ceremonyKindMintToken, userID, &req) {
		return
	}
	if !s.mayManage(ctx, w, userID, req.OrganisationID, PrivilegeConnectMachine) {
		return
	}
	token, expiresAt, err := s.orgs.MintEnrolmentToken(ctx, req.OrganisationID, userID, req.Kind, req.Repos)
	if err != nil {
		if errors.Is(err, ErrOrgInvalid) {
			writeError(w, http.StatusBadRequest, codeBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, codeInternal, "could not mint the enrolment token")
		return
	}
	// The token is in the answer and nowhere else: not the auth event, not a
	// log line, not a cache.
	s.recordAuth(ctx, AuthEventEnrolmentTokenMinted, userID,
		"organisation "+req.OrganisationID+", "+req.Kind+", "+strconv.Itoa(len(req.Repos))+" repos entries")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, EnrolmentToken{
		Token: token, ExpiresAt: expiresAt.UTC(), OrganisationID: req.OrganisationID,
		Kind: req.Kind, Repos: req.Repos,
	})
}

// ---------------------------------------------------------------------------
// Repositories and agents
// ---------------------------------------------------------------------------

func (s *Server) handleAccountRepositories(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgs, ids, err := s.membershipIndex(ctx, accountSessionFrom(r).userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return
	}
	grants, err := s.orgs.RepoGrants(ctx, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the repositories")
		return
	}
	names := make([]string, len(grants))
	for i, g := range grants {
		names[i] = g.Repo
	}
	activity, err := s.store.RepoActivity(ctx, names)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the repositories' activity")
		return
	}
	out := AccountRepositories{Repositories: make([]AccountRepository, len(grants))}
	for i, g := range grants {
		row := AccountRepository{
			Repo: g.Repo, OrganisationID: g.AccountID, Organisation: orgs[g.AccountID].Name, Since: g.Since.UTC(),
		}
		_, row.Held = s.prover.RepoPath(g.Repo)
		if a, ok := activity[g.Repo]; ok {
			row.Runs, row.Commits = a.Runs, a.Commits
			last := a.LastEventAt
			row.LastEventAt = &last
		}
		out.Repositories[i] = row
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAccountAgents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, ids, err := s.membershipIndex(ctx, accountSessionFrom(r).userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, organisationsLoadMessage)
		return
	}
	machines, err := s.orgs.Machines(ctx, ids)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the machines")
		return
	}
	names := make(map[string]string, len(machines))
	machineIDs := make([]string, len(machines))
	for i, m := range machines {
		names[m.ID] = m.Name
		machineIDs[i] = m.ID
	}
	types, runs, err := s.store.AgentRuns(ctx, machineIDs, MaxAccountRuns)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not read the agents' runs")
		return
	}
	for i := range runs {
		runs[i].MachineName = names[runs[i].MachineID]
	}
	writeJSON(w, http.StatusOK, AccountAgents{AgentTypes: types, RecentRuns: runs})
}

// ---------------------------------------------------------------------------
// Sign-ins
// ---------------------------------------------------------------------------

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := s.authStore.UserSessions(ctx, accountSessionFrom(r).userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not load the sign-ins")
		return
	}
	current := hashToken(s.cookieToken(r))
	out := AccountSessions{Sessions: make([]AccountSession, len(rows))}
	for i, row := range rows {
		out.Sessions[i] = AccountSession{
			ID: row.Hash[:sessionLabelLen], CreatedAt: row.CreatedAt.UTC(), ExpiresAt: row.ExpiresAt.UTC(),
			Current: row.Hash == current, PasskeyName: row.PasskeyName,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSignOutOthers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := accountSessionFrom(r).userID
	n, err := s.authStore.RevokeOtherSessions(ctx, userID, s.cookieToken(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "could not sign out the other sign-ins")
		return
	}
	s.recordAuth(ctx, AuthEventOtherSessionsSignedOut, userID, strconv.Itoa(n))
	writeJSON(w, http.StatusOK, SignedOut{SignedOut: n})
}

// coreCAFingerprint reads the gateway's CA certificate and answers its
// fingerprint as `innsegl connect --ca-fingerprint` takes it. Read on each
// request: the gateway writes the file when it starts, which may be after
// this API did. Empty when there is no readable certificate.
func (s *Server) coreCAFingerprint() string {
	if s.coreCACertFile == "" {
		return ""
	}
	// #nosec G304 -- the deployment's own configured path.
	text, err := os.ReadFile(s.coreCACertFile)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(text)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

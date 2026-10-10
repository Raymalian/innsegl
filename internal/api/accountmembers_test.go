// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Members, roles and invitations on the account surface (#480, #481). The
// server, sessions, passkeys and the user rows are real; the accounts spine
// is fakeOrgs, as in accountorg_test.go. internal/accounts runs the store's
// half against a real Postgres (ACC-004..007, AUTH-006/007).

type fakeInvite struct {
	account, role string
	used          bool
}

func (f *fakeOrgs) Members(_ context.Context, accountID string) ([]OrgMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.members[accountID], nil
}

func (f *fakeOrgs) SetRole(_ context.Context, accountID, userID, role, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, "role|"+accountID+"|"+userID+"|"+role+"|"+actor)
	return f.memberErr
}

func (f *fakeOrgs) RemoveMember(_ context.Context, accountID, userID, actor string) (OrgRemoval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, "remove|"+accountID+"|"+userID+"|"+actor)
	if f.memberErr != nil {
		return OrgRemoval{}, f.memberErr
	}
	return OrgRemoval{SessionsRevoked: 1, Suspended: []string{machineLaptop}}, nil
}

func (f *fakeOrgs) Invitations(_ context.Context, accountID string) ([]OrgInvitation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []OrgInvitation
	for _, i := range f.invites {
		if i.account == accountID {
			out = append(out, OrgInvitation{ID: 1, AccountID: accountID, Role: i.role, State: InvitationPending})
		}
	}
	return out, f.err
}

func (f *fakeOrgs) CreateInvitation(_ context.Context, accountID, role, actor string) (string, OrgInvitation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, "invite|"+accountID+"|"+role+"|"+actor)
	if f.memberErr != nil {
		return "", OrgInvitation{}, f.memberErr
	}
	code := fmt.Sprintf("iv_%064d", len(f.invites)+1)
	if f.invites == nil {
		f.invites = map[string]*fakeInvite{}
	}
	f.invites[code] = &fakeInvite{account: accountID, role: role}
	return code, OrgInvitation{ID: int64(len(f.invites)), AccountID: accountID, Role: role, State: InvitationPending,
		ExpiresAt: time.Now().Add(72 * time.Hour).UTC()}, nil
}

func (f *fakeOrgs) WithdrawInvitation(_ context.Context, accountID string, invitationID int64, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.memberErr != nil {
		return f.memberErr
	}
	f.changes = append(f.changes, "withdraw|"+accountID+"|"+strconv.FormatInt(invitationID, 10)+"|"+actor)
	return nil
}

func (f *fakeOrgs) usable(code string) (*fakeInvite, error) {
	i, ok := f.invites[code]
	if !ok || i.used {
		return nil, ErrInvitationInvalid
	}
	return i, nil
}

func (f *fakeOrgs) PeekInvitation(_ context.Context, code string) (OrgInvitationPeek, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.usable(code)
	if err != nil {
		return OrgInvitationPeek{}, err
	}
	return OrgInvitationPeek{AccountID: i.account, AccountName: "example-team", Role: i.role,
		ExpiresAt: time.Now().Add(time.Hour).UTC()}, nil
}

func (f *fakeOrgs) acceptLocked(code, userID string) (OrgMembership, error) {
	i, err := f.usable(code)
	if err != nil {
		return OrgMembership{}, err
	}
	for _, m := range f.memberships[userID] {
		if m.AccountID == i.account {
			return OrgMembership{}, ErrAlreadyMember
		}
	}
	i.used = true
	m := OrgMembership{AccountID: i.account, Name: "example-team", Role: i.role}
	f.memberships[userID] = append(f.memberships[userID], m)
	return m, nil
}

func (f *fakeOrgs) AcceptInvitation(_ context.Context, code, userID string) (OrgMembership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acceptLocked(code, userID)
}

// AcceptInvitationAsNewUser lends create a real transaction on the test
// database, so the user and passkey it writes are real rows, committed only
// when the code is usable.
func (f *fakeOrgs) AcceptInvitationAsNewUser(ctx context.Context, code string,
	create func(q Querier) (string, error),
) (OrgMembership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.usable(code); err != nil {
		return OrgMembership{}, err
	}
	conn, err := pgx.Connect(ctx, f.ownerDSN)
	if err != nil {
		return OrgMembership{}, err
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return OrgMembership{}, err
	}
	defer func() { discardError(tx.Rollback(ctx)) }()
	userID, err := create(tx)
	if err != nil {
		return OrgMembership{}, err
	}
	m, err := f.acceptLocked(code, userID)
	if err != nil {
		return OrgMembership{}, err
	}
	return m, tx.Commit(ctx)
}

func (h orgHarness) withMembers(others ...OrgMember) {
	h.orgs.mu.Lock()
	defer h.orgs.mu.Unlock()
	h.orgs.members = map[string][]OrgMember{orgA: append([]OrgMember{
		{UserID: h.userID, DisplayName: "Test Operator", Role: h.orgs.memberships[h.userID][0].Role},
	}, others...)}
}

func sessionOrganisations(t *testing.T, base string, cookie *http.Cookie) SessionStatus {
	t.Helper()
	a := do(t, http.MethodGet, base+"/api/v1/auth/session", "", cookie)
	if a.status != http.StatusOK {
		t.Fatalf("session: %d %s", a.status, a.body)
	}
	var s SessionStatus
	decodeBody(t, a, &s)
	return s
}

// AUTH-005: the session answers the signed-in person's live memberships with
// their roles, read on every request, so a removal shows on the next one.
func TestAUTH005TheSessionAnswersTheUsersMemberships(t *testing.T) {
	h := newOrgHarness(t, roleAdmin, true)
	s := sessionOrganisations(t, h.srv.URL, h.cookie)
	if !s.Authenticated || len(s.Organisations) != 2 || s.Organisations[0].ID != orgA ||
		s.Organisations[0].Role != roleAdmin || s.Organisations[1].Role != roleMember {
		t.Fatalf("session = %+v", s)
	}
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID] = h.orgs.memberships[h.userID][:1]
	h.orgs.mu.Unlock()
	if s = sessionOrganisations(t, h.srv.URL, h.cookie); len(s.Organisations) != 1 {
		t.Errorf("after a membership ended the session still answers %+v", s.Organisations)
	}
	if s = sessionOrganisations(t, h.srv.URL, nil); s.Authenticated || s.Organisations != nil {
		t.Errorf("no session answers %+v", s)
	}
}

// ACC-004 on the member routes: anyone in the organisation reads its members;
// inviting, changing a role and removing take an owner or admin and a fresh
// passkey, and the owner role is the owner's alone.
func TestACC004MemberRoutesFollowTheRoleTable(t *testing.T) {
	member := newOrgHarness(t, roleMember, true)
	member.withMembers(OrgMember{UserID: "u-2", DisplayName: "Second", Role: roleOwner})
	a := do(t, http.MethodGet, member.srv.URL+"/api/v1/account/members?organisation_id="+orgA, "", member.cookie)
	var listed AccountMembers
	decodeBody(t, a, &listed)
	if a.status != http.StatusOK || len(listed.Members) != 2 || !listed.Members[0].You || listed.Invitations == nil ||
		len(listed.Invitations) != 0 || listed.CanManage {
		t.Fatalf("a member's view: %d %+v", a.status, listed)
	}
	if a = do(t, http.MethodGet, member.srv.URL+"/api/v1/account/members?organisation_id="+orgC, "", member.cookie); a.status != http.StatusForbidden {
		t.Errorf("another organisation's members: %d", a.status)
	}
	for route, body := range map[string]any{
		"invitations":    InvitationRequest{OrganisationID: orgA, Role: roleMember},
		"members/role":   MemberRoleRequest{OrganisationID: orgA, UserID: "u-2", Role: roleAdmin},
		"members/remove": MemberRequest{OrganisationID: orgA, UserID: "u-2"},
	} {
		if r := do(t, http.MethodPost, member.srv.URL+"/api/v1/account/"+route+"/begin", mustJSON(t, body), member.cookie); r.status != http.StatusForbidden {
			t.Errorf("a member begins %s: %d %s", route, r.status, r.body)
		}
	}

	admin := newOrgHarness(t, roleAdmin, true)
	admin.withMembers(OrgMember{UserID: "u-2", DisplayName: "Second", Role: roleOwner},
		OrgMember{UserID: "u-3", DisplayName: "Third", Role: roleMember})
	for route, body := range map[string]any{
		"invitations":    InvitationRequest{OrganisationID: orgA, Role: roleOwner},
		"members/role":   MemberRoleRequest{OrganisationID: orgA, UserID: "u-3", Role: roleOwner},
		"members/remove": MemberRequest{OrganisationID: orgA, UserID: "u-2"},
	} {
		if r := do(t, http.MethodPost, admin.srv.URL+"/api/v1/account/"+route+"/begin", mustJSON(t, body), admin.cookie); r.status != http.StatusForbidden {
			t.Errorf("an admin begins %s touching an owner: %d %s", route, r.status, r.body)
		}
	}
	if r := do(t, http.MethodPost, admin.srv.URL+"/api/v1/account/members/role/begin",
		mustJSON(t, MemberRoleRequest{OrganisationID: orgA, UserID: "u-3", Role: "guest"}), admin.cookie); r.status != http.StatusBadRequest {
		t.Errorf("a fourth role: %d", r.status)
	}
	if r := do(t, http.MethodPost, admin.srv.URL+"/api/v1/account/members/remove/begin",
		mustJSON(t, MemberRequest{OrganisationID: orgA, UserID: "nobody"}), admin.cookie); r.status != http.StatusNotFound {
		t.Errorf("removing a non-member: %d", r.status)
	}

	// An admin's confirmed changes reach the spine with the admin as actor.
	r := admin.confirm(t, "members/role", MemberRoleRequest{OrganisationID: orgA, UserID: "u-3", Role: roleAdmin}, admin.auth)
	if r.status != http.StatusOK {
		t.Fatalf("role change: %d %s", r.status, r.body)
	}
	r = admin.confirm(t, "members/remove", MemberRequest{OrganisationID: orgA, UserID: "u-3"}, admin.auth)
	var removed MemberRemoved
	decodeBody(t, r, &removed)
	if r.status != http.StatusOK || removed.SessionsRevoked != 1 || len(removed.SuspendedMachines) != 1 {
		t.Fatalf("removal: %d %s", r.status, r.body)
	}
	want := []string{"role|" + orgA + "|u-3|admin|" + admin.userID, "remove|" + orgA + "|u-3|" + admin.userID}
	if strings.Join(admin.orgs.changes, ",") != strings.Join(want, ",") {
		t.Errorf("changes = %v, want %v", admin.orgs.changes, want)
	}
	details := admin.authEventDetails(t)
	for _, ev := range []string{AuthEventMemberRoleChanged, AuthEventMemberRemoved} {
		if !strings.Contains(details, ev+":") {
			t.Errorf("no %s auth event in\n%s", ev, details)
		}
	}

	// The spine's own refusals at finish.
	admin.orgs.memberErr = ErrLastOwner
	if r = admin.confirm(t, "members/remove", MemberRequest{OrganisationID: orgA, UserID: admin.userID}, admin.auth); r.status != http.StatusConflict {
		t.Errorf("removing the last owner: %d %s", r.status, r.body)
	}
	admin.orgs.memberErr = ErrOrgForbidden
	if r = admin.confirm(t, "members/role", MemberRoleRequest{OrganisationID: orgA, UserID: "u-2", Role: roleMember}, admin.auth); r.status != http.StatusForbidden {
		t.Errorf("a refused change at finish: %d %s", r.status, r.body)
	}
}

// AUTH-006 on the API: an owner's confirmed invitation answers a link whose
// code is in the fragment, once, and the request asks for no email.
func TestAUTH006AnInvitationIsALinkShownOnce(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.withMembers()
	r := h.confirm(t, "invitations", InvitationRequest{OrganisationID: orgA, Role: roleAdmin}, h.auth)
	if r.status != http.StatusOK {
		t.Fatalf("invite: %d %s", r.status, r.body)
	}
	var inv InvitationLink
	decodeBody(t, r, &inv)
	prefix := testWebAuthnConfig.RPOrigin + "/invite#iv_"
	if !strings.HasPrefix(inv.Link, prefix) || inv.Role != roleAdmin || inv.ExpiresAt.IsZero() {
		t.Fatalf("invitation = %+v", inv)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}
	code := strings.TrimPrefix(inv.Link, testWebAuthnConfig.RPOrigin+"/invite#")
	if strings.Contains(h.authEventDetails(t), code) {
		t.Errorf("an auth event holds the code")
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, InvitationRequest{})), &fields); err != nil {
		t.Fatal(err)
	}
	for k := range fields {
		if strings.Contains(strings.ToLower(k), "mail") {
			t.Errorf("the invitation request has a field %q", k)
		}
	}
}

// AUTH-007 with an existing account: signed in, the person accepts the link
// and is a member; a used link and an existing membership are refused.
func TestAUTH007AcceptWithAnExistingAccount(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	code, _, err := h.orgs.CreateInvitation(context.Background(), orgC, roleMember, "someone")
	if err != nil {
		t.Fatal(err)
	}
	r := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/invitations/accept", mustJSON(t, InvitationCode{Code: code}), h.cookie)
	var joined AccountOrganisation
	decodeBody(t, r, &joined)
	if r.status != http.StatusOK || joined.ID != orgC || joined.Role != roleMember || len(joined.Privileges) == 0 {
		t.Fatalf("accept: %d %s", r.status, r.body)
	}
	if s := sessionOrganisations(t, h.srv.URL, h.cookie); len(s.Organisations) != 3 {
		t.Errorf("the session does not show the new membership: %+v", s.Organisations)
	}
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/invitations/accept", mustJSON(t, InvitationCode{Code: code}), h.cookie); r.status != http.StatusNotFound {
		t.Errorf("a used link: %d %s", r.status, r.body)
	}
	again, _, err := h.orgs.CreateInvitation(context.Background(), orgA, roleMember, "someone")
	if err != nil {
		t.Fatal(err)
	}
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/invitations/accept", mustJSON(t, InvitationCode{Code: again}), h.cookie); r.status != http.StatusConflict {
		t.Errorf("already a member: %d %s", r.status, r.body)
	}
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/invitations/accept", mustJSON(t, InvitationCode{Code: again})); r.status != http.StatusUnauthorized {
		t.Errorf("accepting with no session: %d", r.status)
	}
}

// AUTH-007 with a new passkey: no session; the link previews its
// organisation, a registration ceremony of its own kind creates the person
// with their passkey, and the membership comes with the first session.
func TestAUTH007AcceptWithANewPasskey(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	code, _, err := h.orgs.CreateInvitation(context.Background(), orgB, roleMember, h.userID)
	if err != nil {
		t.Fatal(err)
	}
	r := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation", mustJSON(t, InvitationCode{Code: code}))
	var preview InvitationPreview
	decodeBody(t, r, &preview)
	if r.status != http.StatusOK || preview.Organisation != "example-team" || preview.Role != roleMember {
		t.Fatalf("preview: %d %s", r.status, r.body)
	}
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation", mustJSON(t, InvitationCode{Code: "iv_nope"})); r.status != http.StatusNotFound {
		t.Errorf("preview of a bad code: %d", r.status)
	}

	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/begin",
		mustJSON(t, InvitationBegin{Code: code, DisplayName: "Invited Person"}))
	if begin.status != http.StatusOK {
		t.Fatalf("begin: %d %s", begin.status, begin.body)
	}
	var creation ceremonyResponse
	decodeBody(t, begin, &creation)
	auth := newSoftAuthenticator(t)
	credential, err := auth.Register(creation.CredentialCreation, testWebAuthnConfig.RPOrigin)
	if err != nil {
		t.Fatal(err)
	}
	finishBody := mustJSON(t, map[string]any{"ceremony_id": creation.CeremonyID, "credential": json.RawMessage(credential), "code": code})

	// The ceremony is the invitation's kind: first-user enrolment cannot
	// finish it.
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/enrol/finish", finishBody); r.status != http.StatusUnauthorized {
		t.Fatalf("an invitation ceremony finished as enrolment: %d %s", r.status, r.body)
	}
	begin = do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/begin",
		mustJSON(t, InvitationBegin{Code: code, DisplayName: "Invited Person"}))
	decodeBody(t, begin, &creation)
	if credential, err = auth.Register(creation.CredentialCreation, testWebAuthnConfig.RPOrigin); err != nil {
		t.Fatal(err)
	}
	finishBody = mustJSON(t, map[string]any{"ceremony_id": creation.CeremonyID, "credential": json.RawMessage(credential), "code": code})
	r = do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/finish", finishBody)
	if r.status != http.StatusOK {
		t.Fatalf("finish: %d %s", r.status, r.body)
	}
	var done InvitationJoined
	decodeBody(t, r, &done)
	if !done.Authenticated || done.DisplayName != "Invited Person" || len(done.RecoveryCodes) != 10 ||
		done.Organisation.ID != orgB || done.Organisation.Role != roleMember {
		t.Fatalf("finished = %+v", done)
	}
	var cookie *http.Cookie
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if c.Name == sessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	s := sessionOrganisations(t, h.srv.URL, cookie)
	if !s.Authenticated || s.DisplayName != "Invited Person" || len(s.Organisations) != 1 || s.Organisations[0].ID != orgB {
		t.Fatalf("the new person's session = %+v", s)
	}
	userID, _, ok := verifySessionToken(t, h.authStore, cookie.Value)
	if !ok {
		t.Fatal("the session does not verify")
	}
	if keys, kerr := h.authStore.PasskeysByUser(context.Background(), userID); kerr != nil || len(keys) != 1 {
		t.Errorf("the new person's passkeys = %d %v", len(keys), kerr)
	}

	// The link is spent: a second registration is refused at begin.
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/begin",
		mustJSON(t, InvitationBegin{Code: code, DisplayName: "Late"})); r.status != http.StatusNotFound {
		t.Errorf("begin with a spent link: %d %s", r.status, r.body)
	}
	if r = do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/begin",
		mustJSON(t, InvitationBegin{Code: code})); r.status != http.StatusBadRequest {
		t.Errorf("begin with no name: %d", r.status)
	}
}

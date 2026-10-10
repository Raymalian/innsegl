// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// The member and invitation routes' refusals and failures (#480, #481): every
// error path answers, and none of them changes anything.

func TestACC004MemberRoutesRefuseAndFailCleanly(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.withMembers(OrgMember{UserID: "u-2", DisplayName: "Second", Role: roleMember})
	post := func(path, body string) int {
		t.Helper()
		return do(t, http.MethodPost, h.srv.URL+path, body, h.cookie).status
	}

	for _, path := range []string{"/api/v1/account/invitations/begin", "/api/v1/account/members/role/begin",
		"/api/v1/account/members/remove/begin", "/api/v1/account/invitations/accept"} {
		if st := post(path, "{not json"); st != http.StatusBadRequest {
			t.Errorf("%s with a bad body: %d", path, st)
		}
	}
	if st := post("/api/v1/account/invitations/begin", mustJSON(t, InvitationRequest{OrganisationID: orgA, Role: "guest"})); st != http.StatusBadRequest {
		t.Errorf("a fourth role: %d", st)
	}
	if st := post("/api/v1/account/invitations/begin", mustJSON(t, InvitationRequest{OrganisationID: orgC, Role: roleMember})); st != http.StatusForbidden {
		t.Errorf("inviting to another organisation: %d", st)
	}
	if st := post("/api/v1/account/members/role/begin", mustJSON(t, MemberRoleRequest{OrganisationID: orgC, UserID: "u-2", Role: roleAdmin})); st != http.StatusForbidden {
		t.Errorf("a role in another organisation: %d", st)
	}
	if st := post("/api/v1/account/members/remove/begin", mustJSON(t, MemberRequest{OrganisationID: orgC, UserID: "u-2"})); st != http.StatusForbidden {
		t.Errorf("removal in another organisation: %d", st)
	}

	// The spine's answers at finish, each mapped.
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrOrgNotFound, http.StatusNotFound},
		{ErrAlreadyMember, http.StatusConflict},
		{ErrInvitationInvalid, http.StatusNotFound},
		{errors.New("database gone"), http.StatusInternalServerError},
	} {
		h.orgs.memberErr = tc.err
		if a := h.confirm(t, "members/role", MemberRoleRequest{OrganisationID: orgA, UserID: "u-2", Role: roleAdmin}, h.auth); a.status != tc.want {
			t.Errorf("role finish with %v: %d, want %d", tc.err, a.status, tc.want)
		}
		if a := h.confirm(t, "invitations", InvitationRequest{OrganisationID: orgA, Role: roleMember}, h.auth); a.status != tc.want {
			t.Errorf("invite finish with %v: %d, want %d", tc.err, a.status, tc.want)
		}
		if a := h.confirm(t, "members/remove", MemberRequest{OrganisationID: orgA, UserID: "u-2"}, h.auth); a.status != tc.want {
			t.Errorf("remove finish with %v: %d, want %d", tc.err, a.status, tc.want)
		}
	}
	h.orgs.memberErr = nil

	// A spine that cannot be read is a server error, never an empty answer.
	h.orgs.err = errors.New("database gone")
	for _, path := range []string{"/api/v1/account/members?organisation_id=" + orgA, "/api/v1/auth/session"} {
		if a := do(t, http.MethodGet, h.srv.URL+path, "", h.cookie); a.status != http.StatusInternalServerError {
			t.Errorf("GET %s with the spine down: %d", path, a.status)
		}
	}
	for path, body := range map[string]any{
		"/api/v1/account/invitations/begin":    InvitationRequest{OrganisationID: orgA, Role: roleMember},
		"/api/v1/account/members/role/begin":   MemberRoleRequest{OrganisationID: orgA, UserID: "u-2", Role: roleAdmin},
		"/api/v1/account/members/remove/begin": MemberRequest{OrganisationID: orgA, UserID: "u-2"},
	} {
		if st := post(path, mustJSON(t, body)); st != http.StatusInternalServerError {
			t.Errorf("%s with the spine down: %d", path, st)
		}
	}
	h.orgs.err = nil

	// A member the spine does not list.
	h.orgs.mu.Lock()
	h.orgs.members = nil
	h.orgs.mu.Unlock()
	if st := post("/api/v1/account/members/remove/begin", mustJSON(t, MemberRequest{OrganisationID: orgA, UserID: "u-2"})); st != http.StatusNotFound {
		t.Errorf("removing someone not listed: %d", st)
	}
	if !RoleMay(roleOwner, PrivilegeEraseOrganisation) || RoleMay(roleAdmin, PrivilegeEraseOrganisation) {
		t.Error("RoleMay disagrees with the table")
	}
}

// AUTH-007's refusals on the public invitation routes: no spine, a bad body,
// a bad code, a ceremony that does not verify, and a link spent between begin
// and finish, which leaves no user behind.
func TestAUTH007InvitationRegistrationRefusals(t *testing.T) {
	none := newOrgHarness(t, roleOwner, false)
	for _, path := range []string{"/api/v1/auth/invitation", "/api/v1/auth/invitation/begin", "/api/v1/auth/invitation/finish"} {
		if a := do(t, http.MethodPost, none.srv.URL+path, `{}`); a.status != http.StatusServiceUnavailable {
			t.Errorf("%s with no spine: %d", path, a.status)
		}
	}

	h := newOrgHarness(t, roleOwner, true)
	for _, path := range []string{"/api/v1/auth/invitation", "/api/v1/auth/invitation/begin", "/api/v1/auth/invitation/finish"} {
		if a := do(t, http.MethodPost, h.srv.URL+path, "{not json"); a.status != http.StatusBadRequest {
			t.Errorf("%s with a bad body: %d", path, a.status)
		}
	}
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/begin",
		mustJSON(t, InvitationBegin{Code: "iv_nope", DisplayName: "X"})); a.status != http.StatusNotFound {
		t.Errorf("begin with a bad code: %d", a.status)
	}
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/finish",
		mustJSON(t, map[string]string{"ceremony_id": "nope", "code": "iv_nope"})); a.status != http.StatusUnauthorized {
		t.Errorf("finish with no ceremony: %d", a.status)
	}

	code, _, err := h.orgs.CreateInvitation(context.Background(), orgB, roleMember, h.userID)
	if err != nil {
		t.Fatal(err)
	}
	begin := func() (ceremonyResponse, []byte) {
		t.Helper()
		a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/begin", mustJSON(t, InvitationBegin{Code: code, DisplayName: "Late Person"}))
		if a.status != http.StatusOK {
			t.Fatalf("begin: %d %s", a.status, a.body)
		}
		var c ceremonyResponse
		decodeBody(t, a, &c)
		cred, rerr := newSoftAuthenticator(t).Register(c.CredentialCreation, testWebAuthnConfig.RPOrigin)
		if rerr != nil {
			t.Fatal(rerr)
		}
		return c, cred
	}

	// A credential for another ceremony's challenge does not verify.
	c1, _ := begin()
	_, cred2 := begin()
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/finish", mustJSON(t, map[string]any{
		"ceremony_id": c1.CeremonyID, "credential": json.RawMessage(cred2), "code": code})); a.status != http.StatusUnauthorized {
		t.Errorf("a credential for another challenge: %d %s", a.status, a.body)
	}

	// Spent between begin and finish: refused, and no user is left.
	c3, cred3 := begin()
	h.orgs.mu.Lock()
	h.orgs.invites[code].used = true
	h.orgs.mu.Unlock()
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/invitation/finish", mustJSON(t, map[string]any{
		"ceremony_id": c3.CeremonyID, "credential": json.RawMessage(cred3), "code": code})); a.status != http.StatusNotFound {
		t.Errorf("finish with a spent link: %d %s", a.status, a.body)
	}
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.users WHERE display_name = 'Late Person'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a refused acceptance left %d users", n)
	}
}

// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"
)

// RM-333 (#511): the organisation routes' own failure paths. Each breaks one
// table or one stored ceremony with the migration owner's credential (never
// a role the API holds) and reads the refusal back.

func (h orgHarness) ownerExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	if _, err := c.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("owner exec %q: %v", sql, err)
	}
}

func (h orgHarness) mintBegin(t *testing.T) (answer, string) {
	t.Helper()
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if begin.status != http.StatusOK {
		t.Fatalf("begin: %d: %s", begin.status, begin.body)
	}
	var challenge loginCeremonyResponse
	decodeBody(t, begin, &challenge)
	return begin, challenge.CeremonyID
}

func TestRM333ConfirmationNeedsAPasskeyOnTheAccount(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.ownerExec(t, `DELETE FROM innsegl_auth.passkeys`)
	a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if a.status != http.StatusForbidden || !strings.Contains(string(a.body), "passkey") {
		t.Errorf("begin with no passkey = %d: %s", a.status, a.body)
	}
}

func TestRM333ConfirmationBeginReportsAnUnreadableAccount(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.ownerExec(t, `ALTER TABLE innsegl_auth.passkeys RENAME TO passkeys_gone`)
	a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if a.status != http.StatusInternalServerError {
		t.Errorf("begin = %d: %s", a.status, a.body)
	}
	if a := get(t, h.srv.URL, "/api/v1/account/sessions", h.cookie); a.status != http.StatusInternalServerError {
		t.Errorf("sessions = %d: %s", a.status, a.body)
	}
}

func TestRM333ConfirmationBeginReportsACeremonyItCannotSave(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.ownerExec(t, `REVOKE INSERT ON innsegl_auth.webauthn_ceremonies FROM `+AuthWriterRole)
	a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if a.status != http.StatusInternalServerError {
		t.Errorf("begin = %d: %s", a.status, a.body)
	}
}

func TestRM333ConfirmationFinishRefusesAnotherUsersCeremony(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	begin, id := h.mintBegin(t)
	body := h.assertion(t, begin, h.auth)
	h.ownerExec(t, `UPDATE innsegl_auth.webauthn_ceremonies SET pending_user_id = 'someone-else' WHERE ceremony_id = $1`, id)
	if a := h.finish(t, "enrolment-tokens", body); a.status != http.StatusUnauthorized {
		t.Errorf("finish = %d: %s", a.status, a.body)
	}
}

func TestRM333ConfirmationFinishReportsAnUnreadableCeremony(t *testing.T) {
	for name, sql := range map[string]string{
		"session": `UPDATE innsegl_auth.webauthn_ceremonies SET session_data = '{"session": {"expires": 1}}' WHERE ceremony_id = $1`,
		"request": `UPDATE innsegl_auth.webauthn_ceremonies SET session_data = jsonb_set(session_data, '{request}', '"x"') WHERE ceremony_id = $1`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newOrgHarness(t, roleOwner, true)
			begin, id := h.mintBegin(t)
			body := h.assertion(t, begin, h.auth)
			h.ownerExec(t, sql, id)
			if a := h.finish(t, "enrolment-tokens", body); a.status != http.StatusInternalServerError {
				t.Errorf("finish = %d: %s", a.status, a.body)
			}
		})
	}
}

func TestRM333ConfirmationFinishReportsAnUnreadableAccount(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	begin, _ := h.mintBegin(t)
	body := h.assertion(t, begin, h.auth)
	h.ownerExec(t, `ALTER TABLE innsegl_auth.passkeys RENAME TO passkeys_gone`)
	if a := h.finish(t, "enrolment-tokens", body); a.status != http.StatusInternalServerError {
		t.Errorf("finish = %d: %s", a.status, a.body)
	}
}

func TestRM333LedgerReadFailuresAreServerErrors(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.ownerExec(t, `ALTER TABLE innsegl.gateway_run_mapping RENAME TO gateway_run_mapping_gone`)
	for _, path := range []string{"/api/v1/account/machines", "/api/v1/account/agents"} {
		if a := get(t, h.srv.URL, path, h.cookie); a.status != http.StatusInternalServerError {
			t.Errorf("GET %s = %d: %s", path, a.status, a.body)
		}
	}
	h.ownerExec(t, `REVOKE SELECT ON innsegl.events FROM `+ReadOnlyRole)
	if a := get(t, h.srv.URL, "/api/v1/account/repositories", h.cookie); a.status != http.StatusInternalServerError {
		t.Errorf("GET repositories = %d: %s", a.status, a.body)
	}
}

func TestRM333SignOutOthersReportsAFailure(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.ownerExec(t, `REVOKE UPDATE ON innsegl_auth.sessions FROM `+AuthWriterRole)
	a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sessions/sign-out-others", "{}", h.cookie)
	if a.status != http.StatusInternalServerError {
		t.Errorf("sign out others = %d: %s", a.status, a.body)
	}
}

// The revoke finish reads the machine and the role again; a spine that fails
// between begin and finish is reported, and nothing is revoked.
func TestRM333RevokeFinishFailsWhenTheSpineCannotBeRead(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/revoke/begin",
		mustJSON(t, MachineRevokeRequest{MachineID: machineLaptop}), h.cookie)
	body := h.assertion(t, begin, h.auth)
	h.orgs.mu.Lock()
	h.orgs.err = errMachinesGone
	h.orgs.mu.Unlock()
	if a := h.finish(t, "machines/revoke", body); a.status != http.StatusInternalServerError {
		t.Errorf("finish = %d: %s", a.status, a.body)
	}
	if len(h.orgs.revoked) != 0 {
		t.Errorf("revoked %v", h.orgs.revoked)
	}
}

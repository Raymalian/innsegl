// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"slices"
	"testing"
)

// ACC-018 (#481, E28): an owner or admin withdraws a pending invitation
// from the dashboard's members page. A member may not, and a stranger's
// organisation answers as no such invitation.
func TestACC018WithdrawAnInvitationFromTheDashboard(t *testing.T) {
	h := newOrgHarness(t, roleAdmin, true)
	withdraw := func(org string, id int64) answer {
		return do(t, http.MethodPost, h.srv.URL+"/api/v1/account/invitations/withdraw",
			mustJSON(t, InvitationWithdrawRequest{OrganisationID: org, InvitationID: id}), h.cookie)
	}
	if a := withdraw(orgA, 7); a.status != http.StatusOK {
		t.Fatalf("an admin withdrawing = %d: %s", a.status, a.body)
	}
	if !slices.Contains(h.orgs.changes, "withdraw|"+orgA+"|7|"+h.userID) {
		t.Errorf("changes = %v", h.orgs.changes)
	}
	if a := withdraw(orgB, 7); a.status != http.StatusForbidden {
		t.Errorf("a member withdrawing = %d, want 403: %s", a.status, a.body)
	}
	if a := withdraw(orgC, 7); a.status != http.StatusForbidden {
		t.Errorf("a stranger's organisation = %d, want 403 as every member route: %s", a.status, a.body)
	}
	h.orgs.memberErr = ErrOrgNotFound
	if a := withdraw(orgA, 99); a.status != http.StatusNotFound {
		t.Errorf("no such invitation = %d, want 404: %s", a.status, a.body)
	}
}

// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"
)

// ACC-016 (#471): a machine is suspended and resumed from the dashboard,
// each after a fresh passkey ceremony of its own kind, by whoever may
// revoke it: an owner or an admin of its organisation, or the member who
// connected it (api.RoleMay's revoke_machine, the handlers' own-machine
// rule). Suspended is not final; revoked is.
func TestACC016SuspendAndResumeAMachineWithAFreshPasskey(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	status := func(a answer) string {
		t.Helper()
		var m AccountMachine
		decodeBody(t, a, &m)
		return m.Status
	}

	a := h.confirm(t, "machines/suspend", MachineRevokeRequest{MachineID: machineLaptop}, h.auth)
	if a.status != http.StatusOK || status(a) != "suspended" {
		t.Fatalf("suspend: %d: %s", a.status, a.body)
	}
	if a = h.confirm(t, "machines/suspend", MachineRevokeRequest{MachineID: machineLaptop}, h.auth); a.status != http.StatusConflict {
		t.Errorf("suspending a suspended machine = %d, want 409: %s", a.status, a.body)
	}
	a = h.confirm(t, "machines/resume", MachineRevokeRequest{MachineID: machineLaptop}, h.auth)
	if a.status != http.StatusOK || status(a) != "active" {
		t.Fatalf("resume: %d: %s", a.status, a.body)
	}
	if a = h.confirm(t, "machines/resume", MachineRevokeRequest{MachineID: machineLaptop}, h.auth); a.status != http.StatusConflict {
		t.Errorf("resuming an active machine = %d, want 409: %s", a.status, a.body)
	}
	details := h.authEventDetails(t)
	for _, want := range []string{AuthEventMachineSuspended + ":" + machineLaptop, AuthEventMachineResumed + ":" + machineLaptop} {
		if !strings.Contains(details, want) {
			t.Errorf("no %q auth event in %s", want, details)
		}
	}

	// Without the passkey: a made-up ceremony is refused, nothing changes.
	bogus := mustJSON(t, map[string]any{"ceremony_id": "0123456789abcdef0123456789abcdef", "credential": map[string]any{}})
	if a = h.finish(t, "machines/suspend", bogus); a.status != http.StatusUnauthorized {
		t.Errorf("suspend finish with no ceremony = %d, want 401", a.status)
	}

	// The runner is in B, where this person is a member who did not connect it.
	a = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/suspend/begin",
		mustJSON(t, MachineRevokeRequest{MachineID: machineRunner}), h.cookie)
	if a.status != http.StatusForbidden {
		t.Errorf("a member suspending someone else's machine = %d, want 403: %s", a.status, a.body)
	}
	// C's machine is not theirs to know of.
	a = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/suspend/begin",
		mustJSON(t, MachineRevokeRequest{MachineID: machineOther}), h.cookie)
	if a.status != http.StatusNotFound {
		t.Errorf("suspending another organisation's machine = %d, want 404: %s", a.status, a.body)
	}

	// Revoked is final: neither suspended nor resumed.
	if a = h.confirm(t, "machines/revoke", MachineRevokeRequest{MachineID: machineLaptop}, h.auth); a.status != http.StatusOK {
		t.Fatalf("revoke: %d: %s", a.status, a.body)
	}
	for _, route := range []string{"machines/suspend", "machines/resume"} {
		if a = h.confirm(t, route, MachineRevokeRequest{MachineID: machineLaptop}, h.auth); a.status != http.StatusConflict {
			t.Errorf("%s of a revoked machine = %d, want 409: %s", route, a.status, a.body)
		}
	}
}

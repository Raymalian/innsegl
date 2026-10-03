// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"testing"

	"innsegl.dev/innsegl/internal/accounts"
)

// #490: `innsegl connect --disconnect` removed the client's files but left
// its installation active on the core until someone revoked it there. A
// machine now revokes its own installation over its own certificate, and
// that certificate is refused from then on.
func TestAMachineRevokesItsOwnInstallation(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	_, cert := enrol(t, f, g, c)

	if status, body := g.post(t, g.client(t, nil), coreDisconnectPath, "", nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("disconnect without a certificate: %d %s", status, body)
	}

	if status, body := g.post(t, g.client(t, cert), coreDisconnectPath, "", nil); status != http.StatusNoContent {
		t.Fatalf("disconnect: %d %s", status, body)
	}
	inst, err := f.writer.GetInstallation(t.Context(), c.id)
	if err != nil || inst.Status != accounts.StatusRevoked {
		t.Fatalf("installation after disconnect = %+v, %v; want revoked", inst, err)
	}

	if status, body := g.post(t, g.client(t, cert), coreRenewPath, `{"csr":""}`, nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("the disconnected certificate was not refused: %d %s", status, body)
	}
}

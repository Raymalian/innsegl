// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/mirror"
)

// ACC-019 (RM-355, #603): the core enrols, renews and revokes a machine with
// the enroller role, and refuses to start holding the auth-writer.
//
// The hosted gateway here is the real one, on a real Postgres, with the
// enroller provisioned by the shipped grants: every statement the routes
// issue runs as that role, so a grant the code needs and enroller.sql lacks
// is a failed request, not a passing test.
func TestACC019TheCoreEnrolsRenewsAndRevokesWithTheEnroller(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)

	first, cert := enrol(t, f, g, c)

	b, err := json.Marshal(map[string]string{"csr": c.ownCSR(t)})
	if err != nil {
		t.Fatal(err)
	}
	status, body := g.post(t, g.client(t, cert), coreRenewPath, string(b), nil)
	if status != http.StatusOK {
		t.Fatalf("renew with the enroller: %d %s", status, body)
	}
	renewed := parseIssued(t, body)
	if renewed.chain[0].SerialNumber.Cmp(first.chain[0].SerialNumber) == 0 {
		t.Fatal("renew answered the first certificate")
	}
	if inst, gerr := f.writer.GetInstallation(t.Context(), c.id); gerr != nil || inst.LastRenewedAt == nil {
		t.Fatalf("renewal not recorded: %+v, %v", inst, gerr)
	}

	if status, body := g.post(t, g.client(t, c.tlsCert(renewed)), coreDisconnectPath, "", nil); status != http.StatusNoContent {
		t.Fatalf("revoke with the enroller: %d %s", status, body)
	}
	inst, err := f.writer.GetInstallation(t.Context(), c.id)
	if err != nil || inst.Status != accounts.StatusRevoked {
		t.Fatalf("installation after revoke = %+v, %v; want revoked", inst, err)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.audit WHERE subject = $1
		AND action IN ('installation.created', 'installation.renewed', 'installation.revoked')`, c.id); n != 3 {
		t.Fatalf("audit rows for enrol, renew and revoke = %d, want 3", n)
	}

	// The gateway's log says nothing failed underneath.
	if strings.Contains(g.log.String(), "permission denied") {
		t.Fatalf("a route was refused by the enroller's grants:\n%s", g.log.String())
	}
}

func TestACC019TheCoreRefusesTheAuthWriter(t *testing.T) {
	f := newEnFixture(t)
	t.Setenv(mirror.EnvDir, filepath.Join(t.TempDir(), "mirror"))
	keyDir, certDir := gatewayTestCADirs(t)
	args := []string{
		"-listen", "127.0.0.1:0", "-dsn", f.ownerDSN,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
		"-client-auth", clientAuthSPIFFE, "-accounts-dsn", f.authDSN,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	stderr := &syncBuffer{}
	code := runGateway(ctx, args, io.Discard, stderr, gatewayDeps{})
	if code == 0 {
		t.Fatal("the core started holding the auth-writer as its enrolment credential")
	}
	if !strings.Contains(stderr.String(), "enroller") || !strings.Contains(stderr.String(), "read innsegl_auth.users") {
		t.Fatalf("the refusal does not say why:\n%s", stderr.String())
	}
}

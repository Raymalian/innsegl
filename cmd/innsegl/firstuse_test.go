// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/mirror"
)

// A repository is recorded on first use (ADR-0063, amended 2026-10-02): no
// one grants it by hand. The installation's organisation becomes its holder
// the first time a session states it, audited with the installation as the
// actor, and the run is registered under the repository's real name. A
// repository another organisation holds is refused with the guard's 401.

const (
	fuFresh = "github.com/acme/fresh"
	fuHeld  = "github.com/rival/held"
)

// rivalHolds gives a second organisation a live grant on fuHeld.
func rivalHolds(t *testing.T, f *enFixture) {
	t.Helper()
	// A second organisation needs the deployment's switch to pseudonymous
	// repositories recorded first (ACC-008).
	pool := gwIdentityPool(t, f.ownerDSN)
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO innsegl.repo_mode (mode, key_id) VALUES ('pseudonymous', 'rk-test0001') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	rival, err := f.writer.CreateAccount(t.Context(), accounts.CreateAccountParams{Name: "Rival"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.writer.GrantRepo(t.Context(), rival.ID, fuHeld, ""); err != nil {
		t.Fatal(err)
	}
}

func TestHostedRepositoryIsRecordedOnFirstUse(t *testing.T) {
	f := newEnFixture(t)
	rivalHolds(t, f)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	_, cert := enrol(t, f, g, c, accounts.AllRepos)
	cl := g.client(t, cert)

	const session = "55555555-5555-4555-8555-555555555555"
	if status, body := g.post(t, cl, gatewaySessionWorkspacePath, statement(t, session, fuFresh), nil); status != http.StatusNoContent {
		t.Fatalf("statement for a repository nobody holds: %d %s", status, body)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.repo_grants WHERE account_id = $1 AND repo = $2 AND until IS NULL`,
		f.account, fuFresh); n != 1 {
		t.Fatalf("live grants for the organisation on %s = %d, want 1", fuFresh, n)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.audit
	                     WHERE account_id = $1 AND action = 'repo_grant.created' AND subject = (SELECT 'grant:' || grant_id FROM innsegl_auth.repo_grants WHERE repo = $2 AND until IS NULL) AND actor = $3`,
		f.account, fuFresh, accounts.ClaimActor(c.id)); n != 1 {
		t.Fatalf("audit rows for the first-use grant = %d, want 1", n)
	}

	if status, body := g.post(t, cl, "/v1/messages", enMessage, messageHeaders(session)); status != http.StatusOK {
		t.Fatalf("message in the claimed repository: %d %s", status, body)
	}
	if g.upstream.Load() != 1 {
		t.Fatalf("upstream saw %d requests, want 1", g.upstream.Load())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping m JOIN innsegl.events e
	                       ON e.run_id = m.run_id AND e.event_type = 'run_registered'
	                     WHERE m.session_id = $1 AND m.client_id = $2
	                       AND position($3 in convert_from(e.canonical, 'UTF8')) > 0`,
		session, c.id, `"repo":"`+fuFresh+`"`); n != 1 {
		t.Fatalf("runs registered under %s for the session = %d, want 1", fuFresh, n)
	}

	// Held by another organisation: the statement is refused and nothing is
	// registered, but the session's model requests still go through.
	const heldSession = "66666666-6666-4666-8666-666666666666"
	entries := f.ids.entryCount()
	if status, body := g.post(t, cl, gatewaySessionWorkspacePath, statement(t, heldSession, fuHeld), nil); status != http.StatusUnauthorized || body != enGuardRefusal {
		t.Fatalf("statement for another organisation's repository: %d %s", status, body)
	}
	// Never blocked (RM-313): the session's model request is forwarded,
	// unrecorded — no run is registered for a repository this organisation
	// may not record.
	if status, body := g.post(t, cl, "/v1/messages", enMessage, messageHeaders(heldSession)); status != http.StatusOK {
		t.Fatalf("a message for a session in another organisation's repository: %d %s, want it forwarded", status, body)
	}
	if g.upstream.Load() != 2 || f.ids.entryCount() != entries {
		t.Fatalf("upstream saw %d (want 2) and runs went %d -> %d (want unchanged)", g.upstream.Load(), entries, f.ids.entryCount())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.repo_grants WHERE account_id = $1 AND repo = $2`, f.account, fuHeld); n != 0 {
		t.Fatal("another organisation's repository changed hands")
	}
}

// The mirror push uses the same rule: a repository the organisation does not
// hold yet is claimed on the push, and one another organisation holds is
// refused.
func TestHostedPushClaimsARepositoryOnFirstUse(t *testing.T) {
	mirrorRoot := filepath.Join(t.TempDir(), "mirror")
	t.Setenv(mirror.EnvDir, mirrorRoot)
	f := newEnFixture(t)
	rivalHolds(t, f)
	g := startHostedGateway(t, f)

	caPEM, err := os.ReadFile(filepath.Join(g.certDir, gateway.CACertFileName))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	enrolment, err := client.Enrol(ctx, client.EnrolOptions{
		CoreURL: "https://" + g.addr, Token: f.token(t, accounts.AllRepos), Name: "push machine", CA: ca,
	})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	paths := client.ClientPaths(t.TempDir())
	if werr := client.WriteEnrolment(paths, enrolment, "127.0.0.1:0"); werr != nil {
		t.Fatal(werr)
	}
	srv, err := client.NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(srv.Handler())
	t.Cleanup(local.Close)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")
	core := commitpath.Client{BaseURL: local.URL, HTTP: local.Client()}

	stage := func(origin string) error {
		dir, env := pushTestRepo(t)
		if out, gerr := signGit(t, dir, env, "remote", "set-url", "origin", "https://"+origin+".git"); gerr != nil {
			t.Fatalf("%v: %s", gerr, out)
		}
		return core.Stage(ctx, dir, pushToolUseID, []byte(signPushPayload(t, dir, env)))
	}

	if serr := stage(fuFresh); serr != nil {
		t.Fatalf("a push for a repository nobody holds: %v", serr)
	}
	store, err := mirror.New(mirrorRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, derr := store.Dir(fuFresh); derr != nil {
		t.Fatalf("no mirror after the push: %v", derr)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.repo_grants WHERE account_id = $1 AND repo = $2 AND until IS NULL`,
		f.account, fuFresh); n != 1 {
		t.Fatalf("live grants on %s after the push = %d, want 1", fuFresh, n)
	}

	if serr := stage(fuHeld); serr == nil {
		t.Fatal("a push for another organisation's repository was accepted")
	}
	if _, derr := store.Dir(fuHeld); derr == nil {
		t.Fatal("a refused push created a mirror")
	}
}

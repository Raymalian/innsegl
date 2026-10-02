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
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/gateway"
)

// OPS-130 (in process): the real client against the real hosted core. #460
// and #461 were built in parallel against a written contract and each tested
// against a fake of the other; this proves the two halves agree: enrolment,
// a statement and a model request through `innsegl client serve`, renewal,
// and revocation.
func TestOPS130TheClientEnrolsAndWorksThroughTheHostedCore(t *testing.T) {
	f := newEnFixture(t)
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	enrolment, err := client.Enrol(ctx, client.EnrolOptions{
		CoreURL: "https://" + g.addr, Token: f.token(t), Name: "test machine", CA: ca,
	})
	if err != nil {
		t.Fatalf("Enrol against the real core: %v", err)
	}
	paths := client.ClientPaths(t.TempDir())
	if werr := client.WriteEnrolment(paths, enrolment, "127.0.0.1:0"); werr != nil {
		t.Fatal(werr)
	}
	srv, err := client.NewServer(paths, io.Discard)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	local := httptest.NewServer(srv.Handler())
	t.Cleanup(local.Close)

	post := func(path, body string, header map[string]string) (int, string) {
		t.Helper()
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, local.URL+path, strings.NewReader(body))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatalf("POST %s through the client service: %v", path, derr)
		}
		defer func() { _ = resp.Body.Close() }()
		b, berr := io.ReadAll(resp.Body)
		if berr != nil {
			t.Fatalf("read %s: %v", path, berr)
		}
		return resp.StatusCode, strings.TrimSpace(string(b))
	}

	const session = "33333333-3333-4333-8333-333333333333"
	if status, body := post(gatewaySessionWorkspacePath, statement(t, session, enRepo), nil); status != http.StatusNoContent {
		t.Fatalf("statement through the client service: %d %s", status, body)
	}
	if status, body := post("/v1/messages", enMessage, messageHeaders(session)); status != http.StatusOK {
		t.Fatalf("model request through the client service: %d %s", status, body)
	}
	if g.upstream.Load() != 1 {
		t.Fatalf("upstream saw %d requests, want 1", g.upstream.Load())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1 AND client_id = $2`,
		session, enrolment.InstallationID); n != 1 {
		t.Fatalf("mapping rows naming the enrolled installation = %d, want 1", n)
	}

	// A session outside any repository, through the same client service:
	// accepted and forwarded, and recorded nowhere (ADR-0063, amended
	// 2026-10-02).
	const homeSession = "77777777-7777-4777-8777-777777777777"
	if status, body := post(gatewaySessionWorkspacePath, `{"session_id":"`+homeSession+`","cwd":"/client/notes"}`, nil); status != http.StatusNoContent {
		t.Fatalf("directory-only statement through the client service: %d %s", status, body)
	}
	if status, body := post("/v1/messages", enMessage, messageHeaders(homeSession)); status != http.StatusOK {
		t.Fatalf("model request outside any repository: %d %s", status, body)
	}
	if g.upstream.Load() != 2 {
		t.Fatalf("upstream saw %d requests, want 2", g.upstream.Load())
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1`, homeSession); n != 0 {
		t.Fatalf("a session outside any repository has %d mapping rows", n)
	}

	// RM-313: a statement the core refuses for scope is surfaced (401 to the
	// hook), and the session's model requests, carrying the client service's
	// cached statement, are forwarded unrecorded: never a 503 loop.
	const outSession = "55555555-5555-4555-8555-555555555555"
	if status, body := post(gatewaySessionWorkspacePath, statement(t, outSession, enOtherRepo), nil); status != http.StatusUnauthorized {
		t.Fatalf("out-of-scope statement through the client service: %d %s, want 401", status, body)
	}
	if status, body := post("/v1/messages", enMessage, messageHeaders(outSession)); status != http.StatusOK {
		t.Fatalf("model request after an out-of-scope statement: %d %s, want it forwarded", status, body)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1`, outSession); n != 0 {
		t.Fatalf("an out-of-scope session has %d mapping rows", n)
	}
	g.upstream.Store(1)

	// Renewal against the real core, past half-life: same installation, a
	// later expiry, and requests keep working.
	before := srv.Leaf().NotAfter
	srv.Now = func() time.Time { return srv.RenewAt().Add(time.Second) }
	if renewed, rerr := srv.MaybeRenew(ctx); rerr != nil || !renewed {
		t.Fatalf("renewal against the real core: renewed=%v err=%v", renewed, rerr)
	}
	if !srv.Leaf().NotAfter.After(before) && !srv.Leaf().NotAfter.Equal(before) {
		t.Fatalf("renewed certificate expires %v, before %v", srv.Leaf().NotAfter, before)
	}
	if status, body := post("/v1/messages", enMessage, messageHeaders(session)); status != http.StatusOK {
		t.Fatalf("model request after renewal: %d %s", status, body)
	}

	// Revoked on the core: the next request is refused and reaches nothing.
	if serr := f.writer.SetInstallationStatus(ctx, enrolment.InstallationID, accounts.StatusRevoked, "u-1"); serr != nil {
		t.Fatal(serr)
	}
	if status, _ := post("/v1/messages", enMessage, messageHeaders(session)); status != http.StatusUnauthorized {
		t.Fatalf("revoked installation through the client service: %d, want 401", status)
	}
	if g.upstream.Load() != 2 {
		t.Fatalf("upstream saw %d requests after revocation, want 2", g.upstream.Load())
	}
	srv.Now = func() time.Time { return srv.RenewAt().Add(time.Second) }
	if _, rerr := srv.MaybeRenew(ctx); rerr == nil {
		t.Fatal("a revoked installation renewed")
	}
}

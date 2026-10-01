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
	if err := client.WriteEnrolment(paths, enrolment, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
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
		b, _ := io.ReadAll(resp.Body)
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
	if err := f.writer.SetInstallationStatus(ctx, enrolment.InstallationID, accounts.StatusRevoked, "u-1"); err != nil {
		t.Fatal(err)
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

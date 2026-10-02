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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/mirror"
)

// #464: the receive endpoint is mounted on a hosted core with a mirror, and
// nowhere else.

func coreGitPath() string {
	return commitpath.GitPathPrefix + "github.com/acme/widgets.git/info/refs?service=git-receive-pack"
}

func mountedPattern(mux *http.ServeMux) string {
	_, pattern := mux.Handler(httptest.NewRequestWithContext(context.Background(), http.MethodGet, coreGitPath(), nil))
	return pattern
}

func TestTheReceiveEndpointIsAbsentOnASingleHostCore(t *testing.T) {
	mux := http.NewServeMux()
	if err := mountCoreGit(mux, nil); err != nil {
		t.Fatal(err)
	}
	if p := mountedPattern(mux); p != "" {
		t.Fatalf("single-host core mounted %q", p)
	}
	if commitMirror(nil) != nil {
		t.Fatal("a single-host core handed the sign path a mirror")
	}
}

func TestTheReceiveEndpointIsAbsentOnAHostedCoreWithNoMirror(t *testing.T) {
	mux := http.NewServeMux()
	h := &hostedCore{scope: allowAll{}}
	if err := mountCoreGit(mux, h); err != nil {
		t.Fatal(err)
	}
	if p := mountedPattern(mux); p != "" {
		t.Fatalf("a hosted core with no mirror mounted %q", p)
	}
	if commitMirror(h) != nil {
		t.Fatal("a nil mirror reached the sign path as a non-nil interface")
	}
}

func TestTheReceiveEndpointOnAHostedCoreRefusesWithTheGuardsRefusal(t *testing.T) {
	store, err := openCoreMirror(filepath.Join(t.TempDir(), "mirror"))
	if err != nil || store == nil {
		t.Fatalf("openCoreMirror: %v %v", store, err)
	}
	h := &hostedCore{scope: allowAll{}, mirror: store}
	mux := http.NewServeMux()
	if err := mountCoreGit(mux, h); err != nil {
		t.Fatal(err)
	}
	if p := mountedPattern(mux); p != commitpath.GitPathPrefix {
		t.Fatalf("mounted %q, want %q", p, commitpath.GitPathPrefix)
	}
	if commitMirror(h) == nil {
		t.Fatal("the sign path got no mirror")
	}
	// No installation on the request: the guard's own 401.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, coreGitPath(), nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), gateway.ClientRefusalMessage) {
		t.Fatalf("no installation: %d %s", rec.Code, rec.Body.String())
	}
	// With one, in scope: git's advertisement.
	rec = httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, coreGitPath(), nil)
	req = req.WithContext(gateway.WithInstallation(req.Context(), pushInstallation))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "# service=git-receive-pack") {
		t.Fatalf("in scope: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOpenCoreMirrorIsOptional(t *testing.T) {
	store, err := openCoreMirror("")
	if err != nil || store != nil {
		t.Fatalf("openCoreMirror(\"\") = %v, %v; want nil, nil", store, err)
	}
}

// The whole push path against the real hosted core: an enrolled client
// service forwards the client's git push over its certificate, the guard and
// the scope check admit it, and the staging ref lands in the mirror. A
// repository outside the installation's scope, and a caller with no
// certificate, are refused with the guard's one 401.
func TestHostedPushReachesTheMirrorThroughTheClientService(t *testing.T) {
	mirrorRoot := filepath.Join(t.TempDir(), "mirror")
	t.Setenv(mirror.EnvDir, mirrorRoot)
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
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	enrolment, err := client.Enrol(ctx, client.EnrolOptions{
		CoreURL: "https://" + g.addr, Token: f.token(t), Name: "push machine", CA: ca,
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

	if serr := stage(enRepo); serr != nil {
		t.Fatalf("an in-scope push through the client service: %v", serr)
	}
	store, err := mirror.New(mirrorRoot)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := store.Dir(enRepo)
	if err != nil {
		t.Fatalf("no mirror after the push: %v", err)
	}
	ref := commitpath.StagingRef(enrolment.InstallationID, pushToolUseID)
	if out, rerr := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--verify", "--quiet", ref).CombinedOutput(); rerr != nil {
		t.Fatalf("the mirror holds no %s: %v %s", ref, rerr, out)
	}

	if serr := stage(enOtherRepo); serr == nil {
		t.Fatal("a push for a repository outside the installation's scope was accepted")
	}
	if _, derr := store.Dir(enOtherRepo); derr == nil {
		t.Fatal("an out-of-scope push created a mirror")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+g.addr+coreGitPathFor(enRepo), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := g.client(t, nil).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized || strings.TrimSpace(string(body)) != enGuardRefusal {
		t.Fatalf("no certificate: %d %s", resp.StatusCode, body)
	}
}

func coreGitPathFor(repo string) string {
	return commitpath.GitPathPrefix + repo + ".git/info/refs?service=git-receive-pack"
}

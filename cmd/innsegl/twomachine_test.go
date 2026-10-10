// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/gateway"
)

// OPS-174 (#463): a second machine against a core it does not share a
// process, a home directory or a key with. The machine is the shipped
// binary, run as separate processes under a home of its own: `innsegl
// connect` enrols it with a fresh token and writes its own key and
// certificate, `innsegl client serve` holds them, and `innsegl status`
// reports through them. Revoked on the core, its requests and its renewal
// are refused with 401.
//
// The core is the real hosted gateway on a real Postgres, as in OPS-176; the
// model provider is a stub, so this proves the machine-to-core path and not
// a model session.
func TestOPS174ASecondMachineEnrolsWorksAndIsRefusedOnceRevoked(t *testing.T) {
	f := newEnFixture(t)

	// The core's readiness, which /_core/status reports to the machine.
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"ready":true,"repo_mode":"pseudonymous",` +
			`"dependencies":[{"dependency":"ledger","reachable":true}]}`)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(ready.Close)
	t.Setenv(envMCPHealthListen, strings.TrimPrefix(ready.URL, "http://"))

	g := startHostedGateway(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	bin := buildInnsegl(ctx, t)
	home := t.TempDir()
	listen := freeLoopbackAddr(t)
	machine := func(args ...string) (int, string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		// Its own home, and no harness on PATH: connect then says it cannot
		// check the harness instead of asking this host's one.
		cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		code := 0
		if err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("%v: %v\n%s", args, err, out.String())
			}
			code = exitErr.ExitCode()
		}
		return code, out.String()
	}

	// Enrol, with a token minted for this machine and the core's CA by file.
	code, out := machine("connect", "https://"+g.addr, "--token", f.token(t),
		"--ca", filepath.Join(g.certDir, gateway.CACertFileName), "--name", "machine-two",
		"--listen", listen, "--no-service", "--managed-settings", filepath.Join(home, "managed-settings.json"))
	if code != exitOK {
		t.Fatalf("connect exit %d:\n%s", code, out)
	}
	clientDir := filepath.Join(home, ".innsegl", "client")
	var core struct {
		InstallationID string `json:"installation_id"`
	}
	readJSONFile(t, filepath.Join(clientDir, "core.json"), &core)
	if core.InstallationID == "" {
		t.Fatalf("core.json names no installation")
	}

	// Its own certificate: a client identity naming its own installation.
	leaf := readCertFile(t, filepath.Join(clientDir, "cert.pem"))
	if len(leaf.URIs) != 1 || !strings.HasSuffix(leaf.URIs[0].String(), "/client/"+core.InstallationID) {
		t.Fatalf("the machine's certificate names %v, want its own installation %s", leaf.URIs, core.InstallationID)
	}

	// Its client service, a process of its own.
	serve := exec.CommandContext(ctx, bin, "client", "serve", "--listen", listen)
	serve.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	var serveLog bytes.Buffer
	serve.Stdout, serve.Stderr = &serveLog, &serveLog
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if kerr := serve.Process.Kill(); kerr != nil {
			t.Logf("stopping the client service: %v", kerr)
		}
		if werr := serve.Wait(); werr != nil {
			t.Logf("the client service ended: %v", werr)
		}
	})
	waitListening(t, listen, &serveLog)

	code, out = machine("status")
	if code != exitOK {
		t.Fatalf("status exit %d before revocation:\n%s", code, out)
	}
	for _, want := range []string{"client service", "repository names", "pseudonymous", "machine-two"} {
		if !strings.Contains(out, want) {
			t.Errorf("status before revocation does not show %q:\n%s", want, out)
		}
	}
	if status := postThrough(ctx, t, listen, "/v1/messages"); status != http.StatusOK {
		t.Fatalf("a model request through the machine: %d, want 200", status)
	}

	// Revoked on the core.
	if err := f.writer.SetInstallationStatus(ctx, core.InstallationID, accounts.StatusRevoked, "u-1"); err != nil {
		t.Fatal(err)
	}

	code, out = machine("status")
	if code == exitOK || !strings.Contains(out, "401") {
		t.Errorf("status after revocation: exit %d, want the core's 401:\n%s", code, out)
	}
	if status := postThrough(ctx, t, listen, "/v1/messages"); status != http.StatusUnauthorized {
		t.Errorf("a model request after revocation: %d, want 401", status)
	}
	if status := renewWith(ctx, t, g.addr, clientDir); status != http.StatusUnauthorized {
		t.Errorf("renewal after revocation: %d, want 401", status)
	}
}

func buildInnsegl(ctx context.Context, t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "innsegl")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func waitListening(t *testing.T, addr string, log *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: time.Second}
		if c, err := d.DialContext(t.Context(), "tcp", addr); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the client service never listened on %s:\n%s", addr, log.String())
}

func postThrough(ctx context.Context, t *testing.T, listen, path string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+listen+path, strings.NewReader(enMessage))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range messageHeaders("44444444-4444-4444-8444-444444444444") {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s through the machine: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return resp.StatusCode
}

// renewWith presents the machine's own certificate to the core's renewal
// endpoint.
func renewWith(ctx context.Context, t *testing.T, coreAddr, clientDir string) int {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(filepath.Join(clientDir, "cert.pem"), filepath.Join(clientDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(clientDir, "gateway-ca.pem"))
	if err != nil || !roots.AppendCertsFromPEM(ca) {
		t.Fatalf("the machine's copy of the core CA: %v", err)
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{pair}, RootCAs: roots, MinVersion: tls.VersionTLS12,
	}}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+coreAddr+coreRenewPath,
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func readJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- the test's own temporary home.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func readCertFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- the test's own temporary home.
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

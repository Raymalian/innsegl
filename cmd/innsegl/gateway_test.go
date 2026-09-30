// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
)

// gatewayTestCADirs returns two fresh temporary directories for a test's
// own gateway.LoadOrCreateCA call -- the key directory and the public
// certificate directory (RM-246, #391) -- so every test in this package
// that drives the real, unfaked openGateway has somewhere to keep its CA
// that is never the developer's own $HOME. gatewayOptions.caKeyDir/caCertDir
// have no filesystem-touching default for exactly this reason: a test that
// forgets to set them fails loudly (an empty flag is refused by validate)
// rather than silently writing into the operator's real state.
func gatewayTestCADirs(t *testing.T) (keyDir, certDir string) {
	t.Helper()
	return t.TempDir(), t.TempDir()
}

// gatewayTestValidCADirs sets $INNSEGL_GATEWAY_CA_KEY_DIR/CERT_DIR to fresh
// temporary directories for the life of t, via t.Setenv (auto-restored when
// t ends). RM-246 makes both flags required with no fallback default --
// TestGatewayCommandRefusesWithNoCADirsConfigured is the test that holds
// that -- so every OTHER test in this file that reaches
// gatewayOptions.validate() (directly or through runGatewayCommand /
// parseGatewayFlags) needs this first, or the CA-directory check earlier in
// that same switch masks whatever ONE thing the test actually means to
// prove.
func gatewayTestValidCADirs(t *testing.T) {
	t.Helper()
	t.Setenv(envGatewayCAKeyDir, t.TempDir())
	t.Setenv(envGatewayCACertDir, t.TempDir())
}

// gatewayTrustingClient reads the CA certificate a real openGateway already
// wrote to certDir (gateway.LoadOrCreateCA's own PublicDir,
// gateway.CACertFileName) and returns an *http.Client that trusts exactly
// it -- the same shape commitpath.TrustedHTTPClient builds for the real
// host commands, reimplemented here so this package's own tests do not take
// on commitpath's reading of $NODE_EXTRA_CA_CERTS or $HOME. Never
// InsecureSkipVerify: a test that cannot read or parse the certificate
// fails loudly instead.
func gatewayTrustingClient(t *testing.T, certDir string) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(certDir, gateway.CACertFileName))
	if err != nil {
		t.Fatalf("read the test gateway's own CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("the test gateway's own CA certificate in %s is not a valid PEM certificate", certDir)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}

// TestGatewayServesHTTPSFromItsOwnCA is TLS-001's own listener half: the
// gateway's own listener speaks TLS, presenting a leaf signed by the CA it
// created under -ca-key-dir/-ca-cert-dir, and a client trusting ONLY that
// CA can complete a real handshake and get a real reply through the full,
// unfaked openGateway/proxy path.
func TestGatewayServesHTTPSFromItsOwnCA(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok-from-upstream")); err != nil {
			t.Errorf("upstream: write reply: %v", err)
		}
	}))
	defer upstream.Close()

	keyDir, certDir := gatewayTestCADirs(t)
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstream.Client()
		o.caKeyDir = keyDir
		o.caCertDir = certDir
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstream.URL,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
	}
	done := make(chan int, 1)
	go func() {
		done <- runGateway(ctx, args, io.Discard, io.Discard, deps)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never announced a bound address")
	}

	// The CA certificate must already be published: openGateway writes it
	// before returning successfully.
	if _, err := os.Stat(filepath.Join(certDir, gateway.CACertFileName)); err != nil {
		t.Fatalf("the gateway's own CA certificate was not published to -ca-cert-dir: %v", err)
	}

	client := gatewayTrustingClient(t, certDir)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("X-Claude-Code-Session-Id", "3f6a9b1c-2d4e-4f7a-9c8b-1e2f3a4b5c6d")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("https request through the gateway, trusting only its own CA: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(body) != "ok-from-upstream" {
		t.Fatalf("body = %q, want ok-from-upstream", body)
	}
	if resp.TLS == nil {
		t.Fatal("the response carries no TLS connection state")
	}
	if resp.TLS.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version = %#x, want at least TLS 1.2", resp.TLS.Version)
	}

	// A plain, unencrypted request to the same address must never reach the
	// proxy: the listener speaks TLS only. crypto/tls's own server side
	// recognises a plaintext HTTP request arriving on a TLS listener and
	// answers it directly, in plaintext, with its own 400 ("client sent an
	// HTTP request to an HTTPS server") -- so the client call below can
	// return a nil error; what it must never do is carry the UPSTREAM's own
	// reply, which would mean the proxy itself accepted plaintext.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	plainReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if plainResp, err := plainClient.Do(plainReq); err == nil {
		defer func() { _ = plainResp.Body.Close() }()
		plainBody, rerr := io.ReadAll(plainResp.Body)
		if rerr != nil {
			t.Fatalf("read the plain http response: %v", rerr)
		}
		if strings.Contains(string(plainBody), "ok-from-upstream") {
			t.Errorf("a plain http request reached the proxy and got the upstream's own reply: %q", plainBody)
		}
		if plainResp.StatusCode == http.StatusOK {
			t.Errorf("a plain http request got a 200 from the gateway's own listener, want TLS's own refusal")
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not stop within 5s of its context being cancelled")
	}
}

// TestGatewayCommandRelaysRealTrafficEndToEnd runs the PRODUCTION wiring —
// openGateway, unfaked — against a real listener and a real upstream, and
// proves a request made through the bound address comes back with the
// upstream's own reply. This is `innsegl gateway`'s own contract, run
// standalone rather than through `serve -also gateway`; GW-004
// (servealso_test.go) covers the companion's lifecycle inside `serve`.
//
// The upstream is TLS, not plain HTTP (GW-007: an http upstream is refused
// before this command does anything else, see
// TestGatewayCommandRefusesAnHTTPUpstreamBeforeOpeningAnything below) and
// the httptest server's own certificate is trusted only by ITS OWN client
// (upstream.Client()), handed through gatewayOptions.upstreamClient -- the
// one seam that field exists for. openGateway itself is still the real,
// unfaked production function; only the client it hands to
// gateway.NewUpstream comes from the test, exactly the way
// internal/gateway's own tests already inject a client one level down.
func TestGatewayCommandRelaysRealTrafficEndToEnd(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-From-Upstream", "yes")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok-from-upstream")); err != nil {
			t.Errorf("upstream: write reply: %v", err)
		}
	}))
	defer upstream.Close()

	// The real openGateway, tapped only to learn the bound address without
	// racing on stdout: runGateway prints it there exactly once, and
	// reading a bytes.Buffer while another goroutine is still writing to it
	// is what -race exists to catch.
	keyDir, certDir := gatewayTestCADirs(t)
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstream.Client()
		o.caKeyDir = keyDir
		o.caCertDir = certDir
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstream.URL,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
	}
	done := make(chan int, 1)
	go func() {
		done <- runGateway(ctx, args, io.Discard, io.Discard, deps)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never announced a bound address")
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// A recognised harness shape: openGateway wires the harness-shape guard
	// explicitly (GW-011, #374), ahead of the per-session rate limit guard
	// (GW-013, #375) that reads what it attaches, so an unrecognised path
	// or a request with no session header is refused before ever reaching
	// the upstream this test is asserting against.
	req.Header.Set("X-Claude-Code-Session-Id", "3f6a9b1c-2d4e-4f7a-9c8b-1e2f3a4b5c6d")
	resp, err := gatewayTrustingClient(t, certDir).Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(body) != "ok-from-upstream" {
		t.Fatalf("body = %q, want ok-from-upstream", body)
	}
	if got := resp.Header.Get("X-From-Upstream"); got != "yes" {
		t.Errorf("X-From-Upstream = %q, want yes", got)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not stop within 5s of its context being cancelled")
	}
}

// TestGatewayCommandEnforcesGW013RateLimitEndToEnd runs the PRODUCTION
// wiring -- openGateway, unfaked -- with a tiny configured burst, and
// proves a session that exceeds it gets refused with 429, a Retry-After
// header, and a JSON body naming innsegl, while nothing reaches the
// upstream for that refused request.
func TestGatewayCommandEnforcesGW013RateLimitEndToEnd(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	keyDir, certDir := gatewayTestCADirs(t)
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstream.Client()
		o.caKeyDir = keyDir
		o.caCertDir = certDir
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstream.URL,
		"-rate-limit-rate", "1", "-rate-limit-burst", "1",
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
	}
	done := make(chan int, 1)
	go func() {
		done <- runGateway(ctx, args, io.Discard, io.Discard, deps)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never announced a bound address")
	}

	client := gatewayTrustingClient(t, certDir)
	newRequest := func() *http.Request {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/v1/messages", nil)
		if err != nil {
			t.Fatalf("NewRequestWithContext: %v", err)
		}
		req.Header.Set("X-Claude-Code-Session-Id", "3f6a9b1c-2d4e-4f7a-9c8b-1e2f3a4b5c6d")
		return req
	}

	resp1, err := client.Do(newRequest())
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200 (burst is 1)", resp1.StatusCode)
	}

	resp2, err := client.Do(newRequest())
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want %d", resp2.StatusCode, http.StatusTooManyRequests)
	}
	if got := resp2.Header.Get("Retry-After"); got == "" {
		t.Error("second request carries no Retry-After header")
	}
	body, err := io.ReadAll(resp2.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !strings.Contains(string(body), "innsegl") {
		t.Errorf("body %q does not name innsegl", body)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not stop within 5s of its context being cancelled")
	}
}

// TestGatewayCommandRefusesAnUnrecognisedHarnessShapeEndToEnd is GW-011,
// run through the PRODUCTION wiring rather than internal/gateway's own
// package tests: openGateway's guard chain comes from gateway.Guards
// (guard.go), the one ordered list that command and package both build
// from, and this proves the harness-shape guard is still first in it here
// -- not only in internal/gateway's own test suite. A request with no
// recognised harness shape (no session header at all) must be refused with
// 400 before the rate-limit guard, or anything else, ever sees it, and the
// upstream must never be asked.
func TestGatewayCommandRefusesAnUnrecognisedHarnessShapeEndToEnd(t *testing.T) {
	var upstreamHits int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	keyDir, certDir := gatewayTestCADirs(t)
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstream.Client()
		o.caKeyDir = keyDir
		o.caCertDir = certDir
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstream.URL,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
	}
	done := make(chan int, 1)
	go func() {
		done <- runGateway(ctx, args, io.Discard, io.Discard, deps)
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway never announced a bound address")
	}

	// Deliberately no X-Claude-Code-Session-Id header: an unrecognised
	// harness shape.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := gatewayTrustingClient(t, certDir).Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d (GW-011)", resp.StatusCode, http.StatusBadRequest)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !strings.Contains(string(body), "unrecognised harness shape") {
		t.Errorf("body %q does not name the refusal reason", body)
	}
	if got := atomic.LoadInt32(&upstreamHits); got != 0 {
		t.Errorf("upstream received %d requests, want 0 -- nothing should be forwarded", got)
	}

	cancel()
	select {
	case code := <-done:
		if code != exitOK {
			t.Fatalf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not stop within 5s of its context being cancelled")
	}
}

// TestGatewayCommandRefusesAnHTTPUpstreamBeforeOpeningAnything is GW-007:
// an http -upstream is refused at start-up, naming the flag, and nothing is
// opened to prove it -- deps.open must never even be called.
func TestGatewayCommandRefusesAnHTTPUpstreamBeforeOpeningAnything(t *testing.T) {
	gatewayTestValidCADirs(t)
	deps := gatewayDeps{open: func(context.Context, gatewayOptions, *serveLog) (servedGateway, error) {
		t.Fatal("openGateway was called; an http upstream must be refused before anything opens")
		return nil, nil
	}}

	var stdout, stderr bytes.Buffer
	code := runGatewayCommand(
		[]string{"-listen", "127.0.0.1:0", "-upstream", "http://example.invalid"},
		&stdout, &stderr, deps)

	if code != exitUsage {
		t.Errorf("gateway -upstream http://example.invalid = %d, want %d (exitUsage). stderr:\n%s",
			code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-upstream") || !strings.Contains(stderr.String(), "https") {
		t.Errorf("stderr = %q, want it to name -upstream and https", stderr.String())
	}
}

// TestGatewayCommandRefusesAnyNonHTTPSScheme covers the rest of GW-007's
// "or any non-https scheme" clause, not only the http case above.
func TestGatewayCommandRefusesAnyNonHTTPSScheme(t *testing.T) {
	gatewayTestValidCADirs(t)
	for _, upstream := range []string{"ws://example.invalid", "ftp://example.invalid"} {
		t.Run(upstream, func(t *testing.T) {
			deps := gatewayDeps{open: func(context.Context, gatewayOptions, *serveLog) (servedGateway, error) {
				t.Fatal("openGateway was called; a non-https upstream must be refused first")
				return nil, nil
			}}
			var stdout, stderr bytes.Buffer
			code := runGatewayCommand([]string{"-listen", "127.0.0.1:0", "-upstream", upstream},
				&stdout, &stderr, deps)
			if code != exitUsage {
				t.Errorf("gateway -upstream %s = %d, want %d (exitUsage). stderr:\n%s",
					upstream, code, exitUsage, stderr.String())
			}
		})
	}
}

// TestGatewayCommandAcceptsAnyCaseOfHTTPSScheme: the scheme comparison is
// case-insensitive, per RFC 3986 -- "HTTPS://..." is not a different,
// unrecognised scheme.
func TestGatewayCommandAcceptsAnyCaseOfHTTPSScheme(t *testing.T) {
	if problem := upstreamMustBeHTTPS("HTTPS://example.invalid"); problem != "" {
		t.Errorf("upstreamMustBeHTTPS(%q) = %q, want no problem", "HTTPS://example.invalid", problem)
	}
}

// TestUpstreamMustBeHTTPS is GW-007's own unit: table-driven over the
// scheme decision alone, independent of the rest of validate().
func TestUpstreamMustBeHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, upstream string
		wantProblem    bool
	}{
		{"https", "https://api.anthropic.com", false},
		{"http", "http://api.anthropic.com", true},
		{"ftp", "ftp://api.anthropic.com", true},
		{"uppercase scheme", "HTTPS://api.anthropic.com", false},
		{"no scheme, left to NewUpstream", "not a url", false},
		{"unparseable, left to NewUpstream", "https://[::1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := upstreamMustBeHTTPS(tc.upstream)
			if (got != "") != tc.wantProblem {
				t.Errorf("upstreamMustBeHTTPS(%q) = %q, want a problem: %v",
					tc.upstream, got, tc.wantProblem)
			}
		})
	}
}

func TestGatewayCommandHelpExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runGatewayCommand([]string{"-h"}, &stdout, &stderr, gatewayDeps{}); code != exitOK {
		t.Errorf("gateway -h = %d, want %d. stderr:\n%s", code, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "innsegl gateway") {
		t.Errorf("usage does not name the subcommand: %q", stderr.String())
	}
}

func TestGatewayCommandRefusesAnEmptyUpstream(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand([]string{"-listen", "127.0.0.1:0", "-upstream", ""},
		&stdout, &stderr, gatewayDeps{})
	if code != exitUsage {
		t.Errorf("gateway -upstream '' = %d, want %d (exitUsage)", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "-upstream") {
		t.Errorf("stderr = %q, want it to name -upstream", stderr.String())
	}
}

// TestGatewayCommandRefusesWithNoCADirsConfigured is a regression test for a
// review finding: an earlier version of this file defaulted -ca-key-dir and
// -ca-cert-dir to $HOME-relative paths when unset, "for a bare run outside
// compose" -- and that default was exactly what let an incompletely-updated
// test write a real CA private key to a developer's own $HOME (caught in
// review before it shipped). There is no default now, for either flag or
// its environment variable: `innsegl gateway`, run with every OTHER setting
// valid and -ca-key-dir/-ca-cert-dir simply never mentioned, must refuse to
// start -- deps.open (the real openGateway, unfaked) must never even be
// called, so nothing is opened and nothing is written anywhere.
func TestGatewayCommandRefusesWithNoCADirsConfigured(t *testing.T) {
	t.Setenv(envGatewayCAKeyDir, "")
	t.Setenv(envGatewayCACertDir, "")
	deps := gatewayDeps{open: func(context.Context, gatewayOptions, *serveLog) (servedGateway, error) {
		t.Fatal("openGateway was called; the gateway must refuse to start TLS with no CA " +
			"directories configured, before anything is opened or written")
		return nil, nil
	}}

	var stdout, stderr bytes.Buffer
	code := runGatewayCommand(
		[]string{"-listen", "127.0.0.1:0", "-upstream", "https://example.invalid"},
		&stdout, &stderr, deps)

	if code != exitUsage {
		t.Errorf("gateway with no -ca-key-dir/-ca-cert-dir = %d, want %d (exitUsage). stderr:\n%s",
			code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-ca-key-dir") && !strings.Contains(stderr.String(), "-ca-cert-dir") {
		t.Errorf("stderr = %q, want it to name -ca-key-dir or -ca-cert-dir", stderr.String())
	}
}

func TestGatewayCommandRefusesAnUnparseableUpstreamURL(t *testing.T) {
	gatewayTestValidCADirs(t)
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand([]string{"-listen", "127.0.0.1:0", "-upstream", "not a url"},
		&stdout, &stderr, gatewayDeps{})
	if code != exitGatewayUnavailable {
		t.Errorf("gateway -upstream 'not a url' = %d, want %d (exitGatewayUnavailable). stderr:\n%s",
			code, exitGatewayUnavailable, stderr.String())
	}
}

func TestGatewayCommandRefusesANegativeShutdownTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand([]string{"-shutdown-timeout", "-1s"}, &stdout, &stderr, gatewayDeps{})
	if code != exitUsage {
		t.Errorf("gateway -shutdown-timeout -1s = %d, want %d (exitUsage)", code, exitUsage)
	}
}

// --- GW-013 (#375, RM-230): the per-session rate limit's own flags,
// validated at start-up the same way -upstream already is. ---

func TestGatewayCommandRefusesANonPositiveRateLimitRate(t *testing.T) {
	for _, rate := range []string{"0", "-1"} {
		var stdout, stderr bytes.Buffer
		code := runGatewayCommand([]string{"-rate-limit-rate", rate}, &stdout, &stderr, gatewayDeps{})
		if code != exitUsage {
			t.Errorf("gateway -rate-limit-rate %s = %d, want %d (exitUsage)", rate, code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "GW-013") {
			t.Errorf("-rate-limit-rate %s: stderr %q does not name GW-013", rate, stderr.String())
		}
	}
}

func TestGatewayCommandRefusesANonPositiveRateLimitBurst(t *testing.T) {
	for _, burst := range []string{"0", "-1"} {
		var stdout, stderr bytes.Buffer
		code := runGatewayCommand([]string{"-rate-limit-burst", burst}, &stdout, &stderr, gatewayDeps{})
		if code != exitUsage {
			t.Errorf("gateway -rate-limit-burst %s = %d, want %d (exitUsage)", burst, code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "GW-013") {
			t.Errorf("-rate-limit-burst %s: stderr %q does not name GW-013", burst, stderr.String())
		}
	}
}

// TestGatewayCommandDefaultsRateLimitToThePackagesOwnDefaults pins that this
// command's own defaults track internal/gateway's, rather than drifting
// from a second, separately-maintained number.
func TestGatewayCommandDefaultsRateLimitToThePackagesOwnDefaults(t *testing.T) {
	gatewayTestValidCADirs(t)
	for _, name := range []string{envGatewayRate, envGatewayBurst} {
		t.Setenv(name, "")
	}
	o, code, ok := parseGatewayFlags(nil, io.Discard)
	if !ok {
		t.Fatalf("parseGatewayFlags refused a default configuration: exit %d", code)
	}
	if o.rateLimitRate != gateway.DefaultSessionRateLimitRate {
		t.Errorf("rateLimitRate = %d, want %d (internal/gateway's own default)",
			o.rateLimitRate, gateway.DefaultSessionRateLimitRate)
	}
	if o.rateLimitBurst != gateway.DefaultSessionRateLimitBurst {
		t.Errorf("rateLimitBurst = %d, want %d (internal/gateway's own default)",
			o.rateLimitBurst, gateway.DefaultSessionRateLimitBurst)
	}
}

func TestGatewayCommandReadsEveryFlagFromTheEnvironment(t *testing.T) {
	gatewayTestValidCADirs(t)
	for _, name := range []string{
		envGatewayListen, envGatewayUpstream, envGatewayShutdownTimeout, envGatewayRate, envGatewayBurst,
	} {
		t.Setenv(name, "")
	}
	t.Setenv(envGatewayListen, "127.0.0.1:0")
	t.Setenv(envGatewayUpstream, "https://example.invalid")
	t.Setenv(envGatewayShutdownTimeout, "30s")
	t.Setenv(envGatewayRate, "7")
	t.Setenv(envGatewayBurst, "42")

	o, code, ok := parseGatewayFlags(nil, io.Discard)
	if !ok {
		t.Fatalf("parseGatewayFlags refused a valid environment: exit %d", code)
	}
	if o.listen != "127.0.0.1:0" {
		t.Errorf("listen = %q, want the environment value", o.listen)
	}
	if o.upstream != "https://example.invalid" {
		t.Errorf("upstream = %q, want the environment value", o.upstream)
	}
	if o.shutdownTimeout != 30*time.Second {
		t.Errorf("shutdownTimeout = %v, want 30s", o.shutdownTimeout)
	}
	if o.rateLimitRate != 7 {
		t.Errorf("rateLimitRate = %d, want 7", o.rateLimitRate)
	}
	if o.rateLimitBurst != 42 {
		t.Errorf("rateLimitBurst = %d, want 42", o.rateLimitBurst)
	}
}

// fakeGateway is a servedGateway double, for the one path a real listener
// cannot exercise deterministically: the gateway started fine and then
// Serve itself returned an error.
type fakeGateway struct {
	addr     string
	serveErr error
	closed   int
}

func (f *fakeGateway) Addr() string { return f.addr }

func (f *fakeGateway) Serve(ctx context.Context) error {
	if f.serveErr != nil {
		return f.serveErr
	}
	<-ctx.Done()
	return nil
}

func (f *fakeGateway) Close() { f.closed++ }

// TestGatewayCommandReportsFailedWhenServeReturnsAnError covers runGateway's
// OTHER exit path: exitGatewayUnavailable is what a bad configuration or an
// unbindable listener produces (see the other cases in this file and
// gatewayalso_test.go's GW-004); this is what a gateway that started fine
// and then stopped serving produces, and Close must still run.
func TestGatewayCommandReportsFailedWhenServeReturnsAnError(t *testing.T) {
	gatewayTestValidCADirs(t)
	fake := &fakeGateway{addr: "127.0.0.1:1", serveErr: errors.New("listener died")}
	deps := gatewayDeps{open: func(context.Context, gatewayOptions, *serveLog) (servedGateway, error) {
		return fake, nil
	}}

	var stdout, stderr bytes.Buffer
	code := runGatewayCommand(
		[]string{"-listen", "127.0.0.1:0", "-upstream", "https://example.invalid"},
		&stdout, &stderr, deps)

	if code != exitGatewayFailed {
		t.Fatalf("runGatewayCommand = %d, want %d (exitGatewayFailed). stderr:\n%s",
			code, exitGatewayFailed, stderr.String())
	}
	if fake.closed != 1 {
		t.Errorf("Close called %d times, want exactly 1", fake.closed)
	}
	if !strings.Contains(stderr.String(), "listener died") {
		t.Errorf("stderr does not report the underlying error: %q", stderr.String())
	}
}

func TestGatewayCommandRejectsTrailingArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand([]string{"extra"}, &stdout, &stderr, gatewayDeps{})
	if code != exitUsage {
		t.Errorf("gateway with a trailing argument = %d, want %d (exitUsage)", code, exitUsage)
	}
}

// --- RM-237 (#382): -identity-secret/-identity-secret-file and
// -agent-message-key-id, the two settings that turn on the agent-message
// recorder (configureGatewayAgentMessages, gateway.go). ---

func TestGatewayCommandDefaultsAgentMessageKeyID(t *testing.T) {
	gatewayTestValidCADirs(t)
	t.Setenv(envAgentMessageKeyID, "")
	o, code, ok := parseGatewayFlags(nil, io.Discard)
	if !ok {
		t.Fatalf("parseGatewayFlags refused a default configuration: exit %d", code)
	}
	if o.agentMessageKeyID != defaultAgentMessageKeyID {
		t.Errorf("agentMessageKeyID = %q, want the default %q", o.agentMessageKeyID, defaultAgentMessageKeyID)
	}
}

func TestGatewayCommandRefusesAMalformedAgentMessageKeyID(t *testing.T) {
	gatewayTestValidCADirs(t)
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand([]string{"-agent-message-key-id", "Not Valid!"}, &stdout, &stderr, gatewayDeps{})
	if code != exitUsage {
		t.Errorf("gateway -agent-message-key-id %q = %d, want %d (exitUsage)", "Not Valid!", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "agent-message-key-id") {
		t.Errorf("stderr %q does not name the flag", stderr.String())
	}
}

func TestGatewayCommandReadsIdentitySecretFromTheFlag(t *testing.T) {
	gatewayTestValidCADirs(t)
	t.Setenv(envIdentitySecret, "")
	t.Setenv(envIdentitySecretFile, "")
	o, code, ok := parseGatewayFlags([]string{"-identity-secret", "s3cr3t"}, io.Discard)
	if !ok {
		t.Fatalf("parseGatewayFlags refused a valid -identity-secret: exit %d", code)
	}
	if o.identitySecret != "s3cr3t" {
		t.Errorf("identitySecret = %q, want %q", o.identitySecret, "s3cr3t")
	}
}

func TestGatewayCommandReadsIdentitySecretFromAFile(t *testing.T) {
	gatewayTestValidCADirs(t)
	t.Setenv(envIdentitySecret, "")
	t.Setenv(envIdentitySecretFile, "")
	dir := t.TempDir()
	path := dir + "/identity-secret"
	if err := os.WriteFile(path, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	o, code, ok := parseGatewayFlags([]string{"-identity-secret-file", path}, io.Discard)
	if !ok {
		t.Fatalf("parseGatewayFlags refused a valid -identity-secret-file: exit %d", code)
	}
	if o.identitySecret != "from-a-file" {
		t.Errorf("identitySecret = %q, want the trimmed file contents %q", o.identitySecret, "from-a-file")
	}
}

func TestGatewayCommandRefusesBothIdentitySecretAndIdentitySecretFile(t *testing.T) {
	t.Setenv(envIdentitySecret, "")
	t.Setenv(envIdentitySecretFile, "")
	dir := t.TempDir()
	path := dir + "/identity-secret"
	if err := os.WriteFile(path, []byte("from-a-file"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand(
		[]string{"-identity-secret", "s3cr3t", "-identity-secret-file", path}, &stdout, &stderr, gatewayDeps{})
	if code != exitUsage {
		t.Errorf("gateway with both -identity-secret and -identity-secret-file = %d, want %d (exitUsage)",
			code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "two sources for one secret") {
		t.Errorf("stderr %q does not name the two-sources problem", stderr.String())
	}
}

func TestGatewayCommandRefusesAnIdentitySecretFileThatDoesNotExist(t *testing.T) {
	t.Setenv(envIdentitySecret, "")
	t.Setenv(envIdentitySecretFile, "")
	var stdout, stderr bytes.Buffer
	code := runGatewayCommand(
		[]string{"-identity-secret-file", "/does/not/exist"}, &stdout, &stderr, gatewayDeps{})
	if code != exitUsage {
		t.Errorf("gateway with a missing -identity-secret-file = %d, want %d (exitUsage)", code, exitUsage)
	}
}

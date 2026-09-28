// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstream.Client()
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	args := []string{"-listen", "127.0.0.1:0", "-upstream", upstream.URL}
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

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// A recognised harness shape: the production wiring installs the
	// harness-shape guard by default (GW-011, #374 -- internal/gateway's
	// Proxy.ServeHTTP falls back to it whenever Guards is left nil, which
	// openGateway's own construction does), so an unrecognised path or a
	// request with no session header is refused before ever reaching the
	// upstream this test is asserting against.
	req.Header.Set("X-Claude-Code-Session-Id", "3f6a9b1c-2d4e-4f7a-9c8b-1e2f3a4b5c6d")
	resp, err := http.DefaultClient.Do(req)
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

// TestGatewayCommandRefusesAnHTTPUpstreamBeforeOpeningAnything is GW-007:
// an http -upstream is refused at start-up, naming the flag, and nothing is
// opened to prove it -- deps.open must never even be called.
func TestGatewayCommandRefusesAnHTTPUpstreamBeforeOpeningAnything(t *testing.T) {
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

func TestGatewayCommandRefusesAnUnparseableUpstreamURL(t *testing.T) {
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

func TestGatewayCommandReadsEveryFlagFromTheEnvironment(t *testing.T) {
	for _, name := range []string{envGatewayListen, envGatewayUpstream, envGatewayShutdownTimeout} {
		t.Setenv(name, "")
	}
	t.Setenv(envGatewayListen, "127.0.0.1:0")
	t.Setenv(envGatewayUpstream, "https://example.invalid")
	t.Setenv(envGatewayShutdownTimeout, "30s")

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

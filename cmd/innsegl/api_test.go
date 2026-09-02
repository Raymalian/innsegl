// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/api"
)

// API-008 (PROPOSED for doc 07's TC-API) — the operator-facing surface of
// `innsegl api`.
//
// The command's contract is its flags, its environment fallbacks, its exit
// status and what it refuses, because those are what `deploy/compose/*.yml`, a
// Kubernetes Deployment and a human at 3am all consult. Nothing here needs a
// Postgres: the opener is the seam. API-009, API-010 and API-011 run the real
// wiring against a real server, because the one thing this command exists to
// enforce — a credential that cannot write — is a property of a deployment and
// not of this source file.

// minimalAPIArgs is a command line with every required flag and nothing else.
func minimalAPIArgs(extra ...string) []string {
	return append([]string{
		"-dsn", "postgres://innsegl_reader@ledger/innsegl",
		"-repos", "github.com/innsegl/demo=/srv/repos/github.com/innsegl/demo",
		"-fulcio-url", "http://fulcio:5555",
		"-rekor-url", "http://rekor:3000",
		"-listen", "127.0.0.1:0",
	}, extra...)
}

// stubAPI is a served query API whose lifecycle is scripted.
type stubAPI struct {
	addr     string
	readOnly api.ReadOnlyReport
	repos    []string
	serveErr error
	serves   atomic.Int64
	closes   atomic.Int64
}

func (s *stubAPI) Addr() string                 { return s.addr }
func (s *stubAPI) ReadOnly() api.ReadOnlyReport { return s.readOnly }
func (s *stubAPI) Repos() []string              { return s.repos }
func (s *stubAPI) Close()                       { s.closes.Add(1) }

func (s *stubAPI) Serve(ctx context.Context) error {
	s.serves.Add(1)
	if s.serveErr != nil {
		return s.serveErr
	}
	<-ctx.Done()
	return nil
}

func healthyStub() *stubAPI {
	return &stubAPI{
		addr:  "127.0.0.1:34567",
		repos: []string{"github.com/innsegl/demo"},
		readOnly: api.ReadOnlyReport{
			Role: "innsegl_reader",
			Probes: []api.ProbeResult{
				{Name: "insert into innsegl.events", SQLState: "42501"},
				{Name: "create a schema of its own", SQLState: "42501"},
			},
		},
	}
}

// stubAPIDeps hands the command a scripted server and records what it was
// configured with.
func stubAPIDeps(s *stubAPI, seen *apiOptions) apiDeps {
	return apiDeps{
		open: func(_ context.Context, o apiOptions, _ *serveLog) (servedAPI, error) {
			if seen != nil {
				*seen = o
			}
			if s == nil {
				return nil, nil
			}
			return s, nil
		},
	}
}

// failingAPIDeps hands the command an opener that refuses.
func failingAPIDeps(err error) apiDeps {
	return apiDeps{
		open: func(context.Context, apiOptions, *serveLog) (servedAPI, error) {
			return nil, err
		},
	}
}

// syncBuffer is a bytes.Buffer the command writes from its own goroutine while
// this test reads it. Unsynchronised, that is a data race and -race is part of
// the merge gate.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runAPIUntilStopped runs the command, waits for it to publish its bound
// address, then cancels the context — which is what SIGTERM does in
// production.
func runAPIUntilStopped(t *testing.T, args []string, deps apiDeps) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() { done <- runAPI(ctx, args, &out, &errBuf, deps) }()

	deadline := time.After(10 * time.Second)
	for !strings.Contains(out.String(), "\n") {
		select {
		case c := <-done:
			return c, out.String(), errBuf.String()
		case <-deadline:
			t.Fatal("the command never published a bound address")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case c := <-done:
		return c, out.String(), errBuf.String()
	case <-time.After(10 * time.Second):
		t.Fatal("the command did not stop when its context was cancelled")
	}
	return 0, "", ""
}

// ---------------------------------------------------------------------------
// The refusal that is this command's reason to exist.
// ---------------------------------------------------------------------------

// A credential that can write is refused with a status of its own. An
// orchestrator restarting a replica forever cannot fix a GRANT, so "the
// credential is wrong" must not look like "Postgres is not up yet".
func TestAPI008AWritableCredentialIsRefusedWithItsOwnExitStatus(t *testing.T) {
	deps := failingAPIDeps(fmt.Errorf("%w: the role %q is allowed to: "+
		"insert into innsegl.events; create a schema of its own",
		api.ErrWritable, "innsegl"))

	var stdout, stderr bytes.Buffer
	code := runAPICommand(minimalAPIArgs(), &stdout, &stderr, deps)

	if code != exitAPIWritable {
		t.Fatalf("exit = %d, want %d (WRITABLE). stderr: %s", code, exitAPIWritable, stderr.String())
	}
	for _, want := range []string{"insert into innsegl.events", "create a schema of its own"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not name what the credential could do (%q):\n%s",
				want, stderr.String())
		}
	}
}

// An unreachable ledger is UNAVAILABLE and not WRITABLE. Collapsing the two
// would make the refusal untrustworthy in the only direction that matters.
func TestAPI008AnUnreachableLedgerIsUnavailableAndNotWritable(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(minimalAPIArgs(), &stdout, &stderr,
		failingAPIDeps(errors.New("dial tcp 10.0.0.1:5432: connect: connection refused")))

	if code != exitAPIUnavailable {
		t.Fatalf("exit = %d, want %d (UNAVAILABLE). stderr: %s",
			code, exitAPIUnavailable, stderr.String())
	}
}

// There is no flag that turns the read-only assertion off, and the help says
// so. internal/api/store.go: "The assertion is not optional and there is no
// flag to skip it." A `-require-read-only-role` in the shape of `serve`'s
// `-require-append-only-role` would be a way to defeat it.
func TestAPI008ThereIsNoFlagThatDisablesTheReadOnlyAssertion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(minimalAPIArgs("-require-read-only-role=false"), &stdout, &stderr,
		stubAPIDeps(healthyStub(), nil))

	if code != exitUsage {
		t.Fatalf("exit = %d, want %d: a flag that could switch the assertion off must "+
			"not exist", code, exitUsage)
	}

	var help bytes.Buffer
	if hc := runAPICommand([]string{"-h"}, &help, &help, apiDeps{}); hc != exitOK {
		t.Fatalf("-h exit = %d, want %d", hc, exitOK)
	}
	if !strings.Contains(help.String(), "no flag") {
		t.Errorf("the help does not say the assertion cannot be disabled:\n%s", help.String())
	}
}

// The evidence the assertion gathered is reported, not merely acted on. doc 05
// §1's dashboard row says "no write credentials mounted"; an operator reads
// which role was probed and how many probes it was refused.
func TestAPI008TheReadOnlyEvidenceIsReportedAtStartUp(t *testing.T) {
	code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), nil))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr)
	}
	if !strings.Contains(stderr, "innsegl_reader") {
		t.Errorf("the start-up report does not name the role it probed:\n%s", stderr)
	}
}

// ---------------------------------------------------------------------------
// The lifecycle.
// ---------------------------------------------------------------------------

func TestAPI008BoundAddressIsPublishedOnStdout(t *testing.T) {
	code, stdout, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), nil))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr)
	}
	if strings.TrimSpace(stdout) != "127.0.0.1:34567" {
		t.Errorf("stdout = %q, want the bound address on one line", stdout)
	}
}

func TestAPI008AnOrderlyStopExitsZeroAndReleasesTheStore(t *testing.T) {
	s := healthyStub()

	code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(s, nil))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr)
	}
	if s.closes.Load() == 0 {
		t.Error("the store was never closed; a pool left open holds a connection slot")
	}
}

func TestAPI008AServerThatStopsOnAnErrorExitsFailed(t *testing.T) {
	s := healthyStub()
	s.serveErr = errors.New("accept tcp 127.0.0.1:8082: use of closed network connection")

	var stdout, stderr bytes.Buffer
	code := runAPICommand(minimalAPIArgs(), &stdout, &stderr, stubAPIDeps(s, nil))

	if code != exitAPIFailed {
		t.Fatalf("exit = %d, want %d (FAILED). stderr: %s", code, exitAPIFailed, stderr.String())
	}
}

func TestAPI008AnOpenerThatReturnsNothingIsUnavailable(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(minimalAPIArgs(), &stdout, &stderr, stubAPIDeps(nil, nil))

	if code != exitAPIUnavailable {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitAPIUnavailable, stderr.String())
	}
}

// ---------------------------------------------------------------------------
// The command line.
// ---------------------------------------------------------------------------

func TestAPI008RequiredFlagsAreRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		drop string
		want string
	}{
		{"-dsn", envAPIDSN},
		{"-repos", envAPIRepos},
		{"-fulcio-url", envFulcioURL},
		{"-rekor-url", envRekorURL},
	} {
		t.Run(tc.drop, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := runAPICommand(withoutAPIFlag(minimalAPIArgs(), tc.drop),
				&stdout, &stderr, stubAPIDeps(healthyStub(), nil))

			if code != exitUsage {
				t.Fatalf("exit = %d, want %d. stderr: %s", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.drop) ||
				!strings.Contains(stderr.String(), tc.want) {
				t.Errorf("the refusal names neither %s nor $%s:\n%s",
					tc.drop, tc.want, stderr.String())
			}
		})
	}
}

// -listen has a default, so it is refused only when it is explicitly emptied.
// A deployment that set $INNSEGL_API_LISTEN to nothing gets a message naming
// the flag rather than a listener on every interface.
func TestAPI008AnEmptyListenAddressIsRefusedByName(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(append(withoutAPIFlag(minimalAPIArgs(), "-listen"), "-listen", ""),
		&stdout, &stderr, stubAPIDeps(healthyStub(), nil))

	if code != exitUsage {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-listen") ||
		!strings.Contains(stderr.String(), envAPIListen) {
		t.Errorf("the refusal names neither -listen nor $%s:\n%s", envAPIListen, stderr.String())
	}
}

// withoutAPIFlag removes one "-flag value" pair from a command line.
func withoutAPIFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// Every required setting has an environment fallback so that a container is
// configured entirely by environment: the read-only DSN carries a password and
// does not belong on a command line the process table can read.
func TestAPI008EveryRequiredFlagHasAnEnvironmentFallback(t *testing.T) {
	t.Setenv(envAPIDSN, "postgres://innsegl_reader:secret@ledger/innsegl")
	t.Setenv(envAPIRepos, "github.com/innsegl/demo=/srv/demo")
	t.Setenv(envFulcioURL, "http://fulcio:5555")
	t.Setenv(envRekorURL, "http://rekor:3000")
	t.Setenv(envAPIListen, "0.0.0.0:9999")
	t.Setenv(envIssuer, "https://oidc.innsegl.dev")

	var seen apiOptions
	code, _, stderr := runAPIUntilStopped(t, nil, stubAPIDeps(healthyStub(), &seen))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr)
	}
	if seen.dsn != "postgres://innsegl_reader:secret@ledger/innsegl" {
		t.Errorf("-dsn did not fall back to $%s: %q", envAPIDSN, seen.dsn)
	}
	if seen.listen != "0.0.0.0:9999" {
		t.Errorf("-listen did not fall back to $%s: %q", envAPIListen, seen.listen)
	}
	if seen.issuer != "https://oidc.innsegl.dev" {
		t.Errorf("-issuer did not fall back to $%s: %q", envIssuer, seen.issuer)
	}
	if seen.repos["github.com/innsegl/demo"] != "/srv/demo" {
		t.Errorf("-repos did not fall back to $%s: %v", envAPIRepos, seen.repos)
	}
	if strings.Contains(stderr, "secret") {
		t.Errorf("the DSN's password was logged:\n%s", stderr)
	}
}

// The default listen address is loopback. A dashboard published on every
// interface by omission is an operator's mistake this command should not make
// for them; doc 05 §3 puts it behind Cloudflare Access, and a container
// publishes the port deliberately.
func TestAPI008DefaultListenAddressIsLoopback(t *testing.T) {
	var seen apiOptions

	code, _, stderr := runAPIUntilStopped(t,
		withoutAPIFlag(minimalAPIArgs(), "-listen"), stubAPIDeps(healthyStub(), &seen))

	if code != exitOK {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitOK, stderr)
	}
	if !strings.HasPrefix(seen.listen, "127.0.0.1:") {
		t.Errorf("default -listen = %q, want a loopback address", seen.listen)
	}
}

func TestAPI008RefusesAReposListItCannotParse(t *testing.T) {
	for _, tc := range []struct{ name, repos string }{
		{"no equals sign", "github.com/innsegl/demo"},
		{"empty name", "=/srv/demo"},
		{"empty path", "github.com/innsegl/demo="},
		{"a name twice", "a=/srv/one,a=/srv/two"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := runAPICommand(append(withoutAPIFlag(minimalAPIArgs(), "-repos"),
				"-repos", tc.repos), &stdout, &stderr, stubAPIDeps(healthyStub(), nil))

			if code != exitUsage {
				t.Fatalf("exit = %d, want %d. stderr: %s", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), "-repos") {
				t.Errorf("the refusal does not name -repos:\n%s", stderr.String())
			}
		})
	}
}

func TestAPI008RefusesATrailingArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(minimalAPIArgs("dashboard"), &stdout, &stderr,
		stubAPIDeps(healthyStub(), nil))

	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), `"dashboard"`) {
		t.Errorf("the refusal does not name the argument:\n%s", stderr.String())
	}
}

func TestAPI008RefusesABadFlagValue(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(minimalAPIArgs("-shutdown-timeout", "soon"), &stdout, &stderr,
		stubAPIDeps(healthyStub(), nil))

	if code != exitUsage {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitUsage, stderr.String())
	}
}

func TestAPI008RefusesANegativeShutdownTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := runAPICommand(minimalAPIArgs("-shutdown-timeout", "-1s"), &stdout, &stderr,
		stubAPIDeps(healthyStub(), nil))

	if code != exitUsage {
		t.Fatalf("exit = %d, want %d. stderr: %s", code, exitUsage, stderr.String())
	}
}

func TestAPI008HelpExitsZeroAndDocumentsEveryExitStatus(t *testing.T) {
	var out bytes.Buffer

	code := runAPICommand([]string{"-h"}, &out, &out, apiDeps{})

	if code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	for _, want := range []string{
		"innsegl api",
		fmt.Sprintf("  %d ", exitUsage),
		fmt.Sprintf("  %d ", exitAPIUnavailable),
		fmt.Sprintf("  %d ", exitAPIFailed),
		fmt.Sprintf("  %d ", exitAPIWritable),
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the help does not document %q:\n%s", want, out.String())
		}
	}
}

// The command holds no authentication and says so. #70 puts the dashboard
// behind Cloudflare Access (doc 05 §3); inventing an auth scheme here would be
// a second thing to get wrong and a second place to review.
func TestAPI008HelpSaysTheCommandHoldsNoAuthentication(t *testing.T) {
	var out bytes.Buffer

	if code := runAPICommand([]string{"-h"}, &out, &out, apiDeps{}); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	help := strings.ToLower(out.String())
	if !strings.Contains(help, "no authentication") {
		t.Errorf("the help does not say the command holds no authentication:\n%s", help)
	}
	if !strings.Contains(help, "cloudflare access") {
		t.Errorf("the help does not name what is expected to hold it:\n%s", help)
	}
}

// The five routes are named in the help, because an operator wiring a reverse
// proxy in front of this needs to know what it serves.
func TestAPI008HelpNamesTheRoutesItServes(t *testing.T) {
	var out bytes.Buffer

	if code := runAPICommand([]string{"-h"}, &out, &out, apiDeps{}); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	for _, route := range apiRoutes {
		if !strings.Contains(out.String(), route) {
			t.Errorf("the help does not name %s:\n%s", route, out.String())
		}
	}
}

func TestAPI008IsReachableFromTheDispatchTable(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"api", "-dsn", ""}, &stdout, &stderr)

	if code != exitUsage {
		t.Fatalf("run(api) = %d, want %d (its own refusal, reached through dispatch). "+
			"stderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "innsegl api") {
		t.Errorf("the refusal did not come from `innsegl api`:\n%s", stderr.String())
	}
}

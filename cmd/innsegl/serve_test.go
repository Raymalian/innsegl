// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
)

// serveEnv is every environment variable `innsegl serve` reads. The tests
// clear all of them so a developer's own shell cannot make a required-flag
// case pass.
var serveEnv = []string{
	envLedgerDSN, envSPIREAddress, envTrustDomain, envSPIREServerID, envParentID,
	envWorkloadAPI, envMCPSVIDFile, envMCPKeyFile, envMCPBundleFile,
	envFulcioURL, envRekorURL, envMCPListen, envMCPHealthListen, envMCPAddrFile,
	envSPIRETimeout, envRunTTL, envIdempotencyLease, envRegisterRateCalls,
	envRegisterRateWindow, envClockSkewBound, envTrustedOrigins,
	envMCPSessionTimeout, envMCPShutdownTimeout, envHealthTimeout,
	envRequireAppendOnlyRole, envMigrate,
}

func clearServeEnv(t *testing.T) {
	t.Helper()
	for _, name := range serveEnv {
		t.Setenv(name, "")
	}
}

// completeServeArgs is a command line that passes validation, so a case can
// change one thing and see only that thing refused.
func completeServeArgs(extra ...string) []string {
	return append([]string{
		"serve",
		"-dsn", "postgres://innsegl@127.0.0.1:5432/innsegl",
		"-spire-address", "127.0.0.1:8081",
		"-trust-domain", "innsegl.dev",
		"-parent-id", "spiffe://innsegl.dev/spire/agent/x509pop/abc",
		"-fulcio-url", "http://127.0.0.1:5555",
		"-rekor-url", "http://127.0.0.1:5556",
	}, extra...)
}

// ---------------------------------------------------------------------------
// A fake server, so the command's own behaviour — configuration, the address
// file, the exit statuses and the lifecycle — is testable without Postgres and
// SPIRE. What is wired to what is not asserted here and cannot be: that claim
// is only true of the SERVED tools, and test/failure/serve_test.go makes it
// against the shipped binary, a real Postgres and a real SPIRE.
// ---------------------------------------------------------------------------

type fakeServer struct {
	addr    string
	serveFn func(context.Context) error

	mu     sync.Mutex
	closed int
}

func (f *fakeServer) Addr() string       { return f.addr }
func (f *fakeServer) HealthAddr() string { return f.addr }

// BoundTools and MissingTools are the SHIPPED server's answer, not a list this
// file writes down: mcp.New runs every registered binder, so what it reports
// missing is what really has no binder. The command's duty is to say so, and
// that is what this fake lets these cases assert.
func (f *fakeServer) BoundTools() []mcp.ToolName   { return realSurface().BoundTools() }
func (f *fakeServer) MissingTools() []mcp.ToolName { return realSurface().MissingTools() }

func realSurface() *mcp.Server {
	s, err := mcp.New(mcp.Config{})
	if err != nil {
		panic("mcp.New: " + err.Error())
	}
	return s
}

func (f *fakeServer) Serve(ctx context.Context) error {
	if f.serveFn != nil {
		return f.serveFn(ctx)
	}
	<-ctx.Done()
	return nil
}

func (f *fakeServer) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
}

func (f *fakeServer) closes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func fakeDeps(s *fakeServer, openErr error) serveDeps {
	return serveDeps{open: func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		if openErr != nil {
			return nil, openErr
		}
		return s, nil
	}}
}

// ---------------------------------------------------------------------------

// TestServeIsNoLongerAStub. RM-001 wired `serve` to a placeholder; four MCP
// tools have been built against dependencies nothing constructs since.
func TestServeIsNoLongerAStub(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	code := run([]string{"serve"}, &stdout, &stderr)

	if strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("`innsegl serve` still reports %q", strings.TrimSpace(stderr.String()))
	}
	if code == exitNotImplemented {
		t.Fatalf("`innsegl serve` exits %d (exitNotImplemented)", code)
	}
	if code != exitUsage {
		t.Errorf("`innsegl serve` with no configuration = %d, want %d (exitUsage)", code, exitUsage)
	}
}

// TestServeRefusesEachMissingRequirementByName. An operator must be told which
// setting is missing, not that "the server did not start".
func TestServeRefusesEachMissingRequirementByName(t *testing.T) {
	required := []struct {
		flag string
		env  string
	}{
		{"-dsn", envLedgerDSN},
		{"-spire-address", envSPIREAddress},
		{"-trust-domain", envTrustDomain},
		{"-parent-id", envParentID},
		{"-fulcio-url", envFulcioURL},
		{"-rekor-url", envRekorURL},
	}

	for _, req := range required {
		t.Run(req.flag, func(t *testing.T) {
			clearServeEnv(t)
			args := append([]string{}, completeServeArgs()...)
			// Drop the flag under test and its value.
			out := args[:1]
			for i := 1; i < len(args); i += 2 {
				if args[i] == req.flag {
					continue
				}
				out = append(out, args[i], args[i+1])
			}

			var stdout, stderr bytes.Buffer
			code := runServeCommand(out[1:], &stdout, &stderr, fakeDeps(&fakeServer{}, nil))

			if code != exitUsage {
				t.Fatalf("serve without %s = %d, want %d (exitUsage)", req.flag, code, exitUsage)
			}
			if !strings.Contains(stderr.String(), req.flag) {
				t.Errorf("stderr = %q, want it to name %s", stderr.String(), req.flag)
			}
			if !strings.Contains(stderr.String(), req.env) {
				t.Errorf("stderr = %q, want it to name $%s", stderr.String(), req.env)
			}
		})
	}
}

// TestEverySettingIsReadableFromTheEnvironment. doc 05 runs this as a
// container; RM-011's canary set the precedent that a secret is never put on a
// command line the process table can read, and the ledger DSN carries a
// password.
func TestEverySettingIsReadableFromTheEnvironment(t *testing.T) {
	clearServeEnv(t)
	t.Setenv(envLedgerDSN, "postgres://innsegl@127.0.0.1:5432/innsegl")
	t.Setenv(envSPIREAddress, "127.0.0.1:8081")
	t.Setenv(envTrustDomain, "innsegl.dev")
	t.Setenv(envParentID, "spiffe://innsegl.dev/spire/agent/x509pop/abc")
	t.Setenv(envFulcioURL, "http://127.0.0.1:5555")
	t.Setenv(envRekorURL, "http://127.0.0.1:5556")

	var captured serveOptions
	deps := serveDeps{open: func(_ context.Context, o serveOptions, _ *serveLog) (servedMCP, error) {
		captured = o
		return &fakeServer{}, nil
	}}

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runServe(ctx, nil, &stdout, &stderr, deps)

	if code != exitOK {
		t.Fatalf("serve configured entirely from the environment = %d, want %d. stderr:\n%s",
			code, exitOK, stderr.String())
	}
	if captured.dsn == "" || captured.spireAddress == "" || captured.trustDomain == "" ||
		captured.parentID == "" || captured.fulcioURL == "" || captured.rekorURL == "" {
		t.Fatalf("the environment was not read into the options: %+v", captured)
	}
}

// TestServeAnnouncesItsBoundAddressAtomically. A harness or an orchestrator
// that reads the file must see a complete address or nothing.
func TestServeAnnouncesItsBoundAddressAtomically(t *testing.T) {
	clearServeEnv(t)
	dir := t.TempDir()
	addrFile := filepath.Join(dir, "addr")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runServe(ctx, completeServeArgs("-addr-file", addrFile)[1:], &stdout, &stderr,
		fakeDeps(&fakeServer{addr: "127.0.0.1:34567"}, nil))

	if code != exitOK {
		t.Fatalf("serve = %d, want %d. stderr:\n%s", code, exitOK, stderr.String())
	}
	raw, err := os.ReadFile(addrFile)
	if err != nil {
		t.Fatalf("the address file was not written: %v", err)
	}
	if string(raw) != "127.0.0.1:34567" {
		t.Fatalf("the address file holds %q, want the bound address", raw)
	}
	// The same address on stdout, so a shell can capture it without an address
	// file and without parsing the structured log on stderr.
	if strings.TrimSpace(stdout.String()) != "127.0.0.1:34567" {
		t.Errorf("stdout = %q, want the bound address on its own line", stdout.String())
	}
	if _, err := os.Stat(addrFile + ".partial"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the partial file survives: %v", err)
	}
}

// TestServeFailsWhenTheAddressFileCannotBeWritten. Publishing the address is
// how anything reaches this server; a silent failure would leave a process
// running that nobody can find.
func TestServeFailsWhenTheAddressFileCannotBeWritten(t *testing.T) {
	clearServeEnv(t)
	unwritable := filepath.Join(t.TempDir(), "no-such-directory", "addr")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := runServe(ctx, completeServeArgs("-addr-file", unwritable)[1:], &stdout, &stderr,
		fakeDeps(&fakeServer{addr: "127.0.0.1:1"}, nil))

	if code != exitServeUnavailable {
		t.Fatalf("serve with an unwritable address file = %d, want %d", code, exitServeUnavailable)
	}
}

// TestServeReportsAnUnstartableServerAsUnavailable, and says so rather than
// exiting zero.
func TestServeReportsAnUnstartableServerAsUnavailable(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	code := runServe(context.Background(), completeServeArgs()[1:], &stdout, &stderr,
		fakeDeps(nil, errors.New("dial the SPIRE admin API: connection refused")))

	if code != exitServeUnavailable {
		t.Fatalf("serve = %d, want %d (exitServeUnavailable)", code, exitServeUnavailable)
	}
	if !strings.Contains(stderr.String(), "connection refused") {
		t.Errorf("stderr = %q, want the failure that stopped it", stderr.String())
	}
}

// TestServeReportsAFailedListenerAsFailed, distinctly from never having
// started: the first means traffic stopped, the second means it never began.
func TestServeReportsAFailedListenerAsFailed(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	code := runServe(context.Background(), completeServeArgs()[1:], &stdout, &stderr,
		fakeDeps(&fakeServer{serveFn: func(context.Context) error {
			return errors.New("accept tcp: too many open files")
		}}, nil))

	if code != exitServeFailed {
		t.Fatalf("serve = %d, want %d (exitServeFailed)", code, exitServeFailed)
	}
	if !strings.Contains(stderr.String(), "too many open files") {
		t.Errorf("stderr = %q, want the serving failure", stderr.String())
	}
}

// TestServeShutsDownOnASignalAndReleasesEverythingItOpened.
//
// IP §6.6 kills this process with SIGKILL and requires the invariants to hold
// without any shutdown running at all — so nothing here is load-bearing for
// correctness. It is load-bearing for an ORDINARY stop: a replica rolled by an
// orchestrator gets SIGTERM, and a process that ignored it would be SIGKILLed
// a grace period later with its connections still open.
func TestServeShutsDownOnASignalAndReleasesEverythingItOpened(t *testing.T) {
	clearServeEnv(t)
	fake := &fakeServer{addr: "127.0.0.1:1"}

	// The test keeps its own SIGTERM registration for the whole case. Two
	// things follow, and both are needed: a SIGTERM that arrives before the
	// command has installed its handler is consumed here instead of killing
	// the test binary, and the same is true of one that arrives after the
	// command has removed it. Without this the case is a race against a signal
	// whose default disposition is death.
	sink := make(chan os.Signal, 16)
	signal.Notify(sink, syscall.SIGTERM)
	defer signal.Stop(sink)

	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runServeCommand(completeServeArgs()[1:], &stdout, &stderr, fakeDeps(fake, nil))
	}()

	// The command installs the signal handler itself; signalling this process
	// is the only way to reach the path an orchestrator takes.
	deadline := time.After(30 * time.Second)
	for {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("SIGTERM: %v", err)
		}
		select {
		case code := <-done:
			if code != exitOK {
				t.Fatalf("serve interrupted = %d, want %d. stderr:\n%s", code, exitOK, stderr.String())
			}
			if fake.closes() != 1 {
				t.Fatalf("the server was closed %d times, want exactly 1; a replica that "+
					"leaks its pool and its SPIRE connection cannot be rolled", fake.closes())
			}
			return
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatal("serve did not stop within 30s of SIGTERM")
		}
	}
}

// TestServeNamesTheMissingToolSurfaceAtStartUp.
//
// `sign_commit` lands with RM-033. Until then the server advertises four of
// the five IP §4 tools, and ADR-0024 makes the reporting duty explicit: an
// incomplete surface is reported and never silent. An operator reading the log
// of a server that will refuse `sign_commit` must be able to see why.
func TestServeNamesTheMissingToolSurfaceAtStartUp(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := runServe(ctx, completeServeArgs()[1:], &stdout, &stderr, fakeDeps(&fakeServer{}, nil))
	if code != exitOK {
		t.Fatalf("serve = %d, want %d. stderr:\n%s", code, exitOK, stderr.String())
	}

	log := stderr.String()
	for _, name := range mcp.ToolNames() {
		if !strings.Contains(log, string(name)) {
			t.Errorf("the start-up report does not name %s:\n%s", name, log)
		}
	}
	if !strings.Contains(log, "missing") && !strings.Contains(log, "MISSING") {
		t.Errorf("the start-up report does not say a tool is missing:\n%s", log)
	}
}

// TestServeRefusesANegativeRateLimit rather than treating it as unmetered.
func TestServeRefusesANegativeRateLimit(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	code := runServeCommand(completeServeArgs("-register-rate-calls", "-1")[1:],
		&stdout, &stderr, fakeDeps(&fakeServer{}, nil))

	if code != exitUsage {
		t.Fatalf("serve -register-rate-calls=-1 = %d, want %d (exitUsage)", code, exitUsage)
	}
}

// TestServeRejectsTrailingArguments. Every setting is a flag; a bare word is a
// typo, and a server that ignored it would run with a configuration its
// operator did not write.
func TestServeRejectsTrailingArguments(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	code := runServeCommand(completeServeArgs("please")[1:], &stdout, &stderr,
		fakeDeps(&fakeServer{}, nil))

	if code != exitUsage {
		t.Fatalf("serve with a trailing argument = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "please") {
		t.Errorf("stderr = %q, want it to quote the rejected argument", stderr.String())
	}
}

// TestServeHelpExitsZero, so `innsegl serve -h` is usable.
func TestServeHelpExitsZero(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	if code := runServeCommand([]string{"-h"}, &stdout, &stderr, fakeDeps(&fakeServer{}, nil)); code != exitOK {
		t.Fatalf("serve -h = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stderr.String(), "innsegl serve") {
		t.Errorf("stderr = %q, want the usage block", stderr.String())
	}
}

// TestServeRefusesAnUnparseableFlag.
func TestServeRefusesAnUnparseableFlag(t *testing.T) {
	clearServeEnv(t)
	var stdout, stderr bytes.Buffer

	if code := runServeCommand([]string{"-frobnicate"}, &stdout, &stderr,
		fakeDeps(&fakeServer{}, nil)); code != exitUsage {
		t.Fatalf("serve -frobnicate = %d, want %d", code, exitUsage)
	}
}

// TestTheShippedSurfaceIsFourToolsAndSignCommitIsTheMissingOne.
//
// `MissingTools` is derived from the binders that registered themselves, so
// this is the shipped answer and not a list written down twice. It is asserted
// in the entry point's own package because the entry point is what has to
// REPORT it (ADR-0024) — and because the day RM-033 lands `sign_commit`, this
// case fails and says so rather than the report quietly going stale.
func TestTheShippedSurfaceIsFourToolsAndSignCommitIsTheMissingOne(t *testing.T) {
	server := realSurface()

	bound := server.BoundTools()
	if len(bound) != 4 {
		t.Errorf("the shipped server binds %d tools (%v), want 4", len(bound), bound)
	}
	if slices.Contains(bound, mcp.ToolSignCommit) {
		t.Errorf("%s is bound; RM-033 (#41) has not built it", mcp.ToolSignCommit)
	}
	for _, want := range []mcp.ToolName{
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent, mcp.ToolRetireAgent,
	} {
		if !slices.Contains(bound, want) {
			t.Errorf("the shipped server does not bind %s: %v", want, bound)
		}
	}

	missing := server.MissingTools()
	if len(missing) != 1 || missing[0] != mcp.ToolSignCommit {
		t.Fatalf("MissingTools() is %v, want exactly [%s]. Either the surface changed or "+
			"RM-033 landed, and the start-up report and both health endpoints are now saying "+
			"something untrue.", missing, mcp.ToolSignCommit)
	}
	if len(bound)+len(missing) != len(mcp.ToolNames()) {
		t.Errorf("bound %d + missing %d != the five IP §4 tools", len(bound), len(missing))
	}
}

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

	"innsegl.dev/innsegl/internal/identity"
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
	envIdentityMode, envIdentitySecret, envIdentitySecretFile,
	// E11's three (#211). mcp.EnvHostProjects is the tool's OWN name for the
	// host root and is cleared here for the same reason as the rest: a
	// developer's shell must not be able to make a refusal case pass.
	mcp.EnvHostProjects, envProjectsMount, envObserveBodyDir, envSessionDir,
}

// testIdentitySecret is a 32-byte fixture for RM-079's pseudonymous default.
// The default mode needs a secret and refuses to start without one, which is
// the behaviour TestServeRefusesPseudonymousIdentityWithNoSecret pins.
const testIdentitySecret = "serve-test-fixture-secret-012345"

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
		"-identity-secret", testIdentitySecret,
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
		// RM-079 (#116). The mode defaults to pseudonymous, so a deployment
		// that named no secret is refused by name here — not started with the
		// caller's ticket references going into every Rekor entry.
		{"-identity-secret", envIdentitySecret},
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

// TestPRI002ServeRefusesPseudonymousIdentityWithNoSecret, and starts under
// `literal` when an operator asks for it on purpose.
//
// RM-079 (#116). The two failure shapes this pins out of existence are a
// silent fall back to literal values — the configuration would say the
// deployment is private while every ticket number went into Rekor — and a
// per-process random secret, which would give one run a second SPIFFE ID after
// a restart and leave SPIRE holding two entries for it.
func TestPRI002ServeRefusesPseudonymousIdentityWithNoSecret(t *testing.T) {
	drop := func(args []string, flag string) []string {
		out := args[:1:1]
		for i := 1; i < len(args); i += 2 {
			if args[i] != flag {
				out = append(out, args[i], args[i+1])
			}
		}
		return out
	}

	t.Run("no secret refuses", func(t *testing.T) {
		clearServeEnv(t)
		args := drop(completeServeArgs(), "-identity-secret")
		var stdout, stderr bytes.Buffer
		code := runServeCommand(args[1:], &stdout, &stderr, fakeDeps(&fakeServer{}, nil))
		if code != exitUsage {
			t.Fatalf("serve with no identity secret = %d, want %d (exitUsage). "+
				"Starting would have put this deployment's ticket references into "+
				"every certificate and every Rekor entry, permanently.", code, exitUsage)
		}
		if !strings.Contains(stderr.String(), string(identity.ModeLiteral)) {
			t.Errorf("the refusal does not name %q, so an operator is not told how to ask "+
				"for the old behaviour deliberately:\n%s", identity.ModeLiteral, stderr.String())
		}
	})

	t.Run("literal starts, with no secret", func(t *testing.T) {
		clearServeEnv(t)
		args := drop(completeServeArgs(), "-identity-secret")
		args = append(args, "-identity-mode", string(identity.ModeLiteral))
		var stdout, stderr bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if code := runServe(ctx, args[1:], &stdout, &stderr,
			fakeDeps(&fakeServer{}, nil)); code != exitOK {
			t.Fatalf("serve in %s mode = %d, want %d. stderr:\n%s",
				identity.ModeLiteral, code, exitOK, stderr.String())
		}
	})

	t.Run("a secret in literal mode refuses", func(t *testing.T) {
		clearServeEnv(t)
		args := append(completeServeArgs(), "-identity-mode", string(identity.ModeLiteral))
		var stdout, stderr bytes.Buffer
		if code := runServeCommand(args[1:], &stdout, &stderr,
			fakeDeps(&fakeServer{}, nil)); code != exitUsage {
			t.Fatalf("serve with a secret in %s mode = %d, want %d (exitUsage): an "+
				"operator who set a secret asked for pseudonyms",
				identity.ModeLiteral, code, exitUsage)
		}
	})
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
	t.Setenv(envIdentitySecret, testIdentitySecret)

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
		captured.parentID == "" || captured.fulcioURL == "" || captured.rekorURL == "" ||
		captured.identitySecret == "" {
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

// TestServeNamesTheWholeToolSurfaceAtStartUp.
//
// RM-131 (#210) opened the surface to eight and left three names with no
// implementation, so this case asserted that the start-up report WARNED about
// them. RM-128 (#207) bound the last of the three, so the assertion turns
// over: the report names eight tools and says nothing is missing.
//
// It is the same duty either way. ADR-0024 requires an incomplete surface to
// be REPORTED and never silent, and the value of reporting rather than
// asserting is that a tool which quietly stopped registering its binder shows
// up here — which is exactly what the silence below now protects.
func TestServeNamesTheWholeToolSurfaceAtStartUp(t *testing.T) {
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
	// And nothing is missing. Every one of the eight has a binder since #207,
	// so a report that still warned would be telling an operator its surface
	// is incomplete when it is not — which is the same failure as staying
	// silent about one that really had gone, read from the other side.
	if strings.Contains(log, "MISSING") {
		t.Errorf("the start-up report still warns about a missing tool, and all %d IP §4 "+
			"tools are bound:\n%s", len(mcp.ToolNames()), log)
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

// TestTheShippedSurfaceIsAllEightToolsOfIP4.
//
// `BoundTools` and `MissingTools` are derived from the binders that registered
// themselves, so this is the shipped answer and not a list written down twice.
// It is asserted in the entry point's own package because the entry point is
// what has to REPORT it (ADR-0024).
//
// The name of this case has now changed three times, and each change was a
// ratchet firing rather than a rename. RM-068 left it asserting four bound
// tools and `sign_commit` missing, so that the day RM-033 (#41) bound the
// fifth it would fail rather than let the start-up report and both health
// endpoints go stale. RM-131 (#210) reopened the same mechanism in the other
// direction — eight names, implementations arriving one issue at a time — and
// #205, #206 and #207 each fired it on the day they bound their tool.
//
// #207 is the last, so `outstanding` is empty and this case goes back to being
// what it was before the surface opened: an assertion that every IP §4 tool
// ships. There is no list left to go stale.
//
// BOUND IS STILL NOT CONFIGURED, and this assertion can only see the first —
// which is exactly as far as it should reach. A binder registering says
// nothing about whether this process installed the tool's dependencies, and
// for the three E11 tools the answer was "no" for two waves while every report
// an operator could read said the surface was complete.
//
// #211 wired all three and put the other half of the claim where it belongs:
// `toolWiring` in servewiring.go refuses to start a listener advertising a
// tool this process never decided about (MCP-058), and the contract stack
// refuses to pass one (MCP-060). A tool an operator deliberately left
// unconfigured is still bound, still advertised, and still counted here — it
// refuses every call by name and says so in the start-up log, which is a
// decision rather than an omission.
func TestTheShippedSurfaceIsAllEightToolsOfIP4(t *testing.T) {
	server := realSurface()

	implemented := []mcp.ToolName{
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent,
		mcp.ToolSignCommit, mcp.ToolRetireAgent,
		// #205, #206 and #207 bound theirs. Each landing fired this assertion,
		// which is what it is for.
		mcp.ToolDescribeWorkspace, mcp.ToolObserveToolCall, mcp.ToolObserveSession,
	}
	// Empty since #207: no name on IP §4's surface is without a binder.
	var outstanding []mcp.ToolName

	bound := server.BoundTools()
	if len(bound) != len(implemented) {
		t.Errorf("the shipped server binds %d tools (%v), want %d", len(bound), bound, len(implemented))
	}
	for _, want := range implemented {
		if !slices.Contains(bound, want) {
			t.Errorf("the shipped server does not bind %s: %v", want, bound)
		}
	}

	missing := server.MissingTools()
	if !slices.Equal(missing, outstanding) {
		t.Fatalf("MissingTools() is %v, want %v. The start-up report and both health "+
			"endpoints are now saying something untrue.", missing, outstanding)
	}
	if len(bound)+len(missing) != len(mcp.ToolNames()) {
		t.Errorf("bound %d + missing %d != the eight IP §4 tools", len(bound), len(missing))
	}
}

// TestPRI005ServeReadsTheDeploymentSecretFromAFile.
//
// RM-084 (#124). #119 made the secret mandatory in the default mode and the
// shipped compose stack set neither variable, so `innsegl-mcp` crashlooped on
// a clean `docker compose up`. The stack's fix is a one-shot that writes 32
// random bytes into a volume, and a volume is a FILE — compose cannot inject a
// file's contents into an environment variable, so the server has to be able
// to read one.
//
// `INNSEGL_MCP_SVID_FILE`, `INNSEGL_MCP_KEY_FILE` and `INNSEGL_MCP_BUNDLE_FILE`
// are the same convention already in this file; this joins them rather than
// inventing a second spelling.
//
// THE CASE THAT MATTERS IS "both at once is refused". A configuration that
// quietly prefers one of two sources is how #124 happened in the first place:
// the deployment said one thing and the process did another, and nothing
// reported the difference.
func TestPRI005ServeReadsTheDeploymentSecretFromAFile(t *testing.T) {
	withoutSecret := func(extra ...string) []string {
		full := completeServeArgs()
		out := full[:1:1]
		for i := 1; i < len(full); i += 2 {
			if full[i] != "-identity-secret" {
				out = append(out, full[i], full[i+1])
			}
		}
		return append(out[1:], extra...)
	}

	// captureOptions runs serve to a cancelled context and hands back the
	// resolved configuration, so the SECRET ITSELF can be compared rather than
	// only the exit status.
	captureOptions := func(t *testing.T, args []string) (serveOptions, int, string) {
		t.Helper()
		var captured serveOptions
		deps := serveDeps{open: func(_ context.Context, o serveOptions, _ *serveLog) (servedMCP, error) {
			captured = o
			return &fakeServer{}, nil
		}}
		var stdout, stderr bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		code := runServe(ctx, args, &stdout, &stderr, deps)
		return captured, code, stderr.String()
	}

	secretFile := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "identity-secret")
		if err := os.WriteFile(path, []byte(body), 0o400); err != nil {
			t.Fatalf("writing the secret fixture: %v", err)
		}
		return path
	}

	t.Run("the file's contents are the secret", func(t *testing.T) {
		clearServeEnv(t)
		path := secretFile(t, testIdentitySecret)

		o, code, stderr := captureOptions(t, withoutSecret("-identity-secret-file", path))

		if code != exitOK {
			t.Fatalf("serve -identity-secret-file = %d, want %d. A stack that can only put "+
				"the secret on a volume cannot start at all:\n%s", code, exitOK, stderr)
		}
		if o.identitySecret != testIdentitySecret {
			t.Errorf("the resolved secret is %q, want the file's %q",
				o.identitySecret, testIdentitySecret)
		}
	})

	t.Run("the environment variable is read", func(t *testing.T) {
		clearServeEnv(t)
		t.Setenv(envIdentitySecretFile, secretFile(t, testIdentitySecret))

		o, code, stderr := captureOptions(t, withoutSecret())

		if code != exitOK {
			t.Fatalf("serve with $"+envIdentitySecretFile+" = %d, want %d. A container is "+
				"configured by environment (doc 05 §1):\n%s", code, exitOK, stderr)
		}
		if o.identitySecret != testIdentitySecret {
			t.Errorf("the resolved secret is %q, want the file's %q",
				o.identitySecret, testIdentitySecret)
		}
	})

	t.Run("a trailing newline is not part of the secret", func(t *testing.T) {
		clearServeEnv(t)
		// `openssl rand -hex 32 > secret` and every heredoc that ever wrote a
		// key file end it with a newline. A secret one byte longer than the
		// operator believes changes EVERY pseudonym, silently and forever.
		path := secretFile(t, testIdentitySecret+"\n")

		o, code, stderr := captureOptions(t, withoutSecret("-identity-secret-file", path))

		if code != exitOK {
			t.Fatalf("serve with a newline-terminated secret file = %d, want %d:\n%s",
				code, exitOK, stderr)
		}
		if o.identitySecret != testIdentitySecret {
			t.Errorf("the resolved secret is %q, want %q — the trailing newline is not "+
				"part of the key", o.identitySecret, testIdentitySecret)
		}
	})

	t.Run("both sources at once is refused", func(t *testing.T) {
		clearServeEnv(t)
		path := secretFile(t, "a-different-32-byte-fixture-0123")

		args := completeServeArgs("-identity-secret-file", path)[1:]
		var stdout, stderr bytes.Buffer
		code := runServeCommand(args, &stdout, &stderr, fakeDeps(&fakeServer{}, nil))

		if code != exitUsage {
			t.Fatalf("serve with -identity-secret AND -identity-secret-file = %d, want %d "+
				"(exitUsage). Silently preferring one of two disagreeing sources is how "+
				"#124 shipped: the deployment says one thing and the process does another.",
				code, exitUsage)
		}
		for _, want := range []string{"-identity-secret", "-identity-secret-file"} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("the refusal does not name %s:\n%s", want, stderr.String())
			}
		}
	})

	t.Run("an unreadable file is refused by name", func(t *testing.T) {
		clearServeEnv(t)
		missing := filepath.Join(t.TempDir(), "never-written")

		args := withoutSecret("-identity-secret-file", missing)
		var stdout, stderr bytes.Buffer
		code := runServeCommand(args, &stdout, &stderr, fakeDeps(&fakeServer{}, nil))

		if code != exitUsage {
			t.Fatalf("serve with an unreadable -identity-secret-file = %d, want %d "+
				"(exitUsage): the one-shot that writes it did not run, and that is a "+
				"deployment fault to be named rather than a start-up mystery", code, exitUsage)
		}
		if !strings.Contains(stderr.String(), missing) {
			t.Errorf("the refusal does not name the path it could not read:\n%s", stderr.String())
		}
	})

	t.Run("an empty file is refused", func(t *testing.T) {
		clearServeEnv(t)
		path := secretFile(t, "\n\n")

		args := withoutSecret("-identity-secret-file", path)
		var stdout, stderr bytes.Buffer
		code := runServeCommand(args, &stdout, &stderr, fakeDeps(&fakeServer{}, nil))

		if code != exitUsage {
			t.Fatalf("serve with an empty -identity-secret-file = %d, want %d (exitUsage): "+
				"a half-written secret file must not become a zero-length key", code, exitUsage)
		}
	})

	t.Run("a short secret is still refused when it comes from a file", func(t *testing.T) {
		clearServeEnv(t)
		path := secretFile(t, "tooshort")

		args := withoutSecret("-identity-secret-file", path)
		var stdout, stderr bytes.Buffer
		code := runServeCommand(args, &stdout, &stderr, fakeDeps(&fakeServer{}, nil))

		if code != exitUsage {
			t.Fatalf("serve with an 8-byte secret file = %d, want %d (exitUsage): "+
				"identity.MinSecretBytes is %d and reading the secret from a file must not "+
				"be a way around the floor", code, exitUsage, identity.MinSecretBytes)
		}
	})
}

// ---------------------------------------------------------------------------
// MCP-059 — the three ingestion tools are configured like every other
// dependency: a flag, an environment variable behind it, and a refusal that
// names both.
// ---------------------------------------------------------------------------

// TestMCP059TheIngestionToolsAreConfiguredFromFlagsAndTheEnvironment.
//
// E11's three tools (#205, #206, #207) each need one thing this process cannot
// work out for itself:
//
//   - the host directory the projects mount CORRESPONDS TO. A container knows
//     where the mount is and never what it is a mount of, and every plausible
//     guess describes a repository confidently and may describe the wrong one —
//     into an append-only record.
//   - the local volume `observe_tool_call` writes bodies to. Bodies carry file
//     contents and commands; doc 05 keeps them on the operator's machine, so
//     the MCP must be told where that is and may not invent it.
//   - the local volume `observe_session` keeps its session→run mapping on. A
//     mapping that was never written is a run nothing will ever retire.
//
// None has a defensible default, so each is opt-in — sign_commit's shape, for
// sign_commit's reason — and each is read from the environment as well as a
// flag, because doc 05 runs this as a container configured entirely by
// environment.
func TestMCP059TheIngestionToolsAreConfiguredFromFlagsAndTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	projects := filepath.Join(dir, "projects")
	bodies := filepath.Join(dir, "bodies")
	sessions := filepath.Join(dir, "sessions")

	capture := func(t *testing.T, args []string) serveOptions {
		t.Helper()
		var captured serveOptions
		deps := serveDeps{open: func(_ context.Context, o serveOptions, _ *serveLog) (servedMCP, error) {
			captured = o
			return &fakeServer{}, nil
		}}
		var stdout, stderr bytes.Buffer
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if code := runServe(ctx, args, &stdout, &stderr, deps); code != exitOK {
			t.Fatalf("serve = %d, want %d. stderr:\n%s", code, exitOK, stderr.String())
		}
		return captured
	}

	t.Run("from flags", func(t *testing.T) {
		clearServeEnv(t)
		o := capture(t, completeServeArgs(
			"-host-projects", projects,
			"-observe-body-dir", bodies,
			"-session-dir", sessions,
		)[1:])
		if o.hostProjects != projects {
			t.Errorf("-host-projects = %q, want %q", o.hostProjects, projects)
		}
		if o.observeBodyDir != bodies {
			t.Errorf("-observe-body-dir = %q, want %q", o.observeBodyDir, bodies)
		}
		if o.sessionDir != sessions {
			t.Errorf("-session-dir = %q, want %q", o.sessionDir, sessions)
		}
		// The mount is where the container sees that directory, and defaults
		// to the path deploy/compose/innsegl.workrepo.yml mounts it at. A
		// deployment that mounts it elsewhere says so; nothing guesses.
		if o.projectsMount != mcp.DefaultProjectsMount {
			t.Errorf("-projects-mount defaulted to %q, want %q", o.projectsMount, mcp.DefaultProjectsMount)
		}
	})

	t.Run("from the environment", func(t *testing.T) {
		clearServeEnv(t)
		t.Setenv(envLedgerDSN, "postgres://innsegl@127.0.0.1:5432/innsegl")
		t.Setenv(envSPIREAddress, "127.0.0.1:8081")
		t.Setenv(envTrustDomain, "innsegl.dev")
		t.Setenv(envParentID, "spiffe://innsegl.dev/spire/agent/x509pop/abc")
		t.Setenv(envFulcioURL, "http://127.0.0.1:5555")
		t.Setenv(envRekorURL, "http://127.0.0.1:5556")
		t.Setenv(envIdentitySecret, testIdentitySecret)
		// mcp.EnvHostProjects, and not a second spelling of it: the tool reads
		// this name when nothing is installed over it, and two names for one
		// setting is a deployment that can set the wrong one.
		t.Setenv(mcp.EnvHostProjects, projects)
		t.Setenv(envProjectsMount, projects)
		t.Setenv(envObserveBodyDir, bodies)
		t.Setenv(envSessionDir, sessions)

		o := capture(t, nil)
		if o.hostProjects != projects || o.projectsMount != projects ||
			o.observeBodyDir != bodies || o.sessionDir != sessions {
			t.Fatalf("the environment was not read into the options: %+v", o)
		}
	})

	t.Run("every unusable shape is refused by name", func(t *testing.T) {
		base := serveOptions{
			dsn: "postgres://x", spireAddress: "h:1", trustDomain: "innsegl.dev",
			parentID: "spiffe://innsegl.dev/spire/agent/x", fulcioURL: "http://f", rekorURL: "http://r",
			listen: "127.0.0.1:0", healthListen: "127.0.0.1:0",
			identityMode: string(identity.ModePseudonymous), identitySecret: testIdentitySecret,
		}
		if problem := base.validate(); problem != "" {
			t.Fatalf("the complete configuration was refused: %s", problem)
		}
		for _, tc := range []struct {
			name  string
			patch func(*serveOptions)
			want  string
		}{
			// A relative path here names a directory that resolves against
			// whatever this process happens to be standing in, which is not a
			// thing an operator can have meant.
			{"a relative host root", func(o *serveOptions) {
				o.hostProjects = "projects"
			}, "-host-projects"},
			{"a relative projects mount", func(o *serveOptions) {
				o.projectsMount = "projects"
			}, "-projects-mount"},
			{"a relative body volume", func(o *serveOptions) {
				o.observeBodyDir = "bodies"
			}, "-observe-body-dir"},
			{"a relative marker volume", func(o *serveOptions) {
				o.sessionDir = "sessions"
			}, "-session-dir"},
			// observe_session RESOLVES the workspace through
			// describe_workspace on every start. Without the host root, every
			// start it was configured for would refuse — a tool wired to a
			// dependency that is not, which is this issue's own defect in
			// miniature.
			{"a marker volume with no host root", func(o *serveOptions) {
				o.sessionDir = sessions
			}, "-host-projects"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				o := base
				tc.patch(&o)
				problem := o.validate()
				if problem == "" {
					t.Fatal("accepted")
				}
				if !strings.Contains(problem, tc.want) {
					t.Errorf("refusal %q does not name %q", problem, tc.want)
				}
			})
		}

		// All three together, absolute, with the host root they need.
		whole := base
		whole.hostProjects, whole.observeBodyDir, whole.sessionDir = projects, bodies, sessions
		if problem := whole.validate(); problem != "" {
			t.Errorf("the three ingestion settings together were refused: %s", problem)
		}
	})
}

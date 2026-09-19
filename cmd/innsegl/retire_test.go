// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
)

// MCP-086 — `innsegl retire <run_id>`, and the four answers an operator acts
// on differently: the run ended here, it had already ended, this deployment
// holds no such run, and the surface could not be reached.
//
// The surface under test is a STAND-IN for the admin listener, not a mock of
// the command's own internals: it speaks the real MCP transport over a real
// HTTP server and implements exactly what IP §4 publishes for `retire_agent` —
// one `run_id` in, `{retired_at}` out, RUN_NOT_FOUND for a run it does not
// hold, and idempotence that answers a second call with the ORIGINAL instant
// and appends nothing. Everything from the flag parse to the JSON-RPC frame is
// the shipped code. What is absent is SPIRE and a ledger, which is what lets
// this run in a unit suite; that retire_agent itself honours the contract
// asserted here is internal/mcp's MCP-005 and not repeated.

// fakeRetireArgs is IP §4's parameter list for the tool, spelled the way the
// wire spells it.
type fakeRetireArgs struct {
	RunID string `json:"run_id"`
}

// fakeLifecycleSurface is `retire_agent`'s published behaviour and nothing
// else. `appends` counts the retirements it actually recorded, which is how
// "safe to run twice" is measured rather than asserted.
type fakeLifecycleSurface struct {
	mu      sync.Mutex
	known   map[string]bool
	retired map[string]string
	appends int

	// refuse, when set, is returned for every call: the refusals that are
	// neither "no such run" nor a success.
	refuse *mcp.Error
	// garble, when set, is answered verbatim as the structured content — a
	// surface that is answering, but not answering this. garbleIsError marks
	// it as a refusal rather than a result.
	garble        any
	garbleIsError bool
}

func newFakeLifecycleSurface(known ...string) *fakeLifecycleSurface {
	f := &fakeLifecycleSurface{known: map[string]bool{}, retired: map[string]string{}}
	for _, runID := range known {
		f.known[runID] = true
	}
	return f
}

func (f *fakeLifecycleSurface) call(runID string) *sdk.CallToolResult {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case f.refuse != nil:
		return fakeRefusal(f.refuse)
	case f.garble != nil:
		return &sdk.CallToolResult{
			Content:           []sdk.Content{&sdk.TextContent{Text: "garbled"}},
			StructuredContent: f.garble,
			IsError:           f.garbleIsError,
		}
	case !f.known[runID]:
		return fakeRefusal(mcp.Errorf(mcp.ClassRunNotFound, runID, "no run %q", runID))
	}

	if f.retired[runID] == "" {
		// The ledger's clock, stamped once. Every later call is answered with
		// this same instant, which is what IP §4 requires and what the command
		// reads to tell a retirement it caused from one it found.
		f.retired[runID] = event.NewTimestamp(time.Now()).String()
		f.appends++
	}
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: f.retired[runID]}},
		StructuredContent: map[string]any{"retired_at": f.retired[runID]},
	}
}

func (f *fakeLifecycleSurface) recorded() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.appends
}

// fakeRefusal is the shape internal/mcp puts a classified error on the wire in:
// IsError, with the IP §4 object as the structured content.
func fakeRefusal(e *mcp.Error) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: e.Error()}},
		StructuredContent: e,
		IsError:           true,
	}
}

// serveFakeLifecycle binds the stand-in on a real HTTP listener and returns
// its URL, with nothing in front of it: a deployment that enforces no
// credential, which is single-listener mode and every deployment before #264.
func serveFakeLifecycle(t *testing.T, f *fakeLifecycleSurface) string {
	t.Helper()
	return serveGatedLifecycle(t, f, nil)
}

// serveGatedLifecycle binds the stand-in behind gate, which is #264's
// middleware reduced to what a CLIENT can observe of it.
func serveGatedLifecycle(t *testing.T, f *fakeLifecycleSurface, gate *credentialGate) string {
	t.Helper()

	srv := sdk.NewServer(&sdk.Implementation{Name: "innsegl", Version: "v0.0.0-test"}, nil)
	sdk.AddTool(srv, &sdk.Tool{
		Name:        string(mcp.ToolRetireAgent),
		Description: "stand-in for the shipped tool: IP §4's contract, without SPIRE or a ledger",
	}, func(_ context.Context, _ *sdk.CallToolRequest, in fakeRetireArgs) (*sdk.CallToolResult, any, error) {
		return f.call(in.RunID), nil, nil
	})

	var handler http.Handler = sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return srv }, nil)
	if gate != nil {
		handler = gate.wrap(handler)
	}
	httpSrv := httptest.NewServer(handler)
	t.Cleanup(httpSrv.Close)
	return httpSrv.URL
}

// closedEndpoint is an address nothing is listening on: a surface that is down
// rather than one that refuses.
func closedEndpoint(t *testing.T) string {
	t.Helper()
	httpSrv := httptest.NewServer(http.NotFoundHandler())
	url := httpSrv.URL
	httpSrv.Close()
	return url
}

func TestMCP086RetireReportsWhichOfTheFourOutcomesHappened(t *testing.T) {
	const runID = "run-4c1f9a2b7d3e"

	t.Run("ended: one retirement is recorded and the instant is reported", func(t *testing.T) {
		surface := newFakeLifecycleSurface(runID)
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{"-url", serveFakeLifecycle(t, surface), runID}, &stdout, &stderr)

		if code != exitOK {
			t.Fatalf("code = %d, want exitOK (%d); stderr=%s", code, exitOK, stderr.String())
		}
		if surface.recorded() != 1 {
			t.Errorf("the surface recorded %d retirements, want exactly 1", surface.recorded())
		}
		if !strings.Contains(stdout.String(), runID) {
			t.Errorf("stdout = %q, want the run named", stdout.String())
		}
	})

	t.Run("already ended: nothing is appended and the original instant is reported", func(t *testing.T) {
		surface := newFakeLifecycleSurface(runID)
		url := serveFakeLifecycle(t, surface)

		var first bytes.Buffer
		if code := retireCommand([]string{"-url", url, runID}, &first, &first); code != exitOK {
			t.Fatalf("the first run = %d, want exitOK; output=%s", code, first.String())
		}

		// doc 02 §1 instants are millisecond-precise, so the second invocation
		// has to begin in a later millisecond than the first retirement for the
		// two to be distinguishable at all. A second `innsegl retire` typed by
		// a human is many milliseconds later; this makes the test not depend on
		// how fast the machine running it is.
		time.Sleep(5 * time.Millisecond)

		var stdout, stderr bytes.Buffer
		code := retireCommand([]string{"-url", url, runID}, &stdout, &stderr)

		if code != exitRetireAlreadyEnded {
			t.Fatalf("code = %d, want exitRetireAlreadyEnded (%d); stderr=%s",
				code, exitRetireAlreadyEnded, stderr.String())
		}
		if surface.recorded() != 1 {
			t.Errorf("the surface recorded %d retirements across two runs, want exactly 1",
				surface.recorded())
		}
		if !strings.Contains(stderr.String(), "ALREADY ENDED") {
			t.Errorf("stderr = %q, want it to say the run had already ended", stderr.String())
		}
		if !strings.Contains(stderr.String(), "nothing was appended") {
			t.Errorf("stderr = %q, want it to say nothing was appended", stderr.String())
		}
		if !strings.Contains(stderr.String(), runID) {
			t.Errorf("stderr = %q, want the run named", stderr.String())
		}
	})

	t.Run("no such run: the refusal is carried through and nothing is recorded", func(t *testing.T) {
		surface := newFakeLifecycleSurface()
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{"-url", serveFakeLifecycle(t, surface), runID}, &stdout, &stderr)

		if code != exitRetireNoSuchRun {
			t.Fatalf("code = %d, want exitRetireNoSuchRun (%d); stderr=%s",
				code, exitRetireNoSuchRun, stderr.String())
		}
		if surface.recorded() != 0 {
			t.Errorf("the surface recorded %d retirements, want none", surface.recorded())
		}
		if !strings.Contains(stderr.String(), runID) {
			t.Errorf("stderr = %q, want the run named", stderr.String())
		}
	})

	t.Run("unreachable: nothing is claimed about the run", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := retireCommand(
			[]string{"-url", closedEndpoint(t), "-timeout", "5s", runID}, &stdout, &stderr)

		if code != exitRetireUnreachable {
			t.Fatalf("code = %d, want exitRetireUnreachable (%d); stderr=%s",
				code, exitRetireUnreachable, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want nothing reported about a run that was never reached",
				stdout.String())
		}
		if !strings.Contains(stderr.String(), "could not be reached") {
			t.Errorf("stderr = %q, want it to say the surface could not be reached", stderr.String())
		}
	})
}

// A refusal that is neither a success nor RUN_NOT_FOUND is the fourth status
// and not a fifth: the class is what the operator needs, and the run's state is
// unchanged or unknown either way.
func TestRetireReportsAnyOtherRefusalAsUnreachableAndNamesTheClass(t *testing.T) {
	const runID = "run-4c1f9a2b7d3e"

	for _, tc := range []struct {
		name    string
		surface *fakeLifecycleSurface
		want    string
	}{
		{
			name: "the ledger is gone",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.refuse = mcp.Errorf(mcp.ClassLedgerUnavailable, runID, "the ledger is unreachable")
				return f
			}(),
			want: string(mcp.ClassLedgerUnavailable),
		},
		{
			name: "SPIRE would not delete the entry",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.refuse = mcp.Errorf(mcp.ClassIdentityUnavailable, runID, "spire-server is unreachable")
				return f
			}(),
			want: string(mcp.ClassIdentityUnavailable),
		},
		{
			name: "an answer with no instant in it",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.garble = map[string]any{"retired": true}
				return f
			}(),
			want: "retired_at",
		},
		{
			name: "an instant that is not a doc 02 §1 instant",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.garble = map[string]any{"retired_at": "yesterday"}
				return f
			}(),
			want: "yesterday",
		},
		{
			name: "an answer that is not an object at all",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.garble = []any{"retired"}
				return f
			}(),
			want: "IP §4 requires an object",
		},
		{
			name: "a refusal with no class on it",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.garble = map[string]any{"message": "it did not work"}
				f.garbleIsError = true
				return f
			}(),
			want: "error_class",
		},
		{
			name: "a refusal whose class is outside the closed vocabulary",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.garble = map[string]any{"error_class": "TEAPOT", "message": "no"}
				f.garbleIsError = true
				return f
			}(),
			want: "TEAPOT",
		},
		{
			name: "a refusal with a class and no message",
			surface: func() *fakeLifecycleSurface {
				f := newFakeLifecycleSurface(runID)
				f.garble = map[string]any{"error_class": string(mcp.ClassLedgerUnavailable)}
				f.garbleIsError = true
				return f
			}(),
			want: string(mcp.ClassLedgerUnavailable),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := retireCommand(
				[]string{"-url", serveFakeLifecycle(t, tc.surface), runID}, &stdout, &stderr)

			if code != exitRetireUnreachable {
				t.Fatalf("code = %d, want exitRetireUnreachable (%d); stderr=%s",
					code, exitRetireUnreachable, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
		})
	}
}

// A surface that completes the handshake and then fails the call — a gateway
// in front of the listener, most plausibly — is unreachable too. The run's
// state is unchanged or unknown, which is the same thing to do about it.
func TestRetireReportsACallThatFailsAfterTheHandshakeAsUnreachable(t *testing.T) {
	const runID = "run-4c1f9a2b7d3e"

	surface := newFakeLifecycleSurface(runID)
	inner := sdk.NewServer(&sdk.Implementation{Name: "innsegl", Version: "v0.0.0-test"}, nil)
	sdk.AddTool(inner, &sdk.Tool{
		Name:        string(mcp.ToolRetireAgent),
		Description: "stand-in for the shipped tool",
	}, func(_ context.Context, _ *sdk.CallToolRequest, in fakeRetireArgs) (*sdk.CallToolResult, any, error) {
		return surface.call(in.RunID), nil, nil
	})
	handler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return inner }, nil)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading the proxied body: %v", err)
				return
			}
			if bytes.Contains(body, []byte("tools/call")) {
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(httpSrv.Close)

	var stdout, stderr bytes.Buffer
	code := retireCommand([]string{"-url", httpSrv.URL, "-timeout", "5s", runID}, &stdout, &stderr)

	if code != exitRetireUnreachable {
		t.Fatalf("code = %d, want exitRetireUnreachable (%d); stderr=%s",
			code, exitRetireUnreachable, stderr.String())
	}
	if surface.recorded() != 0 {
		t.Errorf("the surface recorded %d retirements, want none", surface.recorded())
	}
	if !strings.Contains(stderr.String(), "safe") {
		t.Errorf("stderr = %q, want it to say running the command again is safe", stderr.String())
	}
}

func TestRetireRefusesACommandLineItCannotActOn(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no run id at all", nil, "a run id is required"},
		{"two run ids", []string{"run-aaaaaaaaaaaa", "run-bbbbbbbbbbbb"}, "one run at a time"},
		{"an empty endpoint", []string{"-url", "", "run-aaaaaaaaaaaa"}, "-url"},
		{"an unknown flag", []string{"-force", "run-aaaaaaaaaaaa"}, "-force"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := retireCommand(tc.args, &stdout, &stderr)

			if code != exitUsage {
				t.Fatalf("code = %d, want exitUsage (%d); stderr=%s", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
		})
	}
}

func TestRetireUsageNamesEveryExitStatusAnOperatorSwitchesOn(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := retireCommand([]string{"-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, want exitOK", code)
	}

	usage := stdout.String() + stderr.String()
	for _, want := range []string{
		"innsegl retire", envMCPAdminURL,
		fmt.Sprintf("  %d ", exitOK),
		fmt.Sprintf("  %d ", exitUsage),
		fmt.Sprintf("  %d ", exitRetireAlreadyEnded),
		fmt.Sprintf("  %d ", exitRetireNoSuchRun),
		fmt.Sprintf("  %d ", exitRetireUnreachable),
		fmt.Sprintf("  %d ", exitRetireUnauthorized),
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage = %q, want it to mention %q", usage, want)
		}
	}
}

// ---------------------------------------------------------------------------
// MCP-094 — the credential the identity-lifecycle listener requires (#268).
//
// #264 put a repository-scoped credential in front of the six lifecycle tools
// and #266 taught the two callers that existed then to present one. `retire`
// was written on the other epic and was invisible to that survey, so on the
// merged tree it reached an enforcing listener with no credential at all and
// reported the 401 as an UNREACHABLE server — sending an operator to restart a
// deployment that was up.
//
// What these assert, in the order they matter:
//
//   - a refusal is NOT an unreachable server, in the exit status and in the
//     message, and the message says what to run;
//   - the first call carries nothing, a 401 — and only a 401 — mints, and the
//     SAME call is repeated exactly once;
//   - a listener that enforces nothing mints nothing, which is what keeps
//     single-listener mode byte-for-byte as it was;
//   - the credential reaches no stream this command writes.
//
// The gate below is #264's middleware reduced to what a CLIENT can observe of
// it: one 401 for anything that is not the credential it admits, in front of
// the whole listener so `initialize` is refused on the same terms as a tool
// call. That the shipped middleware behaves that way is internal/mcp's
// MCP-087, and is not repeated here.
// ---------------------------------------------------------------------------

// credentialGate records the bearer token of every request that reached it, in
// order, with "" for a request that carried none. Recording rather than
// counting is what makes "the first call carries no credential" a measurement.
type credentialGate struct {
	mu        sync.Mutex
	admits    string
	presented []string
}

func (g *credentialGate) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		}
		g.mu.Lock()
		g.presented = append(g.presented, token)
		g.mu.Unlock()

		if token == "" || token != g.admits {
			// One status, one body, nothing derived from what was wrong.
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// saw returns the tokens the gate was shown, oldest first.
func (g *credentialGate) saw() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.presented...)
}

// admitted counts the requests the gate let through.
func (g *credentialGate) admitted() int {
	n := 0
	for _, token := range g.saw() {
		if token != "" && token == g.admits {
			n++
		}
	}
	return n
}

// stubMint installs $INNSEGL_ADMIN_CREDENTIAL_MINT, the escape hatch the signer
// and the harness hook already publish for an operator whose signing key is not
// on this machine's container volume. Using it here is what keeps this suite
// off the Docker daemon: the shipped path runs a container, and a test that ran
// one would be an integration test.
//
// An empty token is a mint that cannot mint — the operator with no key volume
// and no override, which is the case the remedy exists for.
//
// It returns the repositories the mint was asked for, oldest first, which is
// how the scope is measured rather than asserted.
func stubMint(t *testing.T, token string) func() []string {
	t.Helper()

	dir := t.TempDir()
	log := filepath.Join(dir, "scopes")
	script := filepath.Join(dir, "mint")
	// The log path is single-quoted: a subtest name reaches t.TempDir(), and a
	// name containing `$INNSEGL_REPO_ID` would otherwise be expanded by the
	// shell running this script and the log written somewhere else entirely.
	body := "#!/bin/sh\nprintf '%s\\n' \"$1\" >> '" + log + "'\n"
	if token == "" {
		body += "exit 1\n"
	} else {
		body += "printf '%s\\n' '" + token + "'\n"
	}
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing the stub mint: %v", err)
	}
	t.Setenv(envAdminCredentialMint, script)

	return func() []string {
		raw, err := os.ReadFile(log)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatalf("reading the stub mint's log: %v", err)
		}
		var scopes []string
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line != "" {
				scopes = append(scopes, line)
			}
		}
		return scopes
	}
}

// testRepo is a doc 02 §5 identifier that names no repository that exists.
const testRepo = "github.com/Example-Org/Example-Repo"

func TestMCP094RetirePresentsACredentialToAnEnforcingListener(t *testing.T) {
	const runID = "run-4c1f9a2b7d3e"
	const token = "credential.for.the.listener"

	t.Run("a refusal is not an unreachable server", func(t *testing.T) {
		surface := newFakeLifecycleSurface(runID)
		gate := &credentialGate{admits: token}
		stubMint(t, "") // nothing on this machine can mint one
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{
			"-url", serveGatedLifecycle(t, surface, gate), "-repo", testRepo, runID,
		}, &stdout, &stderr)

		if code != exitRetireUnauthorized {
			t.Fatalf("code = %d, want exitRetireUnauthorized (%d); stderr=%s",
				code, exitRetireUnauthorized, stderr.String())
		}
		if got := stderr.String(); strings.Contains(got, "UNREACHABLE") ||
			strings.Contains(got, "could not be reached") {
			t.Errorf("stderr = %q, want a listener that ANSWERED, not one that is down", got)
		}
		if !strings.Contains(stderr.String(), "admin-credential mint") {
			t.Errorf("stderr = %q, want it to name the mint command", stderr.String())
		}
		if !strings.Contains(stderr.String(), testRepo) {
			t.Errorf("stderr = %q, want it to name the repository to mint for", stderr.String())
		}
		if surface.recorded() != 0 {
			t.Errorf("the surface recorded %d retirements, want none", surface.recorded())
		}
	})

	t.Run("the first call carries none, a refusal mints, and the same call is repeated once",
		func(t *testing.T) {
			surface := newFakeLifecycleSurface(runID)
			gate := &credentialGate{admits: token}
			scopes := stubMint(t, token)
			var stdout, stderr bytes.Buffer

			code := retireCommand([]string{
				"-url", serveGatedLifecycle(t, surface, gate), "-repo", testRepo, runID,
			}, &stdout, &stderr)

			if code != exitOK {
				t.Fatalf("code = %d, want exitOK; stderr=%s", code, stderr.String())
			}
			if surface.recorded() != 1 {
				t.Errorf("the surface recorded %d retirements, want exactly 1", surface.recorded())
			}
			seen := gate.saw()
			if len(seen) == 0 || seen[0] != "" {
				t.Fatalf("the gate saw %q first, want a call carrying NO credential: a deployment "+
					"that enforces nothing must never be probed for one", seen)
			}
			// Once a credential is held it is on EVERY request, because #264
			// wraps the whole listener and a request without one is refused
			// wherever it falls in the session.
			held := false
			for i, token := range seen {
				if token != "" {
					held = true
					continue
				}
				if held {
					t.Errorf("request %d of %q carried no credential after one was held", i, seen)
				}
			}
			if got := scopes(); len(got) != 1 || got[0] != testRepo {
				t.Errorf("the mint was asked for %v, want exactly one credential for %q", got, testRepo)
			}
		})

	t.Run("a credential the listener also refuses is reported once, not looped", func(t *testing.T) {
		surface := newFakeLifecycleSurface(runID)
		gate := &credentialGate{admits: token}
		scopes := stubMint(t, "a.different.credential")
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{
			"-url", serveGatedLifecycle(t, surface, gate), "-repo", testRepo, runID,
		}, &stdout, &stderr)

		if code != exitRetireUnauthorized {
			t.Fatalf("code = %d, want exitRetireUnauthorized (%d); stderr=%s",
				code, exitRetireUnauthorized, stderr.String())
		}
		if len(scopes()) != 1 {
			t.Errorf("the mint ran %d times, want exactly 1: a loop against a server that "+
				"has already said no is still a loop", len(scopes()))
		}
		if gate.admitted() != 0 {
			t.Errorf("the gate admitted %d requests, want none", gate.admitted())
		}
		// The SAME call was repeated: the minted credential did reach the
		// listener, and was refused there rather than never being presented.
		presented := false
		for _, token := range gate.saw() {
			presented = presented || token != ""
		}
		if !presented {
			t.Errorf("the gate saw %q; want the minted credential presented on a retry", gate.saw())
		}
		if surface.recorded() != 0 {
			t.Errorf("the surface recorded %d retirements, want none", surface.recorded())
		}
	})

	t.Run("a listener that enforces nothing mints nothing", func(t *testing.T) {
		surface := newFakeLifecycleSurface(runID)
		scopes := stubMint(t, token)
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{"-url", serveFakeLifecycle(t, surface), runID}, &stdout, &stderr)

		if code != exitOK {
			t.Fatalf("code = %d, want exitOK; stderr=%s", code, stderr.String())
		}
		if got := scopes(); len(got) != 0 {
			t.Errorf("the mint ran for %v; single-listener mode requires no credential and "+
				"must cost nothing", got)
		}
	})

	t.Run("the credential reaches no stream this command writes", func(t *testing.T) {
		for _, tc := range []struct{ name, minted string }{
			{"admitted", token},
			{"refused", "a.different.credential"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				surface := newFakeLifecycleSurface(runID)
				gate := &credentialGate{admits: token}
				stubMint(t, tc.minted)
				var stdout, stderr bytes.Buffer

				retireCommand([]string{
					"-url", serveGatedLifecycle(t, surface, gate), "-repo", testRepo, runID,
				}, &stdout, &stderr)

				if written := stdout.String() + stderr.String(); strings.Contains(written, tc.minted) {
					t.Errorf("output = %q, want it never to carry the credential %q",
						written, tc.minted)
				}
			})
		}
	})
}

// The ordering problem, and what it costs. The credential names a REPOSITORY
// and this command names a RUN, so the repository has to come from somewhere
// the listener is not: an explicit `-repo`, `$INNSEGL_REPO_ID`, or the working
// tree — in that order, and lazily, so a listener that enforces nothing never
// runs git at all.
func TestMCP094RetireScopesTheCredentialToARepository(t *testing.T) {
	const runID = "run-4c1f9a2b7d3e"
	const token = "credential.for.the.listener"

	gated := func(t *testing.T, surface *fakeLifecycleSurface) (string, func() []string) {
		t.Helper()
		return serveGatedLifecycle(t, surface, &credentialGate{admits: token}), stubMint(t, token)
	}

	t.Run("-repo names it outright, which is the stranded run in another checkout",
		func(t *testing.T) {
			t.Setenv(envRepoID, "github.com/Example-Org/Somewhere-Else")
			surface := newFakeLifecycleSurface(runID)
			url, scopes := gated(t, surface)
			var stdout, stderr bytes.Buffer

			if code := retireCommand([]string{"-url", url, "-repo", testRepo, runID},
				&stdout, &stderr); code != exitOK {
				t.Fatalf("code = %d, want exitOK; stderr=%s", code, stderr.String())
			}
			if got := scopes(); len(got) != 1 || got[0] != testRepo {
				t.Errorf("the mint was asked for %v, want %q: an explicit -repo wins", got, testRepo)
			}
		})

	t.Run("$INNSEGL_REPO_ID is next, because the signer and the hook already read it",
		func(t *testing.T) {
			t.Setenv(envRepoID, testRepo)
			surface := newFakeLifecycleSurface(runID)
			url, scopes := gated(t, surface)
			var stdout, stderr bytes.Buffer

			if code := retireCommand([]string{"-url", url, runID}, &stdout, &stderr); code != exitOK {
				t.Fatalf("code = %d, want exitOK; stderr=%s", code, stderr.String())
			}
			if got := scopes(); len(got) != 1 || got[0] != testRepo {
				t.Errorf("the mint was asked for %v, want %q", got, testRepo)
			}
		})

	t.Run("otherwise the working tree, by the rule the signer uses", func(t *testing.T) {
		t.Setenv(envRepoID, "")
		t.Chdir(gitTreeWithOrigin(t, "git@github.com:Example-Org/Example-Repo.git"))

		surface := newFakeLifecycleSurface(runID)
		url, scopes := gated(t, surface)
		var stdout, stderr bytes.Buffer

		if code := retireCommand([]string{"-url", url, runID}, &stdout, &stderr); code != exitOK {
			t.Fatalf("code = %d, want exitOK; stderr=%s", code, stderr.String())
		}
		if got := scopes(); len(got) != 1 || got[0] != testRepo {
			t.Errorf("the mint was asked for %v, want %q - doc 02 §5 lowercases the HOST "+
				"and leaves the org and the name alone", got, testRepo)
		}
	})

	t.Run("a tree with no origin is refused with the flag to type instead", func(t *testing.T) {
		t.Setenv(envRepoID, "")
		t.Chdir(t.TempDir())

		surface := newFakeLifecycleSurface(runID)
		url, _ := gated(t, surface)
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{"-url", url, runID}, &stdout, &stderr)

		if code != exitRetireUnauthorized {
			t.Fatalf("code = %d, want exitRetireUnauthorized (%d); stderr=%s",
				code, exitRetireUnauthorized, stderr.String())
		}
		if !strings.Contains(stderr.String(), "-repo") {
			t.Errorf("stderr = %q, want it to name the flag that resolves this", stderr.String())
		}
	})

	t.Run("a -repo outside doc 02 §5 is a command line, not a refusal", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		code := retireCommand([]string{"-url", "http://127.0.0.1:1/", "-repo", "Example-Repo", runID},
			&stdout, &stderr)

		if code != exitUsage {
			t.Fatalf("code = %d, want exitUsage (%d); stderr=%s", code, exitUsage, stderr.String())
		}
		if !strings.Contains(stderr.String(), "host/org/name") {
			t.Errorf("stderr = %q, want it to say the shape a repository has", stderr.String())
		}
	})

	// THE COST OF DERIVING, stated as a test rather than as a comment. #264
	// answers a run in a repository the credential does not authorise exactly
	// as a run that does not exist, deliberately: a run id is public in every
	// Agent-Run trailer and must not become an oracle over which repository
	// holds it. So an operator standing in the wrong checkout is told the id is
	// wrong when it is right, and the only place that can be qualified is here.
	t.Run("no such run, under a credential, says the repository may be the wrong one",
		func(t *testing.T) {
			surface := newFakeLifecycleSurface() // holds no run at all
			url, _ := gated(t, surface)
			var stdout, stderr bytes.Buffer

			code := retireCommand([]string{"-url", url, "-repo", testRepo, runID}, &stdout, &stderr)

			if code != exitRetireNoSuchRun {
				t.Fatalf("code = %d, want exitRetireNoSuchRun (%d); stderr=%s",
					code, exitRetireNoSuchRun, stderr.String())
			}
			if !strings.Contains(stderr.String(), "-repo") {
				t.Errorf("stderr = %q, want it to say a run in another repository is "+
					"answered identically", stderr.String())
			}
		})
}

// gitTreeWithOrigin makes a working tree whose only property under test is its
// origin remote.
func gitTreeWithOrigin(t *testing.T, remote string) string {
	t.Helper()

	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", remote},
	} {
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	// macOS hands out a symlinked temporary directory and `git -C` reports the
	// resolved one; t.Chdir into the symlink is fine, but a test comparing
	// paths would not be.
	return dir
}

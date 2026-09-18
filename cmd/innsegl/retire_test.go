// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
// its URL.
func serveFakeLifecycle(t *testing.T, f *fakeLifecycleSurface) string {
	t.Helper()

	srv := sdk.NewServer(&sdk.Implementation{Name: "innsegl", Version: "v0.0.0-test"}, nil)
	sdk.AddTool(srv, &sdk.Tool{
		Name:        string(mcp.ToolRetireAgent),
		Description: "stand-in for the shipped tool: IP §4's contract, without SPIRE or a ledger",
	}, func(_ context.Context, _ *sdk.CallToolRequest, in fakeRetireArgs) (*sdk.CallToolResult, any, error) {
		return f.call(in.RunID), nil, nil
	})

	httpSrv := httptest.NewServer(sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return srv }, nil))
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
	} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage = %q, want it to mention %q", usage, want)
		}
	}
}

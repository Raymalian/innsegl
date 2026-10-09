// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
	"innsegl.dev/innsegl/internal/spire"
)

// MCP-086 — `innsegl retire <run_id>`, and the answers an operator acts on
// differently: the run ended here, it had already ended, this deployment holds
// no such run, the core could not finish, and this process is not the core.
//
// The command runs ON THE CORE, in process, through retire_agent's own engine
// (mcp.RetireRunForGateway), the path the gateway uses (ADR-0077). These tests
// drive it against a real, throwaway Postgres: a real *ledger.Store, the real
// run directory and the real engine. SPIRE is the one stand-in, the same fake
// the gateway identity tests use, because deleting an entry is
// internal/spire's own contract (SPI-*) and not this command's.

const retireTestRepo = "github.com/example-org/example-repo"

// retireTestFixture is a ledger with one registered run on it.
type retireTestFixture struct {
	gw    *gwIdentityFixture
	runID string
}

func newRetireTestFixture(t *testing.T) *retireTestFixture {
	t.Helper()
	gw := newGWIdentityFixture(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run, err := mcp.RegisterRunForGateway(ctx, mcp.GatewayRegistration{
		AgentType:      "claude-code",
		TaskID:         "retire-test",
		IdempotencyKey: fmt.Sprintf("retire-test-%d", time.Now().UnixNano()),
		Repo:           retireTestRepo,
		Branch:         "main",
	})
	if err != nil {
		t.Fatalf("RegisterRunForGateway: %v", err)
	}
	if gw.ids.entryCount() != 1 {
		t.Fatalf("SPIRE holds %d entries after registration, want 1", gw.ids.entryCount())
	}
	return &retireTestFixture{gw: gw, runID: run.RunID}
}

// deps opens the fixture's own ledger and directory, as the shipped opener
// opens the deployment's, with entries standing in for SPIRE.
func (f *retireTestFixture) deps(t *testing.T, entries mcp.RetireAgentEntries) retireDeps {
	t.Helper()
	return retireDeps{open: func(ctx context.Context, opts retireOptions) (mcp.RetireAgentConfig, func(), error) {
		store, err := ledger.Open(ctx, opts.dsn)
		if err != nil {
			return mcp.RetireAgentConfig{}, nil, err
		}
		runs, err := rundir.New(rundir.Config{Events: store})
		if err != nil {
			store.Close()
			return mcp.RetireAgentConfig{}, nil, err
		}
		return mcp.RetireAgentConfig{Runs: runs, Entries: entries, Ledger: store}, store.Close, nil
	}}
}

// retirements counts the run_retired events the chain holds for runID.
func (f *retireTestFixture) retirements(t *testing.T, runID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	recs, err := f.gw.store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun(%q): %v", runID, err)
	}
	n := 0
	for _, rec := range recs {
		if rec["event_type"] == "run_retired" {
			n++
		}
	}
	return n
}

// retireArgs is a complete core-side command line for the fixture.
func (f *retireTestFixture) retireArgs(runID string) []string {
	return []string{
		"-dsn", f.gw.dsn,
		"-spire-address", "spire-server:8081",
		"-trust-domain", gwIdentityTrustDomain,
		runID,
	}
}

func TestMCP086RetireReportsWhichOfTheFourOutcomesHappened(t *testing.T) {
	t.Run("ended: one retirement is recorded, the entry is deleted, the instant is reported", func(t *testing.T) {
		f := newRetireTestFixture(t)
		var stdout, stderr bytes.Buffer

		code := runRetireCommand(f.retireArgs(f.runID), &stdout, &stderr, f.deps(t, f.gw.ids))

		if code != exitOK {
			t.Fatalf("code = %d, want exitOK (%d); stderr=%s", code, exitOK, stderr.String())
		}
		if got := f.retirements(t, f.runID); got != 1 {
			t.Errorf("the chain holds %d run_retired for the run, want exactly 1", got)
		}
		if got := f.gw.ids.entryCount(); got != 0 {
			t.Errorf("SPIRE still holds %d entries, want the run's deleted", got)
		}
		if !strings.Contains(stdout.String(), "retired "+f.runID+" at ") {
			t.Errorf("stdout = %q, want the run and its instant", stdout.String())
		}
	})

	t.Run("already ended: nothing is appended and the original instant is reported", func(t *testing.T) {
		f := newRetireTestFixture(t)

		var first bytes.Buffer
		if code := runRetireCommand(f.retireArgs(f.runID), &first, &first, f.deps(t, f.gw.ids)); code != exitOK {
			t.Fatalf("the first run = %d, want exitOK; output=%s", code, first.String())
		}
		// doc 02 §1 instants are millisecond-precise; a second invocation typed
		// by a human is many milliseconds later. This keeps the test from
		// depending on how fast the machine is.
		time.Sleep(5 * time.Millisecond)

		var stdout, stderr bytes.Buffer
		code := runRetireCommand(f.retireArgs(f.runID), &stdout, &stderr, f.deps(t, f.gw.ids))

		if code != exitRetireAlreadyEnded {
			t.Fatalf("code = %d, want exitRetireAlreadyEnded (%d); stderr=%s",
				code, exitRetireAlreadyEnded, stderr.String())
		}
		if got := f.retirements(t, f.runID); got != 1 {
			t.Errorf("the chain holds %d run_retired across two runs, want exactly 1", got)
		}
		for _, want := range []string{"ALREADY ENDED", "nothing was appended", f.runID} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
			}
		}
	})

	t.Run("no such run: nothing is recorded and nothing is deleted", func(t *testing.T) {
		f := newRetireTestFixture(t)
		const unknown = "run-0000000000ab"
		var stdout, stderr bytes.Buffer

		code := runRetireCommand(f.retireArgs(unknown), &stdout, &stderr, f.deps(t, f.gw.ids))

		if code != exitRetireNoSuchRun {
			t.Fatalf("code = %d, want exitRetireNoSuchRun (%d); stderr=%s",
				code, exitRetireNoSuchRun, stderr.String())
		}
		if got := f.retirements(t, unknown); got != 0 {
			t.Errorf("the chain holds %d run_retired for an unknown run, want none", got)
		}
		if got := f.gw.ids.entryCount(); got != 1 {
			t.Errorf("SPIRE holds %d entries, want the registered run's untouched", got)
		}
		if !strings.Contains(stderr.String(), "NO SUCH RUN") || !strings.Contains(stderr.String(), unknown) {
			t.Errorf("stderr = %q, want NO SUCH RUN naming the run", stderr.String())
		}
	})

	t.Run("unreachable: a ledger that cannot be opened decides nothing", func(t *testing.T) {
		var stdout, stderr bytes.Buffer

		// The SHIPPED opener, against a port nothing listens on.
		code := runRetireCommand([]string{
			"-dsn", "postgres://nobody:nothing@" + closedTCPAddr(t) + "/innsegl?sslmode=disable&connect_timeout=2",
			"-spire-address", "spire-server:8081",
			"-trust-domain", gwIdentityTrustDomain,
			"-timeout", "10s",
			"run-4c1f9a2b7d3e",
		}, &stdout, &stderr, retireDeps{})

		if code != exitRetireUnreachable {
			t.Fatalf("code = %d, want exitRetireUnreachable (%d); stderr=%s",
				code, exitRetireUnreachable, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout = %q, want nothing reported about a run that was never reached", stdout.String())
		}
		for _, want := range []string{"UNREACHABLE", "safe"} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
			}
		}
	})
}

// A SPIRE that will not delete the entry leaves the retirement recorded
// (ledger first, ADR-0018) and the command UNREACHABLE, naming the class. A
// second run converges: it appends nothing and deletes the entry.
func TestRetireReportsASPIREFailureAsUnreachableAndConvergesOnRetry(t *testing.T) {
	f := newRetireTestFixture(t)
	broken := &failingRetireEntries{err: &spire.Error{
		Class: spire.ClassIdentityUnavailable, Op: "retire_agent", RunID: f.runID,
		Message: "spire-server is unreachable",
	}}

	var stdout, stderr bytes.Buffer
	code := runRetireCommand(f.retireArgs(f.runID), &stdout, &stderr, f.deps(t, broken))

	if code != exitRetireUnreachable {
		t.Fatalf("code = %d, want exitRetireUnreachable (%d); stderr=%s",
			code, exitRetireUnreachable, stderr.String())
	}
	for _, want := range []string{string(mcp.ClassIdentityUnavailable), "safe"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to name %q", stderr.String(), want)
		}
	}
	if got := f.retirements(t, f.runID); got != 1 {
		t.Fatalf("the chain holds %d run_retired, want the record written before the deletion", got)
	}

	time.Sleep(5 * time.Millisecond)
	stdout.Reset()
	stderr.Reset()
	code = runRetireCommand(f.retireArgs(f.runID), &stdout, &stderr, f.deps(t, f.gw.ids))
	if code != exitRetireAlreadyEnded {
		t.Fatalf("the retry = %d, want exitRetireAlreadyEnded (%d); stderr=%s",
			code, exitRetireAlreadyEnded, stderr.String())
	}
	if got := f.retirements(t, f.runID); got != 1 {
		t.Errorf("the chain holds %d run_retired after the retry, want exactly 1", got)
	}
	if got := f.gw.ids.entryCount(); got != 0 {
		t.Errorf("SPIRE still holds %d entries after the retry, want the entry deleted", got)
	}
}

// Run anywhere but the core, the process has no SPIRE admin identity. That is
// REFUSED and not UNREACHABLE: the deployment may be fine, and the move is to
// run the command where the identity is.
func TestRetireRefusesAProcessWithNoAdminIdentity(t *testing.T) {
	f := newRetireTestFixture(t)
	var stdout, stderr bytes.Buffer

	code := runRetireCommand([]string{
		"-dsn", f.gw.dsn,
		"-spire-address", "spire-server:8081",
		"-trust-domain", gwIdentityTrustDomain,
		"-workload-api", "unix://" + filepath.Join(t.TempDir(), "no-agent.sock"),
		f.runID,
	}, &stdout, &stderr, retireDeps{})

	if code != exitRetireUnauthorized {
		t.Fatalf("code = %d, want exitRetireUnauthorized (%d); stderr=%s",
			code, exitRetireUnauthorized, stderr.String())
	}
	for _, want := range []string{"REFUSED", "docker exec innsegl-mcp innsegl retire " + f.runID} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
		}
	}
	if got := f.retirements(t, f.runID); got != 0 {
		t.Errorf("the chain holds %d run_retired, want none: nothing was decided", got)
	}
}

func TestRetireRefusesACommandLineItCannotActOn(t *testing.T) {
	complete := []string{"-dsn", "postgres://x@y/z", "-spire-address", "s:1", "-trust-domain", "innsegl.dev"}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no run id at all", complete, "a run id is required"},
		{"two run ids", append(append([]string{}, complete...), "run-aaaaaaaaaaaa", "run-bbbbbbbbbbbb"), "one run at a time"},
		{"an unknown flag", append([]string{"-force"}, complete...), "-force"},
		{"the retired listener flag", append([]string{"-url", "http://127.0.0.1:28090/"}, complete...), "-url"},
		{"no ledger", []string{"-dsn", "", "-spire-address", "s:1", "-trust-domain", "innsegl.dev", "run-aaaaaaaaaaaa"}, "docker exec innsegl-mcp"},
		{"no SPIRE", []string{"-dsn", "postgres://x@y/z", "-spire-address", "", "-trust-domain", "innsegl.dev", "run-aaaaaaaaaaaa"}, "-spire-address"},
		{"no trust domain", []string{"-dsn", "postgres://x@y/z", "-spire-address", "s:1", "-trust-domain", "", "run-aaaaaaaaaaaa"}, "-trust-domain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			opened := false
			deps := retireDeps{open: func(context.Context, retireOptions) (mcp.RetireAgentConfig, func(), error) {
				opened = true
				return mcp.RetireAgentConfig{}, nil, errors.New("must not be reached")
			}}

			code := runRetireCommand(tc.args, &stdout, &stderr, deps)

			if code != exitUsage {
				t.Fatalf("code = %d, want exitUsage (%d); stderr=%s", code, exitUsage, stderr.String())
			}
			if opened {
				t.Error("the ledger and SPIRE were opened for a command line that cannot be acted on")
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr = %q, want it to name %q", stderr.String(), tc.want)
			}
		})
	}
}

func TestRetireUsageNamesEveryExitStatusAndWhereToRunIt(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if code := retireCommand([]string{"-h"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("code = %d, want exitOK", code)
	}

	usage := stdout.String() + stderr.String()
	for _, want := range []string{
		"innsegl retire", "docker exec innsegl-mcp innsegl retire", envLedgerDSN,
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

// The five statuses are a contract scripts switch on; their numbers do not
// move with the command's new home.
func TestRetireExitStatusesKeepTheirNumbers(t *testing.T) {
	for name, got := range map[string]int{
		"ALREADY ENDED": exitRetireAlreadyEnded,
		"NO SUCH RUN":   exitRetireNoSuchRun,
		"UNREACHABLE":   exitRetireUnreachable,
		"REFUSED":       exitRetireUnauthorized,
	} {
		want := map[string]int{"ALREADY ENDED": 18, "NO SUCH RUN": 19, "UNREACHABLE": 20, "REFUSED": 21}[name]
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}
}

// failingRetireEntries is a SPIRE that refuses every deletion.
type failingRetireEntries struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (f *failingRetireEntries) RetireRun(context.Context, spire.RunRef) (spire.Retirement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return spire.Retirement{}, f.err
}

// closedTCPAddr is a loopback address nothing listens on.
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

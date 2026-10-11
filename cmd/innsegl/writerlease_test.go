// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/ledger"
)

// OPS-182, replicas: doc 05 §2 runs N MCP replicas on one ledger, with the
// loops single-active. The lease is the singletons' (serve -also): a replica
// with no companions serves beside the core that holds it.
func TestOPS182AReplicaWithoutCompanionsServesBesideTheCore(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t)
	leases := testLeases(t, dsn)
	if _, err := leases.Acquire(t.Context(), "the-core", time.Minute); err != nil {
		t.Fatal(err)
	}
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		return &fakeServer{}, nil
	}, writerLeasePoll)
	o := leaseTestOptions(dsn)
	o.also = nil
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	s, err := open(ctx, o, newServeLog(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("a replica with no companions waited for the core's lease: %v", err)
	}
	s.Close()
	if held, live, err := leases.Status(t.Context()); err != nil || !live || held.Holder != "the-core" {
		t.Fatalf("the replica touched the core's lease: %+v live %v %v", held, live, err)
	}
}

// OPS-182, fail fast: a core whose role -require-append-only-role refuses
// is refused at once, naming what the role holds, rather than waiting for a
// lease another core holds.
func TestOPS182ARefusedRoleFailsBeforeWaitingForTheLease(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t) // the owning role: it holds DELETE
	leases := testLeases(t, dsn)
	if _, err := leases.Acquire(t.Context(), "the-core", time.Minute); err != nil {
		t.Fatal(err)
	}
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		t.Error("the server was opened under a refused role")
		return &fakeServer{}, nil
	}, writerLeasePoll)
	o := leaseTestOptions(dsn)
	o.requireRole = true
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := open(ctx, o, newServeLog(&bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "DELETE") {
		t.Fatalf("open under the owning role with -require-append-only-role = %v; want a refusal naming DELETE, at once", err)
	}
}

// OPS-182, a killed core: the next core on the same ledger starts within a
// poll of the old one's death, not after its lease's TTL (MCP-011 restarts a
// SIGKILLed core again and again).
func TestOPS182ACoreKilledWithoutReleasingIsReplacedAtOnce(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t)
	testLeases(t, dsn)
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		return &fakeServer{}, nil
	}, writerLeasePoll)
	o := leaseTestOptions(dsn)
	o.writerLeaseTTL = time.Minute
	first, err := open(t.Context(), o, newServeLog(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("first core: %v", err)
	}
	// SIGKILL: renewal stops and every session ends; nothing is released.
	ls, ok := first.(*leasedServer)
	if !ok {
		t.Fatalf("open answered %T, not a leased server", first)
	}
	held := ls.held
	held.stopRenew()
	held.leases.Close()

	start := time.Now()
	second, err := open(t.Context(), o, newServeLog(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("second core: %v", err)
	}
	defer second.Close()
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("the second core waited %s for a dead core's lease; want about one poll (%s)", waited, writerLeasePoll)
	}
}

// OPS-182, fresh database: a core started with -migrate on an empty ledger
// (the bootstrap OPS-004 drives) migrates before it takes the lease. Taking
// the lease first asked for a table no migration had made yet, and the core
// never served (#580, measured in CI on a fresh clone).
func TestOPS182AFreshLedgerIsMigratedBeforeTheLeaseIsTaken(t *testing.T) {
	c := requireAPIPG(t)
	name := fmt.Sprintf("lease_fresh_%d_%d", os.Getpid()%100000, apiDBSeq.Add(1))
	admin, err := pgx.Connect(t.Context(), c.ownerDSN(apiPGDatabase))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if _, cerr := admin.Exec(t.Context(), "CREATE DATABASE "+apiQuoteIdent(name)); cerr != nil {
		t.Fatal(cerr)
	}
	dsn := c.ownerDSN(name)
	t.Cleanup(func() { ledger.UseProcessWriter("") })

	opened := false
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		opened = true
		return &fakeServer{}, nil
	}, 20*time.Millisecond)
	o := leaseTestOptions(dsn)
	o.migrate = true
	var logs bytes.Buffer
	s, err := open(t.Context(), o, newServeLog(&logs))
	if err != nil || !opened {
		t.Fatalf("open on a fresh ledger with -migrate = %v (opened %v)\n%s", err, opened, logs.String())
	}
	defer s.Close()
	if _, live, err := testLeases(t, dsn).Status(t.Context()); err != nil || !live {
		t.Fatalf("after open the lease is live %v (%v); want this core's", live, err)
	}
}

// OPS-182 — the core takes the writer lease before it serves, waits while
// another core or a freeze holds the ledger, stops when it loses the lease,
// and releases it when it stops (RM-326, #580).

func testLeases(t *testing.T, dsn string) *ledger.Leases {
	t.Helper()
	l, err := ledger.OpenLeases(t.Context(), dsn)
	if err != nil {
		t.Fatalf("OpenLeases: %v", err)
	}
	t.Cleanup(l.Close)
	// A test that fails before its core releases must not leave every later
	// store in this process naming a writer.
	t.Cleanup(func() { ledger.UseProcessWriter("") })
	return l
}

func leaseTestOptions(dsn string) serveOptions {
	// A core: it runs the single-active companions, so it takes the lease.
	return serveOptions{dsn: dsn, writerLeaseTTL: 300 * time.Millisecond, also: []string{"gateway"}}
}

func TestOPS182TheCoreServesOnlyUnderTheWriterLease(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t)
	leases := testLeases(t, dsn)
	ctx := t.Context()

	other, err := leases.Acquire(ctx, "another-core", time.Minute)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	var opened atomic.Bool
	srv := &fakeServer{addr: "127.0.0.1:0"}
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		opened.Store(true)
		return srv, nil
	}, 20*time.Millisecond)

	var logs bytes.Buffer
	type result struct {
		s   servedMCP
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, oerr := open(ctx, leaseTestOptions(dsn), newServeLog(&logs))
		done <- result{s, oerr}
	}()

	time.Sleep(200 * time.Millisecond)
	if opened.Load() {
		t.Fatal("the core opened its server while another core held the writer lease")
	}
	if rerr := leases.Release(ctx, other); rerr != nil {
		t.Fatalf("Release: %v", rerr)
	}
	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the core did not take the lease after the other core released it")
	}
	if r.err != nil || !opened.Load() {
		t.Fatalf("open = %v (opened %v); want the server opened under the lease", r.err, opened.Load())
	}
	if !strings.Contains(logs.String(), "another-core") {
		t.Errorf("the wait did not name the holder it waited for:\n%s", logs.String())
	}

	held, live, err := leases.Status(ctx)
	if err != nil || !live || held.Holder == "another-core" {
		t.Fatalf("after open the lease is %+v (live %v, %v); want this core's", held, live, err)
	}

	t.Run("it renews while it serves", func(t *testing.T) {
		time.Sleep(time.Second)
		now, live, err := leases.Status(ctx)
		if err != nil || !live || now.Holder != held.Holder || now.Epoch != held.Epoch {
			t.Fatalf("after three lease periods the lease is %+v (live %v, %v); want the same holding, renewed", now, live, err)
		}
	})

	t.Run("it stops serving when the lease is taken from it", func(t *testing.T) {
		served := make(chan error, 1)
		go func() { served <- r.s.Serve(ctx) }()
		if _, err := leases.Freeze(ctx, "a test takes the ledger away"); err != nil {
			t.Fatalf("Freeze: %v", err)
		}
		select {
		case err := <-served:
			if err == nil {
				t.Fatal("Serve returned nil after the lease was lost; the process would exit as an orderly stop")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Serve kept running after the lease was lost")
		}
		r.s.Close()
		if srv.closes() != 1 {
			t.Fatalf("the inner server was closed %d times, want 1", srv.closes())
		}
		if err := leases.Thaw(ctx); err != nil {
			t.Fatalf("Thaw: %v", err)
		}
	})
}

func TestOPS182AFrozenLedgerIsNeverServed(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t)
	leases := testLeases(t, dsn)
	if _, err := leases.Freeze(t.Context(), "copied to a new host"); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	var opened atomic.Bool
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		opened.Store(true)
		return &fakeServer{}, nil
	}, 20*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	var logs bytes.Buffer
	_, err := open(ctx, leaseTestOptions(dsn), newServeLog(&logs))
	if err == nil || opened.Load() {
		t.Fatalf("open on a frozen ledger = %v (opened %v); want it to wait and never open", err, opened.Load())
	}
	if !strings.Contains(logs.String(), "copied to a new host") || !strings.Contains(logs.String(), "thaw") {
		t.Errorf("the wait did not say the ledger is frozen, why, and how to thaw it:\n%s", logs.String())
	}
}

func TestOPS182AStoppedCoreReleasesTheLease(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t)
	leases := testLeases(t, dsn)
	open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
		return &fakeServer{}, nil
	}, 20*time.Millisecond)
	s, err := open(t.Context(), leaseTestOptions(dsn), newServeLog(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.Close()
	if _, live, err := leases.Status(t.Context()); err != nil || live {
		t.Fatalf("after Close the lease is live %v (%v); the next core would wait for it to expire", live, err)
	}

	t.Run("a server that does not open gives the lease back", func(t *testing.T) {
		open := withWriterLease(func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
			return nil, errors.New("no SPIRE")
		}, 20*time.Millisecond)
		if _, err := open(t.Context(), leaseTestOptions(dsn), newServeLog(&bytes.Buffer{})); err == nil {
			t.Fatal("open succeeded with a failing inner open")
		}
		if _, live, serr := leases.Status(t.Context()); serr != nil || live {
			t.Fatal("a core that failed to open kept the writer lease")
		}
	})
}

func TestOPS182TheLedgerCommandReportsFreezesAndThaws(t *testing.T) {
	dsn, _, _ := freshLedgerDB(t)
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := runLedgerCommand(t.Context(), args, &out, &errOut)
		return code, out.String(), errOut.String()
	}

	if code, out, _ := run("lease", "-dsn", dsn); code != exitOK || !strings.Contains(out, "not held") ||
		!strings.Contains(out, "not frozen") {
		t.Fatalf("ledger lease on a fresh ledger = %d %q", code, out)
	}
	if code, _, errOut := run("freeze", "-dsn", dsn); code != exitUsage || !strings.Contains(errOut, "-reason") {
		t.Fatalf("freeze with no reason = %d %q; want usage naming -reason", code, errOut)
	}
	if code, out, errOut := run("freeze", "-dsn", dsn, "-reason", "moving host"); code != exitOK ||
		!strings.Contains(out, "frozen") {
		t.Fatalf("freeze = %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("lease", "-dsn", dsn); code != exitOK || !strings.Contains(out, "moving host") {
		t.Fatalf("lease after freeze = %d %q; want the reason", code, out)
	}
	if code, out, errOut := run("thaw", "-dsn", dsn); code != exitOK || !strings.Contains(out, "thawed") {
		t.Fatalf("thaw = %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("lease", "-dsn", dsn); code != exitOK || !strings.Contains(out, "not frozen") {
		t.Fatalf("lease after thaw = %d %q", code, out)
	}
	if code, _, _ := run("melt", "-dsn", dsn); code != exitUsage {
		t.Fatalf("an unknown subcommand = %d, want %d", code, exitUsage)
	}
	if code, _, _ := run(); code != exitUsage {
		t.Fatalf("no subcommand = %d, want %d", code, exitUsage)
	}
	if code, _, errOut := run("lease", "-dsn", "postgres://nobody@127.0.0.1:1/x?connect_timeout=1"); code != exitLedgerUnavailable ||
		errOut == "" {
		t.Fatalf("an unreachable ledger = %d %q, want %d", code, errOut, exitLedgerUnavailable)
	}
	if code, _, _ := run("lease", "-h"); code != exitOK {
		t.Fatalf("lease -h = %d", code)
	}
}

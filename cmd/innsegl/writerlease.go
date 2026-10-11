// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/ledger"
)

// The writer lease (RM-326, #580; internal/ledger/lease.go). One core writes
// a ledger at a time: `innsegl serve` takes the lease before it opens
// anything, waits while another core holds it or the ledger is frozen,
// renews it while it runs, stops when it loses it, and releases it when it
// stops. Its companions open their stores after it holds the lease, and every
// store this process opens names it as the writer, so the database refuses
// their appends the moment the lease is gone.

// defaultWriterLeaseTTL is how long a lease lasts unrenewed. A core that
// crashed holds the next one up for at most this; a core renews at a third
// of it.
const defaultWriterLeaseTTL = 15 * time.Second

// writerLeasePoll is how often a waiting core asks again. A core killed
// without releasing is taken over as soon as the ledger has ended its
// session (internal/ledger's presence lock), so a restart waits about this
// long, not the TTL; only a holder whose host vanished holds the next core
// up for the TTL.
const writerLeasePoll = 250 * time.Millisecond

// exitLedgerUnavailable is `innsegl ledger`'s status when the ledger cannot
// be reached or read.
const exitLedgerUnavailable = 32

// writerHolder names this process as a lease holder: the host, and a random
// part so two processes on one host are two holders.
func writerHolder() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "core"
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return host + "-" + hex.EncodeToString(b)
}

// withWriterLease wraps open: the server is opened only under the writer
// lease, its Serve ends with an error when the lease is lost, and its Close
// releases the lease. poll is how often a waiting core asks again.
func withWriterLease(open func(context.Context, serveOptions, *serveLog) (servedMCP, error), poll time.Duration) func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
	return func(ctx context.Context, o serveOptions, log *serveLog) (servedMCP, error) {
		ttl := o.writerLeaseTTL
		if ttl <= 0 {
			ttl = defaultWriterLeaseTTL
		}
		// The lease is the singletons': the companions (seal, reconcile,
		// reap, gateway) are single-active (doc 05 §2). A replica that runs
		// none serves beside the core that holds it, as doc 05 §2's N MCP
		// replicas do; the database still refuses its appends to a frozen
		// ledger.
		if len(o.also) == 0 {
			log.info("no companion subcommands: serving as a replica, without the writer lease")
			return open(ctx, o, log)
		}
		// With -migrate the core makes its own schema (a fresh clone's
		// bootstrap): the lease's table is one of the migrations, so they
		// run first. Migrating twice is a no-op; openServer's own run then
		// finds nothing to do.
		if o.migrate {
			if err := migrateLedger(ctx, o.dsn); err != nil {
				return nil, err
			}
		}
		// Refusals come before the wait: a core this database role cannot
		// run is told so at once, not after another core lets go.
		if err := preflightRole(ctx, o, log); err != nil {
			return nil, err
		}
		leases, err := ledger.OpenLeases(ctx, o.dsn)
		if err != nil {
			return nil, fmt.Errorf("open the writer lease: %w", err)
		}
		holder := writerHolder()
		lease, err := waitForWriterLease(ctx, leases, holder, ttl, poll, log)
		if err != nil {
			leases.Close()
			return nil, err
		}
		log.info("holding the writer lease", "holder", holder, "epoch", lease.Epoch, "ttl", ttl.String())
		ledger.UseProcessWriter(holder)
		h := &heldLease{leases: leases, lease: lease, ttl: ttl, log: log, lost: make(chan struct{})}
		// Renewal outlives a cancelled start: it ends when the lease is
		// released, after the companions have stopped.
		renewCtx, stopRenew := context.WithCancel(context.WithoutCancel(ctx))
		h.stopRenew = stopRenew
		go h.renew(renewCtx)

		srv, err := open(ctx, o, log)
		if err != nil {
			h.release(ctx)
			return nil, err
		}
		return &leasedServer{servedMCP: srv, held: h}, nil
	}
}

// preflightRole is openServer's database-role check, run before the lease
// wait so a refused role fails fast.
func preflightRole(ctx context.Context, o serveOptions, log *serveLog) error {
	pool, err := pgxpool.New(ctx, o.dsn)
	if err != nil {
		return fmt.Errorf("open the ledger to check its role: %w", err)
	}
	defer pool.Close()
	return enforceChainPrivileges(ctx, pool, o, log)
}

// migrateLedger applies the shipped migrations through a store of its own.
func migrateLedger(ctx context.Context, dsn string) error {
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open the ledger to migrate it: %w", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("apply the ledger migrations: %w", err)
	}
	return nil
}

// waitForWriterLease takes the lease, waiting while another core holds it or
// the ledger is frozen. Each change in what it waits for is logged once.
func waitForWriterLease(ctx context.Context, leases *ledger.Leases, holder string, ttl, poll time.Duration, log *serveLog) (ledger.WriterLease, error) {
	said := ""
	for {
		lease, err := leases.Acquire(ctx, holder, ttl)
		if err == nil {
			return lease, nil
		}
		var held *ledger.LeaseHeldError
		switch {
		case errors.As(err, &held):
			if said != "held:"+held.Lease.Holder {
				said = "held:" + held.Lease.Holder
				log.info("waiting for the writer lease; another core holds this ledger",
					"holder", held.Lease.Holder, "until", held.Lease.ExpiresAt.UTC().Format(time.RFC3339))
			}
		case errors.Is(err, ledger.ErrFrozen):
			if said != "frozen" {
				said = "frozen"
				log.warn("the ledger is frozen; this core does not serve or run its loops until it is thawed "+
					"(`innsegl ledger thaw`, or `make innsegl-thaw`)", "freeze", err.Error())
			}
		default:
			return ledger.WriterLease{}, fmt.Errorf("take the writer lease: %w", err)
		}
		select {
		case <-ctx.Done():
			return ledger.WriterLease{}, fmt.Errorf("stopped while waiting for the writer lease: %w", ctx.Err())
		case <-time.After(poll):
		}
	}
}

// heldLease is the lease this process holds, renewed in the background.
type heldLease struct {
	leases    *ledger.Leases
	ttl       time.Duration
	log       *serveLog
	stopRenew context.CancelFunc

	mu    sync.Mutex
	lease ledger.WriterLease

	lost     chan struct{}
	lostOnce sync.Once
	once     sync.Once
}

func (h *heldLease) markLost(reason string, err error) {
	h.lostOnce.Do(func() {
		h.log.error("this core lost the writer lease and stops; another core or a freeze has the ledger",
			"reason", reason, "err", err)
		close(h.lost)
	})
}

// renew extends the lease every third of its life until ctx ends. A lease
// taken over or frozen is lost at once. One that cannot be renewed because
// the ledger does not answer is kept trying: nobody else can take it while
// the ledger is down, the database refuses this core's appends once it has
// expired, and the next renewal that reaches the ledger either keeps it
// (nobody took it) or finds it lost.
func (h *heldLease) renew(ctx context.Context) {
	tick := time.NewTicker(h.ttl / 3)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		h.mu.Lock()
		cur := h.lease
		h.mu.Unlock()
		next, err := h.leases.Renew(ctx, cur, h.ttl)
		switch {
		case err == nil:
			h.mu.Lock()
			h.lease = next
			h.mu.Unlock()
		case errors.Is(err, ledger.ErrLeaseLost), errors.Is(err, ledger.ErrFrozen):
			h.markLost("taken", err)
			return
		case ctx.Err() != nil:
			return
		default:
			h.log.warn("renewing the writer lease failed; trying again", "err", err)
		}
	}
}

// release stops renewing and gives the lease back, once.
func (h *heldLease) release(ctx context.Context) {
	h.once.Do(func() {
		h.stopRenew()
		ledger.UseProcessWriter("")
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		h.mu.Lock()
		cur := h.lease
		h.mu.Unlock()
		if err := h.leases.Release(rctx, cur); err != nil {
			h.log.warn("the writer lease was not released; the next core waits for it to expire", "err", err)
		}
		h.leases.Close()
	})
}

// leasedServer is a server that runs only while its lease is held.
type leasedServer struct {
	servedMCP
	held *heldLease
}

// Serve runs the server until ctx ends, or ends it with an error when the
// lease is lost: the process then exits and starts again, waiting its turn.
func (s *leasedServer) Serve(ctx context.Context) error {
	inner, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.servedMCP.Serve(inner) }()
	select {
	case err := <-done:
		return err
	case <-s.held.lost:
		cancel()
		<-done
		return errors.New("the writer lease was lost")
	}
}

// Close closes the server, then releases the lease.
func (s *leasedServer) Close() {
	s.servedMCP.Close()
	s.held.release(context.Background())
}

// ---- innsegl ledger lease|freeze|thaw --------------------------------------

const ledgerUsage = `usage: innsegl ledger <lease|freeze|thaw> [-dsn DSN] [flags]

  lease    say who holds the writer lease and whether the ledger is frozen
  freeze   freeze the ledger: every append is refused, and no core serves it,
           until it is thawed. -reason is required
  thaw     end a freeze

The ledger connection is -dsn or $` + envLedgerDSN + `.
`

func ledgerCommand(args []string, stdout, stderr io.Writer) int {
	return runLedgerCommand(context.Background(), args, stdout, stderr)
}

func runLedgerCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fprintf(stderr, "%s", ledgerUsage)
		return exitUsage
	}
	sub := args[0]
	switch sub {
	case "lease", "freeze", "thaw":
	case "-h", "--help", "help":
		fprintf(stdout, "%s", ledgerUsage)
		return exitOK
	default:
		fprintf(stderr, "innsegl ledger: unknown subcommand %q\n%s", sub, ledgerUsage)
		return exitUsage
	}
	fs := flag.NewFlagSet("innsegl ledger "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("dsn", os.Getenv(envLedgerDSN), "ledger connection string ($"+envLedgerDSN+")")
	reason := ""
	if sub == "freeze" {
		fs.StringVar(&reason, "reason", "", "why the ledger is frozen, kept with the freeze (required)")
	}
	if err := fs.Parse(args[1:]); errors.Is(err, flag.ErrHelp) {
		return exitOK
	} else if err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	if *dsn == "" {
		fprintf(stderr, "innsegl ledger %s: no ledger: set -dsn or $%s\n", sub, envLedgerDSN)
		return exitUsage
	}
	if sub == "freeze" && strings.TrimSpace(reason) == "" {
		fprintf(stderr, "innsegl ledger freeze: -reason is required; it is kept with the freeze\n")
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	leases, err := ledger.OpenLeases(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "innsegl ledger %s: %v\n", sub, err)
		return exitLedgerUnavailable
	}
	defer leases.Close()

	switch sub {
	case "freeze":
		w, ferr := leases.Freeze(ctx, reason)
		if ferr != nil {
			fprintf(stderr, "innsegl ledger freeze: %v\n", ferr)
			return exitLedgerUnavailable
		}
		fprintf(stdout, "frozen since %s: %s\n", w.FrozenAt.UTC().Format(time.RFC3339), w.FrozenReason)
		return exitOK
	case "thaw":
		if terr := leases.Thaw(ctx); terr != nil {
			fprintf(stderr, "innsegl ledger thaw: %v\n", terr)
			return exitLedgerUnavailable
		}
		fprintf(stdout, "thawed: a core may take the writer lease\n")
		return exitOK
	}
	w, live, err := leases.Status(ctx)
	if err != nil {
		fprintf(stderr, "innsegl ledger lease: %v\n", err)
		return exitLedgerUnavailable
	}
	if live {
		fprintf(stdout, "writer lease: held by %s (epoch %d) until %s\n", w.Holder, w.Epoch,
			w.ExpiresAt.UTC().Format(time.RFC3339))
	} else {
		fprintf(stdout, "writer lease: not held\n")
	}
	if w.FrozenAt != nil {
		fprintf(stdout, "freeze: frozen since %s: %s\n", w.FrozenAt.UTC().Format(time.RFC3339), w.FrozenReason)
	} else {
		fprintf(stdout, "freeze: not frozen\n")
	}
	return exitOK
}

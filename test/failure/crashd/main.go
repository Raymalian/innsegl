// SPDX-License-Identifier: Apache-2.0

// Command crashd is the innsegl MCP server as a process that can be killed.
//
// WHY THIS BINARY EXISTS
// ----------------------
// IP §6.6 is written about a process: "kill -9 at arbitrary points (fuzz the
// kill timing in tests) must never violate I1–I6 after restart +
// reconciliation." MCP-011 is therefore not a test of a function, it is a test
// of what survives when the operating system removes the server between two
// instructions.
//
// There is nothing to kill. `cmd/innsegl` is the CLI (reaper, canary); nothing
// in this repository wires the five tools of IP §4 onto a listener, which
// RM-026 and RM-027 both flagged. So this file is the missing entry point,
// built for one purpose and shipped nowhere: it is the smallest thing that can
// be SIGKILLed and still be honestly called "the MCP server", because every
// line of it below the flags is the shipped package's own configuration API.
//
// WHAT IS REAL HERE AND WHAT IS NOT — stated rather than implied
// --------------------------------------------------------------
// Real: the four tools are `internal/mcp`'s, installed through the exported
// Configure* seams; the transport is `mcp.Server.Handler` over `net/http`; the
// ledger is `internal/ledger` on a real Postgres; the idempotency store is
// `internal/mcp`'s on the same database; SPIRE is a real containerised server
// reached over mTLS with a real admin SVID. A caller reaching this process
// reaches exactly the code a deployed replica would run.
//
// Not real: the process is started by a test rather than by an orchestrator,
// it holds its admin SVID as PEM files rather than as an attested workload's
// X509Source, and it is not behind a load balancer. None of those three is on
// the path IP §6.6 is about — what a crash leaves behind in Postgres and in
// SPIRE — and the harness that drives this binary says so in its own words.
//
// TWO PIECES ARE THE HARNESS'S AND NOT THE SHIPPED SERVER'S
// ---------------------------------------------------------
//  1. ledgerRuns, below. `internal/mcp` declares CredentialRuns and ships no
//     implementation of it: the component that reads `run_registered` and
//     `run_retired` back out of the chain has not been written. RM-028 wrote
//     one for the contract suite and it is a _test.go file in another package,
//     so it cannot be imported. This is a second copy, kept deliberately dumb:
//     it scans the chain and believes nothing it did not read there.
//  2. the SVID source. In a deployment the MCP is an attested workload and its
//     credential is a *workloadapi.X509Source. There is no innsegl-mcp
//     workload yet, so the harness mints the admin SVID with `spire-server
//     x509 mint` and hands it over as files — which is what
//     internal/mcp/get_credential_test.go and test/failure/harness_test.go
//     already do for the same reason.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "crashd: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	dsn         string
	spireAddr   string
	trustDomain string
	serverID    string
	parentID    string
	svidPEM     string
	keyPEM      string
	bundlePEM   string
	addrFile    string
	lease       time.Duration
	migrate     bool
}

func parseFlags() (options, error) {
	var o options
	fs := flag.NewFlagSet("crashd", flag.ContinueOnError)
	fs.StringVar(&o.dsn, "dsn", "", "Postgres DSN for the chain and the idempotency store")
	fs.StringVar(&o.spireAddr, "spire-addr", "", "SPIRE server API, host:port")
	fs.StringVar(&o.trustDomain, "trust-domain", "", "SPIFFE trust domain name")
	fs.StringVar(&o.serverID, "server-id", "", "SPIFFE ID the SPIRE server must present")
	fs.StringVar(&o.parentID, "parent-id", "", "attested node every run entry hangs off")
	fs.StringVar(&o.svidPEM, "svid", "", "PEM file holding the admin X509-SVID")
	fs.StringVar(&o.keyPEM, "key", "", "PEM file holding the admin SVID's private key")
	fs.StringVar(&o.bundlePEM, "bundle", "", "PEM file holding the trust bundle")
	fs.StringVar(&o.addrFile, "addr-file", "", "file to write the bound listener address to")
	fs.DurationVar(&o.lease, "lease", mcp.DefaultIdempotencyLease,
		"how long one idempotency claim is honoured before another caller may take it over")
	fs.BoolVar(&o.migrate, "migrate", false, "apply the ledger migrations before serving")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return options{}, err
	}
	for _, required := range []struct{ name, value string }{
		{"-dsn", o.dsn},
		{"-spire-addr", o.spireAddr},
		{"-trust-domain", o.trustDomain},
		{"-parent-id", o.parentID},
		{"-svid", o.svidPEM},
		{"-key", o.keyPEM},
		{"-bundle", o.bundlePEM},
		{"-addr-file", o.addrFile},
	} {
		if required.value == "" {
			return options{}, fmt.Errorf("%s is required", required.name)
		}
	}
	return o, nil
}

// run wires the four tools and serves them until the process is killed.
//
// Nothing here is graceful and nothing here is deferred on purpose: this
// process exists to be SIGKILLed, and a shutdown path would be a code path the
// scenario never takes.
func run() error {
	o, err := parseFlags()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := ledger.Open(ctx, o.dsn)
	if err != nil {
		return fmt.Errorf("ledger.Open: %w", err)
	}
	if o.migrate {
		if merr := store.Migrate(ctx); merr != nil {
			return fmt.Errorf("ledger.Migrate: %w", merr)
		}
	}

	pool, err := pgxpool.New(ctx, o.dsn)
	if err != nil {
		return fmt.Errorf("pgxpool.New: %w", err)
	}
	idem := mcp.NewIdempotencyStore(pool, mcp.WithIdempotencyLease(o.lease))

	source, err := loadSource(o)
	if err != nil {
		return err
	}
	admin, err := spire.Dial(ctx, spire.Config{
		Address:     o.spireAddr,
		TrustDomain: o.trustDomain,
		ServerID:    o.serverID,
		Source:      source,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("spire.Dial: %w", err)
	}
	mintConn, err := dialMint(o, source)
	if err != nil {
		return err
	}

	runs := ledgerRuns{store: store}
	if _, cerr := mcp.ConfigureRegisterAgent(mcp.RegisterAgentConfig{
		Identities: admin, Ledger: store, Idempotency: idem, ParentID: o.parentID,
	}); cerr != nil {
		return fmt.Errorf("ConfigureRegisterAgent: %w", cerr)
	}
	if cerr := mcp.ConfigureGetCredential(mcp.CredentialConfig{
		Runs: runs, Entries: admin, Minter: mcp.NewSPIREMinter(mintConn), Ledger: store,
	}); cerr != nil {
		return fmt.Errorf("ConfigureGetCredential: %w", cerr)
	}
	if _, cerr := mcp.ConfigureRecordEvent(mcp.RecordEventConfig{
		Runs: runs, Ledger: store, Idempotency: idem,
	}); cerr != nil {
		return fmt.Errorf("ConfigureRecordEvent: %w", cerr)
	}
	if _, cerr := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{
		Runs: runs, Entries: admin, Ledger: store,
	}); cerr != nil {
		return fmt.Errorf("ConfigureRetireAgent: %w", cerr)
	}

	srv, err := mcp.New(mcp.Config{Version: "v0.0.0-crashd"})
	if err != nil {
		return fmt.Errorf("mcp.New: %w", err)
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if aerr := announce(o.addrFile, ln.Addr().String()); aerr != nil {
		return aerr
	}

	http := &http.Server{
		Handler: srv.Handler(),
		// IP §6.3 forbids indefinite hangs. These bound the transport; nothing
		// here bounds a tool call, which carries the caller's own context.
		ReadHeaderTimeout: 10 * time.Second,
	}
	return http.Serve(ln)
}

// announce publishes the bound address by rename, so a harness that reads the
// file either sees nothing or sees a complete address — never a half-written
// one.
func announce(path, addr string) error {
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, []byte(addr), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, filepath.Base(path), err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The admin credential, from files.
// ---------------------------------------------------------------------------

type fileSource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s fileSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func (s fileSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

func loadSource(o options) (fileSource, error) {
	svid, err := x509svid.Load(o.svidPEM, o.keyPEM)
	if err != nil {
		return fileSource{}, fmt.Errorf("load the admin SVID: %w", err)
	}
	td, err := spiffeid.TrustDomainFromString(o.trustDomain)
	if err != nil {
		return fileSource{}, fmt.Errorf("trust domain %q: %w", o.trustDomain, err)
	}
	raw, err := os.ReadFile(o.bundlePEM)
	if err != nil {
		return fileSource{}, fmt.Errorf("read the trust bundle: %w", err)
	}
	roots, err := parseCerts(raw)
	if err != nil {
		return fileSource{}, fmt.Errorf("parse the trust bundle: %w", err)
	}
	return fileSource{svid: svid, bundle: x509bundle.FromX509Authorities(td, roots)}, nil
}

func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			if len(out) == 0 {
				return nil, errors.New("no PEM certificate found")
			}
			return out, nil
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
}

// dialMint opens the second gRPC connection get_credential's minter needs.
//
// *spire.Client keeps its own connection unexported and offers no accessor, so
// a caller that needs the SVID API dials its own — which is what
// internal/mcp/get_credential_test.go's credStack.adminConn does, with the same
// credential and the same server authorization.
func dialMint(o options, source fileSource) (grpc.ClientConnInterface, error) {
	want := o.serverID
	if want == "" {
		want = "spiffe://" + o.trustDomain + "/spire/server"
	}
	serverID, err := spiffeid.FromString(want)
	if err != nil {
		return nil, fmt.Errorf("server id %q: %w", want, err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(o.spireAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("dial %s for MintJWTSVID: %w", o.spireAddr, err)
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// The run directory, over the real chain.
// ---------------------------------------------------------------------------

type ledgerRuns struct{ store *ledger.Store }

func (d ledgerRuns) CredentialRun(ctx context.Context, runID string) (mcp.CredentialRun, bool, error) {
	head, err := d.store.Head(ctx)
	if err != nil {
		return mcp.CredentialRun{}, false, err
	}
	if head.IsEmpty() {
		return mcp.CredentialRun{}, false, nil
	}
	records, err := d.store.Events(ctx, 1, head.Position)
	if err != nil {
		return mcp.CredentialRun{}, false, err
	}

	var (
		run   mcp.CredentialRun
		found bool
	)
	for _, rec := range records {
		if id, ok := rec[event.FieldRunID].(string); !ok || id != runID {
			continue
		}
		kind, isString := rec[event.FieldEventType].(string)
		if !isString {
			return mcp.CredentialRun{}, false, fmt.Errorf("an event for %q carries no event_type", runID)
		}
		switch kind {
		case event.EventTypeRunRegistered:
			spiffeID, isString := rec[event.FieldSpiffeID].(string)
			if !isString {
				return mcp.CredentialRun{}, false,
					fmt.Errorf("run_registered for %q carries no spiffe_id", runID)
			}
			agentType, taskID, ok := splitRunIdentity(spiffeID, runID)
			if !ok {
				return mcp.CredentialRun{}, false,
					fmt.Errorf("run_registered for %q carries the unusable spiffe_id %q", runID, spiffeID)
			}
			run.RunID, run.SPIFFEID, run.AgentType, run.TaskID = runID, spiffeID, agentType, taskID
			found = true
		case event.EventTypeRunRetired:
			raw, ok := rec[event.FieldTS].(string)
			if !ok {
				return mcp.CredentialRun{}, false, fmt.Errorf("run_retired for %q carries no ts", runID)
			}
			ts, perr := event.ParseTimestamp(raw)
			if perr != nil {
				return mcp.CredentialRun{}, false, perr
			}
			// IP §4 requires every later call to be answered with the
			// ORIGINAL instant, so the earliest wins.
			if run.RetiredAt.IsZero() || ts.Time().Before(run.RetiredAt) {
				run.RetiredAt = ts.Time()
			}
		}
	}
	if !found {
		return mcp.CredentialRun{}, false, nil
	}
	return run, true, nil
}

// splitRunIdentity reads {agent-type} and {task-id} out of a run's SPIFFE ID.
// The grammar is doc 01 §1's:
// spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}.
func splitRunIdentity(spiffeID, runID string) (agentType, taskID string, ok bool) {
	_, rest, found := strings.Cut(spiffeID, "/agent/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[2] != runID {
		return "", "", false
	}
	return parts[0], parts[1], true
}

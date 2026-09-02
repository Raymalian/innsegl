// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/spire"
)

// The wiring: every dependency the four tools run on, constructed once, in the
// one order that is load-bearing.
//
// # The order that matters
//
// ADR-0025: "The limit is opt-in at wiring time. `RateLimitRegisterAgent` must
// be called before `ConfigureRegisterAgent` or the tool is unmetered." The
// meter is a wrapper around the tool's LEDGER, so a configuration installed
// before it is wrapped is a `register_agent` that serves every caller at every
// rate, silently — AB-07 recorded as mitigated and not mitigated. Nothing in
// `internal/mcp` can detect the mistake, because both orders type-check and
// both produce a working tool. The only place the mistake can be made is this
// file, and the only place it can be caught is a test that calls the SERVED
// tool until it is refused: test/failure/serve_test.go.
//
// # Two systems, one credential
//
// IP §1 makes this process the only holder of SPIRE server admin credentials.
// It gets that credential in one of two ways and never both:
//
//   - the Workload API (the default, and what a deployment uses). doc 05 §1
//     runs `innsegl-mcp` as an attested container, so "holding the admin
//     credential" means BEING the workload SPIRE attests — there is no file to
//     steal, and a process that cannot attest gets nothing.
//   - three PEM files, named explicitly. This is for the case where the MCP is
//     not yet an attested workload: bootstrapping a trust domain, and MCP-011's
//     crash campaign, which runs this binary on the host beside a containerised
//     SPIRE whose Workload API socket is inside the container. `internal/mcp`'s
//     own get_credential tests and test/failure's harness mint the admin SVID
//     the same way and for the same reason.
//
// The second is a real reduction in assurance and is therefore never a default
// and never implicit: it takes three flags, all or none.

// serveBootTimeout bounds construction. IP §6.3 forbids indefinite hangs, and
// a replica that hangs at start-up is worse than one that exits: an
// orchestrator can restart the second.
const serveBootTimeout = 60 * time.Second

// runningServer is the shipped servedMCP.
type runningServer struct {
	transport *http.Server
	health    *http.Server
	mcpLn     net.Listener
	healthLn  net.Listener

	server          *mcp.Server
	shutdownTimeout time.Duration

	// closers unwind everything opened, in reverse.
	closers []func()
	log     *serveLog
}

func (s *runningServer) Addr() string       { return s.mcpLn.Addr().String() }
func (s *runningServer) HealthAddr() string { return s.healthLn.Addr().String() }

func (s *runningServer) BoundTools() []mcp.ToolName   { return s.server.BoundTools() }
func (s *runningServer) MissingTools() []mcp.ToolName { return s.server.MissingTools() }

// Serve runs both listeners until ctx is done or one of them fails, then stops
// the other in an orderly way.
//
// Both are watched rather than only the MCP one. A replica whose health
// listener died would keep serving traffic while its orchestrator lost the
// only signal it has for taking the replica out of rotation, which turns one
// failure into an outage nobody is told about.
func (s *runningServer) Serve(ctx context.Context) error {
	failed := make(chan error, 2)
	serveOne := func(srv *http.Server, ln net.Listener) {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		failed <- err
	}
	go serveOne(s.transport, s.mcpLn)
	go serveOne(s.health, s.healthLn)

	var (
		first    error
		received int
	)
	select {
	case <-ctx.Done():
	case first = <-failed:
		received++
	}

	// The orderly stop. Shutdown stops accepting and waits for calls already
	// in flight; the bound is what keeps a replica from refusing to leave.
	// context.WithoutCancel because ctx is the signal context and is already
	// cancelled by the time we get here on the ordinary path.
	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shutdownTimeout)
	defer cancel()
	if err := s.transport.Shutdown(shutCtx); err != nil {
		s.log.warn("the MCP transport did not drain within the shutdown bound", "err", err)
	}
	if err := s.health.Shutdown(shutCtx); err != nil {
		s.log.warn("the health endpoint did not drain within the shutdown bound", "err", err)
	}

	for ; received < 2; received++ {
		if err := <-failed; err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Close releases everything, in reverse order of construction. It is safe to
// call after Serve and safe to call twice.
func (s *runningServer) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
	s.closers = nil
}

// openServer builds the whole server, or returns the first thing that stopped
// it. Anything already opened is released before returning.
//
// failure. Splitting it would hide the order, which is the one thing this
// function exists to get right (ADR-0025).
//
//nolint:gocyclo // Construction: one dependency per step, each with its own
func openServer(ctx context.Context, o serveOptions, log *serveLog) (servedMCP, error) {
	boot, cancel := context.WithTimeout(ctx, serveBootTimeout)
	defer cancel()

	var closers []func()
	unwind := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func(format string, args ...any) (servedMCP, error) {
		unwind()
		return nil, fmt.Errorf(format, args...)
	}

	// ---- the ledger -------------------------------------------------------
	store, err := ledger.Open(boot, o.dsn)
	if err != nil {
		return fail("open the ledger: %w", err)
	}
	closers = append(closers, store.Close)

	if o.migrate {
		// Opt-in, and off by default. A deployment runs migrations as its own
		// step: with N replicas (doc 05 §2) every one of them would otherwise
		// race to migrate at start-up, and a replica that quietly created an
		// empty schema would serve a chain nobody else is reading.
		if merr := store.Migrate(boot); merr != nil {
			return fail("apply the ledger migrations: %w", merr)
		}
		log.info("ledger migrations applied")
	}

	// The idempotency store shares the chain's database (ADR-0005, ADR-0017)
	// and takes a pool the caller owns. It is a second pool to the same
	// database rather than the ledger's own, because *ledger.Store keeps its
	// pool unexported and a component that closed a pool it did not create
	// would take the ledger down with it.
	pool, err := pgxpool.New(boot, o.dsn)
	if err != nil {
		return fail("open the idempotency pool: %w", err)
	}
	closers = append(closers, pool.Close)

	if perr := enforceChainPrivileges(boot, pool, o, log); perr != nil {
		return fail("%w", perr)
	}

	idem := mcp.NewIdempotencyStore(pool, mcp.WithIdempotencyLease(o.lease))

	// ---- the admin credential and SPIRE -----------------------------------
	//
	// ctx, not boot: the Workload API source runs a stream for the life of the
	// process and rotates the SVID on it.
	source, sourceClose, how, err := openCredentialSource(ctx, o)
	if err != nil {
		return fail("%w", err)
	}
	closers = append(closers, sourceClose)
	log.info("admin credential", "source", how)

	admin, err := spire.Dial(boot, spire.Config{
		Address:     o.spireAddress,
		TrustDomain: o.trustDomain,
		ServerID:    o.serverID,
		Source:      source,
		Timeout:     o.spireTimeout,
	})
	if err != nil {
		return fail("dial the SPIRE admin API at %s: %w", o.spireAddress, err)
	}
	closers = append(closers, func() { _ = admin.Close() })

	mintConn, err := dialSVIDAPI(o, source)
	if err != nil {
		return fail("%w", err)
	}
	closers = append(closers, func() { _ = mintConn.Close() })

	// ---- the run directory ------------------------------------------------
	//
	// The component three of the four tools begin at: run_id to identity, and
	// to the EARLIEST run_retired (ADR-0020 §5). Until it shipped, a
	// deployment could not wire get_credential, record_event or retire_agent
	// at all.
	runs, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		return fail("build the run directory: %w", err)
	}

	// ---- Sigstore --------------------------------------------------------
	//
	// One probe, two consumers: /readyz reports it (ADR-0024) and sign_commit
	// asks it before Phase A, so "Sigstore is reachable" means the same thing
	// to an operator watching readiness and to the tool deciding whether to
	// record an intent it may not be able to fulfil (IP §6.3, §6.5).
	sigstore, err := mcp.NewSigstoreEndpoints(mcp.SigstoreConfig{
		FulcioURL: o.fulcioURL,
		RekorURL:  o.rekorURL,
	})
	if err != nil {
		return fail("configure the Sigstore readiness probe: %w", err)
	}

	// ---- pseudonymous identity (RM-079, #116) -----------------------------
	//
	// ONE pseudonymiser for the process, handed to both register_agent and
	// sign_commit. Two would be a way for the Agent-Task trailer to disagree
	// with the identity's {task_id}, and check 3 — the comparison a stranger
	// settles all three trailers with — is exactly that comparison.
	//
	// The choice is logged either way. A privacy control whose state nobody
	// can see is one nobody can audit, and `literal` in particular is a
	// deliberate decision to put this deployment's ticket references into
	// every Fulcio certificate and every Rekor entry, permanently.
	pseudonyms, err := o.pseudonyms()
	if err != nil {
		return fail("configure identity mode: %w", err)
	}
	switch pseudonyms.Mode() {
	case identity.ModePseudonymous:
		log.info("agent identities are PSEUDONYMOUS: the SPIFFE ID, the Fulcio certificate "+
			"and the Agent-Identity trailer carry keyed pseudonyms of agent_type and "+
			"task_ref. The real values are in the ledger's run_registered row, which is "+
			"the only mapping back (RM-079)",
			"mode", string(pseudonyms.Mode()))
	default:
		log.warn("agent identities are LITERAL: every agent_type and task_ref goes into the " +
			"SPIFFE ID, so into the Fulcio certificate, so into the Rekor entry — a " +
			"PERMANENT PUBLIC RECORD under public Sigstore — and into the Agent-Identity " +
			"trailer of every commit. Set -identity-mode " + string(identity.ModePseudonymous) +
			" with a secret to stop that (RM-079)")
	}

	// ---- the five tools, in the one order that matters --------------------
	registerCfg := mcp.RegisterAgentConfig{
		Identities:  admin,
		Ledger:      store,
		Idempotency: idem,
		ParentID:    o.parentID,
		TTL:         o.runTTL,
		Pseudonyms:  pseudonyms,
	}
	if o.rateCalls > 0 {
		limiter, lerr := mcp.NewRateLimiter(mcp.RateLimit{
			Tool:   mcp.ToolRegisterAgent,
			Calls:  o.rateCalls,
			Window: o.rateWindow,
		})
		if lerr != nil {
			return fail("build the register_agent rate limiter: %w", lerr)
		}
		// ADR-0025: BEFORE ConfigureRegisterAgent. The wrapper goes around the
		// tool's ledger, and a configuration installed unwrapped is served
		// unmetered with nothing anywhere reporting it.
		registerCfg, lerr = mcp.RateLimitRegisterAgent(registerCfg, limiter)
		if lerr != nil {
			return fail("meter register_agent: %w", lerr)
		}
		log.info("register_agent is metered per caller (AB-07, ADR-0025)",
			"calls", o.rateCalls, "window", o.rateWindow)
	} else {
		// Never silent. ADR-0025's failure mode is a deployment that believes
		// AB-07 is controlled and is not, so turning the control OFF is an
		// operator decision that appears in the log every time the process
		// starts.
		log.warn("register_agent is UNMETERED: -register-rate-calls is 0, so one caller can " +
			"register runs without limit (AB-07 is not controlled in this deployment)")
	}

	restoreRegister, err := mcp.ConfigureRegisterAgent(registerCfg)
	if err != nil {
		return fail("configure register_agent: %w", err)
	}
	closers = append(closers, restoreRegister)

	if cerr := mcp.ConfigureGetCredential(mcp.CredentialConfig{
		Runs:    runs,
		Entries: admin,
		Minter:  mcp.NewSPIREMinter(mintConn),
		Ledger:  store,
	}); cerr != nil {
		return fail("configure get_credential: %w", cerr)
	}

	restoreRecord, err := mcp.ConfigureRecordEvent(mcp.RecordEventConfig{
		Runs: runs, Ledger: store, Idempotency: idem,
	})
	if err != nil {
		return fail("configure record_event: %w", err)
	}
	closers = append(closers, restoreRecord)

	restoreRetire, err := mcp.ConfigureRetireAgent(mcp.RetireAgentConfig{
		Runs: runs, Entries: admin, Ledger: store,
	})
	if err != nil {
		return fail("configure retire_agent: %w", err)
	}
	closers = append(closers, restoreRetire)

	// sign_commit (RM-033, #41). Opt-in, and never silent either way.
	//
	// The tool is BOUND unconditionally — it is one of IP §4's five and
	// `mcp.New` runs its binder — but it is CONFIGURED only when -workspace
	// names a root. Two reasons, both about failing at the right moment.
	// `signing.NewSigner` resolves `gitsign` and `git` with exec.LookPath at
	// construction, so a deployment without gitsign installed would otherwise
	// fail to start for a tool it may not intend to serve; and there is no
	// defensible default working-tree root, so a guessed one would be a path
	// traversal waiting to be configured. Unconfigured, the tool refuses every
	// call with INVARIANT_VIOLATION and says so — which is the ADR-0025 shape:
	// turning a control off is an operator decision that appears in the log
	// every time the process starts.
	if o.workspace != "" {
		restoreSign, serr := configureSignCommit(o, runs, store, idem, sigstore, pseudonyms, log)
		if serr != nil {
			return fail("configure sign_commit: %w", serr)
		}
		closers = append(closers, restoreSign)
	} else {
		log.warn("sign_commit is NOT CONFIGURED: -workspace (or $" + envWorkspace + ") is " +
			"unset, so the tool is advertised and refuses every call. No commit can be " +
			"signed by this replica.")
	}

	// ---- the transport ----------------------------------------------------
	server, err := mcp.New(mcp.Config{
		Logger:         log.logger,
		TrustedOrigins: o.trustedOrigins,
		SessionTimeout: o.sessionTimeout,
	})
	if err != nil {
		return fail("build the MCP server: %w", err)
	}

	// ---- health -----------------------------------------------------------
	health, err := mcp.NewHealth(mcp.HealthConfig{
		Identities:     admin,
		Ledger:         store,
		Sigstore:       sigstore,
		Tools:          server,
		Timeout:        o.healthTimeout,
		ClockSkewBound: o.clockSkewBound,
		Logger:         log.logger,
	})
	if err != nil {
		return fail("build the health endpoints: %w", err)
	}

	// ---- listeners --------------------------------------------------------
	var lc net.ListenConfig
	mcpLn, err := lc.Listen(boot, "tcp", o.listen)
	if err != nil {
		return fail("listen on %s: %w", o.listen, err)
	}
	closers = append(closers, func() { _ = mcpLn.Close() })

	healthLn, err := lc.Listen(boot, "tcp", o.healthListen)
	if err != nil {
		return fail("listen on %s for %s and %s: %w",
			o.healthListen, mcp.LivePath, mcp.ReadyPath, err)
	}
	closers = append(closers, func() { _ = healthLn.Close() })

	return &runningServer{
		transport: &http.Server{
			Handler: server.Handler(),
			// IP §6.3 forbids indefinite hangs. These bound the TRANSPORT;
			// nothing here bounds a tool call, which carries the caller's own
			// context — a write timeout would cut a legitimately slow SPIRE
			// round trip and report it as something it is not.
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          nil,
		},
		health: &http.Server{
			Handler:           health.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		},
		mcpLn:           mcpLn,
		healthLn:        healthLn,
		server:          server,
		shutdownTimeout: o.shutdownTimeout,
		closers:         closers,
		log:             log,
	}, nil
}

// configureSignCommit installs the fifth tool.
//
// The author policy is built ONCE and handed to the signer factory; the
// factory is what `mcp.ConfigureSignCommit` asks whether the configured author
// is admitted, so there is exactly one statement of I6 in this process and a
// deployment whose policy does not admit its own author refuses to start
// rather than leaving a dangling `commit_intent` on its first signature.
func configureSignCommit(
	o serveOptions,
	runs *rundir.Directory,
	store *ledger.Store,
	idem *mcp.IdempotencyStore,
	sigstore *mcp.SigstoreEndpoints,
	pseudonyms *identity.Pseudonymiser,
	log *serveLog,
) (func(), error) {
	workspace, err := mcp.NewWorkspace(o.workspace)
	if err != nil {
		return nil, err
	}
	author := signing.AuthorPolicy{
		Operators:     o.signAuthorOperators,
		AllowUnlinked: o.signAllowUnlinked,
	}
	signers := mcp.NewGitsignSigners(signing.Config{
		FulcioURL:   o.fulcioURL,
		RekorURL:    o.rekorURL,
		Issuer:      o.oidcIssuer,
		GitsignPath: o.gitsignPath,
		Author:      author,
	})
	restore, err := mcp.ConfigureSignCommit(mcp.SignCommitConfig{
		Runs:        runs,
		Ledger:      store,
		Idempotency: idem,
		Workspace:   workspace,
		Sigstore:    sigstore,
		// The shipped tool, not a second route to SPIRE: one audience
		// allowlist, one retirement check, one `credential_issued` append (I3).
		Credentials: mcp.SignCommitThroughGetCredential{},
		Signers:     signers,
		AuthorName:  o.signAuthorName,
		AuthorEmail: o.signAuthorEmail,
		// The SAME pseudonymiser register_agent holds. See above.
		Pseudonyms: pseudonyms,
	})
	if err != nil {
		return nil, err
	}
	log.info("sign_commit is configured",
		"workspace", o.workspace,
		"issuer", o.oidcIssuer,
		"author", o.signAuthorEmail,
		"author_operators", len(o.signAuthorOperators),
		"author_allow_unlinked", o.signAllowUnlinked)
	return restore, nil
}

// ---------------------------------------------------------------------------
// Least privilege on the database role (doc 05 §1).
// ---------------------------------------------------------------------------

// chainPrivileges is what the role this process connected as may do to the
// chain.
type chainPrivileges struct {
	role                                      string
	canInsert, canUpdate, canDelete, canTrunc bool
}

// appendOnly reports whether the role can add to the chain and not unmake it.
func (p chainPrivileges) appendOnly() bool {
	return p.canInsert && !p.canUpdate && !p.canDelete && !p.canTrunc
}

func (p chainPrivileges) granted() []string {
	var out []string
	for _, g := range []struct {
		name string
		has  bool
	}{
		{"INSERT", p.canInsert}, {"UPDATE", p.canUpdate},
		{"DELETE", p.canDelete}, {"TRUNCATE", p.canTrunc},
	} {
		if g.has {
			out = append(out, g.name)
		}
	}
	return out
}

// probeChainPrivileges asks Postgres what this process's own role may do.
//
// It asks the database rather than trusting the deployment manifest, because
// the manifest is not what enforces it. `migrations/0001_ledger.sql` revokes
// UPDATE, DELETE and TRUNCATE from PUBLIC and the append-only trigger refuses
// them anyway — but a trigger can be disabled by a superuser and the table
// owner is not bound by a revoke, so "the MCP runs as a role that cannot
// delete" is a claim about the ROLE and is measured here.
func probeChainPrivileges(ctx context.Context, pool *pgxpool.Pool) (chainPrivileges, error) {
	var p chainPrivileges
	err := pool.QueryRow(ctx, `
		SELECT current_user,
		       has_table_privilege('innsegl.events', 'INSERT'),
		       has_table_privilege('innsegl.events', 'UPDATE'),
		       has_table_privilege('innsegl.events', 'DELETE'),
		       has_table_privilege('innsegl.events', 'TRUNCATE')`).
		Scan(&p.role, &p.canInsert, &p.canUpdate, &p.canDelete, &p.canTrunc)
	if err != nil {
		return chainPrivileges{}, fmt.Errorf(
			"read this process's own privileges on innsegl.events: %w", err)
	}
	return p, nil
}

// enforceChainPrivileges measures the role and decides what to do about it.
//
// A role that cannot INSERT is always fatal: every tool but get_credential
// appends, I3 admits no action without a record, and a server that could not
// write would fail every call with LEDGER_UNAVAILABLE while looking healthy.
//
// A role that CAN delete is a doc 05 §1 finding rather than an outage — the
// server works, the guarantee is weaker than the topology says — so it is
// reported loudly and, when -require-append-only-role is set, refused. The
// default is to report rather than to refuse because the compose stack does
// not yet create the role (it ships with RM-030), and a start-up refusal on a
// condition that is a configuration defect would take a deployment down for
// something no outage caused. A deployment that has the role sets the flag and
// gets the refusal.
func enforceChainPrivileges(ctx context.Context, pool *pgxpool.Pool, o serveOptions, log *serveLog) error {
	p, err := probeChainPrivileges(ctx, pool)
	if err != nil {
		return err
	}

	if !p.canInsert {
		return fmt.Errorf(
			"the database role %q cannot INSERT into innsegl.events: every tool that acts "+
				"appends first (I3), so this replica could not serve one call", p.role)
	}
	if p.appendOnly() {
		log.info("database role is append-only on the chain (doc 05 §1)",
			"role", p.role, "granted", p.granted())
		return nil
	}

	detail := fmt.Sprintf(
		"the database role %q holds %v on innsegl.events; doc 05 §1 runs the MCP under a role "+
			"that can append and not delete. The append-only trigger still refuses these "+
			"statements (I4), but a trigger is disableable by a superuser and a revoke does not "+
			"bind the table owner, so this deployment is one psql prompt weaker than the "+
			"topology says", p.role, p.granted())
	if o.requireRole {
		return errors.New(detail + " (-require-append-only-role is set)")
	}
	log.warn("DATABASE ROLE IS OVER-PRIVILEGED: " + detail +
		". Set -require-append-only-role (or $" + envRequireAppendOnlyRole +
		") to refuse to start instead of warning.")
	return nil
}

// ---------------------------------------------------------------------------
// The admin credential.
// ---------------------------------------------------------------------------

// openCredentialSource returns the SVID source, a closer, and a word for the
// log naming which of the two it is.
func openCredentialSource(ctx context.Context, o serveOptions) (spire.Source, func(), string, error) {
	if o.svidFile == "" {
		source, err := workloadapi.NewX509Source(ctx,
			workloadapi.WithClientOptions(workloadapi.WithAddr(o.workloadAPI)))
		if err != nil {
			return nil, nil, "", fmt.Errorf(
				"no SVID from the Workload API at %s: the MCP is an attested workload and "+
					"without an identity it holds no SPIRE admin (IP §1, doc 05 §1): %w",
				o.workloadAPI, err)
		}
		return source, func() { _ = source.Close() }, "workload-api:" + o.workloadAPI, nil
	}

	source, err := loadFileSource(o)
	if err != nil {
		return nil, nil, "", err
	}
	return source, func() {}, "files:" + o.svidFile, nil
}

// fileSource is an admin credential held as PEM files. It does not rotate:
// when the SVID expires this process stops being able to reach SPIRE, which is
// one more reason it is not what a deployment uses.
type fileSource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s fileSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }

func (s fileSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

func loadFileSource(o serveOptions) (fileSource, error) {
	svid, err := x509svid.Load(o.svidFile, o.keyFile)
	if err != nil {
		return fileSource{}, fmt.Errorf("load the admin SVID from %s: %w", o.svidFile, err)
	}
	td, err := spiffeid.TrustDomainFromString(o.trustDomain)
	if err != nil {
		return fileSource{}, fmt.Errorf("trust domain %q: %w", o.trustDomain, err)
	}
	raw, err := os.ReadFile(o.bundleFile)
	if err != nil {
		return fileSource{}, fmt.Errorf("read the trust bundle %s: %w", o.bundleFile, err)
	}
	roots, err := parsePEMCertificates(raw)
	if err != nil {
		return fileSource{}, fmt.Errorf("parse the trust bundle %s: %w", o.bundleFile, err)
	}
	return fileSource{svid: svid, bundle: x509bundle.FromX509Authorities(td, roots)}, nil
}

func parsePEMCertificates(pemBytes []byte) ([]*x509.Certificate, error) {
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

// dialSVIDAPI opens the connection get_credential's minter needs.
//
// *spire.Client keeps its own connection unexported and offers no accessor, so
// the SVID API is reached over a second connection built from the SAME
// credential and the same server authorization — not a second credential.
// ADR-0011's segmentation and ADR-0012's authorization policy apply to both
// identically, because both present this process's one admin SVID.
func dialSVIDAPI(o serveOptions, source spire.Source) (*grpc.ClientConn, error) {
	want := o.serverID
	if want == "" {
		want = "spiffe://" + o.trustDomain + "/spire/server"
	}
	serverID, err := spiffeid.FromString(want)
	if err != nil {
		return nil, fmt.Errorf("SPIRE server id %q: %w", want, err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(o.spireAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("dial %s for MintJWTSVID: %w", o.spireAddress, err)
	}
	return conn, nil
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/mirror"
)

// `innsegl api` — the dashboard's backend, wired.
//
// doc 05 §1 lists `innsegl-dashboard` as one of the reference stack's twelve
// services — "Read-only UI + BFF proof checks", with the note "No write
// credentials mounted — enforced by giving it a read-only DB role". RM-076
// (#109) shipped the UI half alone, because no `main` in this module
// constructed an `api.Server`: `internal/api` exported `Open`, `OpenConfig`,
// `NewServer` and `NewProver`, served five routes, and had never run outside
// its own tests. Every query-API view in the shipped dashboard therefore
// rendered its own load-failure state, permanently (RM-083, #121).
//
// # This command WIRES. It does not verify, and it does not query.
//
// doc 04 §5.4 treats a divergent verifier as a divergence in what "verified"
// means, and there is one verifier in this repository: `internal/verify`,
// reached through `internal/api`'s `Prover`. Nothing in this file computes,
// adjusts, upgrades or downgrades a verdict, and nothing in it reads the
// ledger — it constructs a `*api.Store`, a `*api.Prover` and an `*api.Server`,
// binds a listener, and runs it. A check written here would be a second
// implementation of something already proved somewhere else.
//
// # The refusal is the reason this command is careful
//
// `api.Open` asks the SERVER what the credential it was handed can do —
// eight write probes, each inside a transaction that is always rolled back,
// each preceded by `SET TRANSACTION READ WRITE` so that what refuses it is the
// GRANT and not a session setting — and returns an error wrapping
// `api.ErrWritable` if the answer is "write". This command does not repeat any
// of that. What it adds is the operator's half: a distinct exit status, and a
// message that names what the credential was allowed to do.
//
// The distinction that makes the probe work is not "did the statement fail?".
// #109 measured it on postgres:16 and internal/api/readonly.go encodes it: the
// append-only role gets SQLSTATE 42501 — the ACL — while the database OWNER
// gets IN001 from the append-only trigger. Both are refused; only one is
// refused BY PRIVILEGE. A gate asking whether the write failed would pass the
// owner, which is the credential the gate exists to catch. So the probe
// classifies by SQLSTATE and anything that is not a privilege refusal counts
// as allowed. API-009 measures both credentials against a real server.
//
// # Unlike `serve`, there is no flag to switch the gate off
//
// `innsegl serve` has `-require-append-only-role` because doc 05 §1's role did
// not exist when the check landed and refusing on a condition no outage caused
// would have taken deployments down. The reader is the other way round:
// `internal/api/store.go` states that "the assertion is not optional and there
// is no flag to skip it", and a query API that would start on a writing
// credential is one whose read-only property is a claim about its source code
// rather than about its deployment (FD §7, doc 06 P6). So this command exposes
// no such flag, and says so in its usage.
//
// # It requires a signed-in session on every route but two (RM-260/RM-261, ADR-0062)
//
// This used to authenticate nobody at all — doc 05 §3's Cloudflare Access
// (RM-062, #70) was the only door, and loopback the only other. ADR-0062
// found that insufficient: loopback answers which MACHINE may open the
// socket, never which PROCESS on it may, and the flight-recorder threat
// model names exactly that gap (A2/A3: an agent, or any other program,
// running as the operator's own user). So every route here now refuses
// without a valid session UNLESS it is on server.go's own
// authAllowedRoutes — health, and the proof route's live three-check path,
// which never touches stored content by construction (proof.go). The
// passkey ceremonies themselves are the one place this binary answers a
// POST; see internal/api/authhandlers.go.

// Exit statuses, continuing cli.go's contract. The canary owns 3 and 4, the
// reaper 5 and 6, the reconciler 7 and 8, the sealer 9 and 10; these are the
// query API's.
//
// Three rather than two, because an operator and an orchestrator act on them
// differently. A restart loop fixes an unreachable Postgres and never fixes a
// GRANT, so the credential refusal is not folded into UNAVAILABLE.
const (
	// exitAPIUnavailable: the API could not start. Bad configuration, an
	// unreachable ledger. Nothing was served. Retrying may help.
	exitAPIUnavailable = 11
	// exitAPIFailed: the API was serving and stopped on an error.
	exitAPIFailed = 12
	// exitAPIWritable: the database credential can write, so this process
	// refused to hold it. Retrying will NEVER help; a human must fix the role.
	exitAPIWritable = 13
)

// Every flag falls back to an environment variable so a compose service can be
// configured entirely by environment and never put a DSN — which carries a
// password — on a command line the process table can read.
//
// $INNSEGL_FULCIO_URL, $INNSEGL_REKOR_URL and $INNSEGL_OIDC_ISSUER are
// `serve`'s and `verify`'s own names, reused rather than respelled: the proof
// BFF runs the same verifier against the same Sigstore a stranger is handed,
// and a second spelling would be a second thing to get out of step.
//
// The DSN is the exception, and deliberately so. `$INNSEGL_LEDGER_DSN` is the
// APPENDING credential every other subcommand takes; this process must not be
// given it, and doc 05 §1 puts the dashboard on its own network with a
// read-only role for exactly that reason. One name for two different roles is
// a deployment that can hand the dashboard the writer by copying a line.
const (
	envAPIDSN     = "INNSEGL_API_DSN"
	envAPIListen  = "INNSEGL_API_LISTEN"
	envAPILogDir  = "INNSEGL_API_LOG_DIR"
	envAPILogDays = "INNSEGL_API_LOG_DAYS"
	// envAPISnapshotDir names the run page's own read: the gateway's own
	// snapshot store (internal/gateway/snapshot.go's own StoreRoot), which
	// this issue's own routes (api.registerRecordRoutes) read commits and
	// diffs out of. Unset defaults to the "gateway-snapshots" subdirectory
	// of $INNSEGL_API_LOG_DIR, which is where the gateway writes it
	// (cmd/innsegl/gateway.go's own newGatewaySnapshotter) — no second mount
	// is needed for the ordinary case, this variable exists for a
	// deployment that has a reason to point it somewhere else.
	envAPISnapshotDir = "INNSEGL_API_SNAPSHOT_DIR"
	// envAPIMessageKeyDir names the operator's own decision on top of E19
	// (#395-#397): where this process reads RM-237's own derived,
	// CHECK-ONLY agent-message key from, by key id
	// (cmd/innsegl/gateway.go's own writeMessageKeyFile writes it on the
	// SAME named volume, mounted read-write there and read-only here).
	// Unset answers every Brief and Reply unavailable — this process never
	// holds the identity secret itself, only this narrower, derived key.
	envAPIMessageKeyDir   = "INNSEGL_API_MESSAGE_KEY_DIR"
	envAPIShutdownTimeout = "INNSEGL_API_SHUTDOWN_TIMEOUT"
	envAPIUpstreamTimeout = "INNSEGL_API_UPSTREAM_TIMEOUT"
	envAPIGit             = "INNSEGL_GIT"

	// RM-260/RM-261 (ADR-0062) — the sign-in surface's own configuration.
	// $INNSEGL_API_AUTH_DSN is envAuthWriterDSN (adminenrolcode.go): the SAME
	// name, because it names the SAME credential — internal/api.AuthWriterRole
	// — whether this process or `admin-credential enrol-code` is the one
	// holding it.
	envAPIRPID            = "INNSEGL_API_RP_ID"
	envAPIRPOrigin        = "INNSEGL_API_RP_ORIGIN"
	envAPISessionLifetime = "INNSEGL_API_SESSION_LIFETIME"

	// envAPIResolverDSN is RM-330's resolver credential (ADR-0044's
	// 2026-10-03 amendment): internal/api.ResolverRole, which may insert an
	// alert resolution and nothing else. Optional.
	envAPIResolverDSN = "INNSEGL_API_RESOLVER_DSN"
	// envAPIGatewayCACert is the gateway's CA certificate, read so the
	// account page's connect command carries its fingerprint. Optional.
	envAPIGatewayCACert = "INNSEGL_API_GATEWAY_CA_CERT"

	// #475: this process serves the dashboard. envAPIUIDir is the built
	// UI; empty serves the API alone. envAPITLSListen and envAPITLSCert
	// are the browser's HTTPS listener and the file the core writes its
	// certificate and key to (RM-311, ADR-0066's amendment); set together
	// or not at all.
	envAPIUIDir     = "INNSEGL_API_UI_DIR"
	envAPITLSListen = "INNSEGL_API_TLS_LISTEN"
	envAPITLSCert   = "INNSEGL_API_TLS_CERT"
)

const (
	// defaultAPIListen is loopback, not 0.0.0.0, for the reason `serve`'s
	// default is: a surface published on every interface by an operator's
	// omission is an exposure this command should not create for them. 8082
	// follows the MCP's 8080 and its health endpoint's 8081.
	defaultAPIListen = "127.0.0.1:8082"

	// defaultAPIUpstreamTimeout bounds one Fulcio or Rekor request made on
	// behalf of a proof. internal/api uses the same value when given no
	// client; it is a flag here because a deployment on a slow link tunes it
	// and a public page must not hang.
	defaultAPIUpstreamTimeout = 15 * time.Second

	// defaultAPIRPID and defaultAPIRPOrigin are ADR-0062's reference
	// address. "localhost", never an IP literal: a WebAuthn RP ID must be a
	// domain, and 127.0.0.1 is not one. This is why defaultAPIListen above
	// stays a loopback IP (it is a BIND address, never typed into a
	// browser) while this pair is what install.sh now prints and what
	// runbooks/orchestrated-run.md now documents as the address to browse.
	defaultAPIRPID     = "localhost"
	defaultAPIRPOrigin = "http://localhost:8082"
)

// apiRoutes is what this process serves, in the order the usage lists them.
// They are internal/api's, spelled here only so the usage can name them: a
// reverse proxy, a Cloudflare Access policy and a dashboard build all need to
// know what paths exist.
var apiRoutes = []string{
	"GET /api/v1/runs",
	"GET /api/v1/runs/{run_id}",
	"GET /api/v1/runs/{run_id}/record",
	"GET /api/v1/runs/{run_id}/steps/{n}/diff",
	"GET /api/v1/overview",
	"GET /api/v1/repos",
	"GET /api/v1/proof/{commit_sha}",
	"GET /api/v1/health",
	// RM-260/RM-261 (ADR-0062): every route above except health and proof
	// now refuses without a session. These five are how one is obtained.
	"POST /api/v1/auth/enrol/begin",
	"POST /api/v1/auth/enrol/finish",
	"POST /api/v1/auth/login/begin",
	"POST /api/v1/auth/login/finish",
	"POST /api/v1/auth/logout",
	"GET /api/v1/auth/session",
	// RM-330 (ADR-0044's 2026-10-03 amendment): resolving alerts after a
	// fresh passkey ceremony. 503 unless -resolver-dsn is set.
	"POST /api/v1/alert-resolutions/begin",
	"POST /api/v1/alert-resolutions/finish",
}

// apiOptions is the resolved command line.
type apiOptions struct {
	dsn    string
	listen string
	// mirrorDir is the core's per-repository mirror (ADR-0065), read-only:
	// the only place the proof BFF and the run page read a repository from.
	mirrorDir string
	fulcioURL string
	rekorURL  string
	issuer    string
	gitPath   string
	// logDir is the harness's local tool-call bodies, read-only. Empty means
	// this deployment keeps none, which is a valid answer and not a fault.
	logDir  string
	logDays int
	// snapshotDir is the gateway's own workspace-snapshot store, read-only.
	// Empty means the run page's steps and diffs carry no tree data — see
	// envAPISnapshotDir.
	snapshotDir string
	// messageKeyDir is RM-237's own derived agent-message key directory,
	// read-only. Empty means the run page's Brief and Replies stay
	// unavailable — see envAPIMessageKeyDir.
	messageKeyDir string

	shutdownTimeout time.Duration
	upstreamTimeout time.Duration

	// authDSN is the AUTH-WRITER credential (internal/api.AuthWriterRole) —
	// never $INNSEGL_API_DSN (the reader) and never $INNSEGL_LEDGER_DSN (the
	// appender). RM-260/RM-261, ADR-0062.
	authDSN         string
	rpID            string
	rpOrigin        string
	sessionLifetime time.Duration

	// resolverDSN is the RESOLVER credential (internal/api.ResolverRole).
	// Empty: the dashboard cannot resolve alerts, and says so.
	resolverDSN string

	// gatewayCACert is the gateway's CA certificate file. Empty: the
	// account page's connect command shows a placeholder for it.
	gatewayCACert string

	// trustHistory is the deployment's trust history (ADR-0073), read on
	// every proof. Empty: the published root and log key only.
	trustHistory string

	// uiDir is the built dashboard UI (#475). Empty: the API alone.
	uiDir string
	// tlsListen and tlsCert are the dashboard's HTTPS listener and the
	// file holding its certificate and key. Both or neither.
	tlsListen string
	tlsCert   string
}

// servedAPI is the running query API, as this command needs it. It is an
// interface so the command's own behaviour — the flags, the exit statuses, the
// refusal, the lifecycle — is testable without a Postgres; openAPI is the
// production implementation and API-009/010/011 are what prove it.
type servedAPI interface {
	// Addr is the bound HTTP address, after listening.
	Addr() string
	// ReadOnly is the evidence api.Open gathered from the server itself.
	ReadOnly() api.ReadOnlyReport
	// Repos names the repositories the core's mirror held at start-up.
	Repos() []string
	// Serve runs until ctx is done or the listener fails.
	Serve(ctx context.Context) error
	// Close releases the pool and the listener.
	Close()
}

// apiDeps are the seams this command's tests replace. Production wiring is the
// zero value.
type apiDeps struct {
	open func(context.Context, apiOptions, *serveLog) (servedAPI, error)
}

func (d apiDeps) opener() func(context.Context, apiOptions, *serveLog) (servedAPI, error) {
	if d.open != nil {
		return d.open
	}
	return openAPI
}

// apiCommand is the subcommand body wired into cli.go's dispatch table.
func apiCommand(args []string, stdout, stderr io.Writer) int {
	// SIGINT and SIGTERM stop the server. Nothing served here is a write, so a
	// process killed mid-request loses a response and nothing else.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAPI(ctx, args, stdout, stderr, apiDeps{})
}

// runAPICommand is the entry point for tests that do not drive the lifecycle.
func runAPICommand(args []string, stdout, stderr io.Writer, deps apiDeps) int {
	return runAPI(context.Background(), args, stdout, stderr, deps)
}

// runAPI is the whole command: parse, refuse, open, serve.
func runAPI(ctx context.Context, args []string, stdout, stderr io.Writer, deps apiDeps) int {
	o, code, ok := parseAPIFlags(args, stderr)
	if !ok {
		return code
	}

	log := newServeLog(stderr)

	srv, err := deps.opener()(ctx, o, log)
	if err != nil {
		return reportAPIStartFailure(err, log, stderr)
	}
	if srv == nil {
		log.error("the query API did not start", "err", errNoServedAPI)
		fprintf(stderr, "innsegl api: UNAVAILABLE - nothing is being served\n")
		return exitAPIUnavailable
	}
	defer srv.Close()

	// The bound address on STDOUT, one line, nothing else — `serve`'s
	// contract, so that `innsegl api -listen 127.0.0.1:0` is usable from a
	// script without parsing the structured log on stderr.
	fprintf(stdout, "%s\n", srv.Addr())

	reportReadOnly(log, srv.ReadOnly())
	log.info("serving the read-only query API",
		"addr", srv.Addr(),
		"routes", strings.Join(apiRoutes, " "),
		"repos", strings.Join(srv.Repos(), ","),
		"authentication", "passkey session required on every route except "+
			"health and proof (ADR-0062, RM-260/RM-261)",
		"webauthn_rp_id", o.rpID,
		"webauthn_rp_origin", o.rpOrigin,
	)

	if serr := srv.Serve(ctx); serr != nil {
		log.error("the query API stopped serving", "err", serr)
		return exitAPIFailed
	}
	log.info("stopped")
	return exitOK
}

// errNoServedAPI is the opener returning neither a server nor an error. It
// cannot happen in production — openAPI returns one or the other — and it is a
// named error rather than a panic so that a seam misused by a future test
// fails the way a bad configuration does.
var errNoServedAPI = errors.New("the opener returned no server and no error")

// reportAPIStartFailure separates the two ways a start-up can fail. See the
// exit statuses above: one of them is a human's to fix and no restart helps.
func reportAPIStartFailure(err error, log *serveLog, stderr io.Writer) int {
	if errors.Is(err, api.ErrWritable) {
		log.error("REFUSED: the database credential can write", "err", err)
		fprintf(stderr, "innsegl api: WRITABLE - %v\n", err)
		fprintf(stderr, "innsegl api: this is not a transient failure and restarting will "+
			"not clear it. doc 05 §1 mounts no write credentials on the dashboard; "+
			"provision the read-only role (api.EnsureReadOnlyRole, "+
			"internal/api/readonly.sql) and point -dsn (or $"+envAPIDSN+") at it.\n")
		return exitAPIWritable
	}
	log.error("the query API did not start", "err", err)
	fprintf(stderr, "innsegl api: UNAVAILABLE - nothing is being served\n")
	return exitAPIUnavailable
}

// reportReadOnly writes the evidence the credential was admitted on.
//
// It is logged rather than assumed because doc 05 §1's "no write credentials
// mounted" is a claim about a deployment, and the probes are the only thing
// that turns it into a measurement an operator can read back. The same report
// is served on GET /api/v1/health, so the two agree by construction.
func reportReadOnly(log *serveLog, r api.ReadOnlyReport) {
	log.info("database credential is read-only, as measured on the server",
		"role", r.Role,
		"superuser", r.Superuser,
		"default_transaction_read_only", r.DefaultTransactionReadOnly,
		"writes_refused", len(r.Probes),
		"reported_at", "GET /api/v1/health",
	)
}

// parseAPIFlags resolves the command line and the environment behind it.
func parseAPIFlags(args []string, stderr io.Writer) (apiOptions, int, bool) {
	fs := flag.NewFlagSet("innsegl api", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dsn = fs.String("dsn", os.Getenv(envAPIDSN),
			"READ-ONLY ledger connection string — prefer the environment variable. This is "+
				"NOT $"+envLedgerDSN+", which is the appending credential; a credential this "+
				"probe finds capable of writing is refused ($"+envAPIDSN+")")
		listen = fs.String("listen", envOr(envAPIListen, defaultAPIListen),
			"address the query API listens on ($"+envAPIListen+")")
		logDir = fs.String("log-dir", envOr(envAPILogDir, ""),
			"directory of harness-written tool-call bodies, one directory per run, "+
				"read-only; empty serves no bodies ($"+envAPILogDir+")")
		logDays = fs.Int("log-retention-days", envIntOr(envAPILogDays, 90),
			"how long the harness keeps those bodies, reported so a reader can tell an "+
				"expired body from one that never existed ($"+envAPILogDays+")")
		snapshotDir = fs.String("snapshot-dir", os.Getenv(envAPISnapshotDir),
			"the gateway's own workspace-snapshot store, read-only; empty defaults to "+
				"\"gateway-snapshots\" under -log-dir (where the gateway writes it) when -log-dir "+
				"is set, and serves no snapshot data otherwise ($"+envAPISnapshotDir+")")
		messageKeyDir = fs.String("message-key-dir", os.Getenv(envAPIMessageKeyDir),
			"RM-237's own derived, CHECK-ONLY agent-message key, by key id, read-only; empty "+
				"answers every run page Brief and Reply unavailable — this process never holds "+
				"the identity secret itself, only this narrower, derived key "+
				"($"+envAPIMessageKeyDir+")")
		mirrorDir = fs.String("mirror-dir", os.Getenv(mirror.EnvDir),
			"the core's per-repository mirror, read-only: the only place repositories are read "+
				"from (ADR-0065). A repository or commit it does not hold yet is a 404 that says "+
				"so, never an empty verdict ($"+mirror.EnvDir+")")
		fulcioURL = fs.String("fulcio-url", os.Getenv(envFulcioURL),
			"base URL of the certificate authority the proof route checks against ($"+envFulcioURL+")")
		rekorURL = fs.String("rekor-url", os.Getenv(envRekorURL),
			"base URL of the transparency log the proof route checks against ($"+envRekorURL+")")
		issuer = fs.String("issuer", os.Getenv(envIssuer),
			"the OIDC issuer a certificate must name; empty reports it and does not "+
				"constrain it ($"+envIssuer+")")
		gitPath = fs.String("git", os.Getenv(envAPIGit),
			"the git binary the BFF reads commit objects with. Empty is a PATH lookup ($"+envAPIGit+")")
		shutdownTimeout = fs.Duration("shutdown-timeout",
			envDuration(envAPIShutdownTimeout, defaultShutdownTimeout),
			"bound on the orderly shutdown after SIGINT or SIGTERM ($"+envAPIShutdownTimeout+")")
		upstreamTimeout = fs.Duration("upstream-timeout",
			envDuration(envAPIUpstreamTimeout, defaultAPIUpstreamTimeout),
			"bound on one Fulcio or Rekor request made for a proof ($"+envAPIUpstreamTimeout+")")
		authDSN = fs.String("auth-dsn", os.Getenv(envAuthWriterDSN),
			"the AUTH-WRITER connection string ($"+envAuthWriterDSN+") — internal/api.AuthWriterRole. "+
				"Required: without it this process cannot check a session for a single route, and "+
				"NewServer refuses to construct at all (ADR-0062)")
		rpID = fs.String("rp-id", envOr(envAPIRPID, defaultAPIRPID),
			"the WebAuthn relying-party ID — a DOMAIN, never an IP literal ($"+envAPIRPID+")")
		rpOrigin = fs.String("rp-origin", envOr(envAPIRPOrigin, defaultAPIRPOrigin),
			"the exact origin the dashboard is served from; a request whose Origin header "+
				"names anything else is refused ($"+envAPIRPOrigin+")")
		gatewayCACert = fs.String("gateway-ca-cert", os.Getenv(envAPIGatewayCACert),
			"the gateway's CA certificate ($"+envAPIGatewayCACert+"), whose fingerprint the account "+
				"page's connect command pins. Optional")
		trustHistory = fs.String("trust-history", os.Getenv(envTrustHistory),
			"the deployment's trust history ($"+envTrustHistory+"): every Fulcio root and log key "+
				"it has used (ADR-0073), read on every proof. Optional")
		resolverDSN = fs.String("resolver-dsn", os.Getenv(envAPIResolverDSN),
			"the RESOLVER connection string ($"+envAPIResolverDSN+") — internal/api.ResolverRole, "+
				"which may insert an alert resolution and nothing else. Optional: without it the "+
				"dashboard cannot resolve alerts")
		sessionLifetime = fs.Duration("session-lifetime", envDuration(envAPISessionLifetime, 0),
			"how long a session lasts before it must be renewed by signing in again; zero "+
				"applies internal/api's own default ($"+envAPISessionLifetime+")")
		uiDir = fs.String("ui-dir", os.Getenv(envAPIUIDir),
			"the built dashboard UI, served next to the API on the same origin; every path "+
				"outside /api/ that is not a file is its index.html. Empty serves the API alone "+
				"($"+envAPIUIDir+")")
		tlsListen = fs.String("tls-listen", os.Getenv(envAPITLSListen),
			"address the dashboard is served on over HTTPS, in addition to -listen; needs "+
				"-tls-cert ($"+envAPITLSListen+")")
		tlsCert = fs.String("tls-cert", os.Getenv(envAPITLSCert),
			"one PEM file holding the dashboard's certificate chain and key, as the core writes "+
				"it; re-read when it changes, so a renewal needs no restart. Needs -tls-listen "+
				"($"+envAPITLSCert+")")
	)

	fs.Usage = func() { apiUsage(stderr, fs) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return apiOptions{}, exitOK, false
		}
		return apiOptions{}, exitUsage, false
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl api: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return apiOptions{}, exitUsage, false
	}

	o := apiOptions{
		dsn: *dsn, listen: *listen, mirrorDir: *mirrorDir,
		fulcioURL: *fulcioURL, rekorURL: *rekorURL, issuer: *issuer, gitPath: *gitPath,
		shutdownTimeout: *shutdownTimeout, upstreamTimeout: *upstreamTimeout,
		logDir: *logDir, logDays: *logDays,
		snapshotDir:   resolveSnapshotDir(*snapshotDir, *logDir),
		messageKeyDir: *messageKeyDir,
		authDSN:       *authDSN, rpID: *rpID, rpOrigin: *rpOrigin, sessionLifetime: *sessionLifetime,
		resolverDSN:   *resolverDSN,
		gatewayCACert: *gatewayCACert,
		trustHistory:  *trustHistory,
		uiDir:         *uiDir, tlsListen: *tlsListen, tlsCert: *tlsCert,
	}
	if problem := o.validate(); problem != "" {
		fprintf(stderr, "innsegl api: %s\n", problem)
		return apiOptions{}, exitUsage, false
	}
	return o, exitOK, true
}

// validate reports the first setting that makes this configuration unusable,
// naming the flag and its environment variable. An operator has to be told
// WHICH one; "the dashboard has no backend" is not actionable.
func (o apiOptions) validate() string {
	switch {
	case o.dsn == "":
		return "-dsn (or $" + envAPIDSN + ") is required: it is the READ-ONLY credential " +
			"doc 05 §1 mounts on the dashboard, and it is not $" + envLedgerDSN
	case o.mirrorDir == "":
		return "-mirror-dir (or $" + mirror.EnvDir + ") is required: the proof BFF reads " +
			"repositories only from the core's mirror (ADR-0065), and guessing another " +
			"place is not one of the states doc 06 §4.6 allows"
	case o.fulcioURL == "":
		return "-fulcio-url (or $" + envFulcioURL + ") is required: the proof route runs " +
			"the same live checks a stranger would, and there is no default pair to fall " +
			"back to (ADR-0010)"
	case o.rekorURL == "":
		return "-rekor-url (or $" + envRekorURL + ") is required: the proof route runs the " +
			"same live checks a stranger would, and there is no default pair to fall back " +
			"to (ADR-0010)"
	case o.listen == "":
		return "-listen (or $" + envAPIListen + ") is required"
	case o.authDSN == "":
		return "-auth-dsn (or $" + envAuthWriterDSN + ") is required: it is the AUTH-WRITER " +
			"credential RM-260/RM-261 gate every other route on, and without it this process " +
			"cannot check a session for a single one (ADR-0062)"
	case o.rpID == "":
		return "-rp-id (or $" + envAPIRPID + ") is required"
	case o.rpOrigin == "":
		return "-rp-origin (or $" + envAPIRPOrigin + ") is required"
	case o.tlsListen != "" && o.tlsCert == "":
		return "-tls-listen (or $" + envAPITLSListen + ") needs -tls-cert (or $" + envAPITLSCert +
			"): an HTTPS listener with no certificate refuses every browser"
	case o.tlsCert != "" && o.tlsListen == "":
		return "-tls-cert (or $" + envAPITLSCert + ") needs -tls-listen (or $" + envAPITLSListen +
			"): a certificate with no listener serves nothing, and the dashboard would stay on plain HTTP"
	case o.sessionLifetime < 0:
		return "-session-lifetime is negative"
	case o.shutdownTimeout < 0:
		return "-shutdown-timeout is negative"
	case o.upstreamTimeout < 0:
		return "-upstream-timeout is negative"
	}
	return ""
}

// resolveSnapshotDir answers -snapshot-dir (or $INNSEGL_API_SNAPSHOT_DIR)
// when one was given, and otherwise the "gateway-snapshots" subdirectory of
// logDir — the SAME path cmd/innsegl/gateway.go's own newGatewaySnapshotter
// writes the store under, so a deployment that has not been told to point
// this anywhere else still finds it without a second mount or a second
// variable. Empty when logDir is also empty: a deployment keeping no
// bodies keeps no snapshots either, and that is a valid answer.
func resolveSnapshotDir(explicit, logDir string) string {
	if explicit != "" {
		return explicit
	}
	if logDir == "" {
		return ""
	}
	return filepath.Join(logDir, "gateway-snapshots")
}

// apiUsage is the help block. It states the things a reader of a compose
// file cannot infer from the flags: which routes need no session, that the
// RP ID must be a domain, and that the read-only gate cannot be switched off.
func apiUsage(stderr io.Writer, fs *flag.FlagSet) {
	fprintf(stderr, "innsegl api - serve the dashboard, its read-only query API and proof BFF "+
		"(doc 05 §1, doc 06 §7)\n\n")
	fprintf(stderr, "Usage:\n  innsegl api [flags]\n\n")
	fprintf(stderr, "Routes:\n")
	for _, route := range apiRoutes {
		fprintf(stderr, "  %s\n", route)
	}
	fprintf(stderr, "\nEVERY ROUTE ABOVE EXCEPT health AND proof REQUIRES A SIGNED-IN SESSION\n"+
		"(RM-260/RM-261, ADR-0062). Passkey (WebAuthn) only, no passwords. -rp-id must be\n"+
		"a DOMAIN — 127.0.0.1 is not a valid RP ID, localhost is — and -rp-origin must be\n"+
		"the exact origin the dashboard is served from; doc 05 §3's Cloudflare Access\n"+
		"(RM-062, #70) remains a second, independent door in front of this one, not a\n"+
		"replacement for it. Do not expose this port to a network you have not also put\n"+
		"an authenticating proxy in front of. The default -listen is loopback for that\n"+
		"reason.\n\n"+
		"The FIRST passkey's enrolment is separately gated by a one-time code only the\n"+
		"operator can mint — see `innsegl admin-credential enrol-code`.\n\n")
	fprintf(stderr, "With -ui-dir it also serves the dashboard's built UI on the same origin, and\n"+
		"with -tls-listen and -tls-cert it serves both over HTTPS too, from the certificate\n"+
		"the core writes (ADR-0066). Every path under /api/ is the API's.\n\n")
	fprintf(stderr, "It refuses to start on a database credential that can write. The check "+
		"asks\nthe SERVER what the credential may do — not the DSN, and not this source\n"+
		"file — and there is no flag that disables it: a query API that would start on\n"+
		"a writing credential has a read-only property that is a claim about its code\n"+
		"rather than about its deployment (doc 06 §7, P6).\n\n")
	fprintf(stderr, "It performs no verification of its own. Every verdict comes from "+
		"internal/verify\nthrough the proof BFF; doc 04 §5.4 treats a second verifier as a "+
		"divergence in\nwhat \"verified\" means.\n\n")
	fprintf(stderr, "Exit status:\n")
	fprintf(stderr, "  %d  the API shut down in an orderly way\n", exitOK)
	fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
	fprintf(stderr, "  %d  UNAVAILABLE - the API could not start; nothing was served\n",
		exitAPIUnavailable)
	fprintf(stderr, "  %d  FAILED - the API was serving and stopped on an error\n", exitAPIFailed)
	fprintf(stderr, "  %d  WRITABLE - the database credential can write, so this process "+
		"refused to hold it; no restart clears this\n", exitAPIWritable)
	fprintf(stderr, "\nFlags:\n")
	fs.PrintDefaults()
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// `innsegl serve` — the MCP server as a process.
//
// IP §1 names this component: "Innsegl MCP server (server name `innsegl`) —
// remote MCP server (HTTP transport), the only component holding SPIRE server
// admin credentials." Four of its five tools were built, tested against a real
// Postgres and a real SPIRE, and until this file nothing constructed the
// dependencies they run on: `internal/mcp` publishes `ConfigureRegisterAgent`,
// `ConfigureGetCredential`, `ConfigureRecordEvent` and `ConfigureRetireAgent`,
// and the only caller in the repository was a throwaway binary built so that
// MCP-011 had something to SIGKILL.
//
// # What this file is responsible for
//
// Configuration, construction, wiring order, the two health endpoints, and the
// lifecycle. Not behaviour: every decision an agent can observe belongs to
// `internal/mcp` and is asserted there. What can only be got wrong HERE is the
// order things are built in, and one order is load-bearing — see servewiring.go.
//
// # Nothing here is load-bearing for correctness under a crash
//
// IP §6.6 removes this process with SIGKILL at arbitrary points and requires
// I1–I6 to hold afterwards without any of the shutdown below having run. That
// is a property of the ledger's append rule, the SPIRE entry's derived id and
// the idempotency store, and it is MCP-011's to prove. The orderly shutdown
// exists for the ORDINARY stop — an orchestrator rolling a replica sends
// SIGTERM and waits — and for nothing else.

// Exit statuses for `innsegl serve`, continuing cli.go's contract. The canary
// owns 3 and 4 and the reaper 5 and 6; these are the server's.
//
// The two are distinguished because an operator acts on them differently.
// "The server never started" is a configuration or a dependency to fix before
// anything can be served at all; "the server stopped serving" is a replica
// that was carrying traffic and is not any more.
const (
	// exitServeUnavailable: the server could not start. Bad configuration, no
	// credential, an unreachable SPIRE or ledger. Nothing was served.
	exitServeUnavailable = 7
	// exitServeFailed: the server was serving and stopped on an error.
	exitServeFailed = 8
)

// Every flag falls back to an environment variable so a container can be
// configured entirely by environment and never put the ledger DSN — which
// carries a password — on a command line the process table can read. RM-011's
// canary set that precedent and the reaper follows it; the four names the
// reaper already defines are reused rather than spelled a second way, because
// two names for one setting is a deployment that can set the wrong one.
const (
	envParentID              = "INNSEGL_SPIRE_PARENT_ID"
	envMCPSVIDFile           = "INNSEGL_MCP_SVID_FILE"
	envMCPKeyFile            = "INNSEGL_MCP_KEY_FILE"
	envMCPBundleFile         = "INNSEGL_MCP_BUNDLE_FILE"
	envFulcioURL             = "INNSEGL_FULCIO_URL"
	envRekorURL              = "INNSEGL_REKOR_URL"
	envMCPListen             = "INNSEGL_MCP_LISTEN"
	envMCPHealthListen       = "INNSEGL_MCP_HEALTH_LISTEN"
	envMCPAddrFile           = "INNSEGL_MCP_ADDR_FILE"
	envRunTTL                = "INNSEGL_RUN_TTL"
	envIdempotencyLease      = "INNSEGL_IDEMPOTENCY_LEASE"
	envRegisterRateCalls     = "INNSEGL_REGISTER_RATE_CALLS"
	envRegisterRateWindow    = "INNSEGL_REGISTER_RATE_WINDOW"
	envClockSkewBound        = "INNSEGL_CLOCK_SKEW_BOUND"
	envTrustedOrigins        = "INNSEGL_TRUSTED_ORIGINS"
	envMCPSessionTimeout     = "INNSEGL_MCP_SESSION_TIMEOUT"
	envMCPShutdownTimeout    = "INNSEGL_MCP_SHUTDOWN_TIMEOUT"
	envHealthTimeout         = "INNSEGL_HEALTH_TIMEOUT"
	envRequireAppendOnlyRole = "INNSEGL_REQUIRE_APPEND_ONLY_ROLE"
	envMigrate               = "INNSEGL_MIGRATE"

	// Pseudonymous identity (RM-079, #116). The secret is a secret: it is read
	// from the environment first for the same reason the ledger DSN is —
	// nothing that grants anything belongs on a command line the process table
	// can read — and the flag exists only so that a one-off invocation can set
	// it without exporting it.
	envIdentityMode   = "INNSEGL_IDENTITY_MODE"
	envIdentitySecret = "INNSEGL_IDENTITY_SECRET" //nolint:gosec // the NAME of the variable, not a secret

	// envIdentitySecretFile names the FILE the secret is in, and exists
	// because a deployment cannot use the variable above (RM-084, #124).
	// Compose can mount a volume and it cannot read one into an environment
	// variable, so a stack that generates its own secret — which is the only
	// way each deployment gets a different one — has nothing to put in
	// $INNSEGL_IDENTITY_SECRET. This is `INNSEGL_MCP_SVID_FILE`'s convention,
	// joined rather than re-invented.
	envIdentitySecretFile = "INNSEGL_IDENTITY_SECRET_FILE" //nolint:gosec // the NAME of the variable, not a secret

	// sign_commit (RM-033, #41). Every one of these is opt-in: the tool is
	// bound unconditionally — it is one of IP §4's five — and is CONFIGURED
	// only when a workspace is named, because a deployment without a gitsign
	// binary and a working-tree root cannot sign and must say so at start-up
	// rather than at an agent's first commit.
	envWorkspace           = "INNSEGL_WORKSPACE"
	envOIDCIssuer          = "INNSEGL_SPIRE_JWT_ISSUER"
	envSignAuthorName      = "INNSEGL_SIGN_AUTHOR_NAME"
	envSignAuthorEmail     = "INNSEGL_SIGN_AUTHOR_EMAIL"
	envSignAuthorOperators = "INNSEGL_SIGN_AUTHOR_OPERATORS"
	envSignAllowUnlinked   = "INNSEGL_SIGN_AUTHOR_ALLOW_UNLINKED"
	envGitsignPath         = "INNSEGL_GITSIGN"
)

// Defaults that are this command's own rather than a package's.
const (
	// defaultMCPListen and defaultHealthListen are loopback, not 0.0.0.0. This
	// process holds SPIRE admin (IP §1), and a default that published it on
	// every interface would make an operator's omission the exposure. A
	// container publishes it deliberately.
	defaultMCPListen    = "127.0.0.1:8080"
	defaultHealthListen = "127.0.0.1:8081"

	// defaultShutdownTimeout bounds the orderly stop. Longer than a tool call
	// and shorter than any orchestrator's default grace period, so a rolled
	// replica finishes its work rather than being SIGKILLed mid-call.
	defaultShutdownTimeout = 15 * time.Second
)

// serveOptions is the resolved command line.
type serveOptions struct {
	dsn          string
	spireAddress string
	trustDomain  string
	serverID     string
	parentID     string

	// The admin credential, one of two ways. See servewiring.go.
	workloadAPI string
	svidFile    string
	keyFile     string
	bundleFile  string

	fulcioURL string
	rekorURL  string

	// sign_commit's own configuration (RM-033). workspace empty means the
	// tool is bound and unconfigured.
	workspace           string
	oidcIssuer          string
	signAuthorName      string
	signAuthorEmail     string
	signAuthorOperators []string
	signAllowUnlinked   bool
	gitsignPath         string

	listen       string
	healthListen string
	addrFile     string

	spireTimeout    time.Duration
	runTTL          time.Duration
	lease           time.Duration
	rateCalls       int
	rateWindow      time.Duration
	clockSkewBound  time.Duration
	trustedOrigins  []string
	sessionTimeout  time.Duration
	shutdownTimeout time.Duration
	healthTimeout   time.Duration

	requireRole bool
	migrate     bool

	// Identity mode and its secret (RM-079, #116). See serveOptions.pseudonyms.
	//
	// identitySecretFile is the other way of supplying the same secret
	// (RM-084, #124). It is resolved INTO identitySecret before validate runs,
	// so everything downstream — pseudonyms(), the wiring, the start-up log —
	// sees one field and cannot be written to prefer a source.
	identityMode       string
	identitySecret     string
	identitySecretFile string
}

// pseudonyms builds what decides whether the SPIFFE ID — and so the Fulcio
// certificate, and so the Rekor entry, and so the Agent-Identity trailer —
// names the caller's task and agent type or a keyed pseudonym of them.
//
// It is called from validate() as well as from the wiring, so that a
// deployment that asked for pseudonyms and gave no secret is refused with a
// usage message naming the flag rather than with a start-up failure naming a
// package.
func (o serveOptions) pseudonyms() (*identity.Pseudonymiser, error) {
	return identity.New(identity.Mode(o.identityMode), o.identitySecret)
}

// resolveIdentitySecret reads -identity-secret-file into identitySecret, or
// reports the configuration problem that stops the server starting (RM-084,
// #124).
//
// # Why a file at all
//
// A pseudonym is deployment-scoped by construction, so each deployment must
// mint its own secret, so the shipped compose stack generates one into a
// volume — and compose can mount a volume but cannot read one into an
// environment variable. Without this the only way to configure the stack was a
// constant in a tracked file, which would have given every deployment the same
// pseudonyms.
//
// # Why BOTH is refused rather than resolved
//
// Two disagreeing sources and a rule about which wins is a configuration that
// quietly does something other than what it says. That is precisely how #124
// shipped: `-identity-mode` said `pseudonymous`, the stack supplied no secret,
// and nothing reconciled the two until the container was already crashlooping.
// A deployment that names two secrets does not know which one it means, and
// guessing for it would make the wrong pseudonyms — permanently, and silently,
// since every one of them is still a valid eight hex characters.
//
// # Whitespace
//
// Trimmed, because every way of writing a key file ends it with a newline:
// `openssl rand -hex 32 > secret`, a heredoc, an editor. A secret one byte
// longer than the operator believes changes every pseudonym this deployment
// mints, and would look like nothing at all.
func (o *serveOptions) resolveIdentitySecret() string {
	if o.identitySecretFile == "" {
		return ""
	}
	if o.identitySecret != "" {
		return "-identity-secret and -identity-secret-file (or $" + envIdentitySecret +
			" and $" + envIdentitySecretFile + ") are both set: two sources for one " +
			"secret is a configuration that can disagree with itself, and choosing " +
			"between them would key every pseudonym with a value the deployment did " +
			"not mean to use. Supply exactly one"
	}
	body, err := os.ReadFile(o.identitySecretFile)
	if err != nil {
		return "-identity-secret-file (or $" + envIdentitySecretFile + "): " + err.Error() +
			". A deployment that generates the secret into a volume must run that " +
			"one-shot to completion before this process starts"
	}
	secret := strings.TrimSpace(string(body))
	if secret == "" {
		return "-identity-secret-file (or $" + envIdentitySecretFile + ") " +
			o.identitySecretFile + " holds no secret: an empty or half-written file " +
			"must not become a zero-length key"
	}
	o.identitySecret = secret
	return ""
}

// serveLog is the server's log. It is structured because a deployment ships
// these lines to something that indexes them, and because
// `internal/mcp`'s transport, health handler and rate limiter all take a
// *slog.Logger — one logger for the process, not three formats on one stream.
type serveLog struct {
	w      io.Writer
	logger *slog.Logger
}

func newServeLog(w io.Writer) *serveLog {
	return &serveLog{
		w:      w,
		logger: slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
}

func (l *serveLog) info(msg string, args ...any)  { l.logger.Info(msg, args...) }
func (l *serveLog) warn(msg string, args ...any)  { l.logger.Warn(msg, args...) }
func (l *serveLog) error(msg string, args ...any) { l.logger.Error(msg, args...) }

// servedMCP is the running server, as this command needs it. It is an
// interface so the command's own behaviour — configuration, the address file,
// the exit statuses, the lifecycle — is testable without a Postgres and a
// SPIRE; openServer is the production implementation, and what it wires to
// what is asserted end to end against real dependencies.
type servedMCP interface {
	// Addr is the bound MCP transport address, after listening.
	Addr() string
	// HealthAddr is the bound health address.
	HealthAddr() string
	// BoundTools and MissingTools are the advertised IP §4 surface.
	BoundTools() []mcp.ToolName
	MissingTools() []mcp.ToolName
	// Serve runs until ctx is done or a listener fails.
	Serve(ctx context.Context) error
	// Close releases everything the server opened.
	Close()
}

// serveDeps are the seams the command's tests replace. Production wiring is
// the zero value.
type serveDeps struct {
	open func(context.Context, serveOptions, *serveLog) (servedMCP, error)
}

func (d serveDeps) opener() func(context.Context, serveOptions, *serveLog) (servedMCP, error) {
	if d.open != nil {
		return d.open
	}
	return openServer
}

// serveCommand is the subcommand body wired into cli.go's dispatch table.
func serveCommand(args []string, stdout, stderr io.Writer) int {
	return runServeCommand(args, stdout, stderr, serveDeps{})
}

func runServeCommand(args []string, stdout, stderr io.Writer, deps serveDeps) int {
	return runServe(context.Background(), args, stdout, stderr, deps)
}

// runServe is the whole command, with its parent context supplied so that a
// test can drive the lifecycle without signalling its own process.
func runServe(parent context.Context, args []string, stdout, stderr io.Writer, deps serveDeps) int {
	o, code, ok := parseServeFlags(args, stderr)
	if !ok {
		return code
	}

	// SIGINT and SIGTERM stop the server; nothing else is handled. SIGKILL
	// cannot be, which is the point of MCP-011.
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := newServeLog(stderr)

	srv, err := deps.opener()(ctx, o, log)
	if err != nil {
		log.error("the MCP server did not start", "err", err)
		fprintf(stderr, "innsegl serve: UNAVAILABLE - nothing is being served\n")
		return exitServeUnavailable
	}
	defer srv.Close()

	if err := announceAddress(o.addrFile, srv.Addr()); err != nil {
		log.error("the bound address could not be published", "err", err)
		fprintf(stderr, "innsegl serve: UNAVAILABLE - the address file is how callers find this "+
			"replica; a server nobody can address is not serving\n")
		return exitServeUnavailable
	}

	// The bound address on STDOUT, one line, nothing else. The structured log
	// is on stderr; a shell that wants to know where the server came up reads
	// this without parsing log lines, and `innsegl serve -listen 127.0.0.1:0`
	// is then usable from a script without an address file.
	fprintf(stdout, "%s\n", srv.Addr())

	reportToolSurface(log, srv)
	log.info("serving",
		"mcp", srv.Addr(),
		"health", srv.HealthAddr(),
		"live_path", mcp.LivePath,
		"ready_path", mcp.ReadyPath,
		"server_name", mcp.ServerName,
	)

	if err := srv.Serve(ctx); err != nil {
		log.error("the MCP server stopped serving", "err", err)
		return exitServeFailed
	}
	log.info("stopped")
	return exitOK
}

// reportToolSurface names what is advertised and what is not.
//
// ADR-0024: "An incomplete tool surface is reported and does not gate
// readiness." RM-033 (#41) bound `sign_commit`, so the shipped surface is now
// all five of IP §4 and the warning below is silent — which is the point of
// reporting the surface rather than asserting it: `Server.MissingTools` is
// derived from the binders that registered themselves, so if a tool ever stops
// registering, an operator reads it here and in both health endpoints instead
// of concluding the server is broken.
func reportToolSurface(log *serveLog, srv servedMCP) {
	bound := srv.BoundTools()
	log.info("tool surface", "bound", names(bound), "count", len(bound))

	missing := srv.MissingTools()
	if len(missing) == 0 {
		return
	}
	log.warn("tools MISSING from the IP §4 surface: no binder is registered for them, "+
		"and a call to one is refused as an unknown tool",
		"missing", names(missing),
		"reported_at", mcp.LivePath+" and "+mcp.ReadyPath,
		"note", "a missing tool never gates readiness (ADR-0024)")
}

func names(tools []mcp.ToolName) string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = string(t)
	}
	return strings.Join(out, ",")
}

// parseServeFlags resolves the command line and the environment behind it.
func parseServeFlags(args []string, stderr io.Writer) (serveOptions, int, bool) {
	fs := flag.NewFlagSet("innsegl serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		spireAddress = fs.String("spire-address", os.Getenv(envSPIREAddress),
			"SPIRE server admin API, host:port ($"+envSPIREAddress+")")
		trustDomain = fs.String("trust-domain", os.Getenv(envTrustDomain),
			"SPIFFE trust domain name, e.g. innsegl.dev ($"+envTrustDomain+")")
		serverID = fs.String("spire-server-id", os.Getenv(envSPIREServerID),
			"SPIFFE ID the SPIRE server must present; empty means spiffe://{trust-domain}/spire/server ($"+envSPIREServerID+")")
		parentID = fs.String("parent-id", os.Getenv(envParentID),
			"attested node every run entry hangs off ($"+envParentID+")")
		workloadAPI = fs.String("workload-api", envOr(envWorkloadAPI, spire.DefaultWorkloadAPIAddress),
			"Workload API socket this process fetches its own admin SVID from ($"+envWorkloadAPI+")")
		svidFile = fs.String("svid", os.Getenv(envMCPSVIDFile),
			"PEM file holding the admin X509-SVID, instead of the Workload API ($"+envMCPSVIDFile+")")
		keyFile = fs.String("key", os.Getenv(envMCPKeyFile),
			"PEM file holding the admin SVID's private key ($"+envMCPKeyFile+")")
		bundleFile = fs.String("bundle", os.Getenv(envMCPBundleFile),
			"PEM file holding the trust bundle ($"+envMCPBundleFile+")")
		fulcioURL = fs.String("fulcio-url", os.Getenv(envFulcioURL),
			"base URL of the configured Fulcio, probed by "+mcp.ReadyPath+" ($"+envFulcioURL+")")
		rekorURL = fs.String("rekor-url", os.Getenv(envRekorURL),
			"base URL of the configured Rekor, probed by "+mcp.ReadyPath+" ($"+envRekorURL+")")
		workspace = fs.String("workspace", os.Getenv(envWorkspace),
			"absolute root of the working trees sign_commit signs in; host/org/name is "+
				"resolved beneath it. Empty leaves sign_commit unconfigured ($"+envWorkspace+")")
		oidcIssuer = fs.String("oidc-issuer", os.Getenv(envOIDCIssuer),
			"the OIDC issuer SPIRE stamps and Fulcio believes; all three must agree "+
				"(ADR-0029 decision 3) ($"+envOIDCIssuer+")")
		signAuthorName = fs.String("sign-author-name", os.Getenv(envSignAuthorName),
			"commit author and committer name ($"+envSignAuthorName+")")
		signAuthorEmail = fs.String("sign-author-email", os.Getenv(envSignAuthorEmail),
			"commit author and committer email; the I6 gate admits it or refuses to start "+
				"($"+envSignAuthorEmail+")")
		signAuthorOperators = fs.String("sign-author-operators", os.Getenv(envSignAuthorOperators),
			"comma-separated addresses this deployment attributes commits to (I6) "+
				"($"+envSignAuthorOperators+")")
		signAllowUnlinked = fs.Bool("sign-author-allow-unlinked", envBool(envSignAllowUnlinked, false),
			"admit an author address in a reserved, undelegatable domain (.invalid, .test, "+
				"example.com and the rest) ($"+envSignAllowUnlinked+")")
		gitsignPath = fs.String("gitsign", os.Getenv(envGitsignPath),
			"the gitsign binary. Empty is a PATH lookup ($"+envGitsignPath+")")
		listen = fs.String("listen", envOr(envMCPListen, defaultMCPListen),
			"address the MCP transport listens on ($"+envMCPListen+")")
		healthListen = fs.String("health-listen", envOr(envMCPHealthListen, defaultHealthListen),
			"address "+mcp.LivePath+" and "+mcp.ReadyPath+" listen on ($"+envMCPHealthListen+")")
		addrFile = fs.String("addr-file", os.Getenv(envMCPAddrFile),
			"file to publish the bound MCP address to, written by rename ($"+envMCPAddrFile+")")
		spireTimeout = fs.Duration("timeout", envDuration(envSPIRETimeout, spire.DefaultTimeout),
			"bound on one SPIRE admin RPC ($"+envSPIRETimeout+")")
		runTTL = fs.Duration("run-ttl", envDuration(envRunTTL, 0),
			"identity lifetime asked for per run; 0 uses internal/spire's default ($"+envRunTTL+")")
		lease = fs.Duration("idempotency-lease", envDuration(envIdempotencyLease, mcp.DefaultIdempotencyLease),
			"how long one idempotency claim is honoured before another caller may take it over ($"+envIdempotencyLease+")")
		rateCalls = fs.Int("register-rate-calls", envInt(envRegisterRateCalls, mcp.DefaultRegisterAgentRateLimitCalls),
			"register_agent calls one caller may make per window; 0 serves it UNMETERED ($"+envRegisterRateCalls+")")
		rateWindow = fs.Duration("register-rate-window", envDuration(envRegisterRateWindow, mcp.DefaultRegisterAgentRateLimitWindow),
			"the window -register-rate-calls is measured over ($"+envRegisterRateWindow+")")
		clockSkewBound = fs.Duration("clock-skew-bound", envDuration(envClockSkewBound, 0),
			"IP §6.8's skew bound, surfaced in "+mcp.ReadyPath+"; 0 reports it unconfigured ($"+envClockSkewBound+")")
		trustedOrigins = fs.String("trusted-origins", os.Getenv(envTrustedOrigins),
			"comma-separated browser origins allowed to make state-changing requests ($"+envTrustedOrigins+")")
		sessionTimeout = fs.Duration("session-timeout", envDuration(envMCPSessionTimeout, 0),
			"close MCP sessions idle this long; 0 never closes them ($"+envMCPSessionTimeout+")")
		shutdownTimeout = fs.Duration("shutdown-timeout", envDuration(envMCPShutdownTimeout, defaultShutdownTimeout),
			"bound on the orderly shutdown after SIGINT or SIGTERM ($"+envMCPShutdownTimeout+")")
		healthTimeout = fs.Duration("health-timeout", envDuration(envHealthTimeout, mcp.DefaultHealthTimeout),
			"bound on one readiness probe ($"+envHealthTimeout+")")
		requireRole = fs.Bool("require-append-only-role", envBool(envRequireAppendOnlyRole, false),
			"refuse to start unless the database role can INSERT and cannot UPDATE, DELETE or "+
				"TRUNCATE the chain (doc 05 §1) ($"+envRequireAppendOnlyRole+")")
		identityMode = fs.String("identity-mode", envOr(envIdentityMode, string(identity.ModePseudonymous)),
			"what the SPIFFE ID says about a run: "+string(identity.ModePseudonymous)+
				" puts a keyed pseudonym of agent_type and task_ref in it, "+string(identity.ModeLiteral)+
				" puts the caller's own values in and so puts your ticket references into "+
				"every Fulcio certificate and every Rekor entry, permanently ($"+envIdentityMode+")")
		identitySecret = fs.String("identity-secret", os.Getenv(envIdentitySecret),
			"the deployment secret the pseudonyms are keyed with, at least "+
				strconv.Itoa(identity.MinSecretBytes)+" bytes — prefer the environment variable. "+
				"It is needed to CREATE a pseudonym and never to resolve one: resolution goes "+
				"through the ledger's run_registered row, so losing or rotating this does not "+
				"orphan history ($"+envIdentitySecret+")")
		identitySecretFile = fs.String("identity-secret-file", os.Getenv(envIdentitySecretFile),
			"file holding that secret, for a deployment that generates one into a volume "+
				"and so has nothing to put in the variable above. Leading and trailing "+
				"whitespace is not part of the key. Setting both this and -identity-secret "+
				"is refused ($"+envIdentitySecretFile+")")
		migrate = fs.Bool("migrate", envBool(envMigrate, false),
			"apply the ledger migrations before serving; a deployment normally runs them as its "+
				"own step ($"+envMigrate+")")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl serve - run the innsegl MCP server (IP §1, §4)\n\n")
		fprintf(stderr, "Usage:\n  innsegl serve [flags]\n\n")
		fprintf(stderr, "Serves the IP §4 tool surface over the MCP HTTP transport, and "+
			mcp.LivePath+" / "+mcp.ReadyPath+" on a separate address.\n")
		fprintf(stderr, "This process is the only component holding the SPIRE admin credential "+
			"(IP §1, doc 05 §1); run it under a database role that can append and not delete.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  the server shut down in an orderly way\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  UNAVAILABLE - the server could not start; nothing was served\n", exitServeUnavailable)
		fprintf(stderr, "  %d  FAILED - the server was serving and stopped on an error\n", exitServeFailed)
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return serveOptions{}, exitOK, false
		}
		return serveOptions{}, exitUsage, false
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl serve: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return serveOptions{}, exitUsage, false
	}

	o := serveOptions{
		dsn: *dsn, spireAddress: *spireAddress, trustDomain: *trustDomain,
		serverID: *serverID, parentID: *parentID,
		workloadAPI: *workloadAPI, svidFile: *svidFile, keyFile: *keyFile, bundleFile: *bundleFile,
		fulcioURL: *fulcioURL, rekorURL: *rekorURL,
		workspace: *workspace, oidcIssuer: *oidcIssuer,
		signAuthorName: *signAuthorName, signAuthorEmail: *signAuthorEmail,
		signAuthorOperators: splitOrigins(*signAuthorOperators),
		signAllowUnlinked:   *signAllowUnlinked,
		gitsignPath:         *gitsignPath,
		listen:              *listen, healthListen: *healthListen, addrFile: *addrFile,
		spireTimeout: *spireTimeout, runTTL: *runTTL, lease: *lease,
		rateCalls: *rateCalls, rateWindow: *rateWindow,
		clockSkewBound: *clockSkewBound, trustedOrigins: splitOrigins(*trustedOrigins),
		sessionTimeout: *sessionTimeout, shutdownTimeout: *shutdownTimeout,
		healthTimeout: *healthTimeout, requireRole: *requireRole, migrate: *migrate,
		identityMode: *identityMode, identitySecret: *identitySecret,
		identitySecretFile: *identitySecretFile,
	}
	// Before validate, because validate builds a Pseudonymiser out of the
	// resolved secret and would otherwise refuse a deployment that supplied
	// one perfectly well — on a volume.
	if problem := o.resolveIdentitySecret(); problem != "" {
		fprintf(stderr, "innsegl serve: %s\n", problem)
		return serveOptions{}, exitUsage, false
	}
	if problem := o.validate(); problem != "" {
		fprintf(stderr, "innsegl serve: %s\n", problem)
		return serveOptions{}, exitUsage, false
	}
	return o, exitOK, true
}

// validate reports the first setting that makes this configuration unusable,
// naming the flag and its environment variable. An operator has to be told
// WHICH one; "the server did not start" is not actionable.
//
// Every required setting below is required because there is no defensible
// default for it. The Fulcio and Rekor addresses in particular: ADR-0010 makes
// the self-hosted pair the shipped default, so a deployment that did not say
// which Sigstore it uses has no address to fall back to, and a readiness probe
// pointed at somebody else's log would report green about the wrong system.
func (o serveOptions) validate() string {
	switch {
	case o.dsn == "":
		return "-dsn (or $" + envLedgerDSN + ") is required"
	case o.spireAddress == "":
		return "-spire-address (or $" + envSPIREAddress + ") is required"
	case o.trustDomain == "":
		return "-trust-domain (or $" + envTrustDomain + ") is required"
	case o.parentID == "":
		return "-parent-id (or $" + envParentID + ") is required: an entry with no reachable " +
			"parent is an entry no workload can ever match"
	case o.workspace != "" && o.oidcIssuer == "":
		return "-oidc-issuer (or $" + envOIDCIssuer + ") is required when -workspace is set: " +
			"Fulcio believes exactly one issuer and a verifier has to be told which " +
			"(ADR-0029 decision 3)"
	case o.workspace != "" && (o.signAuthorName == "" || o.signAuthorEmail == ""):
		return "-sign-author-name and -sign-author-email (or $" + envSignAuthorName + " and $" +
			envSignAuthorEmail + ") are required when -workspace is set: the author line is " +
			"part of the bytes that get signed, and I6 gates the address"
	case o.workspace != "" && len(o.signAuthorOperators) == 0 && !o.signAllowUnlinked:
		return "-sign-author-operators (or $" + envSignAuthorOperators + "), or " +
			"-sign-author-allow-unlinked, is required when -workspace is set: the I6 author " +
			"policy is an allowlist whose zero value admits nothing, on purpose (ADR-0028)"
	case o.fulcioURL == "":
		return "-fulcio-url (or $" + envFulcioURL + ") is required: " + mcp.ReadyPath +
			" reports Sigstore reachability and there is no default pair to fall back to (ADR-0010)"
	case o.rekorURL == "":
		return "-rekor-url (or $" + envRekorURL + ") is required: " + mcp.ReadyPath +
			" reports Sigstore reachability and there is no default pair to fall back to (ADR-0010)"
	case o.listen == "":
		return "-listen (or $" + envMCPListen + ") is required"
	case o.healthListen == "":
		return "-health-listen (or $" + envMCPHealthListen + ") is required: IP §6.6 requires " +
			"the health endpoints, and a replica with none cannot be taken out of rotation"
	case o.rateCalls < 0:
		return fmt.Sprintf("-register-rate-calls %d is negative; 0 serves register_agent "+
			"unmetered and a positive number meters it (AB-07)", o.rateCalls)
	case o.rateCalls > 0 && o.rateWindow <= 0:
		return fmt.Sprintf("-register-rate-window %s is not positive; a limit measured over "+
			"no time is not a limit", o.rateWindow)
	case o.lease < 0:
		return "-idempotency-lease is negative"
	case o.shutdownTimeout < 0:
		return "-shutdown-timeout is negative"
	}
	// RM-079 (#116). The mode defaults to pseudonymous, so a deployment that
	// set no secret is refused here rather than starting with the ticket
	// references going into Rekor.
	if _, err := o.pseudonyms(); err != nil {
		return "-identity-mode / -identity-secret / -identity-secret-file (or $" +
			envIdentityMode + " / $" + envIdentitySecret + " / $" + envIdentitySecretFile +
			"): " + err.Error()
	}
	// One credential, and exactly one way of getting it. See servewiring.go.
	files := 0
	for _, f := range []string{o.svidFile, o.keyFile, o.bundleFile} {
		if f != "" {
			files++
		}
	}
	if files != 0 && files != 3 {
		return "-svid, -key and -bundle are one credential: supply all three or none " +
			"(and none means the Workload API, which is what a deployment uses)"
	}
	return ""
}

// splitOrigins reads the comma-separated trusted-origin list.
func splitOrigins(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// envInt reads an integer from the environment. An unparseable value falls
// back rather than failing, matching envDuration and envBool: the flag it
// defaults is still explicit on the command line, and flag.Parse reports a bad
// -flag value itself.
func envInt(name string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return v
}

// announceAddress publishes the bound address by rename, so a reader sees
// either nothing or a complete address and never a half-written one. An empty
// path publishes nothing, which is the ordinary deployment: an orchestrator
// knows where it put the replica.
func announceAddress(path, addr string) error {
	if path == "" {
		return nil
	}
	tmp := path + ".partial"
	if err := os.WriteFile(tmp, []byte(addr), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, filepath.Base(path), err)
	}
	return nil
}

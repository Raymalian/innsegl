// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/rundir"
)

// `innsegl gateway` — the model-traffic reverse proxy, wired.
//
// ADR-0057: capture agent activity by sitting a reverse proxy in front of
// the model provider a harness is pointed at, instead of depending on that
// harness's own hooks. ADR-0060 places it: a fifth companion of the one
// `innsegl` process (decision 1), so this file wires the same shape `api`,
// `seal`, `reconcile` and `reap` already do — a subcommand this binary can
// run on its own, and a body `serve -also gateway` runs as a goroutine in
// that same process instead of a fifth container.
//
// # What this file wires, and what it does not
//
// It builds an internal/gateway.Proxy in front of a configured upstream and
// serves it. It does NOT decide identity, does not read or write the
// ledger, does not relay WebSocket traffic (#372), and does not redact
// anything from a body (#373). Every one of those is a later issue in epic
// #357.
//
// # https-only, at start-up (RM-226, #371)
//
// gatewayOptions.validate refuses a non-https -upstream before this command
// does anything else -- no listener, no upstream client, nothing relayed.
// There is no flag or environment variable that bypasses it. Certificate
// and hostname strictness against the system roots is internal/gateway's
// own job (see its NewUpstream), not repeated here.
//
// # It is not published on loopback by this process's own bind address
//
// ADR-0060 decision 2 measured that a socket bound to loopback inside a
// container's own network namespace cannot receive what docker forwards in
// from a published host port. What makes this gateway loopback-only as
// experienced from OUTSIDE the container is the compose publish line
// (#370), not -listen's default here.
//
// # Identity from traffic (RM-235, #380)
//
// -dsn (or $INNSEGL_LEDGER_DSN, the SAME variable `serve`, `seal`,
// `reconcile` and `reap` already read) is the one new, OPTIONAL setting
// this issue adds. Set, openGateway builds the real identity stack ADR-0058
// describes: a Postgres-backed MappingStore and a RunStateReader on the
// same database (ADR-0060 decision 3, "one database, no new store"), the
// MCP's own register_agent/retire_agent/describe_workspace reached in
// process (internal/gateway's registrar.go and workspace.go -- this file
// does not configure those tools itself; when this command runs as `serve
// -also gateway`, servewiring.go already has, and this is simply another
// caller of what is already wired; run standalone with no MCP configured in
// this same process, every registration attempt is refused exactly as
// register_agent refuses an unconfigured call, which is the correct,
// fail-closed reading of ADR-0058 decision 11 for a misconfigured
// deployment), and the identity guard (ADR-0058 decision 11) is placed into
// gateway.Guards -- the one ordered list -- ahead of the rate limiter.
// Unset, this command behaves exactly as it did before this issue: no
// identity guard, nothing else changed.
//
// The silence backstop (ADR-0058 decision 7c) and the session-end delivery
// method (decision 7a; see sessionEndHandler below) are both built only
// when -dsn is set, for the same reason: neither means anything without a
// mapping store and a Registrar to retire through.

// Exit statuses, continuing cli.go's contract.
const (
	// exitGatewayUnavailable: the gateway could not start. Bad
	// configuration, an unusable upstream URL, an unbindable listen
	// address. Nothing was relayed.
	exitGatewayUnavailable = 22
	// exitGatewayFailed: the gateway was relaying and stopped on an error.
	exitGatewayFailed = 23
)

// Every flag falls back to an environment variable, matching every other
// companion in this binary — so a compose service can be configured
// entirely by environment.
const (
	envGatewayListen          = "INNSEGL_GATEWAY_LISTEN"
	envGatewayUpstream        = "INNSEGL_GATEWAY_UPSTREAM"
	envGatewayShutdownTimeout = "INNSEGL_GATEWAY_SHUTDOWN_TIMEOUT"
	// envGatewayRate and envGatewayBurst configure GW-013's per-session
	// rate limit (internal/gateway/limit.go, #375). See that file's own
	// doc comment for why the shipped defaults are generous -- a heavy
	// legitimate session (a main agent and several parallel subagents
	// sharing one session id) is meant to never hit them.
	envGatewayRate  = "INNSEGL_GATEWAY_RATE"
	envGatewayBurst = "INNSEGL_GATEWAY_BURST"

	// envGatewayBackstopInterval configures how often the silence backstop
	// (gateway.Backstop, ADR-0058 decision 7c) sweeps. gateway.EnvBackstopHorizon
	// (INNSEGL_GATEWAY_SILENCE_AFTER, internal/gateway/lifecycle.go) is the
	// horizon itself and is read directly, without a second flag of its own
	// here, so that this command and any other future caller of
	// gateway.NewBackstop read the identical setting from the identical
	// variable.
	envGatewayBackstopInterval = "INNSEGL_GATEWAY_BACKSTOP_INTERVAL"
)

const (
	// defaultGatewayListen. Unlike `serve`'s and `api`'s own defaults, this
	// is deliberately NOT loopback — see this file's own doc comment above.
	defaultGatewayListen = ":8095"

	// defaultGatewayUpstream. ADR-0057's spike ran against Anthropic's own
	// API, and every deployment that has not said otherwise forwards there.
	defaultGatewayUpstream = "https://api.anthropic.com"

	// defaultGatewayShutdownTimeout bounds the orderly stop, the same bound
	// `serve` and `api` use.
	defaultGatewayShutdownTimeout = 15 * time.Second

	// gatewayReadHeaderTimeout bounds how long a client may take to send its
	// request headers. A surface with no bound is a slowloris away from
	// holding every connection it has.
	gatewayReadHeaderTimeout = 10 * time.Second

	// gatewayBootTimeout bounds construction. A replica that hangs at
	// start-up is worse than one that exits: an orchestrator can restart
	// the second.
	gatewayBootTimeout = 60 * time.Second

	// defaultGatewayBackstopInterval is how often the silence backstop
	// sweeps once -dsn is set. A fraction of gateway.DefaultBackstopHorizon
	// (seven days) rather than a fraction of a day: this is a background
	// housekeeping loop against the same database the mapping store and the
	// ledger already use, not a latency-sensitive path, and a run silent
	// past its horizon by up to this interval costs nothing worse than the
	// same adoption-instead-of-resume ADR-0058 decision 7 already accepts.
	defaultGatewayBackstopInterval = 15 * time.Minute

	// gatewaySweepTimeout bounds one backstop sweep (the enumeration query
	// and every Retire it triggers), the same reasoning gatewayBootTimeout
	// gives construction: a sweep that hangs is worse than one that fails
	// and tries again next tick.
	gatewaySweepTimeout = 5 * time.Minute
)

// gatewayOptions is the resolved command line.
type gatewayOptions struct {
	listen          string
	upstream        string
	shutdownTimeout time.Duration
	// rateLimitRate and rateLimitBurst configure GW-013's per-session rate
	// limit (internal/gateway.SessionRateLimit). validate refuses either
	// one non-positive before the gateway starts -- see that method.
	rateLimitRate  int
	rateLimitBurst int

	// dsn is RM-235 (#380)'s one new, OPTIONAL setting: the ledger database
	// the identity stack reads and writes (ADR-0060 decision 3). Empty means
	// no identity guard, no backstop, no session-end endpoint -- exactly
	// this command's behaviour before this issue. See this file's own doc
	// comment, "Identity from traffic".
	dsn string
	// backstopInterval is how often the silence backstop sweeps, once dsn is
	// set. validate refuses a non-positive value.
	backstopInterval time.Duration

	// upstreamClient overrides the client openGateway hands to
	// gateway.NewUpstream. Always nil on every path a flag or an
	// environment variable can reach -- parseGatewayFlags never sets it --
	// so it is not a production escape hatch. It exists only so this file's
	// own end-to-end test can prove the REAL openGateway wiring against a
	// TLS upstream the test process trusts, the same seam
	// internal/gateway's own tests reach through NewUpstream's client
	// parameter, one level up.
	upstreamClient *http.Client
}

// validate reports the first setting that makes this configuration
// unusable, naming the flag and its environment variable.
func (o gatewayOptions) validate() string {
	switch {
	case o.listen == "":
		return "-listen (or $" + envGatewayListen + ") is required"
	case o.upstream == "":
		return "-upstream (or $" + envGatewayUpstream + ") is required"
	case o.shutdownTimeout < 0:
		return "-shutdown-timeout is negative"
	case o.rateLimitRate <= 0:
		return fmt.Sprintf("-rate-limit-rate (or $%s) must be a positive number of requests per "+
			"second, got %d (GW-013)", envGatewayRate, o.rateLimitRate)
	case o.rateLimitBurst <= 0:
		return fmt.Sprintf("-rate-limit-burst (or $%s) must be a positive number of requests, "+
			"got %d (GW-013)", envGatewayBurst, o.rateLimitBurst)
	case o.backstopInterval <= 0:
		return fmt.Sprintf("-backstop-interval (or $%s) must be positive, got %s",
			envGatewayBackstopInterval, o.backstopInterval)
	}
	if problem := upstreamMustBeHTTPS(o.upstream); problem != "" {
		return problem
	}
	return ""
}

// upstreamMustBeHTTPS is GW-007: only an https:// upstream is ever
// accepted, refused here before the gateway does anything else -- no
// listener opened, no upstream client built, nothing relayed. The gateway
// puts a model provider credential on every request it forwards
// (ADR-0057); an http upstream would put that credential on the wire in
// clear text with no TLS handshake ever happening to protect it, so this is
// caught at start-up rather than left for a certificate check that an http
// URL never triggers in the first place. There is no flag or environment
// variable that bypasses this -- production configuration gets no escape
// hatch (see gatewayOptions.upstreamClient's own doc comment for the one
// seam this package does keep, and why it is not one).
//
// A URL that cannot even be parsed, or that parses with no scheme at all,
// is left to gateway.NewUpstream's own error, raised later when openGateway
// builds the upstream: that error already names the problem, and duplicating
// it here would only produce two different messages for the same one cause.
// This function only ever adds the https-or-refuse rule on top of a URL
// that parses AND names some other scheme.
func upstreamMustBeHTTPS(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return ""
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Sprintf(
			"-upstream (or $%s) %q must use https -- an http (or any other non-https) "+
				"upstream is refused before anything is relayed (GW-007)",
			envGatewayUpstream, raw)
	}
	return ""
}

// servedGateway is the running gateway, as this command needs it. It is an
// interface so the command's own behaviour — the flags, the exit statuses,
// the lifecycle — is testable without a real listener; openGateway is the
// production implementation.
type servedGateway interface {
	// Addr is the bound address, after listening.
	Addr() string
	// Serve runs until ctx is done or the listener fails.
	Serve(ctx context.Context) error
	// Close releases the listener.
	Close()
}

// gatewayDeps are the seams this command's tests replace. Production wiring
// is the zero value.
type gatewayDeps struct {
	open func(context.Context, gatewayOptions, *serveLog) (servedGateway, error)
}

func (d gatewayDeps) opener() func(context.Context, gatewayOptions, *serveLog) (servedGateway, error) {
	if d.open != nil {
		return d.open
	}
	return openGateway
}

// gatewayCommand is the subcommand body wired into cli.go's dispatch table,
// and the function `serve -also gateway` runs as a goroutine in this
// process instead of a fifth container (ADR-0060 decision 1).
func gatewayCommand(args []string, stdout, stderr io.Writer) int {
	// SIGINT and SIGTERM stop the gateway. Nothing here decides identity or
	// writes the ledger, so a process killed mid-request loses a relay in
	// flight and nothing else.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runGateway(ctx, args, stdout, stderr, gatewayDeps{})
}

// runGatewayCommand is the entry point for tests that do not drive the
// lifecycle with an OS signal.
func runGatewayCommand(args []string, stdout, stderr io.Writer, deps gatewayDeps) int {
	return runGateway(context.Background(), args, stdout, stderr, deps)
}

// runGateway is the whole command: parse, open, serve.
func runGateway(ctx context.Context, args []string, stdout, stderr io.Writer, deps gatewayDeps) int {
	o, code, ok := parseGatewayFlags(args, stderr)
	if !ok {
		return code
	}

	log := newServeLog(stderr)

	srv, err := deps.opener()(ctx, o, log)
	if err != nil {
		log.error("the gateway did not start", "err", err)
		fprintf(stderr, "innsegl gateway: UNAVAILABLE - nothing is being relayed\n")
		return exitGatewayUnavailable
	}
	defer srv.Close()

	// The bound address on STDOUT, one line, nothing else — `serve`'s and
	// `api`'s own contract, so a script can find it without parsing the
	// structured log on stderr.
	fprintf(stdout, "%s\n", srv.Addr())

	log.info("relaying model traffic",
		"addr", srv.Addr(),
		"upstream", o.upstream,
	)

	if serr := srv.Serve(ctx); serr != nil {
		log.error("the gateway stopped relaying", "err", serr)
		return exitGatewayFailed
	}
	log.info("stopped")
	return exitOK
}

// parseGatewayFlags resolves the command line and the environment behind it.
func parseGatewayFlags(args []string, stderr io.Writer) (gatewayOptions, int, bool) {
	fs := flag.NewFlagSet("innsegl gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		listen = fs.String("listen", envOr(envGatewayListen, defaultGatewayListen),
			"address the gateway listens on. NOT loopback by default — the compose publish "+
				"line (#370) is what makes it loopback-only from outside the container "+
				"(ADR-0060 decision 2) ($"+envGatewayListen+")")
		upstream = fs.String("upstream", envOr(envGatewayUpstream, defaultGatewayUpstream),
			"base URL every request is forwarded to, unchanged ($"+envGatewayUpstream+")")
		shutdownTimeout = fs.Duration("shutdown-timeout",
			envDuration(envGatewayShutdownTimeout, defaultGatewayShutdownTimeout),
			"bound on the orderly shutdown after SIGINT or SIGTERM ($"+envGatewayShutdownTimeout+")")
		rateLimitRate = fs.Int("rate-limit-rate",
			envIntOr(envGatewayRate, gateway.DefaultSessionRateLimitRate),
			"sustained requests per second admitted from one session before GW-013 refuses the "+
				"rest, alerts once, and forwards nothing ($"+envGatewayRate+")")
		rateLimitBurst = fs.Int("rate-limit-burst",
			envIntOr(envGatewayBurst, gateway.DefaultSessionRateLimitBurst),
			"requests one session may burst instantaneously before the sustained rate applies "+
				"($"+envGatewayBurst+")")
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string for the identity stack (ADR-0058, ADR-0060 decision 3) -- "+
				"prefer the environment variable ($"+envLedgerDSN+"). OPTIONAL: unset means no "+
				"identity guard, no backstop, no session-end endpoint, exactly as before RM-235")
		backstopInterval = fs.Duration("backstop-interval",
			envDuration(envGatewayBackstopInterval, defaultGatewayBackstopInterval),
			"how often the silence backstop sweeps once -dsn is set (ADR-0058 decision 7c) "+
				"($"+envGatewayBackstopInterval+")")
	)

	fs.Usage = func() { gatewayUsage(stderr, fs) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return gatewayOptions{}, exitOK, false
		}
		return gatewayOptions{}, exitUsage, false
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl gateway: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return gatewayOptions{}, exitUsage, false
	}

	o := gatewayOptions{
		listen:           *listen,
		upstream:         *upstream,
		shutdownTimeout:  *shutdownTimeout,
		rateLimitRate:    *rateLimitRate,
		rateLimitBurst:   *rateLimitBurst,
		dsn:              *dsn,
		backstopInterval: *backstopInterval,
	}
	if problem := o.validate(); problem != "" {
		fprintf(stderr, "innsegl gateway: %s\n", problem)
		return gatewayOptions{}, exitUsage, false
	}
	return o, exitOK, true
}

func gatewayUsage(stderr io.Writer, fs *flag.FlagSet) {
	fprintf(stderr, "innsegl gateway - relay model traffic unchanged and stream replies back "+
		"(ADR-0057, ADR-0060)\n\n")
	fprintf(stderr, "Usage:\n  innsegl gateway [flags]\n\n")
	fprintf(stderr, "Forwards every request to -upstream unchanged: method, path and query, "+
		"headers\nincluding credentials, and body. Streams the reply back as it arrives, "+
		"flushing\nafter every chunk so a server-sent-events reply is never buffered. "+
		"Credentials\npass through and are never logged or persisted, by this process or "+
		"any other.\n\n")
	fprintf(stderr, "Only an https -upstream is accepted; an http (or any other non-https) "+
		"one is refused\nbefore anything is relayed, and certificates and hostnames are "+
		"verified strictly\nagainst the system roots (RM-226, #371). It does not yet relay "+
		"WebSocket traffic\n(#372), and redacts nothing from a body (#373).\n\n")
	fprintf(stderr, "Each session (the harness's own session id, not the caller's identity, which "+
		"this gateway\ndoes not yet check) is rate-limited: over its rate a request is refused "+
		"with 429, a\nRetry-After header, and nothing forwarded, and an alert is raised once per "+
		"trip episode\n(RM-230, #375). This is a runaway-loop guard, not an anti-DoS control, "+
		"until callers are\nauthenticated -- see internal/gateway/limit.go.\n\n")
	fprintf(stderr, "Exit status:\n")
	fprintf(stderr, "  %d  the gateway shut down in an orderly way\n", exitOK)
	fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
	fprintf(stderr, "  %d  UNAVAILABLE - the gateway could not start; nothing was relayed\n",
		exitGatewayUnavailable)
	fprintf(stderr, "  %d  FAILED - the gateway was relaying and stopped on an error\n",
		exitGatewayFailed)
	fprintf(stderr, "\nFlags:\n")
	fs.PrintDefaults()
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

// runningGateway is the shipped servedGateway.
type runningGateway struct {
	server          *http.Server
	ln              net.Listener
	shutdownTimeout time.Duration
	log             *serveLog

	// backstop, backstopCandidates and backstopInterval are set only when
	// o.dsn was non-empty (RM-235, #380): the silence backstop (ADR-0058
	// decision 7c), swept on this interval for as long as Serve runs.
	// backstop is nil when -dsn was not set, and Serve does not start the
	// sweep loop at all in that case.
	backstop           *gateway.Backstop
	backstopCandidates *gateway.SilentRunCandidates
	backstopInterval   time.Duration

	// sessionEnder is set alongside backstop (o.dsn non-empty) and swept on
	// the SAME ticker: ADR-0058 decision 7a's mark-then-sweep session-end
	// signal (lifecycle.go's own doc comment on the redesign, #380 review)
	// and decision 7c's silence backstop are independent clocks answering
	// the same question -- has this run gone quiet -- so one ticker serving
	// both is not two mechanisms sharing infrastructure by accident.
	sessionEnder *gateway.SessionEnder
	// sessionEndRateLimit bounds sessionEndHandler's own request rate --
	// see that handler's doc comment for the threat this, and the loopback
	// and well-formedness checks beside it, answer.
	sessionEndRateLimit *gateway.SessionRateLimiter

	// closers release every resource openGateway opened beyond the
	// listener (the mapping store's pool, the ledger connection, the
	// backstop's own pool) -- called in Close, in the order they were
	// appended, mirroring how `api` and `serve` release their own
	// Postgres-backed dependencies.
	closers []func()
}

func (g *runningGateway) Addr() string { return g.ln.Addr().String() }

// Serve runs the listener until ctx is done or it fails, then stops it in
// an orderly way — the same shape `runningServer.Serve` and
// `runningAPI.Serve` already use. When the silence backstop is wired
// (o.dsn was set), a second goroutine sweeps it on backstopInterval for as
// long as ctx is not done; it holds no state between Serve and Close, so a
// Serve/Close cycle leaves nothing running.
func (g *runningGateway) Serve(ctx context.Context) error {
	if g.backstop != nil {
		go g.runBackstop(ctx)
	}

	failed := make(chan error, 1)
	go func() {
		err := g.server.Serve(g.ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		failed <- err
	}()

	var first error
	select {
	case <-ctx.Done():
	case first = <-failed:
	}

	// context.WithoutCancel, as `serve`'s and `api`'s own Serve do: ctx is
	// the signal context and is already cancelled by the time we get here
	// on the ordinary path, and a Shutdown handed a cancelled context
	// severs live connections instead of draining them.
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.shutdownTimeout)
	defer cancel()
	if err := g.server.Shutdown(stopCtx); err != nil && first == nil {
		g.log.warn("the gateway did not drain before the shutdown bound", "err", err)
	}
	return first
}

// runBackstop sweeps the silence backstop every backstopInterval, until ctx
// is done. A failed enumeration or a failed sweep is logged and tried again
// next tick — the same "log and continue" posture the reaper and reconciler
// already take toward their own periodic work, because a single failed
// sweep is not a reason to stop relaying traffic.
func (g *runningGateway) runBackstop(ctx context.Context) {
	ticker := time.NewTicker(g.backstopInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.sweepOnce(ctx)
		}
	}
}

func (g *runningGateway) sweepOnce(ctx context.Context) {
	sweepCtx, cancel := context.WithTimeout(ctx, gatewaySweepTimeout)
	defer cancel()

	candidates, err := g.backstopCandidates.Candidates(sweepCtx)
	if err != nil {
		g.log.warn("the backstop could not enumerate silent runs", "err", err)
	} else {
		retired, sweepErr := g.backstop.Sweep(sweepCtx, candidates)
		if sweepErr != nil {
			g.log.warn("the backstop sweep did not finish cleanly", "err", sweepErr)
		}
		if len(retired) > 0 {
			g.log.info("the silence backstop retired silent runs", "count", len(retired))
		}
	}

	// The session-end signal (ADR-0058 decision 7a, lifecycle.go's own
	// redesign): retires the main-agent run of every session whose signal
	// has stood uncancelled past its grace period. Swept alongside the
	// backstop rather than on its own goroutine -- both answer the same
	// question, silence, on independent clocks (lifecycle.go's own doc
	// comment).
	if g.sessionEnder != nil {
		retired, endErr := g.sessionEnder.Sweep(sweepCtx)
		if endErr != nil {
			g.log.warn("the session-end sweep did not finish cleanly", "err", endErr)
		}
		if len(retired) > 0 {
			g.log.info("a session-end signal retired runs after its grace period", "count", len(retired))
		}
	}
}

// Close releases the listener and every other resource openGateway opened.
// Safe to call after Serve and safe to call twice.
func (g *runningGateway) Close() {
	// g.ln can be nil here: openGateway calls Close on an error path that
	// may run before the listener is ever created (RM-235, #380's identity
	// stack is opened first, precisely so a failure there costs nothing
	// already holding a socket).
	if g.ln != nil {
		_ = g.ln.Close()
	}
	closers := g.closers
	g.closers = nil
	for _, closer := range closers {
		closer()
	}
}

// openGateway builds the gateway: an internal/gateway.Upstream, its Proxy,
// and a listener.
func openGateway(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
	boot, cancel := context.WithTimeout(ctx, gatewayBootTimeout)
	defer cancel()

	// The upstream's own construction lives in internal/gateway/upstream.go,
	// on its own: certificate and hostname strictness is NewUpstream's job
	// (#371), not repeated here. o.upstreamClient is nil on every
	// production and CLI-driven path (see gatewayOptions's own doc
	// comment), so a real deployment always gets NewUpstream's own
	// defaultUpstreamClient, which has no per-request Timeout of its own --
	// that would bound a whole streamed reply rather than one round trip,
	// see internal/gateway.NewUpstream's own doc comment.
	up, err := gateway.NewUpstream(o.upstream, o.upstreamClient)
	if err != nil {
		return nil, fmt.Errorf("configure the upstream: %w", err)
	}

	// GW-013 (#375, RM-230): a per-session rate limit, built from
	// -rate-limit-rate/-rate-limit-burst rather than
	// internal/gateway's own package-level defaultGuards, so the
	// configured values actually take effect here -- defaultGuards uses
	// the package's shipped defaults unconditionally (internal/gateway's
	// own guard.go), which is right for a caller that builds a bare Proxy
	// but not for this command line. o.validate already refused a
	// non-positive rate or burst before this function was ever called, so
	// the only way NewSessionRateLimiter fails here is a defect in that
	// check.
	rateLimit, err := gateway.NewSessionRateLimiter(gateway.SessionRateLimit{
		Rate:  o.rateLimitRate,
		Burst: o.rateLimitBurst,
	})
	if err != nil {
		return nil, fmt.Errorf("configure the per-session rate limit: %w", err)
	}

	running := &runningGateway{shutdownTimeout: o.shutdownTimeout, log: log}

	// RM-235 (#380): the identity stack, only when -dsn (or $INNSEGL_LEDGER_DSN)
	// names a database. See this file's own doc comment, "Identity from
	// traffic", for what stays unchanged when it does not.
	var identityGuard gateway.Guard
	var toolUse gateway.ToolUseObserver
	if o.dsn != "" {
		ig, ise, stackErr := openIdentityStack(boot, o, running)
		if stackErr != nil {
			running.Close()
			return nil, fmt.Errorf("configure the identity stack: %w", stackErr)
		}
		identityGuard, toolUse = ig, ise
	}

	proxy := &gateway.Proxy{
		Upstream: up,
		ToolUse:  toolUse,
		// gateway.Guards is internal/gateway's OWN ordered guard chain
		// (guard.go) -- the harness-shape guard, then (when identityGuard is
		// non-nil) the identity guard, then the rate-limit guard built from
		// rateLimit, in that order. This command does not maintain a
		// second, hand-written copy of that ordering: a guard added inside
		// Guards reaches this command line for free, with nothing here to
		// remember to update.
		Guards: gateway.Guards(rateLimit, identityGuard),
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(boot, "tcp", o.listen)
	if err != nil {
		running.Close()
		return nil, fmt.Errorf("listen on %s: %w", o.listen, err)
	}
	running.ln = ln

	mux := http.NewServeMux()
	// WithRetryAfterHeader sets the Retry-After header a GW-013 refusal
	// carries -- internal/gateway's Guard interface has no access to the
	// ResponseWriter to do that itself (limit.go's own doc comment explains
	// why), so this wraps the proxy handler specifically. It is a
	// transparent pass-through for every response this guard chain does not
	// refuse, streaming (GW-002) included.
	mux.Handle("/", gateway.WithRetryAfterHeader(proxy))
	if running.sessionEnder != nil {
		// gatewaySessionEndPath: see sessionEndHandler's own doc comment for
		// why this is minimal and local-only rather than a documented,
		// versioned part of the gateway's public contract.
		mux.HandleFunc(gatewaySessionEndPath, sessionEndHandler(running.sessionEnder, running.sessionEndRateLimit, log))
	}

	running.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: gatewayReadHeaderTimeout,
	}
	return running, nil
}

// gatewaySessionEndPath is the local-only delivery method ADR-0060 decision
// 6's session-end hook calls (E18, #389 later wires the hook itself). It is
// deliberately not a versioned, documented part of this gateway's public
// contract -- see sessionEndHandler's own doc comment -- so its path names
// itself as internal rather than looking like a stable API a caller outside
// this codebase might depend on.
const gatewaySessionEndPath = "/_gateway/session-end"

// gatewaySessionEndRateLimitKey is the one bucket sessionEndHandler's own
// rate limiter meters -- this endpoint has no per-caller identity to key
// on (that is exactly the threat this handler's own doc comment names), so
// every signal, from whatever process sent it, shares one bound.
const gatewaySessionEndRateLimitKey = "session-end"

// sessionEndHandler is ADR-0058 decision 7a's session-end signal, delivered
// as a loopback-only HTTP endpoint on this SAME listener.
//
// # The threat, stated plainly, and why it does not need solving here
//
// This process cannot tell the harness's own session-end hook apart from
// any OTHER process a user or an agent can run: ADR-0060 decision 7 puts
// the hook on the host as an ordinary process under the operator's own
// user, and an agent's own tool calls run as that same user with the same
// reach to this same loopback port. So this handler's own checks -- POST
// only, loopback only, a well-formed session id only, and a bounded rate --
// are a FLOOD and NOISE control, never an authentication one: they stop an
// obviously-wrong caller and stop this endpoint from being a cheap way to
// exhaust memory or spam retirements, but they do not and cannot tell a
// genuine hook from a forging agent. Nothing here decides that question,
// because nothing here has to: lifecycle.go's own SessionEnder answers it
// instead, by never retiring on receipt of a signal at all. A signal only
// marks a session; SessionEnder.Sweep retires the run it names only once
// the mark has stood uncancelled for a grace period, and ANY request from
// that session's main agent in the meantime cancels it (identity.go). A
// forged signal against a session that is still genuinely talking is
// cancelled before it ever matters; a forged signal against a session that
// has genuinely gone quiet only accelerates, by the grace period, a
// retirement the ordinary silence backstop would have made anyway for the
// identical reason. See lifecycle.go's own doc comment on this redesign for
// the full argument -- this handler's job is only to keep the SIGNAL itself
// cheap to receive and impossible to use as a memory-exhaustion vector, and
// to make every signal -- forged or not -- visible in the operational log,
// so a flood of them is something an operator can SEE even though it
// retires nothing on its own.
//
// Kept deliberately minimal and undocumented as a public contract: one
// method, one JSON field, one call into gateway.SessionEnder.SessionEnded.
func sessionEndHandler(ender *gateway.SessionEnder, rateLimit *gateway.SessionRateLimiter, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "innsegl gateway: session end: only POST is accepted", http.StatusMethodNotAllowed)
			return
		}
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			// Belt and suspenders over the compose publish line (ADR-0060
			// decision 2): this process itself refuses a caller whose
			// connection did not come from loopback, rather than resting
			// entirely on the network topology being right.
			http.Error(w, "innsegl gateway: session end: refused from a non-loopback address",
				http.StatusForbidden)
			return
		}
		if retryAfter, refused := rateLimit.Allow(r.Context(), gatewaySessionEndRateLimitKey); refused {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
			http.Error(w, "innsegl gateway: session end: too many signals", http.StatusTooManyRequests)
			return
		}
		var in struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !gateway.IsSessionID(in.SessionID) {
			http.Error(w, "innsegl gateway: session end: a JSON body naming a well-formed session_id "+
				"is required", http.StatusBadRequest)
			return
		}
		// Recorded regardless of what SessionEnded does with it: a forged
		// signal retires nothing (see this handler's own doc comment), but
		// it is still visible here, which is the whole of what makes a
		// flood of them something an operator can notice.
		log.info("session-end signal received", "session_id", in.SessionID)
		if err := ender.SessionEnded(r.Context(), in.SessionID); err != nil {
			http.Error(w, "innsegl gateway: session end: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// isLoopbackRemoteAddr reports whether remoteAddr -- an *http.Request's own
// RemoteAddr, host:port form -- names a loopback address. A RemoteAddr this
// function cannot parse at all is never loopback by assumption: refusing an
// unparseable caller is the same "refuse rather than guess" posture
// harness.go's own recognisers already take.
func isLoopbackRemoteAddr(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// openIdentityStack builds RM-235 (#380)'s identity stack: a Postgres-backed
// MappingStore and RunStateReader on o.dsn (ADR-0060 decision 3, the SAME
// database the ledger already uses), the MCP's own register_agent,
// retire_agent and describe_workspace reached in process (registrar.go,
// workspace.go -- never configured here; see this file's own doc comment),
// the tree linker, the shipped LifecyclePolicy, and the silence backstop,
// wired onto running so Serve can sweep it and Close can release every
// pool this function opens. It returns the identity guard, the tool-use
// spawn recorder (Proxy.ToolUse) and the SessionEnder for the loopback
// session-end endpoint.
func openIdentityStack(
	ctx context.Context, o gatewayOptions, running *runningGateway,
) (gateway.Guard, gateway.ToolUseObserver, error) {
	mappings, err := gateway.OpenPostgresMappingStore(ctx, o.dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open the run mapping store: %w", err)
	}
	running.closers = append(running.closers, mappings.Close)

	store, err := ledger.Open(ctx, o.dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open the ledger: %w", err)
	}
	running.closers = append(running.closers, store.Close)

	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		return nil, nil, fmt.Errorf("build the run directory: %w", err)
	}
	runStates := gateway.NewCredentialRunStates(dir, ledger.RestoreHorizonFromEnv(), nil)

	tree := gateway.NewInMemoryTreeLinker(gateway.TreeLinkerConfig{})
	registrar := gateway.NewMCPRegistrar()
	resolver := gateway.NewMCPWorkspaceResolver()

	// RM-235 (#380) code review: the session-end signal never retires by
	// itself -- see lifecycle.go's own doc comment. sessionEndSignals is
	// shared between the identity guard (Cancel, on every further request)
	// and the SessionEnder built below (Mark, via the endpoint; Sweep, on
	// running.sessionEnder's own ticker).
	sessionEndSignals := gateway.NewSessionEndSignals(0)

	identityGuard, err := gateway.NewIdentityGuard(gateway.IdentityGuardConfig{
		Mappings:          mappings,
		Tree:              tree,
		Policy:            gateway.NewPolicy(),
		Registrar:         registrar,
		Workspaces:        resolver,
		RunStates:         runStates,
		SessionEndSignals: sessionEndSignals,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build the identity guard: %w", err)
	}

	candidates, err := gateway.OpenSilentRunCandidates(ctx, o.dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open the silent-run enumeration: %w", err)
	}
	running.closers = append(running.closers, candidates.Close)

	backstop, err := gateway.NewBackstop(gateway.BackstopConfig{
		Registrar: registrar,
		Horizon:   backstopHorizonFromEnv(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build the silence backstop: %w", err)
	}
	running.backstop = backstop
	running.backstopCandidates = candidates
	running.backstopInterval = o.backstopInterval

	sessionEndRateLimit, err := gateway.NewSessionRateLimiter(gateway.SessionRateLimit{
		Rate: sessionEndRateLimitRate, Burst: sessionEndRateLimitBurst,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("build the session-end rate limit: %w", err)
	}
	running.sessionEnder = gateway.NewSessionEnder(sessionEndSignals, mappings, registrar, sessionEndGraceFromEnv(), nil)
	running.sessionEndRateLimit = sessionEndRateLimit

	spawnRecorder := gateway.NewSpawnRecorder(tree, nil)
	return identityGuard, spawnRecorder, nil
}

// sessionEndRateLimitRate and sessionEndRateLimitBurst bound
// sessionEndHandler's own request rate (see that handler's doc comment for
// why this is a flood control, not an authentication one). This endpoint
// carries no meaningful legitimate traffic beyond a few signals per
// session end, so these are deliberately far below the model-traffic rate
// limit's own defaults (DefaultSessionRateLimitRate/Burst).
const (
	sessionEndRateLimitRate  = 5
	sessionEndRateLimitBurst = 20
)

// sessionEndGraceFromEnv reads gateway.EnvSessionEndGrace, the same way
// backstopHorizonFromEnv reads its own variable: unset, unparseable or
// non-positive all fall back to gateway.DefaultSessionEndGrace.
func sessionEndGraceFromEnv() time.Duration {
	d, err := time.ParseDuration(os.Getenv(gateway.EnvSessionEndGrace))
	if err != nil || d <= 0 {
		return gateway.DefaultSessionEndGrace
	}
	return d
}

// backstopHorizonFromEnv reads gateway.EnvBackstopHorizon, the same way
// ledger.RestoreHorizonFromEnv reads its own variable: unset, unparseable
// or negative all fall back to gateway.DefaultBackstopHorizon rather than
// to zero, which means something else (gateway.NewBackstop's own doc
// comment: "there is no reading of a negative silence horizon that means
// anything a deployment would choose on purpose").
func backstopHorizonFromEnv() time.Duration {
	d, err := time.ParseDuration(os.Getenv(gateway.EnvBackstopHorizon))
	if err != nil || d < 0 {
		return gateway.DefaultBackstopHorizon
	}
	return d
}

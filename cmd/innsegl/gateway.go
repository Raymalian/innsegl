// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
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
)

// gatewayOptions is the resolved command line.
type gatewayOptions struct {
	listen          string
	upstream        string
	shutdownTimeout time.Duration

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

	o := gatewayOptions{listen: *listen, upstream: *upstream, shutdownTimeout: *shutdownTimeout}
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
}

func (g *runningGateway) Addr() string { return g.ln.Addr().String() }

// Serve runs the listener until ctx is done or it fails, then stops it in
// an orderly way — the same shape `runningServer.Serve` and
// `runningAPI.Serve` already use.
func (g *runningGateway) Serve(ctx context.Context) error {
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

// Close releases the listener. Safe to call after Serve and safe to call
// twice.
func (g *runningGateway) Close() {
	_ = g.ln.Close()
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

	proxy := &gateway.Proxy{Upstream: up}

	var lc net.ListenConfig
	ln, err := lc.Listen(boot, "tcp", o.listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", o.listen, err)
	}

	return &runningGateway{
		server: &http.Server{
			Handler:           proxy,
			ReadHeaderTimeout: gatewayReadHeaderTimeout,
		},
		ln:              ln,
		shutdownTimeout: o.shutdownTimeout,
		log:             log,
	}, nil
}

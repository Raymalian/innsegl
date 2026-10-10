// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/mirror"
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
// MCP's own register_agent/retire_agent reached in process
// (internal/gateway's registrar.go -- this file
// does not configure those tools itself; when this command runs as `serve
// -also gateway`, servewiring.go already has, and this is simply another
// caller of what is already wired; with no MCP tool configured in this same
// process, every registration attempt is refused exactly as
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

	// envGatewayCAKeyDir / envGatewayCACertDir: RM-246 (#391). The
	// gateway's own TLS listener (see this file's own doc comment,
	// "https-only listener") is a certificate from a CA this deployment
	// owns (internal/gateway.CA). envGatewayCAKeyDir names the directory
	// holding the CA's PRIVATE key -- in a compose deployment, a named
	// Docker volume mounted into no other service (deploy/compose/innsegl.yml's
	// innsegl-gateway-ca-key). envGatewayCACertDir names the directory the
	// CA's PUBLIC certificate is (re)published to on every start -- in a
	// compose deployment, a host bind mount ($HOME/.innsegl/ca), so
	// internal/commitpath's host commands (`innsegl git-hook`, `innsegl
	// sign`) can find and trust exactly it.
	envGatewayCAKeyDir  = "INNSEGL_GATEWAY_CA_KEY_DIR"
	envGatewayCACertDir = "INNSEGL_GATEWAY_CA_CERT_DIR"

	// envGatewayBackstopInterval configures how often the silence backstop
	// (gateway.Backstop, ADR-0058 decision 7c) sweeps. gateway.EnvBackstopHorizon
	// (INNSEGL_GATEWAY_SILENCE_AFTER, internal/gateway/lifecycle.go) is the
	// horizon itself and is read directly, without a second flag of its own
	// here, so that this command and any other future caller of
	// gateway.NewBackstop read the identical setting from the identical
	// variable.
	envGatewayBackstopInterval = "INNSEGL_GATEWAY_BACKSTOP_INTERVAL"

	// envAgentMessageKeyID configures which derived key RM-237 (#382)'s
	// agent_message recorder keys payload_digest under (ADR-0061 decision 2
	// and its 2026-09-28 amendment). mcp.ValidateAgentMessageKeyID holds
	// whatever this names to doc 02 §5's identifier grammar; a value that
	// fails it is refused at start-up (gatewayOptions.validate), before
	// anything is relayed, exactly as every other malformed setting in this
	// file is.
	envAgentMessageKeyID = "INNSEGL_AGENT_MESSAGE_KEY_ID"

	// envMessageKeyDir names where this process writes RM-237's own derived
	// agent-message key — the SAME value mcp.DeriveAgentMessageKey computes
	// from -identity-secret and -agent-message-key-id, restated to a file
	// named by the key id (E19, #395-#397: the run page's own read of a
	// brief or an assistant turn). A named Docker volume mounted read-write
	// here and read-only into innsegl-api in a compose deployment — the
	// CHECK-ONLY half of the key's own capability: it computes a message
	// digest and nothing else, because it IS the digest key, not the
	// identity secret it was derived from. OPTIONAL: unset means the key is
	// still derived and still used to key agent_message.payload_digest
	// exactly as before RM-237 — it is simply never written anywhere a
	// reader could find it, and the run page's Brief/Replies stay
	// unavailable — the same "unset means off" posture every other
	// optional setting in this file takes.
	envMessageKeyDir = "INNSEGL_MCP_MESSAGE_KEY_DIR"

	// envGatewayClientAuth switches hosted mode on (RM-284, #460; ADR-0063):
	// "spiffe" makes every client-facing route require an enrolled client's
	// certificate. Unset is single-host mode, exactly as before.
	envGatewayClientAuth = "INNSEGL_GATEWAY_CLIENT_AUTH"
	// envGatewayAccountsDSN is the accounts writer (the auth-writer role)
	// enrolment and renewal write through. The gateway's own ledger role
	// only reads installations and grants. Required in hosted mode.
	envGatewayAccountsDSN = "INNSEGL_GATEWAY_ACCOUNTS_DSN"
)

// clientAuthSPIFFE is the one hosted-mode value of -client-auth.
const clientAuthSPIFFE = "spiffe"

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

	// defaultAgentMessageKeyID is what a deployment that never rotated the
	// agent-message key uses. It is one deployment-wide label, not a
	// per-deployment secret -- ADR-0061's own key is derived from
	// -identity-secret, which IS per-deployment (agentmessagekey.go's own
	// doc comment) -- so a shared literal default costs nothing: rotating
	// away from it is deploying a new -agent-message-key-id, at which point
	// this default is simply the id an event minted before that rotation
	// stays verifiable under, forever.
	defaultAgentMessageKeyID = "gateway-v1"
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

	// caKeyDir and caCertDir are RM-246 (#391)'s own settings: where the
	// gateway's own TLS certificate authority keeps its private key, and
	// where its public certificate is published. BOTH ARE REQUIRED, WITH NO
	// FALLBACK DEFAULT -- deliberately. An earlier version of this file
	// defaulted them to $HOME-relative paths for a bare `innsegl gateway`
	// run outside compose, and that default is exactly what let an
	// incompletely-updated test write a real CA private key to a
	// developer's own $HOME (caught in review, never shipped): a caller
	// that forgets these two flags is a caller that has not decided where a
	// private key lives, and a filesystem-touching guess is the wrong
	// answer to that, every time. validate refuses either one empty before
	// LoadOrCreateCA is ever called. A compose deployment sets both to the
	// container's own mount points (envGatewayCAKeyDir/envGatewayCACertDir's
	// own doc comment); every one of this package's own tests that drives a
	// real listener sets both to a temporary directory (gatewayTestCADirs,
	// gateway_test.go) -- see TestGatewayCommandRefusesWithNoCADirsConfigured
	// for the regression this holds.
	caKeyDir  string
	caCertDir string

	// dsn is RM-235 (#380)'s one new, OPTIONAL setting: the ledger database
	// the identity stack reads and writes (ADR-0060 decision 3). Empty means
	// no identity guard, no backstop, no session-end endpoint -- exactly
	// this command's behaviour before this issue. See this file's own doc
	// comment, "Identity from traffic".
	dsn string
	// backstopInterval is how often the silence backstop sweeps, once dsn is
	// set. validate refuses a non-positive value.
	backstopInterval time.Duration

	// identitySecret is RM-237 (#382)'s own OPTIONAL setting: the SAME
	// per-deployment secret serve's own -identity-secret (or
	// -identity-secret-file) derives run tokens and pseudonyms from
	// (RM-079, RM-084, RM-212), resolved the identical way here
	// (resolveGatewayIdentitySecret) so the two commands can never disagree
	// about what it is. Empty means no agent_message is ever recorded from
	// this gateway -- logged once at start-up (configureGatewayAgentMessages)
	// -- exactly the same "unset means off" posture dsn itself has for the
	// rest of RM-235's identity stack.
	identitySecret string
	// agentMessageKeyID is RM-237's own key id (ADR-0061's 2026-09-28
	// amendment): validated against doc 02 §5's grammar at start-up
	// (validate, below), defaulted to defaultAgentMessageKeyID. Meaningless
	// on its own when identitySecret is empty -- there is no key to derive
	// an id for -- but validated regardless, so a malformed value is caught
	// before a deployment relies on it, whether or not it also set a
	// secret yet.
	agentMessageKeyID string
	// messageKeyDir is where the derived agent-message key is written, by
	// key id — see envMessageKeyDir's own doc comment. OPTIONAL like
	// identitySecret itself; empty means the key is derived and used exactly
	// as before RM-237 but never written to disk.
	messageKeyDir string

	// clientAuth is "" (single-host) or clientAuthSPIFFE (hosted, RM-284).
	clientAuth string
	// accountsDSN is the accounts writer enrolment and renewal use. Required
	// in hosted mode, unused otherwise.
	accountsDSN string

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
// exposureEnv answers checkGatewayExposure from the environment for the bind
// address and from the parsed option for client authentication, so the flag
// counts the same as $INNSEGL_GATEWAY_CLIENT_AUTH.
func (o gatewayOptions) exposureEnv(key string) string {
	if key == envGatewayClientAuth {
		return o.clientAuth
	}
	return os.Getenv(key)
}

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
	case o.caKeyDir == "":
		return "-ca-key-dir (or $" + envGatewayCAKeyDir + ") is required (RM-246)"
	case o.caCertDir == "":
		return "-ca-cert-dir (or $" + envGatewayCACertDir + ") is required (RM-246)"
	case checkGatewayExposure(o.exposureEnv) != nil:
		// The deployment publishes this gateway beyond loopback ($INNSEGL_BIND)
		// and it would not authenticate its clients (ADR-0063, ADR-0030 as
		// amended): refuse to start rather than serve the network unchecked.
		return checkGatewayExposure(o.exposureEnv).Error()
	case o.clientAuth != "" && o.clientAuth != clientAuthSPIFFE:
		return fmt.Sprintf("-client-auth (or $%s) %q: the only value is %q (hosted mode); unset is single-host mode",
			envGatewayClientAuth, o.clientAuth, clientAuthSPIFFE)
	case o.clientAuth == clientAuthSPIFFE && o.dsn == "":
		return "-client-auth " + clientAuthSPIFFE + " needs -dsn (or $" + envLedgerDSN + "): hosted mode reads " +
			"installations and records runs in the ledger database"
	case o.clientAuth == clientAuthSPIFFE && o.accountsDSN == "":
		return "-client-auth " + clientAuthSPIFFE + " needs -accounts-dsn (or $" + envGatewayAccountsDSN + "): " +
			"enrolment and renewal write installations through the accounts writer"
	case o.clientAuth == clientAuthSPIFFE && os.Getenv(mirror.EnvDir) == "":
		return "-client-auth " + clientAuthSPIFFE + " needs $" + mirror.EnvDir + ": a hosted client's commits " +
			"are read from the core's mirror before they are signed, and the mirror is evidence (ADR-0065)"
	}
	if problem := upstreamMustBeHTTPS(o.upstream); problem != "" {
		return problem
	}
	if err := mcp.ValidateAgentMessageKeyID(o.agentMessageKeyID); err != nil {
		return fmt.Sprintf("-agent-message-key-id (or $%s) %q: %v",
			envAgentMessageKeyID, o.agentMessageKeyID, err)
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

// runGateway is the whole command: parse, open, serve. `serve -also
// gateway` runs it as a goroutine in this process instead of a fifth
// container (ADR-0060 decision 1), on serve's own context: SIGINT and
// SIGTERM stop it with the process (OPS-177). Nothing here decides identity
// or writes the ledger, so a process killed mid-request loses a relay in
// flight and nothing else.
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
		identitySecret = fs.String("identity-secret", os.Getenv(envIdentitySecret),
			"the SAME per-deployment secret serve's own -identity-secret derives run tokens "+
				"and pseudonyms from -- RM-237 (#382) keys agent_message.payload_digest from it "+
				"too (ADR-0061 decision 2). OPTIONAL: unset means no agent_message is ever "+
				"recorded from this gateway ($"+envIdentitySecret+")")
		identitySecretFile = fs.String("identity-secret-file", os.Getenv(envIdentitySecretFile),
			"file holding the secret, instead of -identity-secret -- the SAME file serve's own "+
				"-identity-secret-file names ($"+envIdentitySecretFile+")")
		agentMessageKeyID = fs.String("agent-message-key-id",
			envOr(envAgentMessageKeyID, defaultAgentMessageKeyID),
			"doc 02 §5 identifier naming which derived key RM-237's agent_message.payload_digest "+
				"is under (ADR-0061's 2026-09-28 amendment); rotate by deploying a new value here "+
				"-- an event minted under an earlier id stays verifiable under that id forever "+
				"($"+envAgentMessageKeyID+")")
		caKeyDir = fs.String("ca-key-dir", os.Getenv(envGatewayCAKeyDir),
			"directory holding the gateway's own TLS certificate authority's PRIVATE key, "+
				"created 0700 -- a named Docker volume mounted into the core and NOTHING else "+
				"in a compose deployment (RM-246, #391). REQUIRED: no default, on purpose -- "+
				"see gatewayOptions.caKeyDir's own doc comment ($"+envGatewayCAKeyDir+")")
		caCertDir = fs.String("ca-cert-dir", os.Getenv(envGatewayCACertDir),
			"directory the gateway's own CA certificate (public) is published to on every "+
				"start -- a host bind mount in a compose deployment, so the host commands "+
				"(internal/commitpath) can find and trust exactly it. REQUIRED: no default "+
				"($"+envGatewayCACertDir+")")
		messageKeyDir = fs.String("message-key-dir", os.Getenv(envMessageKeyDir),
			"directory the derived agent-message key (RM-237, ADR-0061 decision 2) is written "+
				"to, by key id -- a named Docker volume mounted read-write here and read-only "+
				"into innsegl-api in a compose deployment (E19, #395-#397), so the run page's "+
				"query API can VERIFY a brief or a reply's own digest without ever holding "+
				"-identity-secret itself. OPTIONAL: unset means the key is still derived and "+
				"used, just never written anywhere ($"+envMessageKeyDir+")")
		clientAuth = fs.String("client-auth", os.Getenv(envGatewayClientAuth),
			"\""+clientAuthSPIFFE+"\" for hosted mode: every client-facing route requires an enrolled "+
				"client's certificate, and /_core/enrol and /_core/renew are served (ADR-0063). Unset is "+
				"single-host mode ($"+envGatewayClientAuth+")")
		accountsDSN = fs.String("accounts-dsn", os.Getenv(envGatewayAccountsDSN),
			"accounts writer connection string enrolment and renewal write through; required in hosted "+
				"mode -- prefer the environment variable ($"+envGatewayAccountsDSN+")")
	)

	fs.Usage = func() { gatewayUsage(stderr, fs) }

	redactCredentialDefaults(fs)
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

	resolvedSecret, secretProblem := resolveGatewayIdentitySecret(*identitySecret, *identitySecretFile)
	if secretProblem != "" {
		fprintf(stderr, "innsegl gateway: %s\n", secretProblem)
		return gatewayOptions{}, exitUsage, false
	}

	o := gatewayOptions{
		listen:            *listen,
		upstream:          *upstream,
		shutdownTimeout:   *shutdownTimeout,
		rateLimitRate:     *rateLimitRate,
		rateLimitBurst:    *rateLimitBurst,
		dsn:               *dsn,
		backstopInterval:  *backstopInterval,
		identitySecret:    resolvedSecret,
		agentMessageKeyID: *agentMessageKeyID,
		messageKeyDir:     *messageKeyDir,
		caKeyDir:          *caKeyDir,
		caCertDir:         *caCertDir,
		clientAuth:        *clientAuth,
		accountsDSN:       *accountsDSN,
	}
	if problem := o.validate(); problem != "" {
		fprintf(stderr, "innsegl gateway: %s\n", problem)
		return gatewayOptions{}, exitUsage, false
	}
	return o, exitOK, true
}

// resolveGatewayIdentitySecret reads -identity-secret-file into the
// resolved secret, or reports the configuration problem that stops this
// command starting -- the SAME two-sources-one-secret rule
// serveOptions.resolveIdentitySecret (serve.go) already enforces for
// `serve`'s own -identity-secret/-identity-secret-file, restated here
// rather than shared as a method: the two option types agree on what the
// rule says, not on how their own fields are named, and gatewayOptions has
// no serveOptions to call it on. secretFile empty means secret (however it
// was set, including "") is used as given -- the OPTIONAL, unset-means-off
// case this file's own doc comments describe throughout.
func resolveGatewayIdentitySecret(secret, secretFile string) (resolved, problem string) {
	if secretFile == "" {
		return secret, ""
	}
	if secret != "" {
		return "", "-identity-secret and -identity-secret-file (or $" + envIdentitySecret +
			" and $" + envIdentitySecretFile + ") are both set: two sources for one secret " +
			"is a configuration that can disagree with itself. Supply exactly one"
	}
	body, err := os.ReadFile(filepath.Clean(secretFile))
	if err != nil {
		return "", "-identity-secret-file (or $" + envIdentitySecretFile + "): " + err.Error() +
			". A deployment that generates the secret into a volume must run that one-shot to " +
			"completion before this process starts"
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", "-identity-secret-file (or $" + envIdentitySecretFile + ") " + secretFile +
			" holds no secret: an empty or half-written file must not become a zero-length key"
	}
	return trimmed, ""
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
	server *http.Server

	// commitResolver is set with the identity stack: the relayed tool calls
	// the commit path authorises against (mountCommitPath).
	commitResolver commitpath.Resolver

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
	// sessionWorkspaces is where the session hook states each session's
	// working directory; the identity guard reads it. Set alongside
	// sessionEnder.
	sessionWorkspaces *gateway.SessionWorkspaces
	// sessionWorkspaceRateLimit bounds sessionWorkspaceHandler's rate.
	sessionWorkspaceRateLimit *gateway.SessionRateLimiter
	// callers decides who the session endpoints admit: this machine in
	// single-host mode, the verified installation in hosted mode.
	callers sessionCallers

	// dashboardCert keeps the dashboard's certificate current (RM-311);
	// nil when $INNSEGL_DASHBOARD_TLS_DIR is unset.
	dashboardCert *dashboardCert

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
	if g.dashboardCert != nil {
		go g.dashboardCert.run(ctx)
	}

	failed := make(chan error, 1)
	go func() {
		// ServeTLS, not Serve: g.server.TLSConfig carries the gateway's own
		// CA's GetCertificate (RM-246, #391), and the empty certFile/keyFile
		// arguments are exactly what ServeTLS documents for a TLSConfig that
		// already populates GetCertificate -- there is no cert/key FILE
		// pair for this listener at all, only the CA's own in-memory issuer.
		err := g.server.ServeTLS(g.ln, "", "")
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

	// RM-284 (#460): hosted mode, before the identity stack, which pins
	// sessions and checks scope through what this builds.
	var hosted *hostedCore
	if o.clientAuth == clientAuthSPIFFE {
		h, hostErr := openHostedCore(boot, o, running)
		if hostErr != nil {
			running.Close()
			return nil, fmt.Errorf("configure hosted mode: %w", hostErr)
		}
		hosted = h
	}

	// RM-235 (#380): the identity stack, only when -dsn (or $INNSEGL_LEDGER_DSN)
	// names a database. See this file's own doc comment, "Identity from
	// traffic", for what stays unchanged when it does not.
	var identityGuard gateway.Guard
	var witnesses []gateway.Guard
	var toolUse gateway.ToolUseObserver
	var replyText gateway.ReplyTextObserver
	if o.dsn != "" {
		ig, wit, ise, rt, stackErr := openIdentityStack(boot, o, running, hosted)
		if stackErr != nil {
			running.Close()
			return nil, fmt.Errorf("configure the identity stack: %w", stackErr)
		}
		identityGuard, witnesses, toolUse, replyText = ig, wit, ise, rt
	}

	proxy := &gateway.Proxy{
		Upstream:  up,
		ToolUse:   toolUse,
		ReplyText: replyText,
		// gateway.Guards is internal/gateway's OWN ordered guard chain
		// (guard.go) -- the harness-shape guard, then (when identityGuard is
		// non-nil) the identity guard, then the rate-limit guard built from
		// rateLimit, then every witness in witnesses, in that order. This
		// command does not maintain a second, hand-written copy of that
		// ordering: a guard added inside Guards reaches this command line
		// for free, with nothing here to remember to update.
		Guards: gateway.Guards(rateLimit, identityGuard, witnesses...),
	}
	// The gateway sees a subagent finish (its final reply ends the turn and
	// asks for no tool) and marks it, as SubagentStop does from the hook.
	if running.sessionEnder != nil {
		proxy.SubagentEnds = running.sessionEnder
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(boot, "tcp", o.listen)
	if err != nil {
		running.Close()
		return nil, fmt.Errorf("listen on %s: %w", o.listen, err)
	}
	running.ln = ln

	// RM-246 (#391): the gateway's own listener serves TLS, from a CA this
	// deployment owns (internal/gateway.CA) rather than the system's public
	// root store. LoadOrCreateCA is deliberately AFTER the listen call
	// above, not before: an unbindable -listen address is refused without
	// ever touching -ca-key-dir/-ca-cert-dir, which matters for a
	// configuration that has not set them to anything writable either (the
	// two failures should not be conflated, and a test forcing the listen
	// failure alone should not have to configure a CA it will never reach).
	caConfig, err := gatewayCAConfig(o.caKeyDir, o.caCertDir, os.Getenv)
	if err != nil {
		running.Close()
		return nil, fmt.Errorf("configure the gateway's certificate names: %w", err)
	}
	ca, err := gateway.LoadOrCreateCA(caConfig)
	if err != nil {
		running.Close()
		return nil, fmt.Errorf("configure the gateway's own TLS certificate authority: %w", err)
	}

	if dir := os.Getenv(envDashboardTLSDir); dir != "" {
		d, dErr := openDashboardCert(ca, dir, log)
		if dErr != nil {
			running.Close()
			return nil, fmt.Errorf("write the dashboard's certificate ($%s): %w", envDashboardTLSDir, dErr)
		}
		running.dashboardCert = d
	}

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
		mux.HandleFunc(gatewaySessionEndPath, sessionEndHandler(running.sessionEnder, running.sessionEndRateLimit, running.callers, log))
	}
	if running.sessionWorkspaces != nil {
		mux.HandleFunc(gatewaySessionWorkspacePath, sessionWorkspaceHandler(
			running.sessionWorkspaces, running.sessionWorkspaceRateLimit, running.callers, log))
	}
	mountCommitPath(mux, running.commitResolver)
	mountTelemetry(mux, os.Getenv(envObserveBodyDir))
	if err := mountCoreJournal(mux, hosted, proxy, log); err != nil {
		running.Close()
		return nil, fmt.Errorf("mount the client-journal import: %w", err)
	}
	if err := mountCoreGit(mux, hosted); err != nil {
		running.Close()
		return nil, fmt.Errorf("mount the repository mirror's receive endpoint: %w", err)
	}

	var handler http.Handler = mux
	tlsConfig := ca.ServerTLSConfig()
	if hosted != nil {
		handler, tlsConfig = hosted.wrap(mux, tlsConfig, log) //nolint:contextcheck // each handshake's own context bounds its bundle read, not boot's
	}

	running.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: gatewayReadHeaderTimeout,
		TLSConfig:         tlsConfig,
	}
	return running, nil
}

// hostedCore is what hosted mode adds to the gateway (RM-284, #460;
// ADR-0063): the client-certificate guard, the session pins, the accounts
// writer enrolment and renewal use, and the authority they mint through.
type hostedCore struct {
	guard     *gateway.ClientGuard
	pins      *gateway.SessionPins
	scope     gateway.ScopeChecker
	writer    *accounts.Store
	authority clientAuthority
	// mirror is the per-repository evidence store (ADR-0065), nil when
	// INNSEGL_MIRROR_DIR is unset (coregit.go).
	mirror *mirror.Store
}

// openHostedCore builds hosted mode. The authority is the MCP's own admin
// client, published by serve (enrol.go, MCP-096): there is none to open
// here, and hosted mode refuses to start without it.
func openHostedCore(ctx context.Context, o gatewayOptions, running *runningGateway) (*hostedCore, error) {
	authority := publishedClientAuthority()
	if authority == nil {
		return nil, errors.New("hosted mode mints client certificates through the MCP's own SPIRE admin " +
			"client, and none was published in this process: run the gateway as `serve -also gateway`. " +
			"The gateway opens no admin identity of its own")
	}

	// Status and scope are read with the gateway's own ledger role, which
	// may SELECT installations and repo_grants and nothing else of the
	// account schema.
	pool, err := pgxpool.New(ctx, o.dsn)
	if err != nil {
		return nil, fmt.Errorf("open the installation reader: %w", err)
	}
	running.closers = append(running.closers, pool.Close)
	if perr := pool.Ping(ctx); perr != nil {
		return nil, fmt.Errorf("open the installation reader: %w", perr)
	}
	installations := accountsInstallations{store: accounts.New(pool)}

	writer, err := accounts.Open(ctx, o.accountsDSN)
	if err != nil {
		return nil, fmt.Errorf("open the accounts writer: %w", err)
	}
	running.closers = append(running.closers, writer.Close)

	limiter, err := gateway.NewSessionRateLimiter(gateway.SessionRateLimit{
		Rate: gateway.DefaultInstallationRateLimitRate, Burst: gateway.DefaultInstallationRateLimitBurst,
	})
	if err != nil {
		return nil, fmt.Errorf("build the per-installation rate limit: %w", err)
	}
	guard, err := gateway.NewClientGuard(gateway.ClientGuardConfig{
		TrustDomain:   authority.TrustDomain(),
		Bundle:        authority,
		Installations: installations,
		RateLimit:     limiter,
	})
	if err != nil {
		return nil, err
	}
	store, err := openCoreMirror(os.Getenv(mirror.EnvDir))
	if err != nil {
		return nil, err
	}
	return &hostedCore{
		guard: guard, pins: gateway.NewSessionPins(0), scope: firstUseScope{reader: installations, writer: writer},
		writer: writer, authority: authority, mirror: store,
	}, nil
}

// wrap puts the guard in front of every route but enrolment, serves renewal
// behind it, and has the TLS layer request (not require) a client
// certificate, naming the deployment's authorities as acceptable.
func (h *hostedCore) wrap(mux *http.ServeMux, base *tls.Config, log *serveLog) (http.Handler, *tls.Config) {
	mux.Handle(coreRenewPath, renewHandler(h.writer, h.authority, log))
	mux.Handle(coreDisconnectPath, disconnectHandler(h.writer, log))
	mux.Handle(coreStatusPath, statusHandler(h.writer, log))
	// ADR-0074: the encrypted trust-key backup, for the operator's machine.
	backup := trustBackupHandler(os.Getenv(envTrustBackupDir), h.writer, newBackupLimiter(nil), log)
	mux.Handle(coreTrustBackupPath, backup)
	mux.Handle(coreTrustBackupPath+"/", backup)
	// ADR-0076: the CA key store's unlock, for the same machine.
	custody := caCustodyHandler(os.Getenv(envCACustodianURL), h.writer, newCustodyLimiter(nil), log)
	mux.Handle(coreCACustodyPath, custody)
	mux.Handle(coreCACustodyPath+"/", custody)
	// #545: the operator author a machine reports, pinned on first use.
	mux.Handle(coreOperatorAuthorPath, operatorAuthorHandler(h.writer, log))

	outer := http.NewServeMux()
	outer.Handle(coreEnrolPath, enrolHandler(h.writer, h.authority, log))
	outer.Handle("/", h.guard.Wrap(mux))

	base.ClientAuth = tls.RequestClientCert
	cfg := base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.ClientCAs = h.guard.ClientCAs(hello.Context())
		return c, nil
	}
	return outer, cfg
}

// gatewaySessionEndPath is the local-only delivery method ADR-0060 decision
// 6's session-end hook calls (E18, #389 later wires the hook itself). It is
// deliberately not a versioned, documented part of this gateway's public
// contract -- see sessionEndHandler's own doc comment -- so its path names
// itself as internal rather than looking like a stable API a caller outside
// this codebase might depend on.
const gatewaySessionEndPath = "/_gateway/session-end"

// gatewaySessionWorkspacePath is where `innsegl hook session` states a
// session's working directory. Local-only and internal, like
// gatewaySessionEndPath.
const gatewaySessionWorkspacePath = "/_gateway/session-workspace"

// gatewaySessionWorkspaceRateLimitKey is sessionWorkspaceHandler's one
// rate-limit bucket, for the reason gatewaySessionEndRateLimitKey gives.
const gatewaySessionWorkspaceRateLimitKey = "session-workspace"

// maxWorkingDirectoryBytes bounds a stated directory: a path, not a payload.
const maxWorkingDirectoryBytes = 4096

// sessionWorkspaceHandler records the harness's own statement of where a
// session (and, with agent_id, one of its subagents) works. The statement may
// carry the workspace the client derived from its own tree (repo, worktree,
// branch, task, head: gatewaystatement.go), which the identity guard then uses
// without reading any filesystem. The hook sends
// it from the host on SessionStart, UserPromptSubmit, SubagentStart and
// CwdChanged; the identity guard registers a new run from it.
//
// In single-host mode, like sessionEndHandler, its checks are flood and noise
// controls, never authentication: an agent's own shell could post here too.
// A statement that names only a directory is refused, because the core reads
// no client tree (ADR-0071); one that names a repository is recorded as
// stated (workspaceregistry.go). In
// hosted mode (RM-284, #460) the client-certificate guard has verified the
// installation, a stated repository must be in its scope (claimed on first
// use; a statement naming none is a session outside any repository), and the session
// must be this installation's (hostedCallers, enrol.go).
func sessionWorkspaceHandler(ws *gateway.SessionWorkspaces, rateLimit *gateway.SessionRateLimiter,
	callers sessionCallers, log *serveLog,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "innsegl gateway: session workspace: only POST is accepted", http.StatusMethodNotAllowed)
			return
		}
		if !callers.admitRequest(r) {
			callers.refuseCaller(w, "session workspace")
			return
		}
		if retryAfter, refused := rateLimit.Allow(r.Context(), callers.rateKey(r, gatewaySessionWorkspaceRateLimitKey)); refused {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
			http.Error(w, "innsegl gateway: session workspace: too many statements", http.StatusTooManyRequests)
			return
		}
		var in sessionWorkspaceStatement
		if err := json.NewDecoder(io.LimitReader(r.Body, 4*maxWorkingDirectoryBytes)).Decode(&in); err != nil || !in.valid() {
			http.Error(w, "innsegl gateway: session workspace: a JSON body naming a well-formed session_id, "+
				"an optional agent_id, an absolute, clean cwd and, optionally, the derived repo (host/org/name), "+
				"branch, task, worktree and head is required", http.StatusBadRequest)
			return
		}
		// Hosted mode (RM-284, #460): the stated repository must be in the
		// installation's scope, and the session must be this installation's.
		// A refused statement records nothing, so no run is registered from it.
		verdict, err := callers.admitStatement(r.Context(), in.SessionID, in.stated())
		if err != nil {
			log.warn("a session workspace statement could not be checked", "err", err)
			http.Error(w, "innsegl gateway: session workspace: the scope check is unavailable; retry",
				http.StatusServiceUnavailable)
			return
		}
		switch verdict {
		case gateway.StatementAdmitted:
		case gateway.StatementOutOfScope:
			// Refused, so the hook can say so; the session's model requests
			// are forwarded unrecorded, never refused (RM-313).
			inst, _ := gateway.InstallationFromContext(r.Context())
			log.warn("finding: a session statement names a repository outside the installation's scope; "+
				"the session runs unrecorded", "reason", string(gateway.UnrecordedOutOfScope),
				"session_id", in.SessionID, "agent_id", in.AgentID, "installation_id", inst, "repo", in.Repo)
			callers.refuseCaller(w, "session workspace")
			return
		default:
			callers.refuseCaller(w, "session workspace")
			return
		}
		ws.RecordStated(in.SessionID, in.AgentID, in.stated())
		log.info("session workspace stated", "session_id", in.SessionID, "agent_id", in.AgentID)
		w.WriteHeader(http.StatusNoContent)
	}
}

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
func sessionEndHandler(ender *gateway.SessionEnder, rateLimit *gateway.SessionRateLimiter, callers sessionCallers, log *serveLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "innsegl gateway: session end: only POST is accepted", http.StatusMethodNotAllowed)
			return
		}
		if !callers.admitRequest(r) {
			// Belt and suspenders over the compose publish line (ADR-0060
			// decision 2): in single-host mode this process itself refuses a
			// caller whose connection did not come from loopback, rather
			// than resting entirely on the network topology being right. In
			// hosted mode the client-certificate guard decides instead.
			callers.refuseCaller(w, "session end")
			return
		}
		if retryAfter, refused := rateLimit.Allow(r.Context(), callers.rateKey(r, gatewaySessionEndRateLimitKey)); refused {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Round(time.Second)/time.Second)))
			http.Error(w, "innsegl gateway: session end: too many signals", http.StatusTooManyRequests)
			return
		}
		var in struct {
			SessionID string `json:"session_id"`
			// AgentID names a subagent that finished (the harness's
			// SubagentStop); empty for the session's own end.
			AgentID string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !gateway.IsSessionID(in.SessionID) ||
			!isAgentIDShape(in.AgentID) {
			http.Error(w, "innsegl gateway: session end: a JSON body naming a well-formed session_id "+
				"is required", http.StatusBadRequest)
			return
		}
		if !callers.admitSession(r.Context(), in.SessionID) {
			callers.refuseCaller(w, "session end")
			return
		}
		// Recorded regardless of what SessionEnded does with it: a forged
		// signal retires nothing (see this handler's own doc comment), but
		// it is still visible here, which is the whole of what makes a
		// flood of them something an operator can notice.
		log.info("session-end signal received", "session_id", in.SessionID, "agent_id", in.AgentID)
		var endErr error
		if in.AgentID != "" {
			endErr = ender.SubagentEnded(r.Context(), in.SessionID, in.AgentID)
		} else {
			endErr = ender.SessionEnded(r.Context(), in.SessionID)
		}
		if err := endErr; err != nil {
			http.Error(w, "innsegl gateway: session end: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// isAgentIDShape admits an empty agent id (the session's own end) or one a
// harness sends: letters, digits, dash and underscore, at most 128 bytes.
func isAgentIDShape(id string) bool {
	if len(id) > 128 {
		return false
	}
	for _, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

// openIdentityStack builds RM-235 (#380)'s identity stack: a Postgres-backed
// MappingStore and RunStateReader on o.dsn (ADR-0060 decision 3, the SAME
// database the ledger already uses), the MCP's own register_agent and
// retire_agent reached in process (registrar.go -- never configured here; see
// this file's own doc comment), a resolver that refuses a directory-only
// statement (workspace.go, ADR-0071),
// the tree linker, the shipped LifecyclePolicy, and the silence backstop,
// wired onto running so Serve can sweep it and Close can release every
// pool this function opens.
//
// RM-236 (#381), E16: this is also where the flight recorder's own
// witness is composed in. gateway.ToolCallRecorder pairs each tool_use a
// reply streams with the tool_result the next request carries for it and
// records one `tool_call` per pair through the MCP's own observe_tool_call
// service, in process (internal/mcp/gatewayrecord.go) -- the SAME
// observe_tool_call this same process's `serve -also gateway` already
// configures from `-observe-body-dir` (servewiring.go), reached here only
// through mcp.RecordGatewayToolCall's own package-level seam, never
// re-configured. A gateway whose process left observe_tool_call
// unconfigured records nothing either, exactly as failing to configure it
// already answers every other in-process caller (mcp.RecordGatewayToolCall's
// own doc comment): a logged, counted failure per attempt, never a reason
// to refuse a request.
//
// Its workspace-snapshot witness (ADR-0061 member 3) reuses
// envObserveBodyDir (serve.go), the SAME body-store volume observe_tool_call
// itself is configured onto (ADR-0060 decision 5: "inside the existing
// body-store volume") -- a dedicated subdirectory of it, never a second
// volume or a second flag. Unset, this recorder never attaches a
// workspace_tree_hash; every tool_call it records still carries the rest.
//
// RM-237 (#382), E16: the SECOND witness composed in here is the brief and
// assistant-text recorder, gateway.MessageRecorder, wired onto RM-237's own
// mcp.ConfigureAgentMessageRecorder by configureGatewayAgentMessages
// (below). Unlike observe_tool_call, this recorder's dependencies are built
// HERE, independently of servewiring.go: agent_message is not one of doc 01
// §4's eight tools (internal/mcp/agentmessage.go's own doc comment), so it
// has no reason to wait on that file's own tool-by-tool bookkeeping, and
// building it here is what makes it work identically whatever `serve`
// configured -- the companion always runs through this same function. (A
// standalone `innsegl gateway` command existed until ADR-0071.)
//
// guard.go's own Guards function now takes every witness as its own
// variadic parameter (that function's own doc comment), so this function
// returns the identity guard and its witnesses SEPARATELY rather than
// composing them into one Guard first (gateway.ChainGuards, RM-236's own
// stand-in for the room Guards used to have for exactly one identity slot,
// is gone: see Guards' own doc comment for why growing a second such list
// was worth closing rather than working around again here). Proxy still
// has exactly one ToolUse slot, so CombineToolUseObservers stays needed for
// that one -- record.go's own doc comment says why.
func openIdentityStack(
	ctx context.Context, o gatewayOptions, running *runningGateway, hosted *hostedCore,
) (identityGuard gateway.Guard, witnesses []gateway.Guard, toolUse gateway.ToolUseObserver, replyText gateway.ReplyTextObserver, err error) {
	mappings, err := gateway.OpenPostgresMappingStore(ctx, o.dsn)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open the run mapping store: %w", err)
	}
	running.closers = append(running.closers, mappings.Close)

	store, err := ledger.Open(ctx, o.dsn)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open the ledger: %w", err)
	}
	running.closers = append(running.closers, store.Close)

	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build the run directory: %w", err)
	}
	runStates := gateway.NewCredentialRunStates(dir, store, ledger.RestoreHorizonFromEnv(), nil)

	tree := gateway.NewInMemoryTreeLinker(gateway.TreeLinkerConfig{})
	registrar := gateway.NewMCPRegistrar()
	// The core reads no client tree (ADR-0071): a session that stated only
	// its directory is refused by name.
	resolver := gateway.NoTreeResolver{}

	// RM-235 (#380) code review: the session-end signal never retires by
	// itself -- see lifecycle.go's own doc comment. sessionEndSignals is
	// shared between the identity guard (Cancel, on every further request)
	// and the SessionEnder built below (Mark, via the endpoint; Sweep, on
	// running.sessionEnder's own ticker).
	sessionEndSignals := gateway.NewSessionEndSignals(0)
	// The marks survive a restart of the core (migration 0012): each is
	// written to the gateway's own append-only table, and the open ones are
	// reloaded here, so a restart inside a grace period loses none.
	sessionEndSignals.Persist(context.WithoutCancel(ctx), gateway.NewPostgresSessionEndStore(mappings.Pool()), func(format string, args ...any) {
		running.log.warn(fmt.Sprintf(format, args...))
	})
	if lerr := sessionEndSignals.Load(ctx, time.Now().Add(-gateway.SessionEndReload)); lerr != nil {
		running.log.warn("could not reload the session-end marks; sessions that ended before this start are retired by the backstop", "err", lerr)
	}
	sessionWorkspaces := gateway.NewSessionWorkspaces(0)

	cfg := gateway.IdentityGuardConfig{
		Mappings:          mappings,
		Tree:              tree,
		Policy:            gateway.NewPolicy(),
		Registrar:         registrar,
		Workspaces:        resolver,
		RunStates:         runStates,
		SessionEndSignals: sessionEndSignals,
		SessionWorkspaces: sessionWorkspaces,
	}
	// Hosted mode (RM-284, #460): sessions are pinned to an installation and
	// a run is registered only for a repository in its scope. The session
	// endpoints admit the verified installation instead of this machine.
	running.callers = localCallersFromHost()
	if hosted != nil {
		cfg.Pins, cfg.Scope = hosted.pins, hosted.scope
		running.callers = hostedCallers{scope: hosted.scope, pins: hosted.pins}
	}
	// RM-313: the client service's statement on a model request refills a
	// registry a restart emptied; what cannot be recorded is forwarded and
	// logged as a finding.
	cfg.HeaderStatements = headerStatements{callers: running.callers}
	cfg.OnUnrecorded = logUnrecorded(running.log)
	cfg.OnAgentTypeWitness = logAgentTypeWitness(running.log)
	identityGuard, err = gateway.NewIdentityGuard(cfg)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build the identity guard: %w", err)
	}

	candidates, err := gateway.OpenSilentRunCandidates(ctx, o.dsn)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("open the silent-run enumeration: %w", err)
	}
	running.closers = append(running.closers, candidates.Close)

	backstop, err := gateway.NewBackstop(gateway.BackstopConfig{
		Registrar: registrar,
		Horizon:   backstopHorizonFromEnv(),
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build the silence backstop: %w", err)
	}
	running.backstop = backstop
	running.backstopCandidates = candidates
	running.backstopInterval = o.backstopInterval

	sessionEndRateLimit, err := gateway.NewSessionRateLimiter(gateway.SessionRateLimit{
		Rate: sessionEndRateLimitRate, Burst: sessionEndRateLimitBurst,
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build the session-end rate limit: %w", err)
	}
	running.sessionEnder = gateway.NewSessionEnder(sessionEndSignals, mappings, registrar, sessionEndGraceFromEnv(), nil)
	running.sessionEndRateLimit = sessionEndRateLimit
	sessionWorkspaceRateLimit, err := gateway.NewSessionRateLimiter(gateway.SessionRateLimit{
		Rate: sessionWorkspaceRateLimitRate, Burst: sessionWorkspaceRateLimitBurst,
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build the session-workspace rate limit: %w", err)
	}
	running.sessionWorkspaces = sessionWorkspaces
	running.sessionWorkspaceRateLimit = sessionWorkspaceRateLimit

	spawnRecorder := gateway.NewSpawnRecorder(tree, nil)

	toolCallRecorder := gateway.NewToolCallRecorder(newToolCallRecorderConfig(running, hosted != nil))
	toolUse = gateway.CombineToolUseObservers(spawnRecorder, toolCallRecorder)

	// The commit path (ADR-0059, E17) authorises a commit by a git commit
	// tool call this recorder saw relayed and is still waiting on.
	restoreSignPayload, err := mcp.ConfigureSignPayload(mcp.SignPayloadConfig{
		Resolver: toolCallRecorder,
		ClaimFor: mcp.CommitClaimForRun,
		Mirror:   commitMirror(hosted),
		// #545: each installation's pinned operator author, admitted by
		// gate 3 for that installation's commits.
		OperatorAuthors: operatorAuthors(hosted),
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("configure the commit-sign path: %w", err)
	}
	running.closers = append(running.closers, restoreSignPayload)
	running.commitResolver = toolCallRecorder

	amRestore, err := configureGatewayAgentMessages(o, dir, store, running)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("configure agent-message recording: %w", err)
	}
	if amRestore != nil {
		running.closers = append(running.closers, amRestore)
	}
	messageGuard, err := gateway.NewMessageRecorder(gateway.MessageRecorderConfig{
		Recorder: gateway.NewMCPAgentMessageRecorder(),
	})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build the message recorder: %w", err)
	}

	witnesses = []gateway.Guard{gateway.NewToolCallRecordGuard(toolCallRecorder), messageGuard}
	// The message recorder also reads each reply's own text: an agent's
	// last reply is never resent in a later request (GREC-005).
	return identityGuard, witnesses, toolUse, messageGuard, nil
}

// configureGatewayAgentMessages wires RM-237 (#382)'s agent_message
// recorder for THIS process -- standalone `innsegl gateway -dsn` and
// `serve -also gateway` alike, since both run through openGateway ->
// openIdentityStack. Unlike observe_tool_call (servewiring.go's own,
// required before internal/gateway/record.go's ToolCallRecorder can record
// anything at all -- see openIdentityStack's own doc comment), this
// recorder's dependencies are built HERE: agent_message is not one of doc
// 01 §4's eight tools and has no reason to wait on servewiring.go's own
// tool-by-tool bookkeeping.
//
// dir and store are the SAME run directory and ledger openIdentityStack
// already built for the identity stack -- no second connection, no second
// CredentialRuns. idempotency is a NEW store built here, over the SAME dsn
// (store.Pool()): a stateless wrapper over one Postgres table, so a second
// instance of it disagrees with nobody. BodyDir reuses envObserveBodyDir --
// the SAME env var newGatewaySnapshotter already reads, for the identical
// reason: one volume, no new flag.
//
// Both identitySecret and the body directory are OPTIONAL; either being
// empty means no agent_message is ever recorded from this process, logged
// once here rather than failing start-up -- the same "unset means off"
// posture every other optional setting in this file takes. A restore
// function is returned only when Configure actually ran, so a caller need
// not guard against appending a nil closer.
func configureGatewayAgentMessages(
	o gatewayOptions, dir *rundir.Directory, store *ledger.Store, running *runningGateway,
) (func(), error) {
	bodyDir := os.Getenv(envObserveBodyDir)
	switch {
	case o.identitySecret == "":
		running.log.info("agent-message recording is not configured: -identity-secret " +
			"(or $" + envIdentitySecret + "/$" + envIdentitySecretFile + ") is unset, so no brief " +
			"or assistant turn will ever be recorded from this gateway")
		return nil, nil
	case bodyDir == "":
		running.log.info("agent-message recording is not configured: $" + envObserveBodyDir +
			" is unset, so there is nowhere to keep a recorded brief or message")
		return nil, nil
	}

	idem := mcp.NewIdempotencyStore(store.Pool())
	restore, err := mcp.ConfigureAgentMessageRecorder(mcp.AgentMessageRecorderConfig{
		Runs:           dir,
		Ledger:         store,
		Idempotency:    idem,
		BodyDir:        bodyDir,
		IdentitySecret: o.identitySecret,
		KeyID:          o.agentMessageKeyID,
	})
	if err != nil {
		return nil, err
	}

	// E19 (#395-#397): the run page's own read needs a way to VERIFY an
	// agent_message's own keyed digest without ever holding -identity-secret
	// -- see envMessageKeyDir's own doc comment for why the derived key,
	// restated to a file, is the whole answer. Derived a SECOND time here
	// (the call above already derived it, internally, to key every message
	// this recorder appends) rather than widening
	// mcp.ConfigureAgentMessageRecorder's own return to hand it back: the
	// derivation is a pure function of two values this process already
	// checked, and asking for it again costs one HMAC, never a discrepancy.
	if o.messageKeyDir != "" {
		key, derr := mcp.DeriveAgentMessageKey(o.identitySecret, o.agentMessageKeyID)
		if derr != nil {
			// Unreachable in practice: ConfigureAgentMessageRecorder above
			// already derived the identical key from the identical inputs
			// and would have refused first. Reported rather than ignored,
			// because a caller that reaches this branch has a real
			// question to answer.
			return restore, fmt.Errorf("re-deriving the agent-message key to write it: %w", derr)
		}
		if werr := writeMessageKeyFile(o.messageKeyDir, o.agentMessageKeyID, key); werr != nil {
			return restore, fmt.Errorf("writing the agent-message key for the run page's own "+
				"query API to verify with: %w", werr)
		}
		// The key itself is NEVER logged, here or anywhere else — only its
		// id and where it landed, both already public in this process's
		// own configuration.
		running.log.info("the run page's query API can verify agent-message digests",
			"message_key_dir", o.messageKeyDir, "key_id", o.agentMessageKeyID)
	}

	running.log.info("agent-message recording is configured",
		"body_dir", bodyDir, "key_id", o.agentMessageKeyID)
	return restore, nil
}

// writeMessageKeyFile idempotently writes keyBytes — RM-237's own derived
// agent-message key (mcp.DeriveAgentMessageKey), exactly as that function
// returns it: a hex-encoded string, used as-is (never re-decoded) as the
// HMAC-SHA256 key both DeriveAgentMessageKey's own caller and the run
// page's API key their digest computation with — to dir/<keyID>.
//
// ATOMIC: written to a temp file and renamed into place, so a reader (the
// API, mounted read-only on the same volume) can never observe a partial
// key. IDEMPOTENT: identical bytes already on disk are left alone rather
// than rewritten, which is what lets two gateway replicas starting at once
// -- or one restarting -- call this without racing each other into a
// corrupt file; DIFFERENT bytes under the same key id is refused outright,
// because that is a configuration problem (two different identity secrets,
// or two different derivations, claiming the same id) and never a rotation
// -- a rotation deploys a NEW key id (ADR-0061's 2026-09-28 amendment).
//
// 0400: read-only, owner only. innsegl-mcp and innsegl-api run as the
// IDENTICAL uid:gid in every deployment this project ships (both "1000:1000"
// in deploy/compose/innsegl.yml), so owner-read is sufficient for the
// reader on the other side of the read-only volume mount without widening
// the file to the group or to everyone.
func writeMessageKeyFile(dir, keyID, keyBytes string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// MkdirAll's own mode only applies to a directory it CREATES; a compose
	// deployment's mountpoint already exists (the image pre-creates it,
	// Dockerfile's own comment on /work and /sessions explains why), so its
	// permission bits are whatever the image gave it and this is the one
	// place they are enforced regardless — explicit, not assumed.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	path := filepath.Join(dir, keyID)

	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if string(existing) == keyBytes {
			return nil
		}
		return fmt.Errorf("%s already holds a different key under id %q; refusing to overwrite it — "+
			"two different derivations claiming one key id is a configuration problem, "+
			"never a rotation (deploy a new key id instead)", path, keyID)
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("read %s: %w", path, err)
	}

	tmp := path + ".part"
	if err := os.WriteFile(tmp, []byte(keyBytes), 0o400); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		if rerr := os.Remove(tmp); rerr != nil {
			return fmt.Errorf("rename %s to %s: %w (and cleaning up %s: %w)", tmp, path, err, tmp, rerr)
		}
		return fmt.Errorf("rename %s to %s: %w", tmp, path, err)
	}
	return nil
}

// newToolCallRecorderConfig builds RM-236 (#381)'s own
// gateway.ToolCallRecorderConfig: OnRecordFailure logs loudly through
// running's own log (this package's one structured logger), and Snapshots
// is set only when the workspace-snapshot store could actually be built
// -- never assigned a typed-nil *gateway.Snapshotter, which
// gateway.ToolCallRecorderConfig's own doc comment on Snapshots warns
// against for exactly this reason: an interface holding one is not itself
// nil.
func newToolCallRecorderConfig(running *runningGateway, hosted bool) gateway.ToolCallRecorderConfig {
	cfg := gateway.ToolCallRecorderConfig{
		Trigger: gateway.NewSnapshotTrigger(),
		OnRecordFailure: func(err error) {
			running.log.error("gateway: could not record a tool call", "err", err)
		},
	}
	if snap := newGatewaySnapshotter(running, hosted); snap != nil {
		cfg.Snapshots = snap
	}
	return cfg
}

// newGatewaySnapshotter builds ADR-0060 decision 5's per-repository
// snapshot store, inside a dedicated subdirectory of the SAME body-store
// volume observe_tool_call is configured onto (envObserveBodyDir,
// serve.go) -- no new flag, no new volume. Unset ($INNSEGL_MCP_LOG_DIR
// empty, or the value is not usable as an absolute store root), this
// returns nil and every tool_call this replica records simply carries no
// workspace_tree_hash -- ADR-0061 member 3 is optional for exactly this
// case, and a missing snapshotter is reported the same way a snapshot
// failure already is (record.go's own OnRecordFailure), once, at start-up,
// rather than once per request.
//
// A hosted core builds none (ADR-0060 decision 5, as amended 2026-10-03). The
// snapshot reads a working tree on this process's own disk, and on a hosted
// core no client's tree is there (ADR-0064 decision 2): it would record the
// core's own files as if they were the client's. Snapshots return to the
// hosted core only as snapshot refs a client pushes to the mirror (ADR-0065
// decision 3).
func newGatewaySnapshotter(running *runningGateway, hosted bool) *gateway.Snapshotter {
	if hosted {
		running.log.info("workspace snapshotting is off on a hosted core: no client's working " +
			"tree is on this disk (ADR-0064), so recorded tool calls carry no workspace_tree_hash " +
			"until clients push snapshot refs (ADR-0065)")
		return nil
	}
	root := os.Getenv(envObserveBodyDir)
	if root == "" {
		running.log.info("workspace snapshotting is not configured: " +
			"$" + envObserveBodyDir + " is unset, so recorded tool calls will carry no workspace_tree_hash")
		return nil
	}
	snap, err := gateway.NewSnapshotter(gateway.SnapshotConfig{
		StoreRoot: filepath.Join(root, "gateway-snapshots"),
	})
	if err != nil {
		running.log.warn("workspace snapshotting is not available; recorded tool calls will carry no "+
			"workspace_tree_hash", "err", err)
		return nil
	}
	return snap
}

// sessionEndRateLimitRate and sessionEndRateLimitBurst bound
// sessionEndHandler's own request rate (see that handler's doc comment for
// why this is a flood control, not an authentication one). This endpoint
// carries no meaningful legitimate traffic beyond a few signals per
// session end, so these are deliberately far below the model-traffic rate
// limit's own defaults (DefaultSessionRateLimitRate/Burst).
const (
	sessionEndRateLimitRate  = 20
	sessionEndRateLimitBurst = 100
)

// sessionWorkspaceRateLimitRate and sessionWorkspaceRateLimitBurst bound
// sessionWorkspaceHandler. The hook runs before every user turn, every
// subagent and every directory change, so a session with many parallel
// subagents sends bursts; the bound is a flood control, not a budget.
const (
	sessionWorkspaceRateLimitRate  = 20
	sessionWorkspaceRateLimitBurst = 100
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

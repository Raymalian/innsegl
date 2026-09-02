// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/api"
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
// # It holds no authentication, on purpose
//
// doc 05 §3 puts `dashboard.innsegl.dev` behind Cloudflare Access, and RM-062
// (#70) is the issue that does it. This process authenticates nobody. That is
// stated in the usage rather than half-solved here: an auth scheme invented in
// this file would be a second thing to review, a second thing to get wrong,
// and a second thing for a deployment to believe it had when it did not. What
// this command does enforce is the half that survives a misconfigured proxy —
// the credential cannot write, whoever reaches it.

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
	envAPIDSN             = "INNSEGL_API_DSN"
	envAPIListen          = "INNSEGL_API_LISTEN"
	envAPIRepos           = "INNSEGL_API_REPOS"
	envAPIShutdownTimeout = "INNSEGL_API_SHUTDOWN_TIMEOUT"
	envAPIUpstreamTimeout = "INNSEGL_API_UPSTREAM_TIMEOUT"
	envAPIGit             = "INNSEGL_GIT"
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
)

// apiRoutes is what this process serves, in the order the usage lists them.
// They are internal/api's, spelled here only so the usage can name them: a
// reverse proxy, a Cloudflare Access policy and a dashboard build all need to
// know what paths exist.
var apiRoutes = []string{
	"GET /api/v1/runs",
	"GET /api/v1/runs/{run_id}",
	"GET /api/v1/overview",
	"GET /api/v1/proof/{commit_sha}",
	"GET /api/v1/health",
}

// apiOptions is the resolved command line.
type apiOptions struct {
	dsn       string
	listen    string
	repos     map[string]string
	fulcioURL string
	rekorURL  string
	issuer    string
	gitPath   string

	shutdownTimeout time.Duration
	upstreamTimeout time.Duration
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
	// Repos names the repositories the proof BFF can answer about.
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
		"authentication", "none - this process authenticates nobody (doc 05 §3, #70)",
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
		repos = fs.String("repos", os.Getenv(envAPIRepos),
			"comma-separated name=path pairs naming the repositories the proof BFF answers "+
				"about, e.g. github.com/acme/app=/srv/repos/github.com/acme/app. A commit in "+
				"no listed repository is a 404, never an empty verdict ($"+envAPIRepos+")")
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

	parsed, err := parseRepos(*repos)
	if err != nil && *repos != "" {
		fprintf(stderr, "innsegl api: -repos (or $"+envAPIRepos+"): %v\n", err)
		return apiOptions{}, exitUsage, false
	}

	o := apiOptions{
		dsn: *dsn, listen: *listen, repos: parsed,
		fulcioURL: *fulcioURL, rekorURL: *rekorURL, issuer: *issuer, gitPath: *gitPath,
		shutdownTimeout: *shutdownTimeout, upstreamTimeout: *upstreamTimeout,
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
	case len(o.repos) == 0:
		return "-repos (or $" + envAPIRepos + ") is required: a proof BFF that serves no " +
			"repository can answer nothing, and guessing is not one of the states " +
			"doc 06 §4.6 allows"
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
	case o.shutdownTimeout < 0:
		return "-shutdown-timeout is negative"
	case o.upstreamTimeout < 0:
		return "-upstream-timeout is negative"
	}
	return ""
}

// parseRepos reads the name=path list.
//
// Every failure is a refusal rather than a skipped entry: a repository silently
// dropped from this map turns every proof request about it into "no repository
// this deployment serves holds that commit", which reads as a verdict about
// the commit and is a statement about the configuration.
func parseRepos(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("no repository was named")
	}
	out := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, path, found := strings.Cut(entry, "=")
		name, path = strings.TrimSpace(name), strings.TrimSpace(path)
		switch {
		case !found:
			return nil, fmt.Errorf("%q is not a name=path pair", entry)
		case name == "":
			return nil, fmt.Errorf("%q names no repository", entry)
		case path == "":
			return nil, fmt.Errorf("%q gives %s no path", entry, name)
		}
		if existing, dup := out[name]; dup {
			return nil, fmt.Errorf("%s is listed twice, as %s and %s", name, existing, path)
		}
		out[name] = path
	}
	if len(out) == 0 {
		return nil, errors.New("no repository was named")
	}
	return out, nil
}

// apiUsage is the help block. It states the two things a reader of a compose
// file cannot infer from the flags: that this process authenticates nobody,
// and that its read-only gate cannot be switched off.
func apiUsage(stderr io.Writer, fs *flag.FlagSet) {
	fprintf(stderr, "innsegl api - serve the dashboard's read-only query API and proof BFF "+
		"(doc 05 §1, doc 06 §7)\n\n")
	fprintf(stderr, "Usage:\n  innsegl api [flags]\n\n")
	fprintf(stderr, "Routes:\n")
	for _, route := range apiRoutes {
		fprintf(stderr, "  %s\n", route)
	}
	fprintf(stderr, "\nThis process holds NO AUTHENTICATION. It authenticates nobody and "+
		"authorises\nnothing: doc 05 §3 puts dashboard.innsegl.dev behind Cloudflare Access, "+
		"and\nRM-062 (#70) is the issue that does it. Do not expose this port to a network\n"+
		"you have not put an authenticating proxy in front of. The default -listen is\n"+
		"loopback for that reason.\n\n")
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

// sortedRepoNames is the repository list in a stable order, for the log line.
func sortedRepoNames(repos map[string]string) []string {
	out := make([]string, 0, len(repos))
	for name := range repos {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
	"innsegl.dev/innsegl/internal/spire"
)

// `innsegl retire <run_id>` — RM-154 (#257), run on the core (ADR-0077).
//
// # Why an operator needs this
//
// Nothing in this system can observe that an agent died. A harness can say a
// run ended, and its stop hook does; the reaper can say nothing has been heard
// from a run since a deadline, and that is a withdrawal of standing
// authorisation, not an ending. Neither is a human who KNOWS the run is over —
// the machine is gone, the work was abandoned, the session will not come back.
// This command is how that knowledge enters the record.
//
// # Where it runs, and why there
//
// The retirement itself is retire_agent's engine, unchanged: it appends
// `run_retired` and then deletes the run's SPIRE entry, in that order, with the
// ordering argument ADR-0018 settled. This command calls that engine IN
// PROCESS, through mcp.RetireRunForGateway, the same function the gateway's
// identity guard uses. It adds no event type, no field, no error class and no
// tool.
//
// It used to be an MCP client of the admin listener. That listener is off by
// default, and the MCP wire surface is deprecated (ADR-0077), so the command
// now runs where the engine's dependencies already are: inside the core's
// container, under the core's own SPIRE admin identity and ledger credential.
//
//	docker exec innsegl-mcp innsegl retire <run_id>
//	make innsegl-retire RUN=<run_id>
//
// It reads the same variables `innsegl serve` and `innsegl reap` read, which
// that container already carries. It adds no credential: a process exec'd into
// the container is attested by SPIRE exactly as the server is (same binary,
// same uid, same image), and anywhere else it is attested as nothing and gets
// no admin identity, which is REFUSED below.
//
// # How "already ended" is known, which is the one subtle part
//
// IP §4 makes retirement idempotent: "retiring a retired run returns success
// with the original timestamp". It NEVER refuses an already-retired run, so a
// refusal is not the signal. The only thing that differs between the two
// cases is the instant itself:
//
//   - a retirement THIS invocation caused is stamped by the ledger while the
//     call is in flight, so it is at or after the instant the call was made;
//   - a retirement that was already on the chain was stamped before this
//     invocation began.
//
// So the command notes the instant it asks, and compares. THE LIMIT: two
// invocations inside the same millisecond (doc 02 §1's resolution) are
// indistinguishable. That misreports the exit status and never what is
// recorded: exactly one `run_retired` per run is enforced by migrations/0004's
// partial unique index, not by this comparison.
//
// # Five statuses because an operator does five different things
//
// Ended, and the record now says so — nothing to do. Already ended — the
// record already said so, and nothing was appended. No such run — the id is
// wrong, or this is the wrong deployment. Unreachable — the core could not
// finish; the run may or may not be retired, and running the command again
// converges. Refused — this process is not the core: it holds no SPIRE admin
// identity, so the move is to run it where the identity is, not to restart a
// deployment that may be healthy.

// Exit statuses, continuing cli.go's contract. The canary owns 3 and 4, the
// reaper 5 and 6, the reconciler 7 and 8, the sealer 9 and 10, `api` 11-13,
// `init` 14 and 15, and 16 and 17 belonged to the removed `resolve-alert`
// (ADR-0071) and stay unused; these are retire's. A successful retirement is
// exitOK. The numbers did not move when the command moved onto the core.
const (
	// exitRetireAlreadyEnded: the run was already retired when this ran. The
	// record is unchanged and the instant reported is the original one.
	exitRetireAlreadyEnded = 18
	// exitRetireNoSuchRun: this deployment's ledger holds no such run. Nothing
	// was written and nothing was deleted.
	exitRetireNoSuchRun = 19
	// exitRetireUnreachable: the ledger or SPIRE could not be reached, or
	// could not finish. The run may or may not be retired; running the command
	// again converges, because a retry appends nothing already appended.
	exitRetireUnreachable = 20
	// exitRetireUnauthorized: this process was not admitted — it holds no
	// SPIRE admin identity, or SPIRE refused the one it has. Nothing was
	// decided. It is deliberately NOT exitRetireUnreachable: the move is to run
	// the command on the core, not to restart the deployment.
	exitRetireUnauthorized = 21
)

const (
	// defaultRetireTimeout bounds the whole command. A dependency that is
	// black-holing packets must become an exit status rather than a hang.
	defaultRetireTimeout = 30 * time.Second
	// envRetireTimeout overrides it.
	envRetireTimeout = "INNSEGL_RETIRE_TIMEOUT"
	// retireOnTheCore is the one command line every remedy names.
	retireOnTheCore = "docker exec innsegl-mcp innsegl retire"
)

// errNoAdminIdentity marks an opener failure that is REFUSED, not
// UNREACHABLE: this process has no SPIRE admin identity to act with.
var errNoAdminIdentity = errors.New("this process holds no SPIRE admin identity")

// retireOptions is the resolved command line.
type retireOptions struct {
	spireAddress string
	trustDomain  string
	serverID     string
	workloadAPI  string
	dsn          string
	spireTimeout time.Duration
}

// retireDeps are the seams the command's tests replace. The zero value is the
// production wiring.
type retireDeps struct {
	// open returns what retire_agent's engine runs on, and a closer.
	open func(context.Context, retireOptions) (mcp.RetireAgentConfig, func(), error)
}

func (d retireDeps) opener() func(context.Context, retireOptions) (mcp.RetireAgentConfig, func(), error) {
	if d.open != nil {
		return d.open
	}
	return openRetireEngine
}

// retireCommand is the subcommand body wired into cli.go's dispatch table.
func retireCommand(args []string, stdout, stderr io.Writer) int {
	return runRetireCommand(args, stdout, stderr, retireDeps{})
}

func runRetireCommand(args []string, stdout, stderr io.Writer, deps retireDeps) int {
	fs := flag.NewFlagSet("innsegl retire", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		spireAddress = fs.String("spire-address", os.Getenv(envSPIREAddress),
			"SPIRE server admin API, host:port ($"+envSPIREAddress+")")
		trustDomain = fs.String("trust-domain", os.Getenv(envTrustDomain),
			"SPIFFE trust domain name ($"+envTrustDomain+")")
		serverID = fs.String("spire-server-id", os.Getenv(envSPIREServerID),
			"SPIFFE ID the SPIRE server must present; empty means spiffe://{trust-domain}/spire/server ($"+
				envSPIREServerID+")")
		workloadAPI = fs.String("workload-api", envOr(envWorkloadAPI, spire.DefaultWorkloadAPIAddress),
			"Workload API socket this process fetches the core's admin SVID from ($"+envWorkloadAPI+")")
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		spireTimeout = fs.Duration("spire-timeout", envDuration(envSPIRETimeout, spire.DefaultTimeout),
			"bound on one SPIRE admin RPC ($"+envSPIRETimeout+")")
		timeout = fs.Duration("timeout", envDuration(envRetireTimeout, defaultRetireTimeout),
			"bound on the whole command ($"+envRetireTimeout+")")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl retire - end a run an operator knows is over (RM-154, #257)\n\n")
		fprintf(stderr, "Usage, on the core host:\n  %s <run_id>\n  make innsegl-retire RUN=<run_id>\n\n",
			retireOnTheCore)
		fprintf(stderr, "Appends one run_retired to the ledger and deletes the run's SPIRE entry, through\n")
		fprintf(stderr, "the core's own retirement engine (ADR-0077). It runs inside the core's container,\n")
		fprintf(stderr, "under the core's SPIRE admin identity, and reads the variables that container\n")
		fprintf(stderr, "already sets. Retirement is effective immediately and permanent (IP §6.2).\n")
		fprintf(stderr, "Running it twice is safe: the second run appends nothing and reports the\n")
		fprintf(stderr, "original instant.\n\n")
		fprintf(stderr, "Use it when you KNOW the run is over. A run that has merely gone quiet is not\n")
		fprintf(stderr, "over; leave that to the reaper, which records a withdrawal a later call undoes.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %2d  the run is retired, and this command is what retired it\n", exitOK)
		fprintf(stderr, "  %2d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %2d  ALREADY ENDED - it was retired before this ran; nothing was appended\n",
			exitRetireAlreadyEnded)
		fprintf(stderr, "  %2d  NO SUCH RUN - check the id, and that this is the right deployment\n",
			exitRetireNoSuchRun)
		fprintf(stderr, "  %2d  UNREACHABLE - the ledger or SPIRE could not finish; run it again\n",
			exitRetireUnreachable)
		fprintf(stderr, "  %2d  REFUSED - this process holds no SPIRE admin identity; run it on the core\n",
			exitRetireUnauthorized)
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	opts := retireOptions{
		spireAddress: *spireAddress, trustDomain: *trustDomain, serverID: *serverID,
		workloadAPI: *workloadAPI, dsn: *dsn, spireTimeout: *spireTimeout,
	}
	runID, code := retireTarget(fs, opts, stderr)
	if code != exitOK {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	cfg, closeAll, err := deps.opener()(ctx, opts)
	if err != nil {
		return reportRetireFailure(stderr, runID, err)
	}
	if closeAll != nil {
		defer closeAll()
	}
	restore, err := mcp.ConfigureRetireAgent(cfg)
	if err != nil {
		return reportRetireFailure(stderr, runID, err)
	}
	defer restore()

	// Noted BEFORE the call, so that an instant the ledger stamps while the
	// call is in flight compares as "at or after this". See the header.
	asked := event.NewTimestamp(time.Now())

	raw, err := mcp.RetireRunForGateway(ctx, runID)
	if err != nil {
		return reportRetireFailure(stderr, runID, err)
	}
	retiredAt, err := event.ParseTimestamp(raw)
	if err != nil {
		return reportRetireFailure(stderr, runID,
			fmt.Errorf("the engine answered an instant that is not doc 02 §1's: %w", err))
	}

	if retiredAt.Time().Before(asked.Time()) {
		fprintf(stderr, "innsegl retire: ALREADY ENDED - run %s was retired at %s, before this ran.\n",
			runID, retiredAt)
		fprintf(stderr, "innsegl retire: nothing was appended; retirement is permanent and there is\n")
		fprintf(stderr, "innsegl retire: nothing left to do for this run.\n")
		return exitRetireAlreadyEnded
	}

	fprintf(stdout, "retired %s at %s\n", runID, retiredAt)
	return exitOK
}

// retireTarget reads the one positional argument and the configuration, and
// says what is wrong in terms of what to type instead. Nothing is opened for a
// command line that cannot be acted on.
func retireTarget(fs *flag.FlagSet, opts retireOptions, stderr io.Writer) (string, int) {
	switch fs.NArg() {
	case 1:
	case 0:
		fprintf(stderr, "innsegl retire: a run id is required - innsegl retire <run_id>\n")
		fprintf(stderr, "innsegl retire: the id is the one the dashboard shows on the run, and the one\n")
		fprintf(stderr, "innsegl retire: in the run's Agent-Run trailers.\n")
		return "", exitUsage
	default:
		fprintf(stderr, "innsegl retire: one run at a time; %q is a second run id. Retirement is\n", fs.Arg(1))
		fprintf(stderr, "innsegl retire: permanent, so this command does not take a list.\n")
		return "", exitUsage
	}

	missing := ""
	switch {
	case opts.dsn == "":
		missing = "-dsn (or $" + envLedgerDSN + ")"
	case opts.spireAddress == "":
		missing = "-spire-address (or $" + envSPIREAddress + ")"
	case opts.trustDomain == "":
		missing = "-trust-domain (or $" + envTrustDomain + ")"
	}
	if missing != "" {
		fprintf(stderr, "innsegl retire: %s is required. This command runs on the core, where the\n", missing)
		fprintf(stderr, "innsegl retire: core's container already sets it:\n")
		fprintf(stderr, "innsegl retire:   %s %s\n", retireOnTheCore, fs.Arg(0))
		return "", exitUsage
	}
	return fs.Arg(0), exitOK
}

// reportRetireFailure turns a failure into the status an operator acts on.
func reportRetireFailure(stderr io.Writer, runID string, err error) int {
	var refused *mcp.Error
	isClassified := errors.As(err, &refused)

	switch {
	case isClassified && refused.Class == mcp.ClassRunNotFound:
		fprintf(stderr, "innsegl retire: NO SUCH RUN - this deployment holds no run %s: %s\n",
			runID, refused.Message)
		fprintf(stderr, "innsegl retire: nothing was written and nothing was deleted. Check the id,\n")
		fprintf(stderr, "innsegl retire: and that this is the deployment the run was registered on.\n")
		return exitRetireNoSuchRun

	case errors.Is(err, errNoAdminIdentity) ||
		(isClassified && refused.Class == mcp.ClassAttestationFailed):
		fprintf(stderr, "innsegl retire: REFUSED - %v\n", err)
		fprintf(stderr, "innsegl retire: run %s is exactly as it was found - nothing was written and\n", runID)
		fprintf(stderr, "innsegl retire: nothing was deleted. Retiring a run needs the core's SPIRE admin\n")
		fprintf(stderr, "innsegl retire: identity, which only the core's own container is issued. Run it there:\n")
		fprintf(stderr, "innsegl retire:   %s %s\n", retireOnTheCore, runID)
		return exitRetireUnauthorized
	}

	fprintf(stderr, "innsegl retire: UNREACHABLE - the core could not finish: %v\n", err)
	fprintf(stderr, "innsegl retire: run %s may or may not be retired. Running this again is safe:\n", runID)
	fprintf(stderr, "innsegl retire: retirement is idempotent, so a retry converges and never appends\n")
	fprintf(stderr, "innsegl retire: a second ending.\n")
	return exitRetireUnreachable
}

// openRetireEngine opens what retire_agent's engine runs on: the ledger, the
// run directory over it, and the core's SPIRE admin client. It is the wiring
// `innsegl serve` builds for the same engine (servewiring.go), reduced to the
// three dependencies retirement needs.
//
// The ledger is opened FIRST, because it is the cheap check: a ledger that
// cannot be reached is UNREACHABLE before anything asks SPIRE for anything.
// Open, never Migrate — this command does not own the schema.
func openRetireEngine(ctx context.Context, opts retireOptions) (mcp.RetireAgentConfig, func(), error) {
	store, err := ledger.Open(ctx, opts.dsn)
	if err != nil {
		return mcp.RetireAgentConfig{}, nil, fmt.Errorf("open the ledger: %w", err)
	}
	runs, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		store.Close()
		return mcp.RetireAgentConfig{}, nil, fmt.Errorf("build the run directory: %w", err)
	}

	// A Workload API socket that does not exist is a process outside the
	// core, and is said so at once rather than after the timeout a client
	// waiting on a missing socket would spend.
	if sock, isUnix := strings.CutPrefix(opts.workloadAPI, "unix://"); isUnix {
		if _, statErr := os.Stat(sock); statErr != nil {
			store.Close()
			return mcp.RetireAgentConfig{}, nil, fmt.Errorf(
				"%w: there is no Workload API at %s", errNoAdminIdentity, opts.workloadAPI)
		}
	}

	client, unwind, err := dialSPIREAdmin(ctx, "innsegl retire",
		opts.spireAddress, opts.trustDomain, opts.serverID, opts.workloadAPI, opts.spireTimeout)
	if err != nil {
		store.Close()
		return mcp.RetireAgentConfig{}, nil, err
	}
	closeAll := func() {
		unwind()
		store.Close()
	}
	return mcp.RetireAgentConfig{Runs: runs, Entries: client, Ledger: store}, closeAll, nil
}

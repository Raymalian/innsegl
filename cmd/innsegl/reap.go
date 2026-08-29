// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// `innsegl reap` — the TTL reaper as an operator-runnable command.
//
// IP §6.7: an agent that crashes without calling `retire_agent` leaves its
// SPIRE registration entry behind. The reaper deletes entries whose runs have
// outlived their identity lifetime and appends `run_expired` — distinct from
// `run_retired`, because retired means the agent finished and expired means it
// died.
//
// # One sweep per invocation
//
// This command sweeps once and exits. It does not loop, and it does not elect a
// leader: doc 05 §2 runs the single-active components under leader election,
// and providing that is the deployment's job, not this binary's — a Kubernetes
// Lease, a scheduled Job with a concurrency policy of Forbid, or whatever the
// deployment already uses for the sealer and the reconciler.
//
// Nothing here breaks if the deployment gets that wrong and two sweeps overlap.
// The append is deduplicated by an idempotency key derived from the run id, the
// ledger serializes appends, and deleting an entry that is already gone is a
// success with nothing deleted. Two concurrent reapers produce one `run_expired`
// per orphan and one deletion between them. See internal/spire/reaper.go.

// Exit statuses for `innsegl reap`, continuing cli.go's contract. The canary
// owns 3 and 4; these are the reaper's.
//
// The distinction is the one an operator acts on: "I swept and could not finish
// reaping an orphan" is a SPIRE or ledger problem to chase, while "I could not
// sweep at all" means the identities are entirely unmonitored and no orphan has
// been ruled out. Neither is a pass.
const (
	// exitReapIncomplete: the sweep ran and at least one orphan could not be
	// reaped. Its entry is still live and its expiry may be unrecorded.
	exitReapIncomplete = 5
	// exitReapInconclusive: the sweep could not run at all — bad
	// configuration, no credential, an unreachable SPIRE or ledger. Nothing
	// was examined, so it fails closed.
	exitReapInconclusive = 6
)

// Every flag falls back to an environment variable so a scheduled job can be
// configured entirely by environment and never put the ledger DSN — which
// carries a password — on a command line the process table can read.
const (
	envSPIREAddress  = "INNSEGL_SPIRE_ADDRESS"
	envTrustDomain   = "INNSEGL_TRUST_DOMAIN"
	envSPIREServerID = "INNSEGL_SPIRE_SERVER_ID"
	envWorkloadAPI   = "INNSEGL_WORKLOAD_API_ADDRESS"
	envLedgerDSN     = "INNSEGL_LEDGER_DSN"
	envReapGrace     = "INNSEGL_REAP_GRACE"
	envSPIRETimeout  = "INNSEGL_SPIRE_TIMEOUT"
)

// reapOptions is the resolved command line.
type reapOptions struct {
	spireAddress string
	trustDomain  string
	serverID     string
	workloadAPI  string
	dsn          string
	grace        time.Duration
	timeout      time.Duration
}

// sweeper is the one thing this command needs of a reaper. It is an interface
// so that the flag handling, the exit statuses and the output can be tested
// without a SPIRE server and a Postgres; *spire.Reaper is the production
// implementation and SPI-003 is what proves it works.
type sweeper interface {
	Sweep(context.Context) (*spire.SweepReport, error)
}

// reapDeps are the seams the command's tests replace. Production wiring is the
// zero value.
type reapDeps struct {
	open func(context.Context, reapOptions) (sweeper, func(), error)
}

func (d reapDeps) opener() func(context.Context, reapOptions) (sweeper, func(), error) {
	if d.open != nil {
		return d.open
	}
	return openReaper
}

// reapCommand is the subcommand body wired into cli.go's dispatch table.
func reapCommand(args []string, stdout, stderr io.Writer) int {
	return runReapCommand(args, stdout, stderr, reapDeps{})
}

func runReapCommand(args []string, stdout, stderr io.Writer, deps reapDeps) int {
	fs := flag.NewFlagSet("innsegl reap", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		spireAddress = fs.String("spire-address", os.Getenv(envSPIREAddress),
			"SPIRE server admin API, host:port ($"+envSPIREAddress+")")
		trustDomain = fs.String("trust-domain", os.Getenv(envTrustDomain),
			"SPIFFE trust domain name, e.g. innsegl.dev ($"+envTrustDomain+")")
		serverID = fs.String("spire-server-id", os.Getenv(envSPIREServerID),
			"SPIFFE ID the SPIRE server must present; empty means spiffe://{trust-domain}/spire/server ($"+envSPIREServerID+")")
		workloadAPI = fs.String("workload-api", envOr(envWorkloadAPI, spire.DefaultWorkloadAPIAddress),
			"Workload API socket this process fetches its own admin SVID from ($"+envWorkloadAPI+")")
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		grace = fs.Duration("grace", envDuration(envReapGrace, spire.DefaultReapGrace),
			"slack added to each entry's own TTL before its run is called orphaned ($"+envReapGrace+")")
		timeout = fs.Duration("timeout", envDuration(envSPIRETimeout, spire.DefaultTimeout),
			"bound on one SPIRE admin RPC ($"+envSPIRETimeout+")")
		asJSON   = fs.Bool("json", false, "write the report as JSON")
		quietRun = fs.Bool("quiet", false, "print nothing when the sweep reaped nothing; failures are always reported")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl reap - delete identity entries orphaned past their TTL (IP §6.7)\n\n")
		fprintf(stderr, "Usage:\n  innsegl reap [flags]\n\n")
		fprintf(stderr, "Sweeps once and exits. Run it on a schedule, single-active; see doc 05 §2.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  the sweep completed; every orphan found was reaped\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  INCOMPLETE - an orphan could not be reaped; its entry is still live\n", exitReapIncomplete)
		fprintf(stderr, "  %d  INCONCLUSIVE - the sweep could not run; nothing was examined, so it fails closed\n", exitReapInconclusive)
		fprintf(stderr, "\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fprintf(stderr, "innsegl reap: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}

	missing := ""
	switch {
	case *spireAddress == "":
		missing = "-spire-address (or $" + envSPIREAddress + ")"
	case *trustDomain == "":
		missing = "-trust-domain (or $" + envTrustDomain + ")"
	case *dsn == "":
		missing = "-dsn (or $" + envLedgerDSN + ")"
	}
	if missing != "" {
		fprintf(stderr, "innsegl reap: %s is required\n", missing)
		return exitUsage
	}
	// A negative grace would reap entries before their TTL had elapsed. The
	// reaper refuses it too; refusing it here means the operator is told which
	// flag was wrong rather than being handed an internal error.
	if *grace < 0 {
		fprintf(stderr, "innsegl reap: -grace %s is negative; that reaps entries before their TTL has elapsed\n", *grace)
		return exitUsage
	}

	opts := reapOptions{
		spireAddress: *spireAddress,
		trustDomain:  *trustDomain,
		serverID:     *serverID,
		workloadAPI:  *workloadAPI,
		dsn:          *dsn,
		grace:        *grace,
		timeout:      *timeout,
	}

	ctx := context.Background()

	reaper, closeAll, err := deps.opener()(ctx, opts)
	if err != nil {
		fprintf(stderr, "innsegl reap: %v\n", err)
		fprintf(stderr, "innsegl reap: INCONCLUSIVE - no entry was examined, so no orphan has been ruled out\n")
		return exitReapInconclusive
	}
	if closeAll != nil {
		defer closeAll()
	}

	report, err := reaper.Sweep(ctx)
	if err != nil {
		fprintf(stderr, "innsegl reap: %v\n", err)
		fprintf(stderr, "innsegl reap: INCONCLUSIVE - no entry was examined, so no orphan has been ruled out\n")
		return exitReapInconclusive
	}
	// A nil report from a nil error would make the verdict depend on a nil
	// check somewhere further down. It fails closed here instead.
	if report == nil {
		fprintf(stderr, "innsegl reap: the sweep returned no report; nothing was examined\n")
		return exitReapInconclusive
	}

	complete := report.OK()
	out := stdout
	if !complete {
		out = stderr
	}
	switch {
	case *asJSON:
		writeReapJSON(out, stderr, report)
	case complete && *quietRun && len(report.Expired) == 0:
	default:
		fprintf(out, "%s", report.String())
	}

	if !complete {
		fprintf(stderr,
			"innsegl reap: INCOMPLETE - %d orphaned entr%s could not be reaped. "+
				"Their SPIRE entries are still live and their expiries may be unrecorded; "+
				"the next sweep retries them and cannot double-record (IP §6.7).\n",
			len(report.Failures), pluralEntries(len(report.Failures)))
		return exitReapIncomplete
	}
	return exitOK
}

func pluralEntries(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// reapReportJSON is the machine-readable report. It is a view rather than json
// tags on spire.SweepReport, because an `error` does not survive
// encoding/json — it marshals to `{}` — and a monitor that saw an empty object
// where a failure should be would read the sweep as clean.
type reapReportJSON struct {
	StartedAt string           `json:"started_at"`
	Examined  int              `json:"examined"`
	Complete  bool             `json:"complete"`
	Expired   []reapExpiryJSON `json:"expired"`
	Live      []reapRunJSON    `json:"live"`
	Skipped   []reapNoteJSON   `json:"skipped,omitempty"`
	Failures  []reapNoteJSON   `json:"failures,omitempty"`
}

type reapExpiryJSON struct {
	RunID    string `json:"run_id"`
	SPIFFEID string `json:"spiffe_id"`
	EntryID  string `json:"entry_id"`
	Deadline string `json:"deadline"`
	EventID  string `json:"event_id,omitempty"`
	Recorded bool   `json:"recorded"`
	Deleted  bool   `json:"deleted"`
}

type reapRunJSON struct {
	RunID    string `json:"run_id"`
	SPIFFEID string `json:"spiffe_id"`
	EntryID  string `json:"entry_id"`
	Deadline string `json:"deadline"`
}

type reapNoteJSON struct {
	EntryID  string `json:"entry_id"`
	SPIFFEID string `json:"spiffe_id,omitempty"`
	Reason   string `json:"reason"`
}

func reapReportView(report *spire.SweepReport) reapReportJSON {
	view := reapReportJSON{
		StartedAt: report.StartedAt.UTC().Format(time.RFC3339),
		Examined:  report.Examined,
		Complete:  report.OK(),
		Expired:   []reapExpiryJSON{},
		Live:      []reapRunJSON{},
	}
	for _, e := range report.Expired {
		view.Expired = append(view.Expired, reapExpiryJSON{
			RunID:    e.Run.RunID,
			SPIFFEID: e.Entry.SPIFFEID,
			EntryID:  e.Entry.ID,
			Deadline: e.Deadline.UTC().Format(time.RFC3339),
			EventID:  e.EventID,
			Recorded: e.Recorded,
			Deleted:  e.Deleted,
		})
	}
	for _, c := range report.Live {
		view.Live = append(view.Live, reapRunJSON{
			RunID:    c.Run.RunID,
			SPIFFEID: c.Entry.SPIFFEID,
			EntryID:  c.Entry.ID,
			Deadline: c.Deadline.UTC().Format(time.RFC3339),
		})
	}
	for _, s := range report.Skipped {
		view.Skipped = append(view.Skipped, reapNoteJSON{
			EntryID: s.EntryID, SPIFFEID: s.SPIFFEID, Reason: s.Reason,
		})
	}
	for _, f := range report.Failures {
		reason := "unknown"
		if f.Err != nil {
			reason = f.Err.Error()
		}
		view.Failures = append(view.Failures, reapNoteJSON{
			EntryID: f.EntryID, SPIFFEID: f.SPIFFEID, Reason: reason,
		})
	}
	return view
}

// writeReapJSON emits the report for a scheduled job that feeds a monitor. A
// report that cannot be encoded is still a report that has to reach someone, so
// the error goes to stderr and the text form is printed rather than the verdict
// changing.
func writeReapJSON(out, stderr io.Writer, report *spire.SweepReport) {
	encoded, err := json.MarshalIndent(reapReportView(report), "", "  ")
	if err != nil {
		fprintf(stderr, "innsegl reap: the report could not be encoded as JSON: %v\n", err)
		fprintf(out, "%s", report.String())
		return
	}
	fprintf(out, "%s\n", encoded)
}

// openReaper is the production wiring: the process's own SVID from the Workload
// API, an admin client dialled with it, the ledger, and a reaper over both.
//
// The admin credential is not a file. IP §1 and doc 05 §1 make innsegl-mcp the
// holder of SPIRE admin, and "holding it" means being the container SPIRE
// attests — so the reaper fetches its identity through the Workload API like
// any other workload, and a process that cannot attest gets no credential and
// reaps nothing.
func openReaper(ctx context.Context, opts reapOptions) (sweeper, func(), error) {
	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(opts.workloadAPI)))
	if err != nil {
		return nil, nil, fmt.Errorf(
			"no SVID from the Workload API at %s: the reaper is an attested workload "+
				"and without an identity it holds no SPIRE admin: %w", opts.workloadAPI, err)
	}
	closers := []func(){func() { _ = source.Close() }}
	unwind := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	client, err := spire.Dial(ctx, spire.Config{
		Address:     opts.spireAddress,
		TrustDomain: opts.trustDomain,
		ServerID:    opts.serverID,
		Source:      source,
		Timeout:     opts.timeout,
	})
	if err != nil {
		unwind()
		return nil, nil, fmt.Errorf("dial the SPIRE admin API at %s: %w", opts.spireAddress, err)
	}
	closers = append(closers, func() { _ = client.Close() })

	// Open, never Migrate. The reaper is not the schema's owner and must not
	// create one: a reaper that quietly migrated an empty database would
	// happily record expiries into a chain nobody else is reading.
	store, err := ledger.Open(ctx, opts.dsn)
	if err != nil {
		unwind()
		return nil, nil, fmt.Errorf("open the ledger: %w", err)
	}
	closers = append(closers, store.Close)

	reaper, err := spire.NewReaper(spire.ReaperConfig{
		Client: client,
		Ledger: store,
		Grace:  opts.grace,
	})
	if err != nil {
		unwind()
		return nil, nil, err
	}
	return reaper, unwind, nil
}

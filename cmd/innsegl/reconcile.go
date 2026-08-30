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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/reconciler"
)

// `innsegl reconcile` — the component IP §6.5 makes required.
//
// It closes the two windows the two-phase signing protocol leaves: a
// `commit_intent` with no signature is expired after a bounded window, and a
// signature with no `commit_recorded` is repaired from the transparency log.
// What that means and how it is proved is internal/reconciler; this file is the
// operator's surface onto it.
//
// # It loops, and it does not elect a leader
//
// IP §6.5 says the reconciler "runs continuously", so the default is a loop and
// `-once` is the opt-out for a scheduled job. doc 05 §2 runs it single-active
// under leader election, and providing that is the deployment's job, not this
// binary's — a Kubernetes Lease, a Job with a concurrency policy of Forbid, or
// whatever already elects the sealer.
//
// Nothing breaks if the deployment gets that wrong and two reconcilers overlap.
// Both appends carry a deterministic idempotency key, `idempotency_key` is
// UNIQUE across the chain (LED-008), and the ledger serialises appends — so two
// cycles over one dangling intent produce ONE event between them. That is
// REC-005, and doc 05 §2 relies on it by name.
//
// # Three verdicts, and only one of them is a pass
//
// A cycle that ruled on every open intent exits 0, whether it repaired,
// expired, or found nothing to do. A cycle that could not rule on one — the
// repository unreadable, the log unreachable, two signatures claiming one
// intent — exits UNRESOLVED, because that intent is a signing path nobody is
// watching and doc 05 §4 lists reconciler drift among the monitoring minimums.
// A cycle that could not run at all exits INCONCLUSIVE: nothing was examined,
// so no window has been ruled closed.

// Exit statuses, continuing cli.go's contract. The canary owns 3 and 4 and the
// reaper owns 5 and 6; these are the reconciler's.
const (
	// exitReconcileUnresolved: the cycle ran and at least one open intent
	// could not be ruled on. Its window is still open and unrecorded.
	exitReconcileUnresolved = 7
	// exitReconcileInconclusive: the cycle could not run — bad configuration,
	// an unreachable ledger. Nothing was examined, so it fails closed.
	exitReconcileInconclusive = 8
)

// Every flag falls back to an environment variable so a scheduled job can be
// configured entirely by environment and never put the ledger DSN — which
// carries a password — on a command line the process table can read.
// $INNSEGL_REKOR_URL, $INNSEGL_WORKSPACE, $INNSEGL_LEDGER_DSN and
// $INNSEGL_TRUST_DOMAIN are `serve`'s and the reaper's own names, reused rather
// than duplicated: the reconciler reads the same Rekor, the same workspace and
// the same chain as the MCP whose crashes it repairs, and a second spelling
// would be a second thing to get out of step in a deployment.
const (
	envExpireAfter = "INNSEGL_RECONCILE_EXPIRE_AFTER"
	envInterval    = "INNSEGL_RECONCILE_INTERVAL"
)

// reconcileOptions is the resolved command line.
type reconcileOptions struct {
	dsn         string
	rekorURL    string
	workspace   string
	trustDomain string
	expireAfter time.Duration
	interval    time.Duration
	once        bool
}

// cycler is the one thing this command needs of a reconciler. It is an
// interface so the flag handling, the exit statuses and the report can be
// tested without a Postgres and a Rekor; *reconciler.Reconciler is the
// production implementation and REC-001/002/005 are what prove it.
type cycler interface {
	Reconcile(context.Context) (reconciler.Result, error)
}

// reconcileDeps are the seams this command's tests replace. Production wiring
// is the zero value.
type reconcileDeps struct {
	open func(context.Context, reconcileOptions) (cycler, func(), error)
}

func (d reconcileDeps) opener() func(context.Context, reconcileOptions) (cycler, func(), error) {
	if d.open != nil {
		return d.open
	}
	return openReconciler
}

// reconcileCommand is the subcommand body wired into cli.go's dispatch table.
func reconcileCommand(args []string, stdout, stderr io.Writer) int {
	// SIGINT and SIGTERM end the loop cleanly: a reconciler killed mid-cycle
	// is harmless — every append is keyed and the next cycle re-derives its
	// state from the chain — but an operator deserves the final report.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runReconcileLoop(ctx, args, stdout, stderr, reconcileDeps{})
}

func runReconcileCommand(args []string, stdout, stderr io.Writer, deps reconcileDeps) int {
	return runReconcileLoop(context.Background(), args, stdout, stderr, deps)
}

// runReconcileLoop is the whole command: parse, refuse, open, cycle.
//
//nolint:gocyclo // One refusal per flag, then one branch per verdict; splitting it would put the exit-status contract in a different file from the flags it is a function of.
func runReconcileLoop(ctx context.Context, args []string, stdout, stderr io.Writer, deps reconcileDeps) int {
	fs := flag.NewFlagSet("innsegl reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		rekorURL = fs.String("rekor-url", os.Getenv(envRekorURL),
			"transparency log base URL, e.g. https://rekor.sigstore.dev ($"+envRekorURL+")")
		workspace = fs.String("workspace", os.Getenv(envWorkspace),
			"root the `repo` of an intent is resolved under, as <root>/host/org/name ($"+envWorkspace+")")
		trustDomain = fs.String("trust-domain", os.Getenv(envTrustDomain),
			"SPIFFE trust domain name, e.g. innsegl.dev ($"+envTrustDomain+")")
		expireAfter = fs.Duration("expire-after",
			envDuration(envExpireAfter, reconciler.DefaultExpireAfter),
			"how long a dangling commit_intent is left alone before it is expired ($"+envExpireAfter+")")
		interval = fs.Duration("interval", envDuration(envInterval, reconciler.DefaultInterval),
			"time between cycles; ignored with -once ($"+envInterval+")")
		once   = fs.Bool("once", false, "run one cycle and exit, for a scheduled job")
		asJSON = fs.Bool("json", false, "write each cycle's report as JSON")
		quiet  = fs.Bool("quiet", false,
			"print nothing for a cycle that found nothing to do; failures are always reported")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl reconcile - expire dangling signing intents and repair missing records (IP §6.5)\n\n")
		fprintf(stderr, "Usage:\n  innsegl reconcile [flags]\n\n")
		fprintf(stderr, "Runs continuously by default. Run it single-active; see doc 05 §2.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  every open intent was ruled on\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  UNRESOLVED - an open intent could not be ruled on; its window is still open\n",
			exitReconcileUnresolved)
		fprintf(stderr, "  %d  INCONCLUSIVE - the cycle could not run; nothing was examined, so it fails closed\n",
			exitReconcileInconclusive)
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
		fprintf(stderr, "innsegl reconcile: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}

	missing := ""
	switch {
	case *dsn == "":
		missing = "-dsn (or $" + envLedgerDSN + ")"
	case *rekorURL == "":
		missing = "-rekor-url (or $" + envRekorURL + ")"
	case *workspace == "":
		missing = "-workspace (or $" + envWorkspace + ")"
	case *trustDomain == "":
		missing = "-trust-domain (or $" + envTrustDomain + ")"
	}
	if missing != "" {
		fprintf(stderr, "innsegl reconcile: %s is required\n", missing)
		return exitUsage
	}
	// A non-positive window expires an intent the instant it is appended,
	// which records "no signature exists" about one that is still being made —
	// and I4 makes that permanent. Refused here so the operator is told which
	// flag was wrong.
	if *expireAfter <= 0 {
		fprintf(stderr, "innsegl reconcile: -expire-after %s is not positive; that expires "+
			"intents whose signature is still in flight, and no record is ever "+
			"corrected by deletion (I4)\n", *expireAfter)
		return exitUsage
	}
	if !*once && *interval <= 0 {
		fprintf(stderr, "innsegl reconcile: -interval %s is not positive; use -once for a "+
			"single cycle\n", *interval)
		return exitUsage
	}

	opts := reconcileOptions{
		dsn: *dsn, rekorURL: *rekorURL, workspace: *workspace,
		trustDomain: *trustDomain, expireAfter: *expireAfter,
		interval: *interval, once: *once,
	}

	engine, closeAll, err := deps.opener()(ctx, opts)
	if err != nil {
		fprintf(stderr, "innsegl reconcile: %v\n", err)
		fprintf(stderr, "innsegl reconcile: INCONCLUSIVE - no intent was examined, "+
			"so no window has been ruled closed\n")
		return exitReconcileInconclusive
	}
	if closeAll != nil {
		defer closeAll()
	}

	report := reconcileReporter{stdout: stdout, stderr: stderr, asJSON: *asJSON, quiet: *quiet}
	if *once {
		return report.cycle(ctx, engine)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	worst := exitOK
	for {
		if code := report.cycle(ctx, engine); code != exitOK {
			worst = code
		}
		select {
		case <-ctx.Done():
			// A cancelled context is the operator stopping the loop, not a
			// failure. The worst verdict seen is still the exit status: a
			// process that repaired nothing for an hour because Rekor was down
			// must not exit 0 when it is finally stopped.
			return worst
		case <-ticker.C:
		}
	}
}

// reconcileReporter writes one cycle's outcome and returns its exit status.
type reconcileReporter struct {
	stdout io.Writer
	stderr io.Writer
	asJSON bool
	quiet  bool
}

func (r reconcileReporter) cycle(ctx context.Context, engine cycler) int {
	result, err := engine.Reconcile(ctx)
	if err != nil {
		// A cancelled context during shutdown is not a failed cycle.
		if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
			return exitOK
		}
		fprintf(r.stderr, "innsegl reconcile: %v\n", err)
		fprintf(r.stderr, "innsegl reconcile: INCONCLUSIVE - the cycle could not run, "+
			"so no window has been ruled closed\n")
		return exitReconcileInconclusive
	}

	stuck := result.Unresolved + result.Ambiguous
	out := r.stdout
	if stuck > 0 {
		out = r.stderr
	}
	switch {
	case r.asJSON:
		r.writeJSON(out, result)
	case r.quiet && stuck == 0 && len(result.Appended) == 0:
	default:
		fprintf(out, "%s", renderReconcileResult(result))
	}

	if stuck > 0 {
		fprintf(r.stderr, "innsegl reconcile: UNRESOLVED - %d open intent(s) could not be "+
			"ruled on. Their windows are still open and nothing has been recorded about "+
			"them; the next cycle retries and cannot double-record (IP §6.5, REC-005).\n", stuck)
		return exitReconcileUnresolved
	}
	return exitOK
}

// renderReconcileResult is the human report. One summary line, then one line
// per finding that is not simply "still inside the window".
func renderReconcileResult(result reconciler.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "intents %d  open %d  repaired %d  expired %d  unresolved %d  ambiguous %d\n",
		result.Intents, result.Open, result.Repaired, result.Expired,
		result.Unresolved, result.Ambiguous)
	for _, f := range result.Findings {
		if f.Outcome == reconciler.OutcomeOpen {
			continue
		}
		fmt.Fprintf(&b, "  %-10s %s  run=%s repo=%s", f.Outcome, f.IntentEventID, f.RunID, f.Repo)
		if f.CommitSHA != "" {
			fmt.Fprintf(&b, " commit=%s rekor=%s/%d", f.CommitSHA, f.RekorEntryUUID, f.RekorLogIndex)
		}
		fmt.Fprintf(&b, "\n             %s\n", f.Detail)
	}
	return b.String()
}

// reconcileReportJSON is the machine-readable report. A view rather than json
// tags on reconciler.Result, so the wire shape is this command's contract and
// not a consequence of a field rename in another package.
type reconcileReportJSON struct {
	Intents    int                    `json:"intents"`
	Open       int                    `json:"open"`
	Repaired   int                    `json:"repaired"`
	Expired    int                    `json:"expired"`
	Unresolved int                    `json:"unresolved"`
	Ambiguous  int                    `json:"ambiguous"`
	Appended   []string               `json:"appended"`
	Findings   []reconcileFindingJSON `json:"findings"`
}

type reconcileFindingJSON struct {
	Outcome         string `json:"outcome"`
	IntentEventID   string `json:"intent_event_id"`
	RunID           string `json:"run_id,omitempty"`
	SPIFFEID        string `json:"spiffe_id,omitempty"`
	Repo            string `json:"repo,omitempty"`
	TreeHash        string `json:"tree_hash,omitempty"`
	CommitSHA       string `json:"commit_sha,omitempty"`
	RekorEntryUUID  string `json:"rekor_entry_uuid,omitempty"`
	RekorLogIndex   int64  `json:"rekor_log_index,omitempty"`
	AgeSeconds      int64  `json:"age_seconds"`
	Detail          string `json:"detail"`
	AppendedEventID string `json:"appended_event_id,omitempty"`
}

func (r reconcileReporter) writeJSON(out io.Writer, result reconciler.Result) {
	view := reconcileReportJSON{
		Intents: result.Intents, Open: result.Open,
		Repaired: result.Repaired, Expired: result.Expired,
		Unresolved: result.Unresolved, Ambiguous: result.Ambiguous,
		Appended: result.Appended, Findings: []reconcileFindingJSON{},
	}
	if view.Appended == nil {
		view.Appended = []string{}
	}
	for _, f := range result.Findings {
		view.Findings = append(view.Findings, reconcileFindingJSON{
			Outcome: string(f.Outcome), IntentEventID: f.IntentEventID,
			RunID: f.RunID, SPIFFEID: f.SPIFFEID, Repo: f.Repo, TreeHash: f.TreeHash,
			CommitSHA: f.CommitSHA, RekorEntryUUID: f.RekorEntryUUID,
			RekorLogIndex: f.RekorLogIndex, AgeSeconds: int64(f.Age.Seconds()),
			Detail: f.Detail, AppendedEventID: f.AppendedEventID,
		})
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(view); err != nil {
		fprintf(r.stderr, "innsegl reconcile: writing the JSON report: %v\n", err)
	}
}

// openReconciler is the production wiring: a ledger, the repositories this
// deployment holds, and the transparency log.
func openReconciler(ctx context.Context, opts reconcileOptions) (cycler, func(), error) {
	store, err := ledger.Open(ctx, opts.dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the ledger: %w", err)
	}
	closeAll := store.Close

	repos, err := reconciler.NewGitWorkspace(opts.workspace)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	log, err := reconciler.NewRekorLog(opts.rekorURL, nil)
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	engine, err := reconciler.New(reconciler.Config{
		Ledger: store, Appender: store, Repos: repos, Log: log,
		TrustDomain: opts.trustDomain, ExpireAfter: opts.expireAfter,
	})
	if err != nil {
		closeAll()
		return nil, nil, err
	}
	return engine, closeAll, nil
}

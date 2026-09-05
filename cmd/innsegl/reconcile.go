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
	"innsegl.dev/innsegl/internal/spire"
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
//
// # A second pass, over a second kind of drift (#153, RM-096)
//
// internal/spire.Reconciler compares SPIRE's registration entries against the
// ledger's record of them — AB-11 and AB-12's detection control, doc 04's
// "periodic reconciliation of expected-vs-actual entries". It shipped correct
// and tested (RM-019, SPI-008) and had no caller anywhere this binary reaches:
// #153 measured that with `grep -rn "spire\.Reconciler|spire\.NewReconciler"
// cmd/ internal/ | grep -v _test.go` and got nothing back. Its drift kinds —
// `spire_entry_missing`, `spire_entry_not_deleted`, the replanted-entry case
// SPI-008 covers — were being detected by code that never ran.
//
// Rather than a third subcommand doc 05 §1 would need a new row for, this
// identity pass runs as `reconcile`'s SECOND pass, once per cycle, alongside
// the transparency-log one above: one command, one schedule, one thing to
// deploy, and an operator already running `reconcile` gets the identity check
// without learning a new noun. It is OFF by default — see -spire-address —
// and every cycle's report says so explicitly when it is, for the same reason
// openReconciler's drift detection does (see its comment on
// Result.Drift.Enabled): a control a deployment cannot see the state of is a
// control it can mistake for running.

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
	envDriftWindow = "INNSEGL_DRIFT_WINDOW"
	envInterval    = "INNSEGL_RECONCILE_INTERVAL"
)

// reconcileOptions is the resolved command line.
type reconcileOptions struct {
	dsn         string
	rekorURL    string
	workspace   string
	trustDomain string
	expireAfter time.Duration
	driftWindow int64
	interval    time.Duration
	once        bool

	// The identity pass's own configuration. Mirrors reapOptions' four SPIRE
	// fields by name — spireAddress, spireServerID, workloadAPI, timeout — so
	// an operator who has already configured `reap` configures this the same
	// way (#153, RM-096). spireAddress empty means the pass is off; see
	// openSpireReconciler.
	spireAddress  string
	spireServerID string
	workloadAPI   string
	spireTimeout  time.Duration
}

// cycler is the one thing this command needs of the transparency-log
// reconciler. It is an interface so the flag handling, the exit statuses and
// the report can be tested without a Postgres and a Rekor; *reconciler.Reconciler
// is the production implementation and REC-001/002/005 are what prove it.
type cycler interface {
	Reconcile(context.Context) (reconciler.Result, error)
}

// spireCycler is cycler's twin for the identity pass. *spire.Reconciler is
// the production implementation and SPI-008 is what proves it; this
// interface exists so this command's wiring and its report are testable
// without a SPIRE server, the same reason cycler exists.
type spireCycler interface {
	Reconcile(context.Context) (spire.Result, error)
}

// reconcileEngines is both passes one cycle runs: the transparency-log
// reconciler, always, and the identity reconciler, only when SpireEnabled.
//
// SpireEnabled is a field rather than something inferred from Spire == nil
// further down, so nothing between opening and reporting can quietly turn
// "off" into "not mentioned" — the same discipline openReconciler's own
// comment holds Result.Drift.Enabled to. DisabledReason is empty when
// SpireEnabled is true and is what the report prints when it is not.
type reconcileEngines struct {
	Rekor          cycler
	Spire          spireCycler
	SpireEnabled   bool
	DisabledReason string
}

// reconcileDeps are the seams this command's tests replace. Production wiring
// is the zero value.
type reconcileDeps struct {
	open func(context.Context, reconcileOptions) (reconcileEngines, func(), error)
}

func (d reconcileDeps) opener() func(context.Context, reconcileOptions) (reconcileEngines, func(), error) {
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
		driftWindow = fs.Int64("drift-window",
			int64(envInt(envDriftWindow, reconciler.DefaultSweepWindow)),
			"how many of the log's most recent entries each cycle cross-checks "+
				"against the chain; 0 turns drift detection off ($"+envDriftWindow+")")
		once   = fs.Bool("once", false, "run one cycle and exit, for a scheduled job")
		asJSON = fs.Bool("json", false, "write each cycle's report as JSON")
		quiet  = fs.Bool("quiet", false,
			"print nothing for a cycle that found nothing to do; failures are always reported")

		// The identity pass (#153, RM-096). Every name and env fallback below
		// is `reap`'s own (reap.go), reused rather than respelled: an operator
		// who has already configured `reap` configures this pass the same way,
		// and two ways to dial SPIRE from two subcommands is the divergence
		// this project keeps filing issues about. Empty -spire-address is a
		// configuration choice, not an error — see openSpireReconciler.
		spireAddress = fs.String("spire-address", os.Getenv(envSPIREAddress),
			"SPIRE server admin API, host:port; empty leaves the identity pass off ($"+envSPIREAddress+")")
		spireServerID = fs.String("spire-server-id", os.Getenv(envSPIREServerID),
			"SPIFFE ID the SPIRE server must present; empty means spiffe://{trust-domain}/spire/server ($"+envSPIREServerID+")")
		workloadAPI = fs.String("workload-api", envOr(envWorkloadAPI, spire.DefaultWorkloadAPIAddress),
			"Workload API socket this process fetches its own admin SVID from, used only when -spire-address is set ($"+envWorkloadAPI+")")
		spireTimeout = fs.Duration("timeout", envDuration(envSPIRETimeout, spire.DefaultTimeout),
			"bound on one SPIRE admin RPC, used only when -spire-address is set ($"+envSPIRETimeout+")")
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
		fprintf(stderr, "\nA second pass, over SPIRE's registration entries (#153, RM-096):\n")
		fprintf(stderr, "  -spire-address unset (the default) leaves it OFF, reported as such every cycle.\n")
		fprintf(stderr, "  -spire-address set turns it on and makes it required to open successfully.\n")
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
		driftWindow: *driftWindow,
		interval:    *interval, once: *once,
		spireAddress: *spireAddress, spireServerID: *spireServerID,
		workloadAPI: *workloadAPI, spireTimeout: *spireTimeout,
	}

	engines, closeAll, err := deps.opener()(ctx, opts)
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
		return report.cycle(ctx, engines)
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	worst := exitOK
	for {
		if code := report.cycle(ctx, engines); code != exitOK {
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

// cycle runs the transparency-log pass and, when configured, the identity
// pass, and reports both.
//
// A rekor-pass failure (other than a cancelled context) short-circuits the
// cycle before the identity pass runs: exitReconcileInconclusive already
// means "nothing was examined this cycle", and the two passes share the same
// ledger connection, so a ledger the rekor pass could not read is a ledger
// the identity pass could not have read either. When the rekor pass DOES
// run, the identity pass — if enabled — always runs too and is always
// reported, on the same cycle, whether or not the rekor pass found anything.
func (r reconcileReporter) cycle(ctx context.Context, engines reconcileEngines) int {
	result, err := engines.Rekor.Reconcile(ctx)
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

	var spireResult spire.Result
	var spireErr error
	if engines.SpireEnabled {
		spireResult, spireErr = engines.Spire.Reconcile(ctx)
	}
	spireFailed := engines.SpireEnabled && spireErr != nil

	stuck := result.Unresolved + result.Ambiguous
	out := r.stdout
	if stuck > 0 || spireFailed {
		out = r.stderr
	}
	switch {
	case r.asJSON:
		r.writeJSON(out, result, engines, spireResult, spireErr)
	case r.quiet && stuck == 0 && len(result.Appended) == 0 && !spireFailed && spireQuiet(engines, spireResult):
		// Nothing on either pass is worth a line: the rekor side found
		// nothing to do, and the identity side is either off (a static
		// setting, not news on every cycle) or ran clean.
	default:
		fprintf(out, "%s", renderReconcileResult(result))
		fprintf(out, "%s", renderSpireResult(engines, spireResult, spireErr))
	}

	if stuck > 0 {
		fprintf(r.stderr, "innsegl reconcile: UNRESOLVED - %d open intent(s) could not be "+
			"ruled on. Their windows are still open and nothing has been recorded about "+
			"them; the next cycle retries and cannot double-record (IP §6.5, REC-005).\n", stuck)
	}
	if spireFailed {
		fprintf(r.stderr, "innsegl reconcile: identity pass UNRESOLVED - SPIRE's entries could "+
			"not be compared against the ledger this cycle, so no identity drift has been ruled "+
			"out: %v\n", spireErr)
	}
	if stuck > 0 || spireFailed {
		return exitReconcileUnresolved
	}
	return exitOK
}

// spireQuiet reports whether the identity pass has nothing quiet mode should
// suppress: it is off (static configuration, not per-cycle news) or it ran
// and found no drift and appended nothing.
func spireQuiet(engines reconcileEngines, result spire.Result) bool {
	if !engines.SpireEnabled {
		return true
	}
	return len(result.Drifts) == 0 && len(result.Appended) == 0
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

// renderSpireResult is the identity pass's section of the human report. It
// prints something on EVERY call — off, failed, or clean — never only when
// there is drift to show: a section that only appears when there is news is
// a section whose absence cannot be told apart from "not run" (#153, RM-096;
// see openReconciler's own comment on this same discipline for Rekor drift).
func renderSpireResult(engines reconcileEngines, result spire.Result, err error) string {
	var b strings.Builder
	switch {
	case !engines.SpireEnabled:
		fmt.Fprintf(&b, "spire: OFF - %s\n", engines.DisabledReason)
	case err != nil:
		fmt.Fprintf(&b, "spire: FAILED - %v\n", err)
	default:
		fmt.Fprintf(&b, "spire: runs %d  active %d  entries %d  drift %d  appended %d  unrecordable %d\n",
			result.LedgerRuns, result.ActiveRuns, result.SPIREEntries,
			len(result.Drifts), len(result.Appended), len(result.Unrecordable))
		for _, d := range result.Drifts {
			fmt.Fprintf(&b, "  %-24s spiffe=%s run=%s entries=%s\n",
				d.Kind, d.SPIFFEID, d.RunID, strings.Join(d.EntryIDs, ","))
		}
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
	// Spire is always present, enabled or not — a monitor reading this report
	// must be able to tell "checked and clean" from "not being checked"
	// without inferring it from a missing key (#153, RM-096).
	Spire spireReportJSON `json:"spire"`
}

// spireReportJSON is the identity pass's machine-readable report.
type spireReportJSON struct {
	// Enabled is false whenever -spire-address (or $INNSEGL_SPIRE_ADDRESS)
	// names nothing; DisabledReason then says why. This is the field a
	// monitor watches so a deployment cannot mistake "off" for "checked".
	Enabled        bool             `json:"enabled"`
	DisabledReason string           `json:"disabled_reason,omitempty"`
	Error          string           `json:"error,omitempty"`
	LedgerRuns     int              `json:"ledger_runs,omitempty"`
	ActiveRuns     int              `json:"active_runs,omitempty"`
	SPIREEntries   int              `json:"spire_entries,omitempty"`
	Drifts         []spireDriftJSON `json:"drifts,omitempty"`
	Appended       []string         `json:"appended,omitempty"`
	Unrecordable   []spireDriftJSON `json:"unrecordable,omitempty"`
}

// spireDriftJSON is one entry of spireReportJSON.Drifts or .Unrecordable.
type spireDriftJSON struct {
	Kind           string   `json:"kind"`
	SPIFFEID       string   `json:"spiffe_id,omitempty"`
	RunID          string   `json:"run_id,omitempty"`
	EntryIDs       []string `json:"entry_ids,omitempty"`
	SubjectEventID string   `json:"subject_event_id,omitempty"`
	Reason         string   `json:"reason,omitempty"`
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

func (r reconcileReporter) writeJSON(
	out io.Writer, result reconciler.Result, engines reconcileEngines, spireResult spire.Result, spireErr error,
) {
	view := reconcileReportJSON{
		Intents: result.Intents, Open: result.Open,
		Repaired: result.Repaired, Expired: result.Expired,
		Unresolved: result.Unresolved, Ambiguous: result.Ambiguous,
		Appended: result.Appended, Findings: []reconcileFindingJSON{},
		Spire: spireReportView(engines, spireResult, spireErr),
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

// spireReportView builds the identity pass's JSON view. Enabled is set
// unconditionally so the shape never depends on whether there was anything
// else to say.
func spireReportView(engines reconcileEngines, result spire.Result, err error) spireReportJSON {
	view := spireReportJSON{Enabled: engines.SpireEnabled}
	switch {
	case !engines.SpireEnabled:
		view.DisabledReason = engines.DisabledReason
		return view
	case err != nil:
		view.Error = err.Error()
		return view
	}
	view.LedgerRuns = result.LedgerRuns
	view.ActiveRuns = result.ActiveRuns
	view.SPIREEntries = result.SPIREEntries
	view.Appended = result.Appended
	if view.Appended == nil {
		view.Appended = []string{}
	}
	for _, d := range result.Drifts {
		view.Drifts = append(view.Drifts, spireDriftView(d))
	}
	for _, d := range result.Unrecordable {
		view.Unrecordable = append(view.Unrecordable, spireDriftView(d))
	}
	return view
}

func spireDriftView(d spire.Drift) spireDriftJSON {
	return spireDriftJSON{
		Kind: string(d.Kind), SPIFFEID: d.SPIFFEID, RunID: d.RunID,
		EntryIDs: d.EntryIDs, SubjectEventID: d.SubjectEventID, Reason: d.Reason,
	}
}

// openReconciler is the production wiring: a ledger, the repositories this
// deployment holds, the transparency log, and — when configured — the SPIRE
// identity pass (#153, RM-096) sharing the same ledger connection.
func openReconciler(ctx context.Context, opts reconcileOptions) (reconcileEngines, func(), error) {
	store, err := ledger.Open(ctx, opts.dsn)
	if err != nil {
		return reconcileEngines{}, nil, fmt.Errorf("opening the ledger: %w", err)
	}
	closeAll := store.Close

	repos, err := reconciler.NewGitWorkspace(opts.workspace)
	if err != nil {
		closeAll()
		return reconcileEngines{}, nil, err
	}
	log, err := reconciler.NewRekorLog(opts.rekorURL, nil)
	if err != nil {
		closeAll()
		return reconcileEngines{}, nil, err
	}
	// Drift detection is IP §6.5's third job and IP §6.10's proof: the Rekor
	// cross-check that makes a compromised MCP detectable. RM-036 (#44) built
	// it and left it optional; a reconciler that does not run it is not doing
	// the job doc 05 §2 lists it for, so it is ON here and -drift-window 0 is
	// the deliberate way off. Result.Drift.Enabled reports which on every
	// cycle, so a deployment cannot believe it is watching when it is not.
	cfg := reconciler.Config{
		Ledger: store, Appender: store, Repos: repos, Log: log,
		TrustDomain: opts.trustDomain, ExpireAfter: opts.expireAfter,
	}
	if opts.driftWindow > 0 {
		cfg.Drift = &reconciler.DriftConfig{Sweep: log, Window: opts.driftWindow}
	}
	engine, err := reconciler.New(cfg)
	if err != nil {
		closeAll()
		return reconcileEngines{}, nil, err
	}

	spireEngine, spireCloser, spireErr := openSpireReconciler(ctx, opts, store)
	if spireErr != nil {
		closeAll()
		return reconcileEngines{}, nil, fmt.Errorf("opening the identity pass: %w", spireErr)
	}
	if spireCloser != nil {
		previous := closeAll
		closeAll = func() {
			spireCloser()
			previous()
		}
	}

	engines := reconcileEngines{Rekor: engine, Spire: spireEngine, SpireEnabled: spireEngine != nil}
	if !engines.SpireEnabled {
		engines.DisabledReason = "-spire-address (or $" + envSPIREAddress + ") is not set; " +
			"SPIRE registration entries are not being compared against the ledger, and the " +
			"drift this pass exists to catch (spire_entry_missing, spire_entry_not_deleted, " +
			"spire_entry_duplicated, spire_entry_unattributed — RM-019, SPI-008) is undetected"
	}
	return engines, closeAll, nil
}

// openSpireReconciler builds the identity pass, or reports that it is
// deliberately off.
//
// -spire-address empty is a configuration CHOICE, not an error: `reconcile`
// has run in this project's reference deployment without SPIRE configured
// since before this pass existed (doc 05 §2), and RM-096 exists to give the
// package a caller, not to make an already-deployed command refuse to start.
// What it must not do is run silently — see openReconciler's DisabledReason
// and every render/writeJSON call, which report it on EVERY cycle rather than
// only when there is drift to show (doc 04's "a table of green cells that
// name tests nobody ran").
//
// Once an operator DOES set -spire-address, though, this half stops being
// optional: a broken dial fails the WHOLE command closed here, in openReconciler,
// exactly like a broken -dsn or -workspace does today. Degrading silently to
// "off" because a control the operator turned on could not be built would be
// the exact false-green #153 exists to fix — internal/spire.NewReconciler's
// own doc calls a reconciler missing one of its three halves "a detection
// control that reports agreement it never checked", and a reconcile that
// swallowed this error and kept running the Rekor pass alone WOULD be
// reporting exactly that: identity agreement it never checked, silently.
func openSpireReconciler(
	ctx context.Context, opts reconcileOptions, store *ledger.Store,
) (spireCycler, func(), error) {
	if opts.spireAddress == "" {
		return nil, nil, nil
	}

	// The dial is shared with `reap` (#153/RM-096) rather than written twice;
	// see spiredial.go.
	client, unwind, err := dialSPIREAdmin(ctx, "reconcile's identity pass",
		opts.spireAddress, opts.trustDomain, opts.spireServerID, opts.workloadAPI, opts.spireTimeout)
	if err != nil {
		return nil, nil, err
	}

	engine, err := spire.NewReconciler(spire.ReconcilerConfig{
		Entries: client, Ledger: store, Appender: store,
	})
	if err != nil {
		unwind()
		return nil, nil, err
	}
	return engine, unwind, nil
}

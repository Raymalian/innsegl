// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"innsegl.dev/innsegl/internal/ledger"
)

// `innsegl resolve-alert` — the write half of alert resolution (RM-102,
// #167, ADR-0044).
//
// # Why this is a CLI subcommand and not a route on `innsegl api`
//
// `innsegl api` IS doc 05 §1's `innsegl-dashboard` row, and that row says "No
// write credentials mounted — enforced by giving it a read-only DB role".
// `internal/api.Open` refuses to start at all on a credential AssertReadOnly
// finds it can write with (RM-083, #121), and FD P6 says it in the frontend's
// own terms: "No mutating action exists anywhere in the UI. No delete, no
// edit... The only 'actions' are copy, filter, export, and navigate." A
// "resolve" button reachable from the dashboard — on any backend — is a
// mutating UI action, which P6 forbids categorically, not only for the
// ledger. See ADR-0044 for the full argument and what it costs.
//
// So this is the fifth write-credentialed operator command beside `reap`,
// `reconcile`, `seal` and `serve`: run from a trusted host, holding
// $INNSEGL_LEDGER_DSN, never reachable from the public dashboard.
//
// # It runs once and exits
//
// Unlike `reap`/`reconcile`/`seal`, there is no loop and no `-once` flag:
// resolving an alert is a single, deliberate human action, not a scheduled
// sweep. There is also no leader-election concern doc 05 §2 needs an opinion
// on, for the same reason.
//
// # Not idempotent, on purpose
//
// internal/ledger.Store.ResolveAlert refuses a second resolution for the
// same event_id (ErrAlertAlreadyResolved) rather than silently succeeding or
// overwriting the first. A different resolvedBy/reason arriving for an
// already-resolved alert is a correction that wants a person looking at both
// values, not code picking one — see the ADR.

// Exit statuses, continuing cli.go's contract. The canary owns 3 and 4, the
// reaper 5 and 6, the reconciler 7 and 8, the sealer 9 and 10, `api` 11-13,
// `init` 14 and 15; these are resolve-alert's.
const (
	// exitResolveRefused: the ledger understood the request and refused it —
	// unknown event_id, not an alert event, or already resolved. Nothing was
	// written.
	exitResolveRefused = 16
	// exitResolveInconclusive: the command could not even ask — bad
	// configuration or an unreachable ledger. Nothing was examined.
	exitResolveInconclusive = 17
)

// resolver is the one thing this command needs of a ledger store. It is an
// interface, matching reap.go's sweeper and reconcile.go's reconcileEngines,
// so the flag handling and the exit statuses are testable without a Postgres.
type resolver interface {
	ResolveAlert(ctx context.Context, eventID, resolvedBy, reason string) (ledger.AlertResolution, error)
}

// resolveAlertDeps are the seams the command's tests replace. Production
// wiring is the zero value.
type resolveAlertDeps struct {
	open func(ctx context.Context, dsn string) (resolver, func(), error)
}

func (d resolveAlertDeps) opener() func(ctx context.Context, dsn string) (resolver, func(), error) {
	if d.open != nil {
		return d.open
	}
	return openResolveAlertStore
}

func openResolveAlertStore(ctx context.Context, dsn string) (resolver, func(), error) {
	s, err := ledger.Open(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	return s, s.Close, nil
}

func resolveAlertCommand(args []string, stdout, stderr io.Writer) int {
	return runResolveAlertCommand(args, stdout, stderr, resolveAlertDeps{})
}

func runResolveAlertCommand(args []string, stdout, stderr io.Writer, deps resolveAlertDeps) int {
	fs := flag.NewFlagSet("innsegl resolve-alert", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"ledger connection string — prefer the environment variable ($"+envLedgerDSN+")")
		eventID = fs.String("event-id", "",
			"event_id of the unattributed_signature_detected or ledger_drift_detected alert to resolve")
		resolvedBy = fs.String("resolved-by", "",
			"who is resolving it — a name, an email, or a ticket handle")
		reason = fs.String("reason", "",
			"why this alert is being resolved")
		asJSON = fs.Bool("json", false, "write the result as JSON")
	)

	fs.Usage = func() {
		fprintf(stderr, "innsegl resolve-alert - record that a human reviewed an integrity alert (RM-102, #167)\n\n")
		fprintf(stderr, "Usage:\n  innsegl resolve-alert -event-id=<id> -resolved-by=<who> -reason=<why> [flags]\n\n")
		fprintf(stderr, "Writes one row to innsegl.alert_resolutions. The alert event itself is never\n")
		fprintf(stderr, "touched: innsegl.events is append-only and permanent (I4), and this command\n")
		fprintf(stderr, "holds no path that could change that. Not reachable from the dashboard — see\n")
		fprintf(stderr, "ADR-0044 for why.\n\n")
		fprintf(stderr, "Exit status:\n")
		fprintf(stderr, "  %d  the alert now carries a resolution\n", exitOK)
		fprintf(stderr, "  %d  the command line was not understood\n", exitUsage)
		fprintf(stderr, "  %d  REFUSED - unknown event_id, not an alert event, or already resolved\n", exitResolveRefused)
		fprintf(stderr, "  %d  INCONCLUSIVE - the ledger could not be reached; nothing was written\n", exitResolveInconclusive)
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
		fprintf(stderr, "innsegl resolve-alert: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitUsage
	}

	missing := ""
	switch {
	case *dsn == "":
		missing = "-dsn (or $" + envLedgerDSN + ")"
	case *eventID == "":
		missing = "-event-id"
	case *resolvedBy == "":
		missing = "-resolved-by"
	case *reason == "":
		missing = "-reason"
	}
	if missing != "" {
		fprintf(stderr, "innsegl resolve-alert: %s is required\n", missing)
		return exitUsage
	}

	ctx := context.Background()

	store, closeAll, err := deps.opener()(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "innsegl resolve-alert: %v\n", err)
		fprintf(stderr, "innsegl resolve-alert: INCONCLUSIVE - the ledger could not be reached; nothing was written\n")
		return exitResolveInconclusive
	}
	if closeAll != nil {
		defer closeAll()
	}

	res, err := store.ResolveAlert(ctx, *eventID, *resolvedBy, *reason)
	if err != nil {
		fprintf(stderr, "innsegl resolve-alert: %v\n", err)
		fprintf(stderr, "innsegl resolve-alert: REFUSED - nothing was written\n")
		return exitResolveRefused
	}

	if *asJSON {
		writeResolveAlertJSON(stdout, stderr, res)
	} else {
		fprintf(stdout, "resolved %s by %s at %s: %s\n",
			res.EventID, res.ResolvedBy, res.ResolvedAt.Format("2006-01-02T15:04:05Z"), res.Reason)
	}
	return exitOK
}

// resolveAlertJSON is the machine-readable result. AlertResolution itself
// carries no json tags — it is not part of doc 02's canonical schema and has
// never needed to serialize — so this is the view, matching reap.go's
// reapReportJSON split for the same reason.
type resolveAlertJSON struct {
	EventID    string `json:"event_id"`
	ResolvedBy string `json:"resolved_by"`
	ResolvedAt string `json:"resolved_at"`
	Reason     string `json:"reason"`
}

func writeResolveAlertJSON(stdout, stderr io.Writer, res ledger.AlertResolution) {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resolveAlertJSON{
		EventID:    res.EventID,
		ResolvedBy: res.ResolvedBy,
		ResolvedAt: res.ResolvedAt.Format("2006-01-02T15:04:05.000Z"),
		Reason:     res.Reason,
	}); err != nil {
		fprintf(stderr, "innsegl resolve-alert: writing JSON: %v\n", err)
	}
}

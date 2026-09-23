// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"fmt"
	"slices"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// The sweep's POPULATION, which is the thing RM-181 (#289) is about.
//
// # The defect, measured
//
// The reaper's population was the SPIRE entry list. The ledger's `active` is
// derived from the absence of `run_retired`/`run_expired` on the chain
// (internal/ledger's RunStateOf). Two different populations, and nothing
// reconciled them.
//
// Measured on a live deployment: the ledger reported four runs active while
// SPIRE held entries for three of them. The fourth had no entry at all, so the
// sweep could not see it and could never expire it — whatever its state. Every
// minute the reaper printed
//
//	reap at …: 3 entries in the agent subtree, 3 live, 0 expired, 0 skipped, 0 failed
//
// beside a ledger reporting four, and that line reads as a count of agents.
//
// # What is NOT wrong, and must not be "fixed"
//
// The reaper's DECISION. It was checked against every entry it could see and it
// returns the right answer every time: silence.go's `orphaned`, over the
// configured grace, against the run's last recorded activity. A run silent for
// 38 hours was offered as proof of a wrong verdict and it was not one — that
// session had a live process behind it, idle rather than gone, and expiring it
// would have repeated the 2026-09-08 sweep that killed two runs mid-task.
//
// So the set the reaper is given is the defect, not the verdict. This file
// widens the SET and changes no part of the DECISION:
//
//   - the grace is unchanged, and is still the only duration in the decision;
//   - no threshold is added, anywhere;
//   - an unentried run is judged by the same `orphaned` predicate, over the
//     same `LastActivity`, with the same grace (see orphanedUnentried).
//
// A run that is working is therefore never expired by this file, whether it has
// an entry or not: its activity is inside the grace and the predicate says live.
// That control is the one that matters most and it is SPI-018's whole table.
//
// # Reconciled, rather than driven from the ledger — and why
//
// The issue offered two shapes: reconcile the two populations, or drive the
// sweep from the ledger instead of from SPIRE. This is the first, and the
// reason is that the second LOSES A CONTROL.
//
// An entry the ledger has no record of at all is doc 04's AB-11 in its purest
// form — an identity planted straight onto the SPIRE admin socket, which
// ADR-0011 records as unauthenticated by construction. A sweep driven from the
// ledger would never list it, because the ledger is exactly what such an entry
// is missing from. The same goes for every entry classify refuses to judge: an
// entry with no TTL, an entry SPIRE reports no creation time for, a SPIFFE ID
// that is not a run identity. All of those are reported today and would become
// invisible, which is the shape of the bug being fixed, aimed the other way.
//
// So SPIRE stays the primary population and the ledger CONTRIBUTES to it: every
// run the ledger calls active that the entry listing held nothing for becomes a
// candidate with no entry. The union is what the sweep considers, and the report
// says which half each run came from.
//
// # Nothing new is ever appended twice, by construction
//
// An unentried run that is expired gets a `run_expired` — the existing event,
// no new type (doc 02 §3 is closed). That event is a WITHDRAWAL, and the one
// rule then reads the run as `lapsed`, not `active`. So the next sweep does not
// see it in this population at all, and cannot record a second withdrawal for
// the same silence. The idempotency key (reaper.go's ExpiryKeyAfter) is the
// belt; this is the braces, and it is why the ledger half needs no dedupe set.
//
// # Cost
//
// ActiveRuns as implemented here walks the chain, because LedgerReader — the
// only ledger surface this package depends on — is positional. That is the same
// walk internal/spire's reconciler already makes on the same interval in the
// same deployment, so it is a doubling of an existing cost rather than a new
// kind of one. A deployment that outgrows it supplies its own RunSource over
// the aggregate the read API already runs (internal/api's runIndexCTE), which
// wants a method on *ledger.Store and therefore an issue of its own.

// UnentriedRun is one run the LEDGER calls active. It carries the two things
// the sweep needs to judge and record a run it has no SPIRE entry for.
type UnentriedRun struct {
	// RunID is the run, as doc 02 §2 spells it.
	RunID string
	// SPIFFEID is the identity the ledger registered for it. It is the
	// ledger's, not SPIRE's — SPIRE holds nothing for this run, which is the
	// whole finding — and it is what a `run_expired` for this run must carry.
	SPIFFEID string
}

// RunSource is the LEDGER's half of the sweep's population.
//
// It is OPTIONAL, exactly as ActivitySource is, and its absence leaves every
// decision the sweep makes byte for byte what it was: the SPIRE entry list
// alone. That is not timidity. A deployment that has not configured one gets a
// report which SAYS the ledger's active runs were not read, rather than a
// report that quietly implies it counted everything — see SweepReport.String.
type RunSource interface {
	// ActiveRuns returns every run the ledger's one rule reads as active at
	// `now`, in SPIFFE ID order.
	//
	// "Active" is internal/ledger's RunStateOf and nothing else. A source that
	// answered on its own terms would put the reaper back in the position
	// RM-155 (#258) took three components out of.
	ActiveRuns(ctx context.Context, now time.Time) ([]UnentriedRun, error)
}

// LedgerRunSource answers RunSource by walking the chain.
//
// It is the reconciler's fold, reused rather than rewritten: one walk, one
// ledgerView, one ledger.RunStateOf. See readLedgerView.
type LedgerRunSource struct {
	reader  LedgerReader
	batch   int64
	horizon time.Duration
}

// NewLedgerRunSource builds a RunSource over a chain reader. *ledger.Store
// satisfies LedgerReader.
//
// The restore horizon comes from ledger.EnvRestoreHorizon, read with the same
// function internal/api and the reconciler read it with. One variable, one
// number, every component: a reaper that drew the Lapsed/Abandoned line
// somewhere else would sweep a population no dashboard agrees with.
func NewLedgerRunSource(reader LedgerReader) (*LedgerRunSource, error) {
	if reader == nil {
		return nil, newError(ClassInvariantViolation, "reap", "",
			"no ledger reader: a run source with no chain to read would report "+
				"that no run is active, which is a silent answer and not a true one",
			false, nil)
	}
	return &LedgerRunSource{
		reader:  reader,
		batch:   defaultLedgerBatch,
		horizon: ledger.RestoreHorizonFromEnv(),
	}, nil
}

// ActiveRuns walks the chain and returns the runs the one rule reads as active.
//
// A run whose `run_registered` this walk could not read is ABSENT rather than
// guessed at, which is the rule compareEntries already applies in the same
// direction: the reaper must not withdraw an identity from a run it cannot
// show was ever registered.
func (s *LedgerRunSource) ActiveRuns(ctx context.Context, now time.Time) ([]UnentriedRun, error) {
	view, err := readLedgerView(ctx, s.reader, s.batch)
	if err != nil {
		return nil, err
	}

	out := make([]UnentriedRun, 0, len(view.runs))
	for spiffeID, run := range view.runs {
		if run.registeredEventID == "" || run.runID == "" {
			continue
		}
		if run.state(now, s.horizon) != ledger.RunActive {
			continue
		}
		out = append(out, UnentriedRun{RunID: run.runID, SPIFFEID: spiffeID})
	}
	slices.SortFunc(out, func(a, b UnentriedRun) int {
		switch {
		case a.SPIFFEID < b.SPIFFEID:
			return -1
		case a.SPIFFEID > b.SPIFFEID:
			return 1
		default:
			return 0
		}
	})
	return out, nil
}

// sweepUnentried adds the ledger's half of the population to a report that
// already holds SPIRE's.
//
// `held` is every SPIFFE ID the entry listing carried inside the agent subtree,
// including the ones classify refused to judge. An entry the reaper would not
// judge is still an entry: counting its run as unentried would report a run as
// having no identity when SPIRE plainly holds one, and would then withdraw it.
//
// A source that cannot answer does not fail the sweep. The SPIRE half's orphans
// are still orphans and still need reaping, so the failure is reported as a
// skip and LedgerRunsRead stays false — which is what makes the report SAY that
// this half was not read rather than imply that it found nothing.
func (r *Reaper) sweepUnentried(ctx context.Context, now time.Time,
	report *SweepReport, held map[string]struct{},
) {
	if r.runs == nil {
		return
	}
	active, err := r.runs.ActiveRuns(ctx, now)
	if err != nil {
		report.Skipped = append(report.Skipped, Skipped{
			Reason: fmt.Sprintf("the ledger could not say which runs are active, so a run "+
				"with no SPIRE entry was not looked at this sweep: %v", err),
		})
		return
	}
	report.LedgerRunsRead = true

	for _, run := range active {
		if _, ok := held[run.SPIFFEID]; ok {
			continue
		}
		cand, skipped := r.unentriedCandidate(run)
		if skipped != nil {
			report.Unentried++
			report.Skipped = append(report.Skipped, *skipped)
			continue
		}
		report.Unentried++

		reap, unknown := r.orphanedUnentried(ctx, now, &cand)
		if unknown != nil {
			report.Skipped = append(report.Skipped, *unknown)
			continue
		}
		if !reap {
			report.Live = append(report.Live, cand)
			continue
		}
		expiry, rerr := r.reap(ctx, cand)
		if rerr != nil {
			report.Failures = append(report.Failures, Failure{
				SPIFFEID: cand.Entry.SPIFFEID,
				Err:      rerr,
			})
			continue
		}
		report.Expired = append(report.Expired, expiry)
	}
}

// unentriedCandidate renders one ledger run as a candidate with no entry.
//
// The SPIFFE ID is parsed under the same rule classify applies to an entry's,
// and for the same reason: an identity that is not this trust domain's run
// identity is not this reaper's to withdraw, whichever side of the comparison
// it arrived from. A ledger that named one is a ledger defect and is reported,
// not acted on.
func (r *Reaper) unentriedCandidate(run UnentriedRun) (Candidate, *Skipped) {
	ref, err := parseRunIdentity(run.SPIFFEID, r.client.trustDomain)
	if err != nil {
		return Candidate{}, &Skipped{
			SPIFFEID: run.SPIFFEID,
			Reason: fmt.Sprintf("the ledger calls run %s active under an identity that is "+
				"not a run identity of this trust domain: %v", run.RunID, err),
		}
	}
	return Candidate{
		// Entry carries the SPIFFE ID and NOTHING ELSE. The empty Entry.ID is
		// the finding: there is no entry, so there is nothing to delete and
		// nothing whose TTL could have dated this run.
		Entry:     Entry{SPIFFEID: run.SPIFFEID},
		Run:       ref,
		Unentried: true,
	}, nil
}

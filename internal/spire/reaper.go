// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"

	"innsegl.dev/innsegl/internal/event"
)

// The TTL reaper (RM-017, #25). IP §6.7 in full:
//
//	Agent crashes without `retire_agent` → SPIRE entry TTL expires it; a reaper
//	deletes expired entries and appends `run_expired` (distinct from
//	`run_retired`).
//
// # Why the two event types must stay distinct
//
// `run_retired` is a statement about the agent: it finished and said so.
// `run_expired` is a statement about the absence of one: nothing ever said so,
// and the identity outlived the lifetime it was granted. An auditor can tell a
// clean shutdown from a crash only because the ledger spells them differently,
// and doc 02 §3 gives them different sources as well — `mcp` for the first,
// `reaper` for this one — so the record also says who noticed. Collapsing them
// would not lose a field; it would lose the only signal §6.7 exists to
// preserve.
//
// # What "expired" means here, and what it cannot mean
//
// SPIRE holds no liveness signal. A registration entry created by
// Client.RegisterRun carries two durable facts and nothing else: when the
// server created it, and the TTL of the SVIDs it issues. There is no field
// that says "the workload behind this entry is still running", and there is no
// callback when one stops. So the reaper cannot detect a crash from SPIRE. What
// it can do is bound a lifetime: an entry that has outlived the identity
// lifetime it was registered with, plus a configured grace, is PAST ITS
// DEADLINE.
//
// It is not thereby orphaned. This file used to say it was — "because a run
// that was still working would have been retired or re-registered" — and that
// clause was measured false on 2026-09-08, when the first production sweep
// deleted the identities of two agents mid-task. A subagent works for hours on
// one registration and re-registers never. See silence.go, which holds the
// decision and the measurement: past the deadline the LEDGER is asked when the
// run last did something, and only a run that has also gone quiet is orphaned.
//
// The bound is a policy, and it is deliberately a knob rather than a derived
// constant — see ADR-0014 and the open question it records.
//
// # Ordering: record first, delete second
//
// I3 is "no action without a record". A reaper that deleted first and crashed
// before appending would erase an identity with nothing anywhere saying it ever
// existed or why it went. Appending first and crashing before the delete leaves
// the entry alive for one more sweep, which the next sweep fixes — and which is
// visible in the ledger the whole time. The recoverable failure is the one this
// code chooses.
//
// # Two reapers at once
//
// Doc 05 §2 runs the single-active components under leader election, and this
// issue does not implement it. Nothing here breaks if two run anyway: the
// append is deduplicated by an idempotency key that names the LAPSE — the run
// id plus the chain position of the last thing the run did before going quiet
// (ADR-0004 leaves the key unconstrained on this event type) — the ledger
// serializes appends under an advisory lock, and a delete of an entry that is
// already gone is a success with nothing deleted. Two reapers produce one
// `run_expired` and one deletion between them.
//
// # One withdrawal per lapse, and never a deletion without one (RM-152, #255)
//
// That key used to be the run id alone, which made "two reapers, one lapse"
// and "one reaper, two lapses" indistinguishable. A run that lapsed, was
// restored by get_credential, worked, and lapsed again had its identity
// deleted a second time with nothing appended — the one thing I3 forbids. The
// key now carries the lapse; ExpiryKey and ExpiryKeyAfter hold the detail, and
// reap refuses to delete an entry it has no event id for.

// DefaultReapGrace is how long a run may be SILENT before it is called
// orphaned.
//
// # It is deliberately not DefaultRunTTL any more
//
// It used to be exactly that — one SVID lifetime — and the two have nothing to
// do with each other. `DefaultRunTTL` is how often a certificate ROTATES: five
// minutes is normal and healthy for SPIFFE, and the agent gets a fresh SVID
// under the same SPIFFE ID without noticing. How long an agent may go quiet
// before we conclude it is dead is a completely different question, and
// answering it with the rotation period made an agent mortal after ten minutes
// of wall clock.
//
// MEASURED, and it is why this changed: an operator's session was killed and
// resumed hours later. The run was never retired and its work was not finished,
// but its entry had been reaped, so the tooling could only mint a NEW run — and
// one logical task fragmented into several identities for no reason but a
// timer. A usage limit, an overnight pause and a lunch break all do this.
//
// # What the reaper is still for
//
// IP §6.7's purpose is intact: an agent that crashes without `retire_agent`
// must not keep a usable identity forever, because an abandoned credential
// nobody is watching is exactly what an attacker wants. Twelve hours bounds
// that while being longer than any pause a working agent takes. An operator who
// wants the old aggressiveness sets $INNSEGL_REAP_GRACE.
//
// Note this is measured against the run's last observed ACTIVITY in the ledger
// (RM-... , #180), not against its age — so a run that is genuinely working is
// never reaped however long it has been alive, and this bound only ever applies
// to silence.
//
// It is NOT applied by ReaperConfig: a zero Grace there means zero grace, so
// that no caller can be surprised into a policy it did not ask for. The default
// belongs to the operator surface, and `innsegl reap` is where it is applied.
const DefaultReapGrace = 12 * time.Hour

// reapPageSize bounds one ListEntries page. SPIRE may return fewer.
const reapPageSize = 500

// expiryKeyPrefix namespaces the reaper's idempotency keys.
//
// PROTECTED-ADJACENT: this prefix is the head of the `idempotency_key` of every
// `run_expired` event, and `idempotency_key` is part of the canonical preimage
// (doc 02 §4). Changing it changes the canonical bytes of events that have
// already been written, which I4 does not allow. See ADR-0014.
//
// RM-152 (#255) added a per-lapse SUFFIX below and did not touch this prefix or
// the single-key form, for exactly that reason: an event already on the chain
// keeps the key it was hashed with, for ever. Only new events are named the new
// way, and the old spelling stays readable — see ExpiryKey.
const expiryKeyPrefix = "reaper:run_expired:"

// lapseKeySeparator divides the run id from the lapse that is being recorded.
//
// `@` cannot occur in a run id — doc 02 §2 holds one to
// `[a-z0-9][a-z0-9-]{0,62}`, which ValidateIdentifier enforces — so a key in
// the single-key form can never be mistaken for a key in the per-lapse form,
// whatever the run is called. The whole key stays inside doc 02 §2's 128 bytes:
// 19 of prefix, at most 63 of run id, one of separator, at most 19 of position.
const lapseKeySeparator = "@"

// ExpiryKey is the SINGLE-KEY form: the idempotency key a `run_expired` carried
// before RM-152 (#255), when one run had one expiry for its whole life.
//
// It is still written, and it is still the key looked up first, in the one case
// where nothing better exists: a deployment with no ActivitySource, or a run the
// ledger has never heard of, has nothing with which to tell one lapse from
// another, and naming them all the same is what every deployment before #255
// did. It is also still READ for every run, because live chains carry events
// under it — see Reaper.record.
//
// What it cannot do is name a SECOND lapse. A run that lapses, is restored,
// works and lapses again has had an entry created, used and deleted twice, and
// a key derived from the run id alone answers the second deletion with the
// first one's event. See ExpiryKeyAfter.
func ExpiryKey(runID string) string { return expiryKeyPrefix + runID }

// ExpiryKeyAfter is the PER-LAPSE form: the idempotency key of the
// `run_expired` that records the silence which began after chain position
// `position`.
//
// # Why the chain position, and why that is stable
//
// A lapse is a stretch of silence, and the only thing that names one uniquely
// is the last thing the run did before it. `chain_position` is assigned once,
// inside the ledger's serialized append, and never reassigned (doc 02 §2), so
// two reapers sweeping the same silence read the same last activity and compute
// the same key — which is the property the single-key form was chosen for and
// the one this must not lose. A restart, a stale listing and a second reaper
// all still produce one event between them.
//
// It is deliberately NOT derived from anything the reaper itself can move: not
// the sweep's clock (two reapers sweep at different instants), not the entry id
// (the restore path creates a new entry, so a retry after a restore would look
// like a new lapse), and not a counter of prior expiries (a sweep that failed
// mid-way would renumber every lapse after it).
//
// ADR-0004 leaves the key's shape unconstrained on this event type, which is
// what makes the suffix legal at all without a major (doc 08).
func ExpiryKeyAfter(runID string, position int64) string {
	return ExpiryKey(runID) + lapseKeySeparator + strconv.FormatInt(position, 10)
}

// EventSink is the ledger surface the reaper needs: append one event, and ask
// whether a key has already produced one.
//
// It is an interface rather than *ledger.Store so that this package keeps the
// property its doc comment claims — it holds no ledger — and so that the error
// paths below are testable without a Postgres. *ledger.Store satisfies it.
type EventSink interface {
	// Append writes one event and returns the stored record. An append whose
	// idempotency key has already been used returns the existing record.
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
	// EventByIdempotencyKey returns the event a key produced, if any.
	EventByIdempotencyKey(ctx context.Context, key string) (event.Fields, bool, error)
}

// ActivityPositionSource is ActivitySource (silence.go) with the one extra
// answer the per-lapse key needs: WHERE in the chain the run's last activity
// sits, not only when it happened.
//
// It is declared as a separate, optional interface rather than added to
// ActivitySource so that an ActivitySource which does not implement it keeps
// working and keeps its old behaviour, and so that #255 adds no method to a
// seam other components already satisfy. *ledger.Store implements it.
//
// Why a position and not the instant ActivitySource already returns: a lapse
// has to be named by something two reapers both compute and neither can move,
// and `chain_position` is assigned once inside the serialized append and never
// reassigned (doc 02 §2). See ExpiryKeyAfter.
type ActivityPositionSource interface {
	LastActivityAt(ctx context.Context, runID string) (time.Time, int64, bool, error)
}

// Candidate is one registration entry the reaper examined, with the two
// timestamps SPIRE holds about it and the deadline they imply.
type Candidate struct {
	// Entry is the entry as SPIRE holds it.
	Entry Entry
	// Run is the run named by the entry's SPIFFE ID.
	Run RunRef
	// CreatedAt is when the SPIRE server created the entry.
	CreatedAt time.Time
	// ExpiresAt is SPIRE's own entry expiry, zero when it holds none.
	// Client.RegisterRun does not set one, so it is normally zero; an entry
	// that carries one is believed over the computed deadline.
	ExpiresAt time.Time
	// Deadline is the instant after which the run is past its identity
	// lifetime. Past it the run is a SUSPECTED orphan, not a confirmed one —
	// see silence.go.
	Deadline time.Time
	// LastActivity is when the ledger last saw this run do something, zero
	// when no activity source was configured or the ledger knows nothing of
	// the run. A candidate in a report's Live list carrying one was spared by
	// its own work rather than by its TTL.
	LastActivity time.Time
	// Unentried is true for a candidate the LEDGER supplied because SPIRE held
	// no entry for it (RM-181, #289). Entry.ID is then empty, CreatedAt and
	// ExpiresAt are zero, and Deadline is the end of the grace measured from
	// LastActivity rather than from any TTL — there is no TTL, which is the
	// finding. Nothing is deleted for such a candidate: there is nothing to
	// delete, and the withdrawal is the whole of what the sweep can do.
	Unentried bool
}

// Expiry is one orphaned run, as reaped.
type Expiry struct {
	Candidate
	// EventID is the `run_expired` event for this run, whether this sweep
	// appended it or found it already there.
	EventID string
	// Recorded is true when this sweep appended the event, false when a
	// previous pass had already recorded the expiry.
	Recorded bool
	// Deleted is true when this sweep deleted the entry, false when SPIRE no
	// longer held it.
	Deleted bool
}

// Skipped is an entry inside the agent subtree that the reaper refused to
// judge. It is never deleted: an entry the reaper cannot date, or cannot read
// as a run identity, is one it has no basis to call orphaned, and deleting an
// identity on no basis is worse than leaving it.
type Skipped struct {
	EntryID  string
	SPIFFEID string
	Reason   string
}

// Failure is an entry the reaper judged orphaned and could not finish reaping.
// The entry stays; the next sweep retries it, and the idempotency key means the
// retry cannot double-record.
type Failure struct {
	EntryID  string
	SPIFFEID string
	Err      error
}

// SweepReport is what one sweep did. It is the operator-facing account of a
// destructive operation, so it names every entry in every outcome rather than
// counting them.
type SweepReport struct {
	// StartedAt is the instant the deadlines were evaluated against.
	StartedAt time.Time
	// Examined is the number of entries inside the agent subtree the sweep
	// looked at, including the skipped ones. Entries outside it are not the
	// reaper's and are counted by Outside instead.
	//
	// It is ENTRIES, not runs, and it is deliberately not the whole population
	// any more — see Unentried and Considered (RM-181, #289).
	Examined int
	// Unentried is how many runs the LEDGER called active that the entry
	// listing held nothing for. Zero on a sweep with no RunSource configured,
	// which is why LedgerRunsRead exists to tell "none found" from "not asked".
	Unentried int
	// Outside is how many entries the listing held that are not in this trust
	// domain's agent subtree: node entries, the MCP's own admin entry, anything
	// a federated peer put there. The sweep does not judge them and never
	// deletes them; the count is here so the report can say what it did NOT
	// look at rather than leaving an operator to assume it looked at
	// everything.
	Outside int
	// LedgerRunsRead is whether the ledger's active-run population was read at
	// all. False means the sweep saw only what SPIRE holds an entry for, so a
	// run active in the ledger with no entry is NOT among the counts below —
	// and the report says so in words.
	LedgerRunsRead bool
	// Live are the runs still inside their identity lifetime.
	Live []Candidate
	// Expired are the runs reaped.
	Expired []Expiry
	// Skipped are the entries the reaper would not judge.
	Skipped []Skipped
	// Failures are the orphans it could not reap.
	Failures []Failure
}

// OK reports whether every orphan the sweep found was reaped.
func (r *SweepReport) OK() bool { return r != nil && len(r.Failures) == 0 }

// Considered is the whole population one sweep judged: the entries SPIRE holds
// in the agent subtree, plus the runs the ledger calls active that SPIRE holds
// no entry for.
//
// It exists so the number a report leads with is a number of RUNS. "3 entries,
// 3 live" beside a ledger reporting four active runs is how an operator comes
// to read the reaper's line as a count of agents, which is the misreading
// RM-181 (#289) was filed over.
func (r *SweepReport) Considered() int {
	if r == nil {
		return 0
	}
	return r.Examined + r.Unentried
}

// FindExpired returns the expiry recorded for a run id.
func (r *SweepReport) FindExpired(runID string) (Expiry, bool) {
	if r == nil {
		return Expiry{}, false
	}
	for _, e := range r.Expired {
		if e.Run.RunID == runID {
			return e, true
		}
	}
	return Expiry{}, false
}

// FindLive returns the candidate a sweep left alone.
func (r *SweepReport) FindLive(runID string) (Candidate, bool) {
	if r == nil {
		return Candidate{}, false
	}
	for _, c := range r.Live {
		if c.Run.RunID == runID {
			return c, true
		}
	}
	return Candidate{}, false
}

// String renders the report for an operator or a log.
//
// # The header counts RUNS, and it says what the sweep did not look at
//
// It used to read
//
//	reap at …: 3 entries in the agent subtree, 3 live, 0 expired, 0 skipped, 0 failed
//
// and that is the line RM-181 (#289) was filed over. Beside a ledger reporting
// four active runs it invites exactly one reading — "three agents are alive" —
// and all three of its claims are narrower than they look: three ENTRIES, not
// three runs; live meaning "recorded activity inside the grace", not an agent
// observed running; and a population that was the entry list alone, so the
// fourth run was not among the numbers at all.
//
// So the header leads with the whole population and decomposes it, and a second
// line states the three things the sweep did NOT look at. The second line is
// unconditional. An operator who has to notice the ABSENCE of a caveat to know
// a number is partial has not been told anything.
func (r *SweepReport) String() string {
	if r == nil {
		return "reap: no report\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "reap at %s: %d run%s considered — %d entr%s in the agent subtree, %s; "+
		"%d live, %d expired, %d skipped, %d failed\n",
		r.StartedAt.UTC().Format(time.RFC3339),
		r.Considered(), plural(r.Considered(), "", "s"),
		r.Examined, plural(r.Examined, "y", "ies"), r.ledgerHalf(),
		len(r.Live), len(r.Expired), len(r.Skipped), len(r.Failures))
	fmt.Fprintf(&b, "  not looked at: %d entr%s outside the agent subtree; %s; whether "+
		"any process is alive — \"live\" here is recorded activity inside the grace, "+
		"not an agent observed running\n",
		r.Outside, plural(r.Outside, "y", "ies"), r.ledgerBlindSpot())
	for _, e := range r.Expired {
		fmt.Fprintf(&b, "  expired  %s entry=%s deadline=%s event=%s recorded=%v deleted=%v%s\n",
			e.Entry.SPIFFEID, entryNote(e.Candidate), e.Deadline.UTC().Format(time.RFC3339),
			orNone(e.EventID), e.Recorded, e.Deleted, unentriedNote(e.Candidate))
	}
	for _, c := range r.Live {
		fmt.Fprintf(&b, "  live     %s entry=%s deadline=%s%s%s\n",
			c.Entry.SPIFFEID, entryNote(c), c.Deadline.UTC().Format(time.RFC3339),
			activeNote(c), unentriedNote(c))
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&b, "  skipped  %s entry=%s: %s\n", orNone(s.SPIFFEID), orNone(s.EntryID), s.Reason)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(&b, "  FAILED   %s entry=%s: %v\n", orNone(f.SPIFFEID), orNone(f.EntryID), f.Err)
	}
	return b.String()
}

// ledgerHalf renders the ledger's contribution to the population, and — when
// there was none — says whether that is because none was found or because the
// ledger was never asked.
//
// The distinction is the whole point of LedgerRunsRead. "0 active in the ledger
// with no entry" is a finding; a deployment with no run source, or a sweep whose
// ledger read failed, has no finding to report and must not print one.
func (r *SweepReport) ledgerHalf() string {
	if !r.LedgerRunsRead {
		return "the ledger's active runs were not read, so a run with no entry is not among these"
	}
	return fmt.Sprintf("%d active in the ledger with no entry", r.Unentried)
}

// ledgerBlindSpot names what the ledger half did NOT cover, which is a
// different set depending on whether it ran.
//
// A sweep that read the ledger leaves out the runs it does not call active —
// retired, lapsed, abandoned — and that is correct and uninteresting. A sweep
// that did not read it leaves out every run with no entry, which is the whole
// defect #289 was filed over, and the line must not spell that the same way.
func (r *SweepReport) ledgerBlindSpot() string {
	if !r.LedgerRunsRead {
		return "every run the ledger calls active that SPIRE holds no entry for"
	}
	return "runs the ledger does not call active (retired, lapsed, abandoned)"
}

// entryNote renders the entry id, or says plainly that there is none. An empty
// `entry=` reads as a formatting bug; `entry=none` is the finding.
func entryNote(c Candidate) string {
	if c.Unentried || c.Entry.ID == "" {
		return "none"
	}
	return c.Entry.ID
}

// unentriedNote spells out what an operator would otherwise have to infer from
// `entry=none`: this run came from the ledger, not from SPIRE, and nothing was
// deleted because there was nothing to delete.
func unentriedNote(c Candidate) string {
	if !c.Unentried {
		return ""
	}
	return " (from the ledger's active list; SPIRE held no entry to sweep)"
}

// activeNote spells out the case an operator would otherwise misread: an entry
// listed as live with a deadline already in the past. It was spared because the
// run is still working, and the report has to say so or it looks like a bug.
func activeNote(c Candidate) string {
	if c.LastActivity.IsZero() {
		return ""
	}
	return " last-active=" + c.LastActivity.UTC().Format(time.RFC3339)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ReaperConfig is what NewReaper needs.
type ReaperConfig struct {
	// Client is the SPIRE admin client. The reaper reuses it rather than
	// dialling its own: one admin credential, one connection, one error
	// vocabulary.
	Client *Client
	// Ledger is where `run_expired` goes. Without one the reaper would delete
	// identities and record nothing, which is I3 inverted.
	Ledger EventSink
	// Grace is added to each entry's own TTL before the run is called
	// orphaned. Zero means zero — see DefaultReapGrace. Negative is refused:
	// it would reap entries before their TTL had elapsed.
	Grace time.Duration
	// Activity is where the reaper asks whether a run past its deadline is
	// nonetheless still working. OPTIONAL, and its absence is the behaviour
	// every deployment had before #180: the deadline decides alone. Supplying
	// one is what stops a long-running agent losing its identity mid-task.
	// See silence.go.
	Activity ActivitySource
	// Runs is the LEDGER's half of the sweep's population: the runs it calls
	// active. OPTIONAL, and its absence is the behaviour every deployment had
	// before #289 — the SPIRE entry list is the whole population, and a run
	// active in the ledger with no entry is invisible to the sweep and can
	// never be expired whatever its state. Supplying one closes that.
	//
	// It requires Activity. A population with nothing to judge it by is a
	// population that could only be judged by a deadline it does not have; see
	// NewReaper and population.go.
	Runs RunSource
}

// Reaper deletes orphaned run entries and records each expiry.
type Reaper struct {
	client   *Client
	ledger   EventSink
	grace    time.Duration
	activity ActivitySource
	runs     RunSource
}

// NewReaper builds a reaper. Every rejection here is an INVARIANT_VIOLATION: a
// reaper that cannot record, or that reaps early, is not a degraded reaper.
func NewReaper(cfg ReaperConfig) (*Reaper, error) {
	fail := func(format string, args ...any) (*Reaper, error) {
		return nil, newError(ClassInvariantViolation, "reap", "",
			fmt.Sprintf(format, args...), false, nil)
	}
	if cfg.Client == nil {
		return fail("no SPIRE client: a reaper with nothing to ask cannot know what is orphaned")
	}
	if cfg.Ledger == nil {
		return fail("no ledger: deleting an identity without recording the expiry is I3 inverted")
	}
	if cfg.Grace < 0 {
		return fail("grace %s is negative; that reaps entries before their TTL has elapsed", cfg.Grace)
	}
	if cfg.Runs != nil && cfg.Activity == nil {
		// A run with no entry has no TTL and no creation time, so the deadline
		// gate that judges an entried candidate does not exist for it. Silence
		// is the only evidence there is, and a reaper handed this population
		// with nothing to measure silence against could only withdraw from
		// every run in it on sight. That is the 2026-09-08 sweep with a wider
		// net, so it is refused at construction rather than survived at
		// runtime.
		return fail("a run source with no activity source: a run with no SPIRE entry " +
			"has no deadline, so silence is the only evidence there is and a reaper " +
			"that cannot read it would withdraw from every active run at once")
	}
	return &Reaper{
		client:   cfg.Client,
		ledger:   cfg.Ledger,
		grace:    cfg.Grace,
		activity: cfg.Activity,
		runs:     cfg.Runs,
	}, nil
}

// Grace returns the slack this reaper adds to each entry's TTL.
func (r *Reaper) Grace() time.Duration { return r.grace }

// Sweep examines every entry in the agent subtree and reaps the orphaned ones.
//
// One failed entry does not abandon the sweep: the others are still orphans and
// still need reaping. Failures are collected and reported, and Report.OK is
// what a caller gates on.
func (r *Reaper) Sweep(ctx context.Context) (*SweepReport, error) {
	now := time.Now().UTC()
	report := &SweepReport{StartedAt: now}

	entries, err := r.list(ctx)
	if err != nil {
		return nil, err
	}
	// held is every identity SPIRE holds an entry for inside the agent subtree,
	// INCLUDING the ones classify refused to judge. It is what stops the ledger
	// half reporting a run as having no identity when SPIRE plainly holds one —
	// and then withdrawing it. See population.go.
	held := make(map[string]struct{}, len(entries))
	for _, wire := range entries {
		cand, skipped, ours := r.classify(wire)
		if !ours {
			report.Outside++
			continue
		}
		report.Examined++
		held[fromWire(wire).SPIFFEID] = struct{}{}
		if skipped != nil {
			report.Skipped = append(report.Skipped, *skipped)
			continue
		}
		reap, unknown := r.orphanedNow(ctx, now, &cand)
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
				EntryID:  cand.Entry.ID,
				SPIFFEID: cand.Entry.SPIFFEID,
				Err:      rerr,
			})
			continue
		}
		report.Expired = append(report.Expired, expiry)
	}
	// The LEDGER's half of the population, second: the runs it calls active
	// that the listing above held nothing for (RM-181, #289). Second and not
	// first because `held` has to be complete before anything can be judged
	// entry-less against it.
	r.sweepUnentried(ctx, now, report, held)
	sortReport(report)
	return report, nil
}

// sortReport orders every list by SPIFFE ID so two sweeps over the same state
// print the same thing. SPIRE does not promise an order.
func sortReport(r *SweepReport) {
	sort.Slice(r.Expired, func(i, j int) bool {
		return r.Expired[i].Entry.SPIFFEID < r.Expired[j].Entry.SPIFFEID
	})
	sort.Slice(r.Live, func(i, j int) bool {
		return r.Live[i].Entry.SPIFFEID < r.Live[j].Entry.SPIFFEID
	})
	// The SPIFFE ID breaks the tie, because a skip or a failure raised for an
	// UNENTRIED run carries no entry id at all (RM-181, #289) and sorting
	// several of them by "" would leave their order to Go's sort.
	sort.Slice(r.Skipped, func(i, j int) bool {
		if r.Skipped[i].EntryID != r.Skipped[j].EntryID {
			return r.Skipped[i].EntryID < r.Skipped[j].EntryID
		}
		if r.Skipped[i].SPIFFEID != r.Skipped[j].SPIFFEID {
			return r.Skipped[i].SPIFFEID < r.Skipped[j].SPIFFEID
		}
		return r.Skipped[i].Reason < r.Skipped[j].Reason
	})
	sort.Slice(r.Failures, func(i, j int) bool {
		if r.Failures[i].EntryID != r.Failures[j].EntryID {
			return r.Failures[i].EntryID < r.Failures[j].EntryID
		}
		return r.Failures[i].SPIFFEID < r.Failures[j].SPIFFEID
	})
}

// list pages through every registration entry the server holds.
//
// The entry API has no path-prefix filter, so the subtree selection is made
// here rather than by the server. Filtering client-side is also the safer way
// round: an entry the reaper cannot classify is one it leaves alone, and a
// server-side filter that quietly matched more than intended would be a filter
// that quietly deleted more than intended.
func (r *Reaper) list(ctx context.Context) ([]*types.Entry, error) {
	var (
		all   []*types.Entry
		token string
	)
	for {
		rpcCtx, cancel := r.client.call(ctx)
		resp, err := r.client.entries.ListEntries(rpcCtx, &entryv1.ListEntriesRequest{
			PageSize:  reapPageSize,
			PageToken: token,
		})
		cancel()
		if err != nil {
			return nil, classifyAdmin("reap", "", err)
		}
		all = append(all, resp.GetEntries()...)
		token = resp.GetNextPageToken()
		if token == "" {
			return all, nil
		}
	}
}

// classify decides what one entry is to the reaper.
//
// It returns ours=false for anything outside this trust domain's agent subtree
// — node entries, the MCP's own admin entry, anything a federated peer put
// there. Those are not the reaper's to judge and are not even counted.
//
// It returns a Skipped for an entry that IS in the subtree but that the reaper
// has no basis to call orphaned: a SPIFFE ID that is not a run identity, an
// entry with no TTL of its own, an entry SPIRE reports no creation time for.
// Each of those is reported and left alone. Deleting an identity because its
// metadata was unreadable is the failure mode this branch exists to prevent.
func (r *Reaper) classify(wire *types.Entry) (Candidate, *Skipped, bool) {
	entry := fromWire(wire)
	prefix := "spiffe://" + r.client.trustDomain + agentPathPrefix
	if !strings.HasPrefix(entry.SPIFFEID, prefix) {
		return Candidate{}, nil, false
	}
	skip := func(reason string) (Candidate, *Skipped, bool) {
		return Candidate{}, &Skipped{
			EntryID:  entry.ID,
			SPIFFEID: entry.SPIFFEID,
			Reason:   reason,
		}, true
	}

	run, err := parseRunIdentity(entry.SPIFFEID, r.client.trustDomain)
	if err != nil {
		return skip(fmt.Sprintf("not a run identity: %v", err))
	}
	if entry.TTL <= 0 {
		return skip("the entry carries no TTL of its own, so it has no identity " +
			"lifetime to have outlived")
	}

	cand := Candidate{Entry: entry, Run: run}
	if secs := wire.GetCreatedAt(); secs > 0 {
		cand.CreatedAt = time.Unix(secs, 0).UTC()
	}
	if secs := wire.GetExpiresAt(); secs > 0 {
		cand.ExpiresAt = time.Unix(secs, 0).UTC()
	}

	deadline, ok := entryDeadline(cand, r.grace)
	if !ok {
		return skip("SPIRE reports neither a creation time nor an expiry for this " +
			"entry, so its age is unknown")
	}
	cand.Deadline = deadline
	return cand, nil, true
}

// entryDeadline returns the instant after which a run is orphaned.
//
// SPIRE's own entry expiry wins when it is set: the server has then already
// stated when the entry stops being valid, and second-guessing it would mean
// holding an identity past the point its issuer says it ended.
// Client.RegisterRun sets none, so the ordinary path is the second one: the
// entry's creation time plus the identity lifetime it was registered with, plus
// the configured grace.
//
// Grace applies to both, because it means one thing in both: how long past the
// end of an identity's life the reaper waits before calling the run orphaned.
func entryDeadline(c Candidate, grace time.Duration) (time.Time, bool) {
	switch {
	case !c.ExpiresAt.IsZero():
		return c.ExpiresAt.Add(grace), true
	case !c.CreatedAt.IsZero():
		return c.CreatedAt.Add(c.Entry.TTL + grace), true
	default:
		return time.Time{}, false
	}
}

// parseRunIdentity reads a run's three path components back out of its SPIFFE
// ID, and refuses anything that is not one.
//
// PROTECTED STRING (doc 01 §1): the grammar is
// spiffe://{trust-domain}/agent/{agent-type}/{task-id}/{run-id}, and this
// defers to event.ValidateSPIFFEID for it rather than growing a second
// definition — the same reason RunRef.SPIFFEID does. The trust domain is
// checked here because ValidateSPIFFEID deliberately checks shape only, and the
// reaper deletes things: an identity from a trust domain that is not ours is
// not ours to expire.
func parseRunIdentity(spiffeID, trustDomain string) (RunRef, error) {
	run, err := RunRefOf(spiffeID)
	if err != nil {
		return RunRef{}, err
	}
	td := strings.TrimPrefix(spiffeID, "spiffe://")
	td = td[:strings.IndexByte(td, '/')]
	if td != trustDomain {
		return RunRef{}, fmt.Errorf("%q is in trust domain %q, not %q",
			spiffeID, td, trustDomain)
	}
	return run, nil
}

// reap records one orphaned run's expiry and then deletes its entry.
//
// The order is I3's, not an implementation detail: see the file comment. A
// caller that hands the same candidate in twice — a second reaper, a restart, a
// stale read from an HA server that still lists a deleted entry — gets
// Recorded=false and no second event.
func (r *Reaper) reap(ctx context.Context, cand Candidate) (Expiry, error) {
	out := Expiry{Candidate: cand}

	eventID, appended, err := r.record(ctx, cand)
	if err != nil {
		// I3, structurally: record failed, so nothing on the chain says this
		// identity went. The entry stays where it is, the sweep reports the
		// failure, and the next sweep retries under the same key.
		return out, err
	}
	if eventID == "" {
		// Unreachable by construction — every success path in record returns an
		// event id — and checked anyway, because the thing on the other side of
		// this branch is a deletion with no record. A future edit to record that
		// grows a path returning ("", nil) fails here rather than silently
		// deleting an identity.
		return out, newError(ClassInvariantViolation, "reap", cand.Run.RunID,
			fmt.Sprintf("the withdrawal of %s was not recorded and the entry was "+
				"therefore not deleted", cand.Entry.SPIFFEID), false, nil)
	}
	out.EventID, out.Recorded = eventID, appended

	if cand.Unentried {
		// There is no entry, which is the whole finding. SPIRE is not asked to
		// delete anything — an empty entry id is not an idempotent deletion,
		// it is a malformed request — and the withdrawal on the chain is the
		// entirety of what this sweep can do for such a run. Deleted stays
		// false and the report says why.
		return out, nil
	}

	deleted, err := r.deleteEntry(ctx, cand)
	if err != nil {
		return out, err
	}
	out.Deleted = deleted
	return out, nil
}

// record appends the `run_expired` event for THIS LAPSE, or finds the one an
// earlier pass over the same lapse appended.
//
// # One event per lapse, not one per run (RM-152, #255)
//
// The key this reaper writes under names the silence it is recording:
// ExpiryKeyAfter, over the chain position of the last thing the run did before
// going quiet. Two reapers looking at one lapse read the same last activity and
// write one event between them, exactly as before. A run that lapses a SECOND
// time has done something since — the restore path exists precisely so that it
// can — so its next silence begins after a later position and is named by a
// different key, and the deletion that ends it has a record of its own.
//
// Without an ActivitySource, or for a run the chain holds nothing about, there
// is nothing to tell one lapse from another and the single-key form is used.
// That is not a fallback chosen for tidiness: it is byte-for-byte what every
// deployment did before #255, for a deployment that has configured no more.
//
// # The single-key form is honoured on lookup, always
//
// Live chains carry `run_expired` events written under ExpiryKey. An event
// there records a lapse too, and the question is only WHICH one: it was
// appended at some position, and if nothing the run did is newer than that
// position, the silence it recorded is the silence being swept now. Then there
// is nothing to append and nothing to double-record. If the run has worked
// since, the old event belongs to an earlier lapse and this one is new.
//
// Idempotency still does not depend on the entry being there. The durable
// marker is the ledger event, so a pass that still sees an entry SPIRE has
// already deleted reaches the same conclusion as one that does not.
func (r *Reaper) record(ctx context.Context, cand Candidate) (eventID string, appended bool, err error) {
	position, known, err := r.lastActivityPosition(ctx, cand.Run.RunID)
	if err != nil {
		return "", false, r.ledgerError(cand, "reading the last activity of", err)
	}

	key := ExpiryKey(cand.Run.RunID)
	if known {
		key = ExpiryKeyAfter(cand.Run.RunID, position)
	}

	existing, found, err := r.ledger.EventByIdempotencyKey(ctx, key)
	if err != nil {
		return "", false, r.ledgerError(cand, "reading the expiry record", err)
	}
	if found {
		id, verr := expiryEventID(existing, cand, key)
		if verr != nil {
			return "", false, verr
		}
		return id, false, nil
	}
	if known {
		id, holds, verr := r.recordedUnderTheSingleKey(ctx, cand, position)
		if verr != nil {
			return "", false, verr
		}
		if holds {
			return id, false, nil
		}
	}

	record, err := r.ledger.Append(ctx, expiryEventBody(cand, key))
	if err != nil {
		// A concurrent reaper may have appended between the read above and
		// this write, in which case the ledger refuses the key rather than
		// writing a second event. That is the outcome we wanted; read it back
		// and report it as already recorded.
		if existing, found, rerr := r.ledger.EventByIdempotencyKey(ctx, key); rerr == nil && found {
			if id, verr := expiryEventID(existing, cand, key); verr == nil {
				return id, false, nil
			}
		}
		return "", false, r.ledgerError(cand, "appending run_expired", err)
	}
	id, ok := record[event.FieldEventID].(string)
	if !ok || id == "" {
		return "", false, newError(ClassInvariantViolation, "reap", cand.Run.RunID,
			"the ledger stored run_expired without an event_id", false, nil)
	}
	return id, true, nil
}

// lastActivityPosition asks where in the chain this run's last activity sits.
//
// It is OPTIONAL twice over, and both refusals are deliberate:
//
//   - A reaper with no ActivitySource has nothing to ask. It gets the
//     single-key form and the behaviour it had before #255.
//   - An ActivitySource that reports only an INSTANT — the ActivitySource
//     interface as silence.go declares it — cannot name a lapse: two lapses of
//     one run are two different instants, but a key built from a clock is not
//     something two reapers agree on. Such a source also gets the single-key
//     form rather than a key neither reaper can reproduce.
//
// *ledger.Store satisfies the richer interface, so a shipped deployment takes
// the per-lapse path; a test double or an embedder that does not is never
// silently given a worse guarantee than it asked for.
func (r *Reaper) lastActivityPosition(ctx context.Context, runID string) (int64, bool, error) {
	positions, ok := r.activity.(ActivityPositionSource)
	if !ok {
		return 0, false, nil
	}
	_, position, known, err := positions.LastActivityAt(ctx, runID)
	if err != nil {
		return 0, false, err
	}
	return position, known, nil
}

// recordedUnderTheSingleKey answers whether the lapse being swept is already
// recorded under the pre-#255 key.
//
// The comparison is the whole of it: an event under that key was appended at
// some chain position, and `position` is the newest thing the run has done. If
// the event is NEWER than that activity, nothing has happened since it was
// written and it records the silence being swept right now — so this sweep
// appends nothing and the run gains no duplicate. If it is OLDER, the run went
// on to work after that withdrawal, and the silence being swept now is a
// different one that has never been recorded.
//
// Both answers stay correct once the per-lapse key is in use, because a
// single-key event can only ever be an old one: nothing writes that key for a
// run whose activity is known.
func (r *Reaper) recordedUnderTheSingleKey(ctx context.Context, cand Candidate, position int64) (string, bool, error) {
	key := ExpiryKey(cand.Run.RunID)

	stored, found, err := r.ledger.EventByIdempotencyKey(ctx, key)
	if err != nil {
		return "", false, r.ledgerError(cand, "reading the expiry record of", err)
	}
	if !found {
		return "", false, nil
	}
	id, err := expiryEventID(stored, cand, key)
	if err != nil {
		return "", false, err
	}
	at, ok := chainPositionOf(stored)
	if !ok {
		// The entry stays. Which lapse that event records cannot be decided,
		// so whether deleting this entry would be recorded cannot be decided
		// either, and I3 does not admit a guess.
		return "", false, newError(ClassInvariantViolation, "reap", cand.Run.RunID,
			fmt.Sprintf("the run_expired stored under %q carries no readable %s, so "+
				"whether it records this lapse or an earlier one is unknown",
				key, event.FieldChainPosition), false, nil)
	}
	return id, at > position, nil
}

// chainPositionOf reads a stored event's chain position. The ledger decodes it
// as an int64; `int` is accepted as well so that a record built in a test is
// read the same way as one read back from Postgres.
func chainPositionOf(stored event.Fields) (int64, bool) {
	switch n := stored[event.FieldChainPosition].(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

// ledgerError wraps a ledger failure in this package's vocabulary without
// pretending to know what the ledger's classes mean. The reaper's caller acts
// on one thing only: the expiry was not recorded, so the entry was not deleted.
func (r *Reaper) ledgerError(cand Candidate, what string, err error) error {
	return newError(ClassIdentityUnavailable, "reap", cand.Run.RunID,
		fmt.Sprintf("%s for %s: %v", what, cand.Entry.SPIFFEID, err),
		true, err)
}

// expiryEventBody is the `run_expired` event of doc 02 §3.
//
// Every member here is a protected string. `source` is `reaper` and not `mcp`:
// doc 02 §2 makes source "who appended it", and the whole point of this event
// is that no MCP tool call produced it. The type carries no type-specific
// members ("—" in doc 02 §3), so the run id and the SPIFFE ID SPIRE actually
// held are the entirety of what it says.
//
// event_id, ts, chain_position, prev_event_hash and event_hash are the
// ledger's to assign (doc 02 §2) and are deliberately absent.
// The key is passed in rather than recomputed here: the event written must
// carry the key that was LOOKED UP, or an append could be deduplicated against
// one lapse and recorded under another.
func expiryEventBody(cand Candidate, key string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunExpired,
		event.FieldRunID:          cand.Run.RunID,
		event.FieldSpiffeID:       cand.Entry.SPIFFEID,
		event.FieldSource:         event.SourceReaper,
		event.FieldIdempotencyKey: key,
	}
}

// expiryEventID reads the event id out of an event found under the reaper's
// key, after checking it really is this run's expiry.
//
// The idempotency key namespace is shared with the MCP's, whose keys are
// caller-supplied (IP §4). A stored event under the reaper's key that is not a
// `run_expired` for this run means something else claimed the key, and the
// reaper must not then delete the entry on the strength of a record that is not
// about it. It is an INVARIANT_VIOLATION, alert-level, and the orphan is left
// in place for a human — see ADR-0014's residual risk.
func expiryEventID(stored event.Fields, cand Candidate, key string) (string, error) {
	reject := func(format string, args ...any) (string, error) {
		return "", newError(ClassInvariantViolation, "reap", cand.Run.RunID,
			fmt.Sprintf("the idempotency key %q is held by ", key)+
				fmt.Sprintf(format, args...), false, nil)
	}
	if got := stored[event.FieldEventType]; got != event.EventTypeRunExpired {
		return reject("a %v event, not a %s", got, event.EventTypeRunExpired)
	}
	if got := stored[event.FieldRunID]; got != cand.Run.RunID {
		return reject("an event for run %v, not %s", got, cand.Run.RunID)
	}
	id, ok := stored[event.FieldEventID].(string)
	if !ok || id == "" {
		return reject("an event with no event_id")
	}
	return id, nil
}

// deleteEntry removes the entry the reaper judged orphaned, by id.
//
// By id, not by run: the entry deleted is the one that was examined and found
// past its deadline, never whatever entry happens to exist for that run now. A
// run re-registered between the sweep and here has a new entry with a new
// creation time, and it is not this one's to delete.
//
// An entry that is already gone is not an error. That is the ordinary outcome
// of a second reaper, a retried sweep, or a stale listing, and IP §4's
// idempotency rule for retirement applies for the same reason: the desired
// state is "no entry", and it holds.
func (r *Reaper) deleteEntry(ctx context.Context, cand Candidate) (bool, error) {
	rpcCtx, cancel := r.client.call(ctx)
	defer cancel()

	resp, err := r.client.entries.BatchDeleteEntry(rpcCtx,
		&entryv1.BatchDeleteEntryRequest{Ids: []string{cand.Entry.ID}})
	if err != nil {
		return false, classifyAdmin("reap", cand.Run.RunID, err)
	}
	results := resp.GetResults()
	if len(results) != 1 {
		return false, newError(ClassInvariantViolation, "reap", cand.Run.RunID,
			fmt.Sprintf("SPIRE returned %d results for one deletion", len(results)), false, nil)
	}
	switch code := codes.Code(results[0].GetStatus().GetCode()); code { //nolint:gosec // a gRPC code from SPIRE's own response
	case codes.OK:
		return true, nil
	case codes.NotFound:
		return false, nil
	default:
		return false, classifyAdmin("reap", cand.Run.RunID, statusError(results[0].GetStatus()))
	}
}

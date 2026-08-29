// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"fmt"
	"sort"
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
// callback when one stops. So the reaper cannot detect a crash. What it can do
// is bound a lifetime: an entry that has outlived the identity lifetime it was
// registered with, plus a configured grace, is orphaned by definition, because
// a run that was still working would have been retired or re-registered.
//
// That bound is a policy, and it is deliberately a knob rather than a derived
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
// append is deduplicated by an idempotency key derived from the run id
// (ADR-0004 leaves the key unconstrained on this event type), the ledger
// serializes appends under an advisory lock, and a delete of an entry that is
// already gone is a success with nothing deleted. Two reapers produce one
// `run_expired` and one deletion between them.

// DefaultReapGrace is the slack a caller normally adds to an entry's own TTL
// before treating it as orphaned — one further identity lifetime, so that a run
// finishing as its TTL elapses is not reaped out from under itself.
//
// It is NOT applied by ReaperConfig: a zero Grace there means zero grace, so
// that no caller can be surprised into a policy it did not ask for. The default
// belongs to the operator surface, and `innsegl reap` is where it is applied.
const DefaultReapGrace = DefaultRunTTL

// reapPageSize bounds one ListEntries page. SPIRE may return fewer.
const reapPageSize = 500

// expiryKeyPrefix namespaces the reaper's idempotency keys.
//
// PROTECTED-ADJACENT: this prefix, plus the run id, is the `idempotency_key` of
// every `run_expired` event, and `idempotency_key` is part of the canonical
// preimage (doc 02 §4). Changing it changes the canonical bytes of events that
// have already been written, which I4 does not allow. See ADR-0014.
const expiryKeyPrefix = "reaper:run_expired:"

// ExpiryKey is the ledger idempotency key for a run's `run_expired` event.
//
// It is derived from the run id alone and from nothing else, which is what
// makes it stable across sweeps, across processes and across restarts: two
// reapers looking at the same orphan compute the same key, and the ledger
// resolves the second one to the first one's event instead of writing a second.
func ExpiryKey(runID string) string { return expiryKeyPrefix + runID }

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
	// Deadline is the instant after which the run is orphaned.
	Deadline time.Time
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
	// reaper's and are not counted.
	Examined int
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
func (r *SweepReport) String() string {
	if r == nil {
		return "reap: no report\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "reap at %s: %d entr%s in the agent subtree, %d live, %d expired, %d skipped, %d failed\n",
		r.StartedAt.UTC().Format(time.RFC3339), r.Examined, plural(r.Examined, "y", "ies"),
		len(r.Live), len(r.Expired), len(r.Skipped), len(r.Failures))
	for _, e := range r.Expired {
		fmt.Fprintf(&b, "  expired  %s entry=%s deadline=%s event=%s recorded=%v deleted=%v\n",
			e.Entry.SPIFFEID, e.Entry.ID, e.Deadline.UTC().Format(time.RFC3339),
			orNone(e.EventID), e.Recorded, e.Deleted)
	}
	for _, c := range r.Live {
		fmt.Fprintf(&b, "  live     %s entry=%s deadline=%s\n",
			c.Entry.SPIFFEID, c.Entry.ID, c.Deadline.UTC().Format(time.RFC3339))
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&b, "  skipped  %s entry=%s: %s\n", orNone(s.SPIFFEID), s.EntryID, s.Reason)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(&b, "  FAILED   %s entry=%s: %v\n", orNone(f.SPIFFEID), f.EntryID, f.Err)
	}
	return b.String()
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
}

// Reaper deletes orphaned run entries and records each expiry.
type Reaper struct {
	client *Client
	ledger EventSink
	grace  time.Duration
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
	return &Reaper{client: cfg.Client, ledger: cfg.Ledger, grace: cfg.Grace}, nil
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
	for _, wire := range entries {
		cand, skipped, ours := r.classify(wire)
		if !ours {
			continue
		}
		report.Examined++
		if skipped != nil {
			report.Skipped = append(report.Skipped, *skipped)
			continue
		}
		if !now.After(cand.Deadline) {
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
	sort.Slice(r.Skipped, func(i, j int) bool { return r.Skipped[i].EntryID < r.Skipped[j].EntryID })
	sort.Slice(r.Failures, func(i, j int) bool { return r.Failures[i].EntryID < r.Failures[j].EntryID })
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
	if err := event.ValidateSPIFFEID(spiffeID); err != nil {
		return RunRef{}, err
	}
	parts := strings.Split(strings.TrimPrefix(spiffeID, "spiffe://"), "/")
	// ValidateSPIFFEID has already established five components, the second of
	// which is "agent"; nothing below can be out of range.
	if parts[0] != trustDomain {
		return RunRef{}, fmt.Errorf("%q is in trust domain %q, not %q",
			spiffeID, parts[0], trustDomain)
	}
	return RunRef{AgentType: parts[2], TaskID: parts[3], RunID: parts[4]}, nil
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
		return out, err
	}
	out.EventID, out.Recorded = eventID, appended

	deleted, err := r.deleteEntry(ctx, cand)
	if err != nil {
		return out, err
	}
	out.Deleted = deleted
	return out, nil
}

// record appends the run's `run_expired` event, or finds the one a previous
// pass appended.
//
// Idempotency does not depend on the entry still being there. The durable
// marker is the ledger event, keyed by run id, so a pass that still sees an
// entry SPIRE has already deleted reaches the same conclusion as one that does
// not: the expiry is already recorded, and there is nothing to append.
func (r *Reaper) record(ctx context.Context, cand Candidate) (eventID string, appended bool, err error) {
	key := ExpiryKey(cand.Run.RunID)

	existing, found, err := r.ledger.EventByIdempotencyKey(ctx, key)
	if err != nil {
		return "", false, r.ledgerError(cand, "reading the expiry record", err)
	}
	if found {
		id, verr := expiryEventID(existing, cand)
		if verr != nil {
			return "", false, verr
		}
		return id, false, nil
	}

	record, err := r.ledger.Append(ctx, expiryEventBody(cand))
	if err != nil {
		// A concurrent reaper may have appended between the read above and
		// this write, in which case the ledger refuses the key rather than
		// writing a second event. That is the outcome we wanted; read it back
		// and report it as already recorded.
		if existing, found, rerr := r.ledger.EventByIdempotencyKey(ctx, key); rerr == nil && found {
			if id, verr := expiryEventID(existing, cand); verr == nil {
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
func expiryEventBody(cand Candidate) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunExpired,
		event.FieldRunID:          cand.Run.RunID,
		event.FieldSpiffeID:       cand.Entry.SPIFFEID,
		event.FieldSource:         event.SourceReaper,
		event.FieldIdempotencyKey: ExpiryKey(cand.Run.RunID),
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
func expiryEventID(stored event.Fields, cand Candidate) (string, error) {
	reject := func(format string, args ...any) (string, error) {
		return "", newError(ClassInvariantViolation, "reap", cand.Run.RunID,
			fmt.Sprintf("the idempotency key %q is held by ", ExpiryKey(cand.Run.RunID))+
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

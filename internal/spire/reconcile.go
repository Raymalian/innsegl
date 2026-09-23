// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// Entry reconciliation — RM-019 (#27), threat model AB-11, test SPI-008.
//
// # What this is for
//
// Doc 04's SPIRE deployment section, in full:
//
//	T: entries mutated out-of-band → periodic reconciliation of
//	expected-vs-actual entries; alert on unexplained entries (extends REC drift
//	model to SPIRE).
//
// Two things can put SPIRE's registration entries and the ledger's record of
// them out of agreement, and both are threats rather than housekeeping:
//
//   - SPIRE holds an entry the ledger does not explain. That is AB-11 —
//     "tamper with SPIRE entries directly to widen a run's identity". The
//     attacker does not need the MCP admin credential at all: ADR-0011 records
//     that the server's local admin socket is unauthenticated by construction
//     and is contained by a private tmpfs, not by authorization. Anything that
//     reaches the SPIRE server host has full admin over the trust domain.
//   - The ledger says a run is active and SPIRE holds no entry for it. That is
//     the hole ADR-0012 names and could not close: BatchDeleteEntry carries
//     opaque entry IDs, rego cannot resolve one to a SPIFFE ID, so the
//     authorization policy cannot scope deletion the way it scopes creation. A
//     stolen admin credential can delete any entry in the trust domain.
//     Detection is the only control that exists.
//
// Prevention is elsewhere and stays elsewhere (SPI-005, ADR-0012). This is
// detection, and detection is the whole of the mitigation doc 04 claims.
//
// # Expected, actual, and what is deliberately not compared
//
// Expected comes from the ledger: a run is expected to have exactly one entry
// while it is ACTIVE, and none once it is not (IP §1, doc 02 §3). Actual comes
// from SPIRE's own entry list, read from the server, whose datastore is
// authoritative — never from an agent cache, which converges later.
//
// "Active" is not this file's own answer any more, and that is RM-155 (#258).
// It used to be: a run was read as closed from its first `run_retired` OR
// `run_expired` for ever, regardless of anything the run did afterwards. But a
// withdrawal is not an ending — internal/mcp's get_credential re-creates the
// SPIRE entry when a quiet run speaks again, by design and through the admin
// path — so every restored run was reported here as `spire_entry_not_deleted`
// while the read API, which had already been taught the right rule, showed the
// same run active. Two components, two answers, and an operator shown both
// learns to believe neither.
//
// The rule now lives in exactly one place, internal/ledger's RunStateOf, and
// this file reads it (see ledgerRun and compareEntries). REC-018 asserts that
// what this control concludes about a run and what the read API serves about
// the same run are the same word, over a fixture holding every combination of
// withdrawal, activity and retirement.
//
// RETIREMENT STAYS FINAL and the distinction is load-bearing: the rule's first
// clause is that a retirement wins unconditionally, so an entry that comes back
// for a RETIRED run is still AB-11 and still alerts (SPI-008). Withdrawal is
// reversible; retirement is not.
//
// The comparison is scoped to the agent subtree, spiffe://{td}/agent/. The
// infrastructure entries the stack needs — spire-oidc's, created by
// deploy/compose/spire/register.sh — live under /innsegl/ and are not run
// identities; flagging them would make the alert noise on every deployment and
// noise is how an alert stops being read. An identity minted OUTSIDE the agent
// subtree is AB-10, whose control is the authorization policy and whose test is
// SPI-005.
//
// # The alert, and the one shape the closed schema has no event for
//
// Doc 02 §3 is closed: an implementation may not invent an event type. Three of
// the four drift kinds below name a ledger event whose claim the SPIRE state
// contradicts, and are appended as `ledger_drift_detected` — doc 02's "Alert:
// ledger claim with no external proof" — carrying that event's id as
// `subject_event_id`:
//
//	spire_entry_missing      subject is the run_registered event, whose meaning
//	                         doc 02 §3 gives as "Identity created; SPIRE entry
//	                         exists". SPIRE holds none, so the claim is unproven.
//	spire_entry_not_deleted  subject is the run_retired or run_expired event.
//	                         Retirement's claim is that the entry was deleted.
//	                         It is there.
//	spire_entry_duplicated   subject is the run_registered event. IP §1 allows
//	                         one entry per run; a second one widens the identity
//	                         without touching the ledger, which is AB-11 exactly.
//
// The fourth, spire_entry_unattributed — SPIRE holds an entry in the agent
// subtree that no ledger run explains at all — HAS NO FITTING EVENT TYPE, and
// this package does not force one. `ledger_drift_detected` requires a
// `subject_event_id` and there is no subject: the whole content of the finding
// is that the ledger says nothing. `unattributed_signature_detected` is the
// right shape and the wrong domain — its three required members
// (`rekor_log_index` as an integer, `rekor_entry_uuid`, `certificate_identity`)
// describe a Rekor entry, and doc 02 §1 forbids empty-string placeholders, so
// there is no honest value to put in two of them.
//
// So that drift is raised through ReconcilerConfig.Alert (an operator alert:
// slog at error level by default) and reported in Result.Unrecordable, and it
// is NOT written to the ledger. Recording it needs a new event type in doc 02
// §3 — an `unattributed_identity_detected` alongside
// `unattributed_signature_detected` — which is a major schema version with a
// migration attestation (doc 02 §7). That is a decision for a human, and it is
// written up in ADR-0013.
//
// # Two of the four kinds need an age, not just a state (#108, RM-075)
//
// ADR-0018 has the ledger write precede the SPIRE mutation, in both
// directions: register_agent appends `run_registered` and only then creates
// the entry; retire_agent and the reaper record `run_retired`/`run_expired`
// and only then delete it. So for exactly two of the four drift kinds — the
// ones asking "is the ledger's claim missing its SPIRE-side counterpart?" —
// the state a healthy, still-in-flight call leaves behind is IDENTICAL to the
// state this control exists to catch:
//
//	DriftEntryMissing      a run_registered with no entry: indistinguishable,
//	                       by state alone, from register_agent between its
//	                       append and its create.
//	DriftEntryNotDeleted   a run_retired/run_expired with an entry still there:
//	                       indistinguishable from retire_agent or the reaper
//	                       between their record and their delete.
//
// OPS-003 found three runs sitting in the first shape at the end of a soak —
// `run_registered`, no entry, no closing event — left by callers that crashed
// before the create and never came back to replay their idempotency key. No
// existing control closed it: the reaper has no entry to reap, and REC-003/004
// cross-check Rekor, which a run that never signed anything never touches.
//
// A read order cannot fix this. DriftEntryUnattributed and DriftEntryDuplicated
// stay immediate: reading SPIRE before the ledger (below) means any entry this
// cycle finds was preceded by a ledger append that happened even earlier, so
// the ledger read is guaranteed to have it — that direction has no window to
// wait out. DriftEntryMissing and DriftEntryNotDeleted have the opposite
// shape: the ledger is allowed to be ahead of SPIRE, by an amount no read
// ordering bounds, so the only way to tell "still in flight" from "orphaned"
// is to wait long enough that the legitimate window could not still be open.
// That is Config.MinAge, resolved against DefaultMinAge; see oldEnough.
// Flagging one of these two kinds before its event has aged past MinAge would
// be a false accusation against a run that is doing nothing wrong — treated in
// this project as worse than the gap detection closes (RM-018, RM-065).
//
// # Idempotency
//
// A cycle appends nothing it has already appended. The dedupe key is
// (subject_event_id, reason) read back out of the chain itself, not held in
// memory, so a restarted or newly leader-elected reconciler (doc 05 §2 runs it
// single-active with failover) is as quiet as the one it replaced. The
// unattributed alert cannot be deduped that way — it has no ledger record to
// read back — and is deduped in process instead, which is a direct consequence
// of the missing event type above.

// DriftKind names one way SPIRE's registration entries and the ledger's record
// of them can disagree.
type DriftKind string

// The four kinds. These are Go constants and internal vocabulary, not schema:
// doc 02 §3 makes `reason` free text, and only the event type, the member names
// and the source enum are protected strings.
const (
	// DriftEntryMissing: the ledger says the run is ACTIVE; SPIRE holds no
	// entry. ADR-0012's unscopeable BatchDeleteEntry, and — the case with no
	// entry ever created at all — #108/RM-075's register_agent crash window.
	// Gated by Config.MinAge against the age of the fact that made the run
	// active (RunFacts.DecidedAt), which for a freshly registered run is its
	// `run_registered` and for a restored one is the activity that overtook its
	// withdrawal; see the file comment.
	DriftEntryMissing DriftKind = "spire_entry_missing"
	// DriftEntryNotDeleted: the ledger says the run is retired, or withdrawn
	// from with nothing heard since; SPIRE holds an entry anyway. Gated by
	// Config.MinAge against the age of that closing fact, for the same reason
	// DriftEntryMissing is; see the file comment.
	DriftEntryNotDeleted DriftKind = "spire_entry_not_deleted"
	// DriftEntryDuplicated: one active run, more than one entry. IP §1 allows
	// one, and the extra one is identity this deployment never granted.
	DriftEntryDuplicated DriftKind = "spire_entry_duplicated"
	// DriftEntryUnattributed: an entry in the agent subtree for an identity the
	// ledger has no record of. AB-11 in its purest form, and the one kind the
	// closed schema cannot record.
	DriftEntryUnattributed DriftKind = "spire_entry_unattributed"
)

// driftReason renders the `reason` member of the alert event.
//
// The text is a constant per kind and carries no entry id, SPIFFE ID or
// timestamp. That is deliberate: `reason` is half the idempotency key, so a
// value that varies with anything but the kind would make the same standing
// finding appendable twice. What varies goes in `run_id`, `spiffe_id` and — for
// the operator, not the ledger — the Drift value and the alert sink.
func driftReason(kind DriftKind) string {
	switch kind {
	case DriftEntryMissing:
		return string(DriftEntryMissing) + ": the ledger shows this run registered and " +
			"not retired or expired, and SPIRE holds no registration entry for it"
	case DriftEntryNotDeleted:
		return string(DriftEntryNotDeleted) + ": the ledger shows this run retired or " +
			"expired, and SPIRE still holds a registration entry for it"
	case DriftEntryDuplicated:
		return string(DriftEntryDuplicated) + ": SPIRE holds more than one registration " +
			"entry for this run, and IP §1 allows exactly one"
	case DriftEntryUnattributed:
		return string(DriftEntryUnattributed) + ": SPIRE holds a registration entry in the " +
			"agent subtree that no ledger run explains"
	default:
		return ""
	}
}

// Drift is one disagreement between SPIRE and the ledger.
type Drift struct {
	// Kind is which of the four.
	Kind DriftKind
	// SPIFFEID is the run identity the disagreement is about.
	SPIFFEID string
	// RunID is the run, empty when no ledger run explains the entry.
	RunID string
	// EntryIDs are the SPIRE entry ids involved, sorted. Empty for
	// DriftEntryMissing, where the finding is that there are none.
	EntryIDs []string
	// SubjectEventID is the ledger event whose claim this contradicts, empty
	// when there is no such event. See Recordable.
	SubjectEventID string
	// Reason is the text carried into the alert event.
	Reason string
}

// Recordable reports whether the closed event schema can carry this drift.
//
// It is false for exactly one kind, DriftEntryUnattributed, and the reason is
// the schema and not this package: `ledger_drift_detected` requires a
// `subject_event_id` and an entry the ledger has never heard of has no subject
// event. A false answer is not "ignore this" — it is "this one reaches the
// operator out of band, and doc 02 §3 needs an event type it does not have".
func (d Drift) Recordable() bool { return d.SubjectEventID != "" }

// dedupeKey identifies a standing unrecordable finding within one process.
// The entry ids are part of it: an attacker who deletes a planted entry and
// plants another has done a second thing, and it gets a second alert.
func (d Drift) dedupeKey() string {
	return string(d.Kind) + "\x00" + d.SPIFFEID + "\x00" + strings.Join(d.EntryIDs, ",")
}

// Result is one reconciliation cycle.
type Result struct {
	// LedgerRuns is how many runs the ledger has ever registered.
	LedgerRuns int
	// ActiveRuns is how many of those the one rule reads as active — the
	// number of entries SPIRE is expected to hold.
	ActiveRuns int
	// RunStates is the state this cycle derived for every run the chain
	// registered, keyed by run id and spelled in internal/ledger's vocabulary.
	//
	// It is the EVIDENCE for ActiveRuns, and it is what REC-018 holds against
	// the read API's answer for the same run: two components that decide a run
	// is closed on different grounds is the defect #258 closes, and the only
	// way to keep them from drifting apart again is for both answers to be
	// observable and compared. A run whose `run_registered` this control could
	// not read is absent rather than guessed at.
	RunStates map[string]string
	// SPIREEntries is how many entries SPIRE holds in the agent subtree.
	SPIREEntries int
	// Drifts is every disagreement found, in SPIFFE ID order.
	Drifts []Drift
	// Appended is the event_id of each alert this cycle wrote. Empty on a
	// cycle that found only drift already recorded — that is the idempotency
	// requirement, stated as an observable.
	Appended []string
	// Unrecordable is the drift the closed schema has no event for. It has
	// been handed to the alert sink; it is here so a caller can see that the
	// ledger is not the whole record and say so.
	Unrecordable []Drift
}

// EntrySource is SPIRE's half of the comparison. *Client implements it.
type EntrySource interface {
	// TrustDomain names the trust domain the entries belong to.
	TrustDomain() string
	// ListAgentEntries returns every registration entry in the agent subtree.
	ListAgentEntries(ctx context.Context) ([]Entry, error)
}

// LedgerReader is the ledger's half: the chain, read in position order.
// *ledger.Store implements it.
//
// The interface is here rather than in internal/ledger so that this package
// depends on the ledger's shape and not on its implementation — and so the
// error paths below (a ledger that cannot be counted, cannot be read, cannot
// be appended to) are reachable from a test without a database.
type LedgerReader interface {
	// Count is how many events the chain holds. doc 02 §2 makes chain_position
	// 1-based and strictly consecutive, so the count is also the last position.
	Count(ctx context.Context) (int64, error)
	// Events returns positions from..to inclusive, in order.
	Events(ctx context.Context, from, to int64) ([]event.Fields, error)
}

// LedgerAppender appends the alert. *ledger.Store implements it.
type LedgerAppender interface {
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// ReconcilerConfig is what NewReconciler needs.
type ReconcilerConfig struct {
	// Entries is SPIRE. Required.
	Entries EntrySource
	// Ledger is the chain to read expected state from. Required.
	Ledger LedgerReader
	// Appender is where alerts are written. Required — an alert that cannot be
	// recorded is not an alert (I3).
	Appender LedgerAppender
	// Alert receives the drift the closed schema cannot record. Defaults to an
	// error-level slog line. It is the only channel that finding has, so a
	// deployment that routes alerts anywhere else must set it.
	Alert func(context.Context, Drift)
	// Observe receives every cycle Run performs, including a failed one.
	// Defaults to slog.
	Observe func(Result, error)
	// Batch bounds one read of the chain. Zero means defaultLedgerBatch.
	Batch int64
	// MinAge is how long a run_registered or a closing event must stand before
	// a disagreeing SPIRE state counts as DriftEntryMissing or
	// DriftEntryNotDeleted rather than an ordinary in-flight register_agent,
	// retire_agent or reap (#108, RM-075; see the file comment). Zero means
	// DefaultMinAge — unlike ReaperConfig.Grace, a zero here is NOT honoured as
	// "no grace period", because that is exactly today's bug: every
	// registration would be accused the instant a cycle catches it mid-flight.
	// A deployment that has measured its own worst-case register_agent latency
	// and wants a different margin sets this explicitly.
	MinAge time.Duration
	// Now reads the clock Config.MinAge is measured against. Nil means
	// time.Now. Exists so a test can move the clock instead of sleeping six
	// minutes.
	Now func() time.Time
}

const (
	// defaultLedgerBatch bounds one Events read, so a long chain is walked in
	// bounded memory rather than materialised whole.
	defaultLedgerBatch = 1000
	// entryPageSize bounds one ListEntries page.
	entryPageSize = 500
	// maxEntryPages stops a server that keeps handing back a page token. A
	// reconciler that loops forever is a reconciler that never alerts.
	maxEntryPages = 10_000
)

// DefaultMinAge is how long a run_registered or a closing event is left alone
// before a SPIRE state that disagrees with it counts as drift instead of an
// ordinary call still in flight (#108, RM-075).
//
// The floor is the worst legitimate gap the ledger can run ahead of SPIRE.
// register_agent's identity() step (internal/mcp/register_agent.go) makes at
// most two admin RPCs after the append that a healthy call can still be
// making: RegisterRun, and — only on SPIRE's own DUPLICATE_REQUEST, taken as
// adoption rather than failure (ADR-0018 decision 3) — a LookupRun to fetch
// the entry it adopts. Each is bounded by Client.Timeout, DefaultTimeout
// (15s), so 30s covers the RPC work of either the register or the retire/reap
// side, whichever this drift kind is asking about (retire_agent and the
// reaper each make one such RPC, BatchDeleteEntry, so 30s is generous for
// them too). Add IP §6.8's 60-second clock-skew tolerance for the gap between
// the host that wrote the event's `ts` and the host running this cycle — the
// same kind of skew OPS-003 measured at 1.65-1.87s in its soak, comfortably
// inside this bound. 30s + 60s = 90s is the worst-case legitimate gap.
//
// DefaultMinAge is four times that floor — six minutes — the same margin
// internal/reconciler's DefaultExpireAfter takes over its own floor: enough
// that a slow SPIRE and a skewed clock together cannot reach it, short enough
// that doc 05 §4's "SPIRE entry count vs expected" monitoring still means an
// operator learns of a genuine orphan inside a reasonable number of cycles.
const DefaultMinAge = 6 * time.Minute

// Reconciler compares SPIRE's registration entries against the ledger's record
// of them, periodically, and alerts on every disagreement.
type Reconciler struct {
	cfg    ReconcilerConfig
	batch  int64
	minAge time.Duration
	// horizon is how long after a withdrawal a run may still be restored. It
	// separates Lapsed from Abandoned and NOTHING ELSE here: both are states in
	// which SPIRE should hold no entry, so no alert this file raises depends on
	// it. It is carried so that Result.RunStates speaks the same four words the
	// read API speaks, which is what REC-018 checks.
	//
	// Read from ledger.EnvRestoreHorizon at construction, from the same
	// function internal/api reads it with. One variable, one number, every
	// component — see that constant.
	horizon time.Duration
	now     func() time.Time

	mu   sync.Mutex
	seen map[string]struct{}
}

// NewReconciler builds a reconciler, or refuses.
//
// Every refusal is an INVARIANT_VIOLATION: a reconciler missing one of its
// three halves is not a degraded reconciler, it is a detection control that
// reports agreement it never checked.
func NewReconciler(cfg ReconcilerConfig) (*Reconciler, error) {
	fail := func(format string, args ...any) (*Reconciler, error) {
		return nil, newError(ClassInvariantViolation, "reconcile", "",
			fmt.Sprintf(format, args...), false, nil)
	}
	switch {
	case cfg.Entries == nil:
		return fail("no entry source: there is nothing to compare the ledger against")
	case cfg.Ledger == nil:
		return fail("no ledger reader: without the ledger every SPIRE entry is unexplained")
	case cfg.Appender == nil:
		return fail("no ledger appender: an alert that cannot be recorded is not an alert (I3)")
	}
	if cfg.Alert == nil {
		cfg.Alert = defaultAlert
	}
	if cfg.Observe == nil {
		cfg.Observe = defaultObserve
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	batch := cfg.Batch
	if batch <= 0 {
		batch = defaultLedgerBatch
	}
	minAge := cfg.MinAge
	if minAge <= 0 {
		minAge = DefaultMinAge
	}
	return &Reconciler{
		cfg:     cfg,
		batch:   batch,
		minAge:  minAge,
		horizon: ledger.RestoreHorizonFromEnv(),
		now:     cfg.Now,
		seen:    map[string]struct{}{},
	}, nil
}

// Reconcile runs one cycle: read both sides, compare, alert on every
// disagreement that is not already recorded.
//
// SPIRE is read first and the ledger second. That order is what keeps
// DriftEntryUnattributed and DriftEntryDuplicated race-free: ADR-0018 has the
// ledger write precede the SPIRE mutation in both directions, so any entry
// this cycle's SPIRE read finds was preceded by a ledger append that already
// happened — and the ledger read, taken after, is guaranteed to see it.
//
// It does NOT make DriftEntryMissing or DriftEntryNotDeleted race-free, and no
// read order can: ADR-0018's whole point is that the ledger is allowed to run
// ahead of SPIRE, so a run_registered (or a closing event) this cycle's ledger
// read sees can predate a SPIRE change that has not happened yet by the time
// of this cycle's SPIRE read, whichever half is read first. Those two kinds
// are instead gated by age — r.minAge, against the event that would have to
// precede the SPIRE change — in compareEntries. See the file comment and
// DefaultMinAge.
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	entries, err := r.cfg.Entries.ListAgentEntries(ctx)
	if err != nil {
		return Result{}, err
	}
	view, err := r.readLedger(ctx)
	if err != nil {
		return Result{}, err
	}

	// ONE CLOCK FOR THE WHOLE CYCLE, for the reason internal/api computes its
	// abandonment cutoff once per request: a run judged against a different
	// "now" than the run beside it is a cycle that can report two states for
	// one chain.
	now := r.now()
	result := Result{
		LedgerRuns:   len(view.runs),
		SPIREEntries: len(entries),
		RunStates:    make(map[string]string, len(view.runs)),
	}
	for _, run := range view.runs {
		state := run.state(now, r.horizon)
		if state == ledger.RunActive {
			result.ActiveRuns++
		}
		// Keyed by run id, which is what the read API answers by. A run the
		// chain never registered has no state to compare — it is a ledger
		// defect, reported elsewhere — so it is left out rather than guessed.
		if run.runID != "" && run.registeredEventID != "" {
			result.RunStates[run.runID] = state
		}
	}
	result.Drifts = compareEntries(view, entries, now, r.minAge, r.horizon)

	for _, drift := range result.Drifts {
		if !drift.Recordable() {
			result.Unrecordable = append(result.Unrecordable, drift)
			r.raiseOutOfBand(ctx, drift)
			continue
		}
		key := alertKey(drift.SubjectEventID, drift.Reason)
		if _, already := view.alerts[key]; already {
			continue
		}
		id, aerr := r.record(ctx, drift)
		if aerr != nil {
			// The drift stays in the result. A ledger that refused the alert
			// is a reason to fail the cycle, never a reason to go quiet about
			// what the cycle found.
			return result, aerr
		}
		view.alerts[key] = struct{}{}
		result.Appended = append(result.Appended, id)
	}
	return result, nil
}

// Run reconciles every interval until ctx is done, handing each cycle to
// Observe. A failed cycle does not end the loop: SPIRE being unreachable is
// IP §6.1's retryable case, and a detection control that stops at the first
// timeout is a detection control that is off.
func (r *Reconciler) Run(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		return newError(ClassInvariantViolation, "reconcile", "",
			fmt.Sprintf("reconciliation interval %s is not positive; doc 04 requires "+
				"reconciliation to be periodic", every), false, nil)
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		result, err := r.Reconcile(ctx)
		r.cfg.Observe(result, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// record appends the alert as a `ledger_drift_detected` event.
func (r *Reconciler) record(ctx context.Context, drift Drift) (string, error) {
	body := event.Fields{
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldSource:         event.SourceReconciler,
		event.FieldSubjectEventID: drift.SubjectEventID,
		event.FieldReason:         drift.Reason,
	}
	// doc 02 §2: run_id and spiffe_id are omitted together, and only for an
	// alert that references no run. This one does. They are omitted anyway if
	// the ledger's own record of the run does not satisfy the grammar — an
	// alert that the ledger refuses on a malformed member is an alert nobody
	// sees, and the finding matters more than the attribution.
	if event.ValidateIdentifier(drift.RunID) == nil && event.ValidateSPIFFEID(drift.SPIFFEID) == nil {
		body[event.FieldRunID] = drift.RunID
		body[event.FieldSpiffeID] = drift.SPIFFEID
	}
	record, err := r.cfg.Appender.Append(ctx, body)
	if err != nil {
		return "", err
	}
	return recordString(record, event.FieldEventID), nil
}

// raiseOutOfBand hands a drift the schema cannot record to the alert sink,
// once per process per distinct finding.
func (r *Reconciler) raiseOutOfBand(ctx context.Context, drift Drift) {
	key := drift.dedupeKey()
	r.mu.Lock()
	_, already := r.seen[key]
	if !already {
		r.seen[key] = struct{}{}
	}
	r.mu.Unlock()
	if already {
		return
	}
	r.cfg.Alert(ctx, drift)
}

// defaultAlert is the sink a deployment gets if it names none. Error level:
// doc 04 calls this an alert, and doc 05 §4 lists "SPIRE entry count vs
// expected" among the monitoring minimums.
func defaultAlert(ctx context.Context, drift Drift) {
	slog.ErrorContext(ctx,
		"SPIRE entry reconciliation: an entry the ledger does not explain (AB-11); "+
			"the closed event schema has no event type for this, so it is not in the ledger",
		"kind", string(drift.Kind),
		"spiffe_id", drift.SPIFFEID,
		"entry_ids", strings.Join(drift.EntryIDs, ","),
		"reason", drift.Reason)
}

// defaultObserve is the per-cycle sink a deployment gets if it names none.
func defaultObserve(result Result, err error) {
	switch {
	case err != nil:
		slog.Error("SPIRE entry reconciliation cycle failed", "error", err)
	case len(result.Drifts) > 0:
		slog.Warn("SPIRE entry reconciliation found drift",
			"drifts", len(result.Drifts),
			"appended", len(result.Appended),
			"unrecordable", len(result.Unrecordable),
			"active_runs", result.ActiveRuns,
			"spire_entries", result.SPIREEntries)
	default:
		slog.Debug("SPIRE entries and the ledger agree",
			"active_runs", result.ActiveRuns, "spire_entries", result.SPIREEntries)
	}
}

// ---------------------------------------------------------------------------
// The ledger side: what the chain says the entries should be.
// ---------------------------------------------------------------------------

// ledgerRun is one run's lifecycle as the ledger records it: the facts the one
// rule reads, and the event ids this control names when it alerts.
//
// It holds FACTS AND NOT A VERDICT. The verdict is ledger.RunStateOf's, taken
// fresh at comparison time against that cycle's clock, because two of the four
// states differ only by how long ago the withdrawal was and a value folded in
// during the chain walk would be stale by the end of it.
type ledgerRun struct {
	runID             string
	spiffeID          string
	registeredEventID string
	// facts is what internal/ledger's rule reads. Nothing else in this file
	// interprets them.
	facts ledger.RunFacts
	// retiredEventID is the EARLIEST `run_retired` for this run, empty when it
	// was never retired. It is the subject of a DriftEntryNotDeleted alert
	// about a retired run: retirement's claim is that the entry was deleted,
	// and the entry is there.
	retiredEventID string
	// withdrawnEventID is the NEWEST `run_expired`, empty when the reaper never
	// took this run's authorisation. It is the subject when the withdrawal is
	// the fact an entry contradicts — the newest one, because that is the
	// withdrawal that stands and the one whose deletion did not happen.
	withdrawnEventID string
}

// state is the run's state by the one rule, at this cycle's clock.
func (r *ledgerRun) state(now time.Time, horizon time.Duration) string {
	return ledger.RunStateOf(r.facts, now, horizon)
}

// closingEventID is the ledger event whose claim a surviving SPIRE entry
// contradicts, given the state this run is in. Empty for an active run, which
// claims the opposite.
func (r *ledgerRun) closingEventID(state string) string {
	switch state {
	case ledger.RunRetired:
		return r.retiredEventID
	case ledger.RunLapsed, ledger.RunAbandoned:
		return r.withdrawnEventID
	default:
		return ""
	}
}

// ledgerView is the whole chain reduced to the two things reconciliation needs.
type ledgerView struct {
	// runs is keyed by SPIFFE ID, which is what a SPIRE entry carries.
	runs map[string]*ledgerRun
	// alerts is the set of (subject_event_id, reason) already recorded. It is
	// what makes a second cycle silent.
	alerts map[string]struct{}
}

func alertKey(subjectEventID, reason string) string {
	return subjectEventID + "\x00" + reason
}

// recordString reads a string member of a ledger record.
//
// Absent and not-a-string both come back as "", which is a value doc 02 §1 does
// not otherwise admit — "Absent and empty are distinct states and only 'absent'
// is allowed for a missing value" — so "" is unambiguously "this control could
// not read the member". Every caller treats that as a record to skip rather
// than as a reason to abandon the cycle; see observe.
func recordString(record event.Fields, name string) string {
	value, ok := record[name].(string)
	if !ok {
		return ""
	}
	return value
}

// parseTS reads an event's `ts` as a time.Time, zero when it is absent or
// unparseable. The same tolerance recordString documents applies here: a
// record this control cannot date is skipped by its caller rather than
// treated as a reason to abandon the cycle, and oldEnough treats a zero time
// as "cannot judge, don't accuse" — the same fail-safe reaper.go's classify
// applies to an entry it cannot date.
func parseTS(record event.Fields) time.Time {
	ts, err := event.ParseTimestamp(recordString(record, event.FieldTS))
	if err != nil {
		return time.Time{}
	}
	return ts.Time()
}

// readLedger walks the chain in bounded batches and reduces it to a view.
func (r *Reconciler) readLedger(ctx context.Context) (*ledgerView, error) {
	return readLedgerView(ctx, r.cfg.Ledger, r.batch)
}

// readLedgerView is readLedger without a Reconciler, because the reaper needs
// the same walk for a different question (RM-181, #289).
//
// The reconciler asks "does SPIRE hold what the ledger says it should?" and
// alerts. The reaper asks "which runs does the ledger call active?" and sweeps.
// Both answers come out of the same fold over the same chain, and duplicating
// the fold is how two components come to disagree about what `active` means —
// which is the defect #258 spent a whole issue removing. So there is one walk,
// one ledgerView and one ledger.RunStateOf, and the two callers differ only in
// what they do with the result. See population.go.
func readLedgerView(ctx context.Context, reader LedgerReader, batch int64) (*ledgerView, error) {
	view := &ledgerView{
		runs:   make(map[string]*ledgerRun),
		alerts: make(map[string]struct{}),
	}
	n, err := reader.Count(ctx)
	if err != nil {
		return nil, err
	}
	for from := int64(1); from <= n; from += batch {
		to := min(from+batch-1, n)
		records, rerr := reader.Events(ctx, from, to)
		if rerr != nil {
			return nil, rerr
		}
		for _, record := range records {
			view.observe(record)
		}
	}
	return view, nil
}

// run returns the view's entry for one identity, creating it if this is the
// first LIFECYCLE event seen for it.
//
// Creating on a closing event and not only on `run_registered` is what lets a
// closing event with no registration — itself a ledger defect, and not this
// control's to report — be matched against a surviving entry and reported
// against that closing event rather than as unattributed, which would be the
// less accurate of the two.
func (v *ledgerView) run(spiffeID, runID string) *ledgerRun {
	existing, known := v.runs[spiffeID]
	if known {
		if existing.runID == "" {
			existing.runID = runID
		}
		return existing
	}
	fresh := &ledgerRun{runID: runID, spiffeID: spiffeID}
	v.runs[spiffeID] = fresh
	return fresh
}

// observe folds one event into the view.
//
// A record whose members are missing or of the wrong type is skipped rather
// than fatal. The ledger validates on the way in (doc 02 §1, closed schema), so
// this cannot happen for anything this deployment wrote; what it can be is an
// event from a newer schema_version, which doc 02 §1 says a verifier tolerates.
// Refusing to reconcile at all because one event was unreadable would turn a
// forward-compatibility case into an outage of the detection control.
//
// # Facts accumulate; nothing resets
//
// Before #258 a `run_registered` REPLACED whatever the view held for that
// identity, "re-opening" a run whose closing event was now spent. Nothing does
// that any more, and the reason is the rule's first clause: a retirement wins
// unconditionally, so a re-registration cannot un-retire a run here any more
// than a straggling tool call can un-retire one in the read API. A run
// registers once in any case — the ledger's idempotency_key is UNIQUE and the
// run directory refuses a chain that registers one twice.
func (v *ledgerView) observe(record event.Fields) {
	eventType := recordString(record, event.FieldEventType)
	if eventType == event.EventTypeLedgerDriftDetected {
		subject := recordString(record, event.FieldSubjectEventID)
		reason := recordString(record, event.FieldReason)
		if subject != "" && reason != "" {
			v.alerts[alertKey(subject, reason)] = struct{}{}
		}
		// An alert still falls through to the activity fold below: doc 02 §2
		// omits run_id and spiffe_id together and only for an alert that
		// references no run, so one that DOES name a run is a run-scoped event
		// like any other and the rule counts it the way the read API counts it.
	}

	spiffeID := recordString(record, event.FieldSpiffeID)
	runID := recordString(record, event.FieldRunID)
	if spiffeID == "" || runID == "" {
		// Not run-scoped: a sealed segment, or a system-scope alert. doc 02 §2
		// omits the two together and never one without the other.
		return
	}
	at := parseTS(record)

	var run *ledgerRun
	switch eventType {
	case event.EventTypeRunRegistered:
		eventID := recordString(record, event.FieldEventID)
		if eventID == "" {
			return
		}
		run = v.run(spiffeID, runID)
		run.registeredEventID = eventID
		run.facts.RegisteredAt = at

	case event.EventTypeRunRetired:
		eventID := recordString(record, event.FieldEventID)
		if eventID == "" {
			return
		}
		run = v.run(spiffeID, runID)
		// EARLIEST, by instant: ADR-0020 §5 makes two concurrent retirements
		// two reports of ONE ending, and every caller is told the original.
		// `Retired` is set independently of the instant because it is what
		// DECIDES — the read API derives it as bool_or over the event type and
		// never needs a timestamp — so a retirement whose `ts` this control
		// could not read still retires the run.
		if !run.facts.Retired || (!at.IsZero() &&
			(run.facts.RetiredAt.IsZero() || at.Before(run.facts.RetiredAt))) {
			run.retiredEventID = eventID
			run.facts.RetiredAt = at
		}
		run.facts.Retired = true

	case event.EventTypeRunExpired:
		eventID := recordString(record, event.FieldEventID)
		if eventID == "" {
			return
		}
		run = v.run(spiffeID, runID)
		// NEWEST, by instant: a run has one withdrawal per quiet spell, and the
		// one an entry's survival contradicts is the one that stands.
		if at.After(run.facts.WithdrawnAt) {
			run.withdrawnEventID = eventID
			run.facts.WithdrawnAt = at
		}

	default:
		// Everything else is only ever ACTIVITY, and only for an identity the
		// chain already explains. An entry for a SPIFFE ID whose whole ledger
		// record is a tool call and no lifecycle event at all stays
		// DriftEntryUnattributed — AB-11 in its purest form — rather than
		// becoming a run this view believes in.
		var known bool
		run, known = v.runs[spiffeID]
		if !known {
			return
		}
	}

	// ACTIVITY IS AN EVENT THE REAPER DID NOT WRITE, which is the read API's
	// own discriminator (`source IS DISTINCT FROM 'reaper'`) and is taken from
	// it verbatim rather than re-decided here. doc 02 §2 makes `source` "who
	// appended it", so an event sourced to the reaper is by construction not
	// something the run did — and counting it would let the reaper read its own
	// withdrawal as evidence that the run it withdrew from is working, so no
	// withdrawal would ever stand.
	//
	// A record whose `source` cannot be read counts as activity, because SQL's
	// `IS DISTINCT FROM` counts a NULL that way and the two renderings must
	// agree on the same chain (REC-018).
	if recordString(record, event.FieldSource) != event.SourceReaper &&
		at.After(run.facts.LastActivityAt) {
		run.facts.LastActivityAt = at
	}
}

// ---------------------------------------------------------------------------
// The comparison.
// ---------------------------------------------------------------------------

// compareEntries is expected against actual, both directions, in SPIFFE ID
// order so a Result is the same for the same state.
//
// now and minAge gate the two drift kinds ADR-0018 lets the ledger run ahead
// of SPIRE on — DriftEntryMissing and DriftEntryNotDeleted, see oldEnough and
// the file comment (#108, RM-075). The other two, DriftEntryUnattributed and
// DriftEntryDuplicated, are reported the instant they are seen: nothing about
// them is a window a healthy call is still inside.
func compareEntries(view *ledgerView, entries []Entry, now time.Time,
	minAge, horizon time.Duration,
) []Drift {
	byID := make(map[string][]string, len(entries))
	for _, entry := range entries {
		byID[entry.SPIFFEID] = append(byID[entry.SPIFFEID], entry.ID)
	}

	var drifts []Drift
	// Direction one: what SPIRE holds that the ledger does not account for.
	for _, spiffeID := range slices.Sorted(maps.Keys(byID)) {
		entryIDs := byID[spiffeID]
		slices.Sort(entryIDs)
		run, known := view.runs[spiffeID]
		var state string
		if known {
			state = run.state(now, horizon)
		}
		switch {
		case !known:
			drifts = append(drifts, newDrift(DriftEntryUnattributed, spiffeID, "", "", entryIDs))
		case state != ledger.RunActive:
			// The run is retired, or withdrawn from with nothing heard since,
			// and SPIRE still holds an entry. A RESTORED run does not land
			// here: its activity is newer than its withdrawal, so the rule
			// reads it active and the entry get_credential re-created is the
			// entry an active run is supposed to have (REC-017).
			if !oldEnough(run.facts.DecidedAt(), now, minAge) {
				// retire_agent or the reaper may still be between recording
				// the closure and deleting the entry (ADR-0018). Not drift
				// yet — the next cycle re-derives this from the chain, so
				// nothing is lost by waiting.
				continue
			}
			drifts = append(drifts, newDrift(DriftEntryNotDeleted, spiffeID, run.runID,
				run.closingEventID(state), entryIDs))
		case len(entryIDs) > 1:
			drifts = append(drifts, newDrift(DriftEntryDuplicated, spiffeID, run.runID,
				run.registeredEventID, entryIDs))
		}
	}
	// Direction two: what the ledger says is active and SPIRE does not hold.
	for _, spiffeID := range slices.Sorted(maps.Keys(view.runs)) {
		run := view.runs[spiffeID]
		if run.registeredEventID == "" || run.state(now, horizon) != ledger.RunActive {
			continue
		}
		if _, held := byID[spiffeID]; held {
			continue
		}
		// Aged against the fact that made the run ACTIVE, not against its
		// registration. For a run registering now those are the same event. For
		// a run whose activity has just overtaken a withdrawal they are not,
		// and the registration is ancient: measuring against it would accuse a
		// run that spoke a second ago of having no entry, when what is really
		// happening is that its next call is the one that restores it.
		if !oldEnough(run.facts.DecidedAt(), now, minAge) {
			// register_agent may still be between the append and the create
			// (ADR-0018) — the legitimate window #108/RM-075 is about. Not
			// drift yet; a later cycle sees the same chain and tries again.
			continue
		}
		drifts = append(drifts, newDrift(DriftEntryMissing, spiffeID, run.runID,
			run.registeredEventID, nil))
	}
	return drifts
}

// oldEnough reports whether at is far enough in the past of now to rule out
// the legitimate ADR-0018 window — the only thing that lets compareEntries
// tell an orphan from a call still in flight.
//
// A zero at — the event's `ts` was absent or unparseable — answers false, the
// same way the reaper's classify refuses to judge an entry it cannot date
// (reaper.go): a run this control cannot age is one it has no basis to
// accuse, and silence is the safer failure.
func oldEnough(at, now time.Time, minAge time.Duration) bool {
	if at.IsZero() {
		return false
	}
	return now.Sub(at) >= minAge
}

func newDrift(kind DriftKind, spiffeID, runID, subjectEventID string, entryIDs []string) Drift {
	return Drift{
		Kind:           kind,
		SPIFFEID:       spiffeID,
		RunID:          runID,
		EntryIDs:       entryIDs,
		SubjectEventID: subjectEventID,
		Reason:         driftReason(kind),
	}
}

// ---------------------------------------------------------------------------
// The SPIRE side.
// ---------------------------------------------------------------------------

// ListAgentEntries returns every registration entry SPIRE holds in the agent
// subtree of this client's trust domain.
//
// It asks the server, not an agent: the server's datastore is authoritative the
// instant a create or delete returns, and an agent's cache converges seconds
// later (RM-014 measured 3–7). Reconciling against a cache would report drift
// that is only latency, and — worse — would miss an entry planted and used
// inside one convergence window.
//
// The subtree filter is applied here rather than server-side because
// ListEntries has no path-prefix filter: its by_spiffe_id is an exact match.
// Reading every entry and discarding what is not a run identity is the only
// available shape, and it is also what makes an out-of-subtree entry invisible
// to this control on purpose — that is AB-10's ground, covered by the
// authorization policy and SPI-005.
func (c *Client) ListAgentEntries(ctx context.Context) ([]Entry, error) {
	prefix := "spiffe://" + c.trustDomain + agentPathPrefix
	var (
		out   []Entry
		token string
	)
	for page := 1; page <= maxEntryPages; page++ {
		rpcCtx, cancel := c.call(ctx)
		resp, err := c.entries.ListEntries(rpcCtx, &entryv1.ListEntriesRequest{
			PageSize:  entryPageSize,
			PageToken: token,
		})
		cancel()
		if err != nil {
			return nil, classifyAdmin("list_entries", "", err)
		}
		for _, wire := range resp.GetEntries() {
			if entry := fromWire(wire); strings.HasPrefix(entry.SPIFFEID, prefix) {
				out = append(out, entry)
			}
		}
		if token = resp.GetNextPageToken(); token == "" {
			return out, nil
		}
	}
	return nil, newError(ClassInvariantViolation, "list_entries", "",
		fmt.Sprintf("SPIRE was still returning a page token after %d pages of %d",
			maxEntryPages, entryPageSize), false, nil)
}

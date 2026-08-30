// SPDX-License-Identifier: Apache-2.0

// Package reconciler closes IP §6.5's two crash windows.
//
// RM-035 (#43); test IDs REC-001, REC-002, REC-005; invariants I3 and I4.
//
// # What this repairs
//
// `sign_commit` (RM-033, ADR-0033) is three phases that never reorder:
//
//	Phase A   append `commit_intent` {repo, tree_hash}  — before any signing
//	Phase B   sign via gitsign — Fulcio and Rekor, as one operation
//	Phase C   append `commit_recorded` {commit_sha, rekor entry, intent id}
//
// Nothing makes the gaps between them disappear: a signature lives in Rekor
// and a record lives in Postgres, and there is no transaction across them. The
// protocol chooses which side the window falls on and makes what is left
// behind recoverable. Recovering it is this package.
//
//	A → B   a `commit_intent` and no signature. Reached by a crash after the
//	        append, by Fulcio or Rekor dying between ADR-0033's gate 7 and
//	        `git commit`, or by gitsign refusing. EXPIRED after a bounded
//	        window, with `commit_intent_expired` (REC-001).
//	B → C   a commit object and a Rekor entry and no `commit_recorded`.
//	        REPAIRED by matching the log entry back to the intent and appending
//	        the missing `commit_recorded` with `source: reconciler` (REC-002).
//
// ADR-0033 records that `sign_commit` is deliberately NOT self-healing in the
// second window — a lease takeover there is refused rather than repaired,
// because recovering the log entry for an existing commit is
// `internal/signing`'s unexported `findRekorEntry` (ADR-0031 decision 6). IP
// §6.5 assigns that repair here, and here is where it lives.
//
// The third thing IP §6.5 asks of a reconciler — a Rekor entry for our trust
// domain with NO intent, raised as `unattributed_signature_detected` — is
// RM-036's (#44, REC-003/REC-004) and is deliberately absent from this file.
//
// # Which direction the join runs, and why
//
// IP §6.5 describes the repair as scanning "Rekor for certificates bearing our
// trust domain's identities" and matching them to intents. That names the
// relation, not the query plan, and this package runs it from the intent side:
//
//	for each OPEN intent:
//	    the repository named by `repo` is asked for every commit object whose
//	    tree is the intent's `tree_hash` and which carries a `gpgsig` header
//	    for each such commit:
//	        Rekor is asked for the entry whose artifact is sha256(commit_sha)
//	        the entry is this intent's iff its certificate's URI SAN is the
//	        intent's own `spiffe_id`, inside our trust domain
//
// Three reasons. It is bounded by the number of open intents rather than by
// the size of the log, so it stays the same cost on public Sigstore as on a
// self-hosted one. The artifact-hash index is the join `internal/signing`
// already uses to prove an entry belongs to a commit, so the reconciler and
// the tool agree on what "this commit's entry" means. And the log-side sweep
// the sentence literally describes is REC-003's, whose whole subject is
// entries with no intent — it belongs to the component that has a use for it.
//
// The trust-domain condition is not dropped by running the join this way: an
// entry is accepted only if its certificate names the intent's own identity
// AND that identity is inside the configured trust domain, so a certificate
// from anywhere else can never complete a repair.
//
// # What must never happen
//
// Appending a `commit_recorded` for an intent that was never signed would be
// FABRICATED ATTRIBUTION — the exact thing RM-036's drift detection exists to
// catch, arriving from the component meant to be the cure. So a repair
// requires, every time: a commit object in the repository whose tree is the
// intent's, carrying a signature; an entry in the transparency log whose
// artifact hash is that commit's; and a certificate on that entry naming that
// run. A missing any-of-three is not a repair, and an expiry is what a missing
// signature earns.
//
// The mirror image is just as bad. `commit_intent_expired` states that no
// signature exists, I4 makes it permanent, and it is only ever appended on a
// POSITIVE answer: the repository was read and holds no signed commit for that
// tree, or every candidate was put to the log and the log said no. A
// repository that cannot be reached or a log that cannot be asked leaves the
// intent OPEN and raises an operator alert. "We could not tell" is never
// recorded as "it never happened".
//
// # Idempotency, and two reconcilers at once
//
// A cycle appends nothing it has already appended, and the state that makes it
// quiet is read back out of the chain: an intent is open until a
// `commit_recorded` or a `commit_intent_expired` names it. Nothing is
// remembered between cycles, so a restarted process or a newly elected leader
// (doc 05 §2 runs this single-active with failover) is as quiet as the one it
// replaced — that is REC-005, and it is proved with a FRESH reconciler rather
// than a second pass.
//
// Leader election is not implemented here; doc 05 §2 puts it in the
// deployment. What is implemented is the property that makes failover
// harmless: both appends carry a deterministic `idempotency_key`, which is
// UNIQUE across the chain (LED-008), so two reconcilers that both read before
// either wrote produce ONE event and not two.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// DefaultExpireAfter is IP §6.5's "bounded window" — how long a `commit_intent`
// with no discoverable signature is left alone before it is expired.
//
// The window is bounded below by the longest a legitimate Phase B can still be
// running, because expiring an intent whose signature is in flight records a
// permanent falsehood (I4). That worst case is `internal/signing`'s own:
// `DefaultTimeout` (2 minutes) bounds the `git commit`, the Rekor search index
// is then polled for `rekorLookupAttempts × rekorLookupDelay` (2.5 seconds),
// and IP §6.8's `DefaultSkew` (1 minute) is the disagreement two hosts' clocks
// may have about when the intent was appended. Call it four minutes.
//
// It is bounded above by doc 05 §4, which lists reconciler drift alerts among
// the monitoring minimums: an intent nobody has ruled on is an outage nobody
// has been told about.
//
// Fifteen minutes is a shade under four times the worst legitimate Phase B —
// enough that a slow Sigstore, a retried gitsign and a skewed clock together
// cannot reach it, short enough that an operator learns of a stuck signing
// path inside one coffee break. It is a default and not a constant:
// `Config.ExpireAfter` and `innsegl reconcile -expire-after` move it, and a
// deployment whose Sigstore is slower should move it.
const DefaultExpireAfter = 15 * time.Minute

// DefaultInterval is how often `innsegl reconcile` runs a cycle when no
// interval is given. IP §6.5 says the reconciler "runs continuously"; a minute
// is short against the expiry window above, so an intent is ruled on within
// about one window of becoming eligible.
const DefaultInterval = time.Minute

// ErrNoEntry reports that the transparency log holds no entry for a commit.
// It is a fact about the log, not a failure to read it: the difference is what
// separates an expiry from an unresolved intent.
var ErrNoEntry = errors.New("reconciler: the transparency log holds no entry for this commit")

// ---------------------------------------------------------------------------
// Idempotency keys.
// ---------------------------------------------------------------------------

// PROTECTED-ADJACENT. These four strings become the `idempotency_key` of
// events in an append-only chain, and `idempotency_key` is part of the
// canonical preimage (doc 02 §4). Changing one makes every replay append a
// second event rather than dedupe, so a change needs the old spelling kept as
// a fallback lookup. ADR-0014 records the same for the reaper's.
//
// The first two are `sign_commit`'s, from ADR-0033 decision 5. They are spelled
// here rather than imported because `internal/mcp` keeps them unexported and
// this package must not depend on the MCP server to repair its records. The
// integration case pins them against keys a real `sign_commit` produced, so a
// divergence fails a test rather than silently forking the chain.
const (
	signCommitIntentKeyPrefix   = "sign_commit/intent/"
	signCommitRecordedKeyPrefix = "sign_commit/recorded/"

	// The reconciler's own namespace, for an intent whose key is not one
	// sign_commit derived and for the expiry, which sign_commit never writes.
	repairedKeyPrefix = "reconciler:commit_recorded:"
	expiredKeyPrefix  = "reconciler:commit_intent_expired:"
)

// RepairKey is the `idempotency_key` a repaired `commit_recorded` carries.
//
// When the intent carries `sign_commit`'s derived intent key, the repair
// carries the RECORDED key that same call would have used — so a repaired
// chain and a chain that never crashed hold the same value in the same member,
// which is what REC-002's state diff is about. Otherwise the reconciler's own
// namespace, keyed by the intent, which is unique by construction.
func RepairKey(intentEventID, intentKey string) string {
	if rest, derived := strings.CutPrefix(intentKey, signCommitIntentKeyPrefix); derived {
		return signCommitRecordedKeyPrefix + rest
	}
	return repairedKeyPrefix + intentEventID
}

// ExpiryKey is the `idempotency_key` a `commit_intent_expired` carries. The
// intent's `event_id` and nothing else, so it is stable across sweeps,
// processes and leaders.
func ExpiryKey(intentEventID string) string { return expiredKeyPrefix + intentEventID }

// ---------------------------------------------------------------------------
// Dependencies.
// ---------------------------------------------------------------------------

// LedgerReader is the chain, read in position order. *ledger.Store implements
// it.
//
// The interface is declared here rather than in internal/ledger so this
// package depends on the ledger's shape and not on its implementation — and so
// the error paths below are reachable from a test with no database.
type LedgerReader interface {
	// Count is how many events the chain holds. doc 02 §2 makes chain_position
	// 1-based and strictly consecutive, so the count is also the last position.
	Count(ctx context.Context) (int64, error)
	// Events returns positions from..to inclusive, in order.
	Events(ctx context.Context, from, to int64) ([]event.Fields, error)
}

// LedgerAppender writes the repair. *ledger.Store implements it.
type LedgerAppender interface {
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// Repos is the git half of the join. *GitWorkspace is the shipped
// implementation.
//
// `repo` is doc 02 §5's `host/org/name`, an identifier in an append-only
// record and never a path — the same boundary ADR-0033 decision 3 draws for
// the MCP, for the same reason: a component that took a path would read any
// directory its process can reach.
type Repos interface {
	// SignedCommitsWithTree returns every commit object in repo whose tree is
	// treeHash and which carries a signature, sorted. An error means the
	// repository could not be read, which is never grounds for an expiry.
	SignedCommitsWithTree(ctx context.Context, repo, treeHash string) ([]string, error)
}

// TransparencyLog is Rekor, read-only. *RekorLog is the shipped
// implementation.
type TransparencyLog interface {
	// EntryForCommit returns the log entry whose artifact is sha256(commitSHA).
	// ErrNoEntry means the log answered and holds none; any other error means
	// the log could not be asked.
	EntryForCommit(ctx context.Context, commitSHA string) (LogEntry, error)
}

// LogEntry is one Rekor entry, reduced to what a repair records and checks.
type LogEntry struct {
	// UUID and LogIndex are doc 02 §3's two members of `commit_recorded`, so
	// the record names the entry the way the schema names it.
	UUID     string
	LogIndex int64
	// IntegratedAt is when the log accepted it.
	IntegratedAt time.Time
	// CertificateIdentity is the URI SAN of the certificate the entry was
	// accepted under — the SPIFFE ID Fulcio put in the certificate it issued.
	// It is the whole of the attribution check.
	CertificateIdentity string
}

// ---------------------------------------------------------------------------
// Findings.
// ---------------------------------------------------------------------------

// Outcome is what one cycle decided about one open intent.
type Outcome string

// The five outcomes. Four of them append nothing.
const (
	// OutcomeRepaired: the B → C window, closed. A `commit_recorded` with
	// `source: reconciler` now names the commit and its log entry.
	OutcomeRepaired Outcome = "repaired"
	// OutcomeExpired: the A → B window, closed. No signature exists and the
	// window has passed, so `commit_intent_expired` says so.
	OutcomeExpired Outcome = "expired"
	// OutcomeOpen: no signature found and the window has not passed. The
	// signature may still be in flight.
	OutcomeOpen Outcome = "open"
	// OutcomeUnresolved: the repository or the log could not be consulted, so
	// neither the repair nor the expiry has been established. Alert-level: an
	// intent nobody can rule on is a signing path nobody is watching.
	OutcomeUnresolved Outcome = "unresolved"
	// OutcomeAmbiguous: more than one signed commit in the log claims this
	// intent. Which one the intent named is not something this component may
	// guess, and two signatures for one intent is itself a finding.
	OutcomeAmbiguous Outcome = "ambiguous"
)

// Finding is one intent's verdict, and the operator-visible half of a cycle.
type Finding struct {
	Outcome       Outcome
	IntentEventID string
	RunID         string
	SPIFFEID      string
	Repo          string
	TreeHash      string
	// CommitSHA and the two Rekor members are set on a repair, and on an
	// ambiguity name the first candidate.
	CommitSHA      string
	RekorEntryUUID string
	RekorLogIndex  int64
	// Age is how long the intent has been open at the moment of the decision.
	Age time.Duration
	// Detail is why, in words an operator reads.
	Detail string
	// AppendedEventID is the repair or expiry this finding produced, empty
	// when the cycle appended nothing for it.
	AppendedEventID string
}

// Result is one reconciliation cycle.
type Result struct {
	// Intents is how many `commit_intent` events the chain holds.
	Intents int
	// Open is how many of them this cycle found still unresolved on arrival.
	Open int
	// Repaired, Expired, Unresolved and Ambiguous partition Open.
	Repaired   int
	Expired    int
	Unresolved int
	Ambiguous  int
	// Findings is one entry per open intent, in chain order.
	Findings []Finding
	// Appended is the event_id of each event this cycle wrote. EMPTY on a
	// cycle over already-reconciled state — that is REC-005 as an observable.
	Appended []string
	// Drift is the cross-check of the chain against the transparency log, in
	// both directions (RM-036, #44). Zero — and `Enabled` false — when no
	// `Config.Drift` was given.
	Drift DriftResult
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

// Config is what New needs.
type Config struct {
	// Ledger reads the chain. Required.
	Ledger LedgerReader
	// Appender writes the repair. Required — I3 admits no action without a
	// record, and a repair nobody can record is not a repair.
	Appender LedgerAppender
	// Repos reads the repositories named by `repo`. Required.
	Repos Repos
	// Log is the transparency log. Required — without it no repair can be
	// established and no expiry can be justified.
	Log TransparencyLog
	// TrustDomain is this deployment's, e.g. "innsegl.dev". Required: it is
	// the scope IP §6.5 puts on the certificates a repair may accept.
	TrustDomain string
	// ExpireAfter is the bounded window. Zero means DefaultExpireAfter.
	ExpireAfter time.Duration
	// Batch bounds one read of the chain. Zero means defaultLedgerBatch.
	Batch int64
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// Alert receives every finding that needs a human: an unresolved intent,
	// an ambiguous one. Defaults to an error-level slog line.
	Alert func(context.Context, Finding)
	// Drift turns on IP §6.5's third job and IP §6.10's proof — the Rekor
	// cross-check that makes a compromised MCP detectable (RM-036, #44,
	// REC-003/REC-004). Nil leaves it OFF, and `Result.Drift.Enabled` says so
	// on every cycle rather than letting a deployment believe a reconciler
	// without it is watching for drift. See drift.go.
	Drift *DriftConfig
	// Observe receives every cycle Run performs, including a failed one.
	Observe func(Result, error)
}

const (
	// defaultLedgerBatch bounds one Events read, so a long chain is walked in
	// bounded memory rather than materialised whole.
	defaultLedgerBatch = 1000
)

// Reconciler repairs the two windows. Build one with New.
type Reconciler struct {
	cfg    Config
	batch  int64
	expire time.Duration
	now    func() time.Time
}

// New builds a reconciler, or refuses.
//
// Every refusal is the same kind of mistake: a reconciler missing one of its
// halves is not a degraded reconciler, it is a repair component that reports
// agreement it never checked — and, worse than the SPIRE reconciler's version
// of that sentence, one that could expire an intent on a question it never
// asked.
func New(cfg Config) (*Reconciler, error) {
	fail := func(detail string) (*Reconciler, error) {
		return nil, fmt.Errorf("reconciler: %s", detail)
	}
	switch {
	case cfg.Ledger == nil:
		return fail("no ledger reader: there is nothing to reconcile")
	case cfg.Appender == nil:
		return fail("no ledger appender: a repair that cannot be recorded is not a repair (I3)")
	case cfg.Repos == nil:
		return fail("no repository reader: a signature cannot be matched to a commit nobody can find")
	case cfg.Log == nil:
		return fail("no transparency log: every expiry would be a negative nobody established (IP §6.5)")
	case cfg.TrustDomain == "":
		return fail("no trust domain: IP §6.5 scopes the repair to certificates bearing ours")
	}
	// RM-036: drift detection is optional, but a half-configured one is not.
	if err := cfg.Drift.validate(); err != nil {
		return nil, err
	}
	if cfg.Alert == nil {
		cfg.Alert = defaultAlert
	}
	if cfg.Observe == nil {
		cfg.Observe = defaultObserve
	}
	r := &Reconciler{
		cfg:    cfg,
		batch:  cfg.Batch,
		expire: cfg.ExpireAfter,
		now:    cfg.Now,
	}
	if r.batch <= 0 {
		r.batch = defaultLedgerBatch
	}
	if r.expire <= 0 {
		r.expire = DefaultExpireAfter
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r, nil
}

// Reconcile runs one cycle: read the chain, resolve every open intent, append
// what the evidence supports.
//
// The chain is read FIRST and in full, and the external world second. That is
// the safe order here: an intent appended after the read is simply not in this
// cycle, and the next one picks it up — whereas reading Rekor first and the
// chain second could match an entry against a chain state that has since
// gained the very `commit_recorded` the match would duplicate.
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	view, err := r.readLedger(ctx)
	if err != nil {
		return Result{}, err
	}

	result := Result{Intents: view.intents}
	for _, intent := range view.open {
		finding := r.resolve(ctx, intent)
		result.Open++
		result.Findings = append(result.Findings, finding)

		switch finding.Outcome {
		case OutcomeRepaired, OutcomeExpired:
			id, aerr := r.record(ctx, intent, finding)
			if aerr != nil {
				// The findings so far stay in the result. A ledger that
				// refused the append is a reason to fail the cycle, never a
				// reason to go quiet about what the cycle found.
				return result, aerr
			}
			result.Findings[len(result.Findings)-1].AppendedEventID = id
			if id != "" {
				result.Appended = append(result.Appended, id)
			}
			if finding.Outcome == OutcomeRepaired {
				result.Repaired++
			} else {
				result.Expired++
			}
		case OutcomeUnresolved:
			result.Unresolved++
			r.cfg.Alert(ctx, finding)
		case OutcomeAmbiguous:
			result.Ambiguous++
			r.cfg.Alert(ctx, finding)
		case OutcomeOpen:
		}
	}

	// RM-036 (#44): the third thing IP §6.5 asks of a reconciler, and IP
	// §6.10's demonstration that a fully compromised MCP still cannot forge
	// attribution. It runs AFTER the repairs so that a `commit_recorded` this
	// same cycle wrote is already on the chain when the log side asks who
	// claimed the entry — otherwise a repair and an "unattributed signature"
	// alert would be raised about the same entry in the same cycle.
	result.Drift = r.detectDrift(ctx, view)
	result.Appended = append(result.Appended, result.Drift.Appended...)
	return result, nil
}

// Run reconciles every interval until ctx is done, handing each cycle to
// Observe.
//
// A failed cycle does not end the loop. Rekor being unreachable is IP §6.3's
// retryable case and Postgres being unreachable is IP §6.4's; a repair
// component that stops at the first timeout is a repair component that is off,
// and the windows it exists to close stay open silently.
func (r *Reconciler) Run(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		return fmt.Errorf("reconciler: interval %s is not positive; IP §6.5 requires "+
			"the reconciler to run continuously", every)
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

// ---------------------------------------------------------------------------
// Resolving one intent.
// ---------------------------------------------------------------------------

// resolve decides one open intent's outcome. It appends nothing.
func (r *Reconciler) resolve(ctx context.Context, in openIntent) Finding {
	finding := Finding{
		IntentEventID: in.eventID,
		RunID:         in.runID,
		SPIFFEID:      in.spiffeID,
		Repo:          in.repo,
		TreeHash:      in.treeHash,
		Age:           r.now().Sub(in.at),
	}

	// The identity the intent claims must be one this deployment could have
	// issued. An intent naming another trust domain can never be repaired —
	// no certificate we would accept could match it — so it is unresolvable
	// rather than expirable, and it is loud.
	if !r.ours(in.spiffeID) {
		finding.Outcome = OutcomeUnresolved
		finding.Detail = fmt.Sprintf(
			"the intent claims %s, which is outside this deployment's trust domain %s; "+
				"no certificate this reconciler would accept can match it",
			in.spiffeID, r.cfg.TrustDomain)
		return finding
	}

	commits, err := r.cfg.Repos.SignedCommitsWithTree(ctx, in.repo, in.treeHash)
	if err != nil {
		finding.Outcome = OutcomeUnresolved
		finding.Detail = fmt.Sprintf(
			"%s could not be read, so whether tree %s was ever committed is unknown "+
				"and no expiry may be recorded: %v", in.repo, in.treeHash, err)
		return finding
	}

	var matches []LogEntry
	for _, commit := range commits {
		entry, lerr := r.cfg.Log.EntryForCommit(ctx, commit)
		switch {
		case errors.Is(lerr, ErrNoEntry):
			// The log answered: this commit was never logged. A commit with no
			// transparency entry is not a signature this system made (IP §6.3
			// — a signature without a transparency entry must not exist), so
			// it is not a candidate and its absence is established.
			continue
		case lerr != nil:
			finding.Outcome = OutcomeUnresolved
			finding.Detail = fmt.Sprintf(
				"the transparency log could not be asked about commit %s: %v", commit, lerr)
			return finding
		}
		if !attributes(entry, in.spiffeID) {
			// A real entry for a real commit, under somebody else's
			// certificate. It is not this intent's, and saying so is the
			// whole difference between a repair and a fabrication.
			continue
		}
		if len(matches) == 0 {
			finding.CommitSHA = commit
			finding.RekorEntryUUID = entry.UUID
			finding.RekorLogIndex = entry.LogIndex
		}
		matches = append(matches, entry)
	}

	switch {
	case len(matches) > 1:
		finding.Outcome = OutcomeAmbiguous
		finding.Detail = fmt.Sprintf(
			"%d signed commits in %s hold tree %s and each has a log entry under %s; "+
				"which one this intent named is not something a reconciler may guess",
			len(matches), in.repo, in.treeHash, in.spiffeID)
	case len(matches) == 1:
		finding.Outcome = OutcomeRepaired
		finding.Detail = fmt.Sprintf(
			"commit %s holds the intent's tree and Rekor entry %s (index %d) was accepted "+
				"under %s: the signature exists and the record did not",
			finding.CommitSHA, finding.RekorEntryUUID, finding.RekorLogIndex, in.spiffeID)
	case finding.Age < r.expire:
		finding.Outcome = OutcomeOpen
		finding.Detail = fmt.Sprintf(
			"no signature for tree %s yet, and the intent is %s old against a %s window",
			in.treeHash, finding.Age.Truncate(time.Second), r.expire)
	default:
		finding.Outcome = OutcomeExpired
		finding.Detail = fmt.Sprintf(
			"no signed commit in %s holds tree %s in the transparency log, and the intent "+
				"is %s old against a %s window", in.repo, in.treeHash,
			finding.Age.Truncate(time.Second), r.expire)
	}
	return finding
}

// ours reports whether a SPIFFE ID is a run identity of this trust domain.
//
// The prefix is the agent subtree, the same scope RM-019's SPIRE
// reconciliation uses: `spiffe://{td}/agent/`. An identity outside it is not a
// run, and a certificate carrying one can never complete a repair.
func (r *Reconciler) ours(spiffeID string) bool {
	return strings.HasPrefix(spiffeID, "spiffe://"+r.cfg.TrustDomain+"/agent/")
}

// attributes reports whether a log entry is this intent's signature: the
// certificate Rekor accepted it under names the intent's own identity.
//
// IP §6.5's scope — "certificates bearing our trust domain's identities" — is
// enforced ONCE, at the intent, by the guard at the top of resolve, and reaches
// the certificate through this equality: an intent's identity is inside the
// trust domain or it is never resolved, and a certificate that is not equal to
// it is never a match. Repeating the trust-domain test here would be a
// condition no input can falsify, and a check that can never fire is a check
// nobody can test (ADR-0033 decision 3's own rule). It was written, and a
// mutation that deleted it changed no test — so it is gone rather than
// standing as untested reassurance.
func attributes(entry LogEntry, spiffeID string) bool {
	return entry.CertificateIdentity == spiffeID
}

// ---------------------------------------------------------------------------
// Appending.
// ---------------------------------------------------------------------------

// record appends the repair or the expiry and returns its event_id.
//
// An append whose idempotency_key is already spent returns the earlier event
// and writes nothing (LED-008); that is what makes two concurrent reconcilers
// harmless, and it is reported as an empty event_id rather than counted as a
// write.
func (r *Reconciler) record(ctx context.Context, in openIntent, finding Finding) (string, error) {
	var body event.Fields
	if finding.Outcome == OutcomeRepaired {
		body = event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeCommitRecorded,
			event.FieldSource:         event.SourceReconciler,
			event.FieldRunID:          in.runID,
			event.FieldSpiffeID:       in.spiffeID,
			event.FieldIdempotencyKey: RepairKey(in.eventID, in.idempotencyKey),
			event.FieldRepo:           in.repo,
			event.FieldTreeHash:       in.treeHash,
			event.FieldCommitSHA:      finding.CommitSHA,
			event.FieldRekorEntryUUID: finding.RekorEntryUUID,
			event.FieldRekorLogIndex:  finding.RekorLogIndex,
			event.FieldIntentEventID:  in.eventID,
		}
	} else {
		body = event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeCommitIntentExpired,
			event.FieldSource:         event.SourceReconciler,
			event.FieldRunID:          in.runID,
			event.FieldSpiffeID:       in.spiffeID,
			event.FieldIdempotencyKey: ExpiryKey(in.eventID),
			event.FieldIntentEventID:  in.eventID,
		}
	}

	record, err := r.cfg.Appender.Append(ctx, body)
	if err != nil {
		return "", fmt.Errorf("reconciler: recording the %s of intent %s: %w",
			finding.Outcome, in.eventID, err)
	}
	// A record we did not just write is one another reconciler wrote between
	// this cycle's read and this append. Reported as "nothing appended",
	// because that is what happened.
	if recordString(record, event.FieldEventType) != recordString(body, event.FieldEventType) {
		return "", fmt.Errorf(
			"reconciler: appending the %s of intent %s returned a %s; the idempotency key "+
				"%q names another event", finding.Outcome, in.eventID,
			recordString(record, event.FieldEventType),
			recordString(body, event.FieldIdempotencyKey))
	}
	if recordString(record, event.FieldIntentEventID) != in.eventID {
		return "", fmt.Errorf(
			"reconciler: appending the %s of intent %s returned an event naming intent %s",
			finding.Outcome, in.eventID, recordString(record, event.FieldIntentEventID))
	}
	return recordString(record, event.FieldEventID), nil
}

// ---------------------------------------------------------------------------
// The ledger side: which intents are still open.
// ---------------------------------------------------------------------------

// openIntent is one `commit_intent` the chain has not yet resolved.
type openIntent struct {
	eventID        string
	runID          string
	spiffeID       string
	repo           string
	treeHash       string
	idempotencyKey string
	at             time.Time
}

// ledgerView is the whole chain reduced to what one cycle needs.
type ledgerView struct {
	// intents is how many commit_intent events the chain holds, open or not.
	intents int
	// order preserves chain order; byID holds the ones not yet resolved.
	order []string
	byID  map[string]openIntent
	// open is byID in chain order, computed by close().
	open []openIntent
	// drift is RM-036's fold of the same walk: the chain-derived state its
	// two cross-checks dedupe against (drift.go). One walk, two readers.
	drift *driftView
}

// readLedger walks the chain in bounded batches and reduces it to a view.
func (r *Reconciler) readLedger(ctx context.Context) (*ledgerView, error) {
	view := &ledgerView{byID: map[string]openIntent{}, drift: newDriftView()}
	n, err := r.cfg.Ledger.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("reconciler: counting the chain: %w", err)
	}
	for from := int64(1); from <= n; from += r.batch {
		to := min(from+r.batch-1, n)
		records, rerr := r.cfg.Ledger.Events(ctx, from, to)
		if rerr != nil {
			return nil, fmt.Errorf("reconciler: reading positions %d..%d: %w", from, to, rerr)
		}
		for _, record := range records {
			view.observe(record)
		}
	}
	view.close()
	return view, nil
}

// observe folds one event into the view.
//
// A record whose members are missing or of the wrong type is skipped rather
// than fatal. The ledger validates on the way in (doc 02 §1, closed schema), so
// this cannot happen for anything this deployment wrote; what it can be is an
// event from a newer schema_version, which doc 02 §1 says a verifier tolerates.
// Refusing to reconcile because one event was unreadable would turn a
// forward-compatibility case into an outage of the repair.
func (v *ledgerView) observe(record event.Fields) {
	v.drift.observe(record) // RM-036 (#44) folds the same record; see drift.go.
	switch recordString(record, event.FieldEventType) {
	case event.EventTypeCommitIntent:
		v.intents++
		eventID := recordString(record, event.FieldEventID)
		at, err := event.ParseTimestamp(recordString(record, event.FieldTS))
		switch {
		case eventID == "", err != nil:
			return
		}
		in := openIntent{
			eventID:        eventID,
			runID:          recordString(record, event.FieldRunID),
			spiffeID:       recordString(record, event.FieldSpiffeID),
			repo:           recordString(record, event.FieldRepo),
			treeHash:       recordString(record, event.FieldTreeHash),
			idempotencyKey: recordString(record, event.FieldIdempotencyKey),
			at:             at.Time(),
		}
		if in.runID == "" || in.spiffeID == "" || in.repo == "" || in.treeHash == "" {
			return
		}
		v.order = append(v.order, eventID)
		v.byID[eventID] = in
	case event.EventTypeCommitRecorded, event.EventTypeCommitIntentExpired:
		// Either one resolves the intent it names. This is the whole of
		// REC-005: the dedupe key is the chain, and nothing is remembered
		// between cycles or between processes.
		delete(v.byID, recordString(record, event.FieldIntentEventID))
	}
}

// close materialises the open intents in chain order.
func (v *ledgerView) close() {
	for _, id := range v.order {
		if in, still := v.byID[id]; still {
			v.open = append(v.open, in)
		}
	}
}

// recordString reads a string member of a ledger record.
//
// Absent and not-a-string both come back as "", which is a value doc 02 §1
// does not otherwise admit — "Absent and empty are distinct states and only
// 'absent' is allowed for a missing value" — so "" is unambiguously "this
// component could not read the member".
func recordString(record event.Fields, name string) string {
	value, ok := record[name].(string)
	if !ok {
		return ""
	}
	return value
}

// ---------------------------------------------------------------------------
// Default sinks.
// ---------------------------------------------------------------------------

// defaultAlert is the sink a deployment gets if it names none. Error level:
// doc 05 §4 lists reconciler drift alerts among the monitoring minimums, and
// an intent nobody can rule on is a signing path nobody is watching.
func defaultAlert(ctx context.Context, finding Finding) {
	slog.ErrorContext(ctx, "signing intent reconciliation: an intent this cycle could not resolve",
		"outcome", string(finding.Outcome),
		"intent_event_id", finding.IntentEventID,
		"run_id", finding.RunID,
		"repo", finding.Repo,
		"tree_hash", finding.TreeHash,
		"age", finding.Age.String(),
		"detail", finding.Detail)
}

// defaultObserve is the per-cycle sink a deployment gets if it names none.
func defaultObserve(result Result, err error) {
	switch {
	case err != nil:
		slog.Error("signing intent reconciliation cycle failed", "error", err)
	case result.Repaired > 0 || result.Expired > 0 || result.Unresolved > 0 ||
		result.Ambiguous > 0 || result.Drift.Unattributed > 0 || result.Drift.Fabricated > 0:
		slog.Warn("signing intent reconciliation acted",
			"intents", result.Intents, "open", result.Open,
			"repaired", result.Repaired, "expired", result.Expired,
			"unresolved", result.Unresolved, "ambiguous", result.Ambiguous,
			"unattributed_signatures", result.Drift.Unattributed,
			"fabricated_records", result.Drift.Fabricated)
	default:
		slog.Debug("every signing intent is accounted for",
			"intents", result.Intents, "open", result.Open,
			"drift_detection", result.Drift.Enabled)
	}
}

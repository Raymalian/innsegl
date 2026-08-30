// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// Drift detection: the control that makes a compromised MCP DETECTABLE.
//
// RM-036 (#44); test IDs REC-003 and REC-004; threat model AB-03; invariants
// I3, I4 and I5.
//
// IP §6.10 states the claim this file exists to make true:
//
//	"The MCP cannot forge attribution even if fully compromised: it never holds
//	 signing keys (E8), so the worst case is fake events, which the reconciler's
//	 Rekor cross-check surfaces as drift."
//
// It is a claim about a cross-check, so the check runs in BOTH directions and
// the two are different findings:
//
//	LOG → CHAIN   an entry in the transparency log, under a certificate bearing
//	              one of our trust domain's identities, that nothing on the
//	              chain claims. `unattributed_signature_detected` (REC-003).
//	              A signature nobody claimed is a possible compromise OF AN
//	              AGENT, or of whatever can reach SPIRE's admin socket
//	              (ADR-0011): somebody minted an identity of ours and signed
//	              with it, and the ledger was never told.
//
//	CHAIN → LOG   a `commit_recorded` whose Rekor entry is not in the log, or is
//	              in the log attesting something else. `ledger_drift_detected`
//	              (REC-004). A claim nobody signed is a possible compromise OF
//	              THE MCP: it is the one attack an MCP with no keys can still
//	              attempt, and it is AB-03 — "fabricates commit_recorded to
//	              frame an agent".
//
// Collapsing them would lose the only thing an operator needs first, which is
// which half of the system to stop trusting.
//
// # The event types fit, and that is checked rather than assumed
//
// ADR-0013 had to refuse one of these types for SPIRE drift because a
// registration entry has no honest value for `rekor_log_index` or
// `rekor_entry_uuid`, and doc 02 §1 forbids an empty-string placeholder. Here
// both types typecheck exactly:
//
//	unattributed_signature_detected  needs rekor_log_index (integer),
//	    rekor_entry_uuid and certificate_identity. Every one is read off the
//	    log entry itself. Its run scope is `runOptional`, and it is appended
//	    system-scope — doc 02 §2's "system-scope alerts that reference no run" —
//	    because the identity in the certificate names a run the chain has never
//	    heard of. Writing that identity's run id into `run_id` would assert a
//	    run exists, in a record I4 makes permanent, on the strength of a
//	    certificate this deployment did not issue. The identity is not lost: it
//	    is in `certificate_identity`, which is where doc 02 §3 puts it.
//
//	ledger_drift_detected  needs subject_event_id and reason. The subject is the
//	    `commit_recorded` whose claim the log contradicts — literally doc 02
//	    §3's own gloss, "a ledger claim with no external proof", with the
//	    transparency log as the external proof. It carries the SUBJECT's run
//	    scope, as ADR-0013's three recordable SPIRE kinds do, so the drift feed
//	    names the agent that was framed.
//
// # What is not detected, and is said rather than hidden
//
// An entry whose certificate is outside our trust domain is not ours to have an
// opinion about, and ADR-0013's reasoning applies unchanged: an alert that
// fires on every stranger's signature is an alert nobody reads.
//
// An entry under one of our identities while that run still holds an OPEN
// `commit_intent` is NOT flagged. That state is REC-002's repair window — the
// signature exists and the record does not yet — and the cycle that finds it
// there has, moments earlier, either repaired it or left it open on purpose.
// Alerting would make the reconciler's own two jobs contradict each other.
//
// The sweep is a WINDOW, not the whole log; see DefaultSweepWindow.
//
// # Idempotency, and a reconciler that has never run before
//
// Neither direction remembers anything. Both dedupe keys are read back out of
// the chain in the same walk that finds the open intents:
//
//	an entry is already reported  iff some `unattributed_signature_detected`
//	                              names its `rekor_entry_uuid`
//	a record is already reported  iff some `ledger_drift_detected` names its
//	                              `event_id` as `subject_event_id`
//
// So a fresh process, a restarted one, or a newly elected leader is exactly as
// quiet as the one it replaced. Both appends also carry a deterministic
// `idempotency_key`, unique across the chain (LED-008), so two reconcilers that
// both read before either wrote produce one event and not two.
//
// Unlike ADR-0013, the dedupe key for the ledger side is the subject ALONE and
// not (subject, reason): a `commit_recorded` is immutable and a transparency
// log is append-only, so exactly one of the reasons below can ever hold for one
// subject, and keying on both would re-alert if the classification ever moved.

// DefaultSweepWindow is how many of the log's most recent entries one cycle
// examines.
//
// The window exists because the sweep has no other bound. IP §6.5 asks for
// "any Rekor entry for our trust domain with no corresponding intent", and the
// only way to find one is to read entries — there is no index from a trust
// domain to the entries signed under it. Reading the whole log every minute is
// linear in the log's lifetime, which is bearable on the self-hosted Rekor
// ADR-0010 ships as the default and is not bearable on the public one.
//
// It is deliberately a plain trailing window with NO cursor. A cursor would
// make a long-running process sweep a different range from a freshly started
// one, and "a fresh reconciler behaves identically" is the property REC-005
// and ADR-0013 both rest on — the same reason nothing else in this package is
// remembered between cycles.
//
// 1024 is four hours of one signature every fourteen seconds. The cost of the
// choice is stated rather than hidden: an entry that is more than a window old
// by the time a reconciler first looks at it is never swept, so a deployment
// whose log is its own should raise `DriftConfig.Window` to cover it, and a
// deployment coming back from a long outage should raise it once.
const DefaultSweepWindow = 1024

// The reason values of a `ledger_drift_detected` appended by this file.
//
// PROTECTED-ADJACENT, exactly as ADR-0013 records for its own: `reason` is part
// of the canonical preimage (doc 02 §4) of an event in an append-only chain,
// and it is operator-facing text. Each is a CONSTANT per kind and carries no
// uuid, commit or timestamp — what varies goes in the event's run scope and in
// the finding's Detail, which is not written to the chain.
const (
	// Doc 02 §6's golden fixture 10 is a `ledger_drift_detected` for exactly
	// this case, and this is its `reason` VERBATIM. The fixture's values are
	// illustrative rather than normative, but a shipped alert that reads
	// differently from the schema document's own example of it is a needless
	// divergence, and the sentence is the right one.
	reasonNoLogEntry   = "commit_recorded claims a Rekor entry that the log does not contain"
	reasonUnusableUUID = "the rekor_entry_uuid this commit_recorded names cannot name any " +
		"transparency log entry"
	reasonOtherArtifact = "the transparency log entry this commit_recorded names attests a " +
		"different artifact from its commit_sha"
	reasonOtherIdentity = "the transparency log entry this commit_recorded names was accepted " +
		"under a different certificate identity from its spiffe_id"
	reasonOtherLogIndex = "the transparency log entry this commit_recorded names is at a " +
		"different rekor_log_index"
)

// Idempotency-key prefixes. PROTECTED-ADJACENT for the reason in reconcile.go:
// a changed spelling makes every cycle append a second event rather than dedupe.
const (
	unattributedKeyPrefix = "reconciler:unattributed_signature_detected:"
	ledgerDriftKeyPrefix  = "reconciler:ledger_drift_detected:"
)

// UnattributedKey is the `idempotency_key` an `unattributed_signature_detected`
// carries: the log entry's uuid, which is unique in the log by construction.
func UnattributedKey(rekorEntryUUID string) string {
	return unattributedKeyPrefix + rekorEntryUUID
}

// LedgerDriftKey is the `idempotency_key` a `ledger_drift_detected` carries:
// the subject event's id, and nothing else, so it is stable across sweeps,
// processes and leaders.
func LedgerDriftKey(subjectEventID string) string {
	return ledgerDriftKeyPrefix + subjectEventID
}

// ---------------------------------------------------------------------------
// The log side, as a dependency.
// ---------------------------------------------------------------------------

// SweptEntry is one entry read off the transparency log by index or by uuid.
//
// It is LogEntry plus the artifact the entry attests. rekor.go's LogEntry omits
// that member because the join that produces it looked the entry up BY the
// artifact hash and already knows it; here nothing is known in advance, and
// REC-004's whole question is whether the artifact is the one claimed.
type SweptEntry struct {
	// UUID and LogIndex are the entry's own identifiers, and are the two
	// members doc 02 §3 puts in `unattributed_signature_detected`.
	UUID     string
	LogIndex int64
	// IntegratedAt is when the log accepted it.
	IntegratedAt time.Time
	// CertificateIdentity is the URI SAN of the certificate the entry was
	// accepted under. EMPTY when the entry carries no certificate — a segment
	// anchor's raw key (ADR-0009), or anything else that attributes nothing.
	CertificateIdentity string
	// ArtifactHash is the sha256 the entry attests, lowercase hex with no
	// prefix. EMPTY when the entry is not a sha256 hashedrekord.
	ArtifactHash string
}

// LogSweeper is the transparency log read the two ways drift detection needs.
// *RekorLog is the shipped implementation (sweep.go).
//
// It is a separate interface from TransparencyLog, and not an extension of it,
// so that a deployment can run RM-035's repair without drift detection and the
// type system says which one it has. *RekorLog satisfies both.
type LogSweeper interface {
	// TreeSize is how many entries the log holds.
	TreeSize(ctx context.Context) (int64, error)
	// EntriesFrom returns the entries at indexes [from, from+count), in index
	// order, as far as the log holds them. An index the log does not hold is
	// absent from the result; an error means the log could not be read.
	EntriesFrom(ctx context.Context, from, count int64) ([]SweptEntry, error)
	// EntryByUUID returns the entry the log holds under uuid. ErrNoEntry means
	// the log answered and holds none — including for a uuid no entry could
	// carry. Any other error means the log could not be asked.
	EntryByUUID(ctx context.Context, uuid string) (SweptEntry, error)
}

// ---------------------------------------------------------------------------
// Findings.
// ---------------------------------------------------------------------------

// DriftKind says which direction of the cross-check produced a finding, which
// is the first thing an operator needs: it names the half of the system to stop
// trusting.
type DriftKind string

const (
	// DriftUnattributedSignature: the log holds a signature under one of our
	// identities that the chain does not claim (REC-003).
	DriftUnattributedSignature DriftKind = "unattributed_signature"
	// DriftFabricatedRecord: the chain claims a signature the log does not
	// hold, or holds attesting something else (REC-004, AB-03).
	DriftFabricatedRecord DriftKind = "fabricated_commit_record"
	// DriftUnresolved: the log could not be read, so neither direction was
	// established. Alert-level and NEVER appended: "we could not tell" is not
	// recorded as "it did not happen".
	DriftUnresolved DriftKind = "unresolved"
)

// DriftFinding is one verdict, and the operator-visible half of the cross-check.
type DriftFinding struct {
	Kind DriftKind
	// The log side of the finding. Set on an unattributed signature, and on a
	// fabricated record whose named entry the log does hold.
	RekorEntryUUID      string
	RekorLogIndex       int64
	CertificateIdentity string
	// The chain side. Set on a fabricated record.
	SubjectEventID string
	RunID          string
	SPIFFEID       string
	CommitSHA      string
	// Reason is the constant that goes into a `ledger_drift_detected`, empty
	// on the other kinds.
	Reason string
	// Detail is why, in words an operator reads, with the identifiers Reason
	// deliberately leaves out.
	Detail string
	// AppendedEventID is the alert this finding produced, empty when the cycle
	// appended nothing for it.
	AppendedEventID string
}

// DriftResult is one cycle's cross-check.
type DriftResult struct {
	// Enabled is false when no Config.Drift was given. A reconciler that is
	// not watching for drift must not be mistaken for one that is.
	Enabled bool
	// SweptFrom and SweptTo are the log index range this cycle examined,
	// half-open. Equal when the log is empty or could not be read.
	SweptFrom int64
	SweptTo   int64
	// Entries is how many swept entries bore a certificate identity inside
	// this deployment's trust domain — the ones this check has standing to
	// have an opinion about.
	Entries int
	// Records is how many `commit_recorded` events the chain holds.
	Records int
	// Unattributed, Fabricated and Unresolved count the findings.
	Unattributed int
	Fabricated   int
	Unresolved   int
	// Findings is one entry per finding, log side first.
	Findings []DriftFinding
	// Appended is the event_id of each alert this cycle wrote. EMPTY on a
	// cycle over already-reported state.
	Appended []string
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

// DriftConfig turns on IP §6.5's third job. Nil in Config leaves it off.
type DriftConfig struct {
	// Sweep is the transparency log. REQUIRED: a detector that cannot read the
	// log is one that reports agreement it never checked.
	Sweep LogSweeper
	// Window is how many of the log's most recent entries one cycle examines.
	// Zero means DefaultSweepWindow.
	Window int64
	// Alert receives every finding, including the ones that were appended.
	// Defaults to an error-level slog line.
	Alert func(context.Context, DriftFinding)
}

// validate refuses a half-configured detector. A nil *DriftConfig is drift
// detection turned off, which is a choice; a DriftConfig with no log is a
// detector that would report "no drift" without looking, which is not.
func (c *DriftConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.Sweep == nil {
		return errors.New("reconciler: drift detection is configured with no transparency " +
			"log sweeper; a detector that cannot read the log reports agreement it never " +
			"checked (IP §6.10)")
	}
	if c.Window < 0 {
		return fmt.Errorf("reconciler: a drift sweep window of %d is not a window; zero means "+
			"the default of %d", c.Window, DefaultSweepWindow)
	}
	return nil
}

func (c *DriftConfig) window() int64 {
	if c.Window <= 0 {
		return DefaultSweepWindow
	}
	return c.Window
}

func (c *DriftConfig) alert(ctx context.Context, finding DriftFinding) {
	if c.Alert != nil {
		c.Alert(ctx, finding)
		return
	}
	defaultDriftAlert(ctx, finding)
}

// ---------------------------------------------------------------------------
// The ledger side of the cross-check, folded out of the same chain walk.
// ---------------------------------------------------------------------------

// recordedCommit is one `commit_recorded`, reduced to the claim REC-004 checks.
type recordedCommit struct {
	eventID   string
	runID     string
	spiffeID  string
	commitSHA string
	uuid      string
	logIndex  int64
}

// driftView is what the chain says, as far as drift detection is concerned. It
// is filled by ledgerView.observe, so the chain is walked once for both jobs.
type driftView struct {
	// records is every `commit_recorded`, in chain order: REC-004's subjects.
	records []recordedCommit
	// claimed is the set of `rekor_entry_uuid` values some `commit_recorded`
	// names. An entry in it is claimed by the chain, whatever else is true of
	// it — the ledger side is what judges whether the claim holds.
	claimed map[string]struct{}
	// reported and subjects are the two dedupe sets, read back out of the
	// chain rather than remembered.
	reported map[string]struct{}
	subjects map[string]struct{}
}

func newDriftView() *driftView {
	return &driftView{
		claimed:  map[string]struct{}{},
		reported: map[string]struct{}{},
		subjects: map[string]struct{}{},
	}
}

// observe folds one event in. It is called for EVERY event, before
// ledgerView's own switch, and skips anything it cannot read for the reason
// recorded there: a newer schema_version is a forward-compatibility case, not
// an outage of the repair.
func (v *driftView) observe(record event.Fields) {
	switch recordString(record, event.FieldEventType) {
	case event.EventTypeCommitRecorded:
		uuid := recordString(record, event.FieldRekorEntryUUID)
		if uuid != "" {
			v.claimed[uuid] = struct{}{}
		}
		eventID := recordString(record, event.FieldEventID)
		if eventID == "" {
			return
		}
		v.records = append(v.records, recordedCommit{
			eventID:   eventID,
			runID:     recordString(record, event.FieldRunID),
			spiffeID:  recordString(record, event.FieldSpiffeID),
			commitSHA: recordString(record, event.FieldCommitSHA),
			uuid:      uuid,
			logIndex:  recordInt64(record, event.FieldRekorLogIndex),
		})
	case event.EventTypeUnattributedSignatureDetected:
		if uuid := recordString(record, event.FieldRekorEntryUUID); uuid != "" {
			v.reported[uuid] = struct{}{}
		}
	case event.EventTypeLedgerDriftDetected:
		// Every `ledger_drift_detected` on the chain, whatever wrote it —
		// RM-019's SPIRE reconciliation and ADR-0009's anchorer both use this
		// type. Their subjects are `run_registered`, `run_retired` and
		// `segment_sealed` events, which are never in v.records, so a wider
		// set cannot suppress a finding of ours.
		if subject := recordString(record, event.FieldSubjectEventID); subject != "" {
			v.subjects[subject] = struct{}{}
		}
	}
}

// recordInt64 reads an integer member of a ledger record.
//
// event.ParseFields normalises every JSON number to int64 on the way out of the
// store, so that is the case that fires in a deployment; the others are for a
// record handed straight to this package without a round trip. Absent, or of no
// integer type at all, is -1 — a value doc 02 §3 does not admit for a log index
// (`checkLogIndex` floors it at 0), so it cannot be confused with a real one.
func recordInt64(record event.Fields, name string) int64 {
	switch value := record[name].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case json.Number:
		n, err := value.Int64()
		if err != nil {
			return -1
		}
		return n
	default:
		return -1
	}
}

// ---------------------------------------------------------------------------
// The cycle.
// ---------------------------------------------------------------------------

// detectDrift cross-checks the chain against the transparency log, both ways.
//
// It runs after the repairs of the same cycle, so a `commit_recorded` this
// cycle wrote is already on the chain — but the chain view was read BEFORE
// them, so a repaired entry is not yet in `view.drift.claimed`. That is why the
// open-intent grace below reads `view.open`, which is the pre-repair set: an
// entry belonging to an intent this cycle just repaired is covered by it, and
// the next cycle sees the repair itself.
// It returns no error, and that is the design rather than an omission: every
// way this cross-check can fail is a log that could not be read, which is a
// DriftUnresolved finding and an operator alert. Failing the cycle would also
// discard the repairs it already made, and would let a Rekor blip turn the
// repair component off.
func (r *Reconciler) detectDrift(ctx context.Context, view *ledgerView) DriftResult {
	if r.cfg.Drift == nil {
		return DriftResult{}
	}
	result := DriftResult{
		Enabled: true,
		Records: len(view.drift.records),
	}
	r.sweepLog(ctx, view, &result)
	r.checkRecords(ctx, view, &result)
	return result
}

// checkRecords is the CHAIN → LOG direction: REC-004, and threat model AB-03.
//
// Every `commit_recorded` on the chain asserts four things about one
// transparency-log entry — that it exists, that it attests this commit, that it
// was accepted under this run's certificate, and that it sits at this index.
// The MCP is the component that wrote them and, compromised, is free to write
// anything; what it cannot do is make the log agree, because it holds no
// signing key (E8) and the log is not its to write. So each assertion is put
// back to the log, and a disagreement is `ledger_drift_detected`.
//
// The four are checked in that order and the FIRST failure is the reason: an
// entry that attests another artifact tells an operator nothing more by also
// being at another index, and one constant reason per subject is what keeps the
// dedupe key stable.
func (r *Reconciler) checkRecords(ctx context.Context, view *ledgerView, result *DriftResult) {
	for _, record := range view.drift.records {
		if _, already := view.drift.subjects[record.eventID]; already {
			continue
		}
		reason, finding, ok := r.judge(ctx, record)
		if !ok {
			// Either the record holds up, or the log could not be asked and
			// judge has already alerted. Neither is an append.
			if finding.Kind == DriftUnresolved {
				r.unresolved(ctx, result, finding)
			}
			continue
		}
		result.Fabricated++
		body := event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeLedgerDriftDetected,
			event.FieldSource:         event.SourceReconciler,
			event.FieldIdempotencyKey: LedgerDriftKey(record.eventID),
			event.FieldSubjectEventID: record.eventID,
			event.FieldReason:         reason,
		}
		// doc 02 §2: run_id and spiffe_id are omitted TOGETHER. The subject is
		// a run's own record, so both are present and the drift feed names the
		// agent that was framed — unless the subject itself was unreadable, in
		// which case inventing a run scope would be a second falsehood on top
		// of the one being reported.
		if record.runID != "" && record.spiffeID != "" {
			body[event.FieldRunID] = record.runID
			body[event.FieldSpiffeID] = record.spiffeID
		}
		r.appendDriftAlert(ctx, result, finding, body)
	}
}

// judge asks the log about one record. It appends nothing and decides nothing
// about outages beyond refusing to call them findings.
//
// The three returns: the `reason` constant for the chain, the finding for the
// operator, and whether this is drift at all. A record that holds up returns
// false with a zero finding; a log that could not be asked returns false with a
// DriftUnresolved finding, already alerted by nobody — the caller records it.
func (r *Reconciler) judge(ctx context.Context, record recordedCommit) (string, DriftFinding, bool) {
	finding := DriftFinding{
		Kind:           DriftFabricatedRecord,
		SubjectEventID: record.eventID,
		RunID:          record.runID,
		SPIFFEID:       record.spiffeID,
		CommitSHA:      record.commitSHA,
		RekorEntryUUID: record.uuid,
		RekorLogIndex:  record.logIndex,
	}

	// A uuid no Rekor entry could carry is answered WITHOUT asking the log.
	// rekor-server refuses such a value with HTTP 422, which every reader in
	// this package is required to treat as an outage, and an outage suppresses
	// the finding — so an attacker who wrote a malformed uuid would buy
	// permanent silence with a typo. The reader has the same guard for its own
	// callers; this one is here because the ANSWER is a finding, and findings
	// are decided in this file.
	if !IsRekorEntryUUID(record.uuid) {
		finding.Reason = reasonUnusableUUID
		finding.Detail = fmt.Sprintf(
			"commit_recorded %s names %q as its rekor_entry_uuid. A rekor entry uuid is 64 or "+
				"80 hex characters, so no entry in any transparency log can carry that value "+
				"and the claim cannot be checked by anyone, ever (I5)",
			record.eventID, record.uuid)
		return finding.Reason, finding, true
	}

	entry, err := r.cfg.Drift.Sweep.EntryByUUID(ctx, record.uuid)
	switch {
	case errors.Is(err, ErrNoEntry):
		finding.Reason = reasonNoLogEntry
		finding.Detail = fmt.Sprintf(
			"commit_recorded %s says run %s signed commit %s and that the transparency log "+
				"holds entry %s for it at index %d. The log holds no such entry. A record with "+
				"no entry behind it is a claim this system made about itself and nothing else "+
				"can check (IP §6.10, AB-03): %v",
			record.eventID, record.runID, record.commitSHA, record.uuid, record.logIndex, err)
		return finding.Reason, finding, true
	case err != nil:
		return "", DriftFinding{
			Kind:           DriftUnresolved,
			SubjectEventID: record.eventID,
			RunID:          record.runID,
			SPIFFEID:       record.spiffeID,
			CommitSHA:      record.commitSHA,
			RekorEntryUUID: record.uuid,
			Detail: fmt.Sprintf(
				"the transparency log could not be asked about entry %s, which commit_recorded "+
					"%s names, so the record is neither confirmed nor contradicted this cycle "+
					"and nothing is written: %v", record.uuid, record.eventID, err),
		}, false
	}

	// The entry exists. Now the three things it must agree with. Order is the
	// reason's: the first disagreement is the finding.
	finding.RekorEntryUUID = entry.UUID
	finding.CertificateIdentity = entry.CertificateIdentity
	switch {
	case entry.ArtifactHash != artifactHashOf(record.commitSHA):
		finding.Reason = reasonOtherArtifact
		finding.Detail = fmt.Sprintf(
			"commit_recorded %s names entry %s as the signature of commit %s, whose artifact "+
				"hash is sha256:%s. The log holds that entry attesting sha256:%s. The entry is "+
				"real and it is not this commit's",
			record.eventID, entry.UUID, record.commitSHA,
			artifactHashOf(record.commitSHA), entry.ArtifactHash)
	case entry.CertificateIdentity != record.spiffeID:
		finding.Reason = reasonOtherIdentity
		finding.Detail = fmt.Sprintf(
			"commit_recorded %s attributes commit %s to %s, and the log accepted entry %s "+
				"under a certificate naming %q. The signature is real and it is not this run's",
			record.eventID, record.commitSHA, record.spiffeID, entry.UUID,
			entry.CertificateIdentity)
	case entry.LogIndex != record.logIndex:
		finding.Reason = reasonOtherLogIndex
		finding.Detail = fmt.Sprintf(
			"commit_recorded %s says entry %s is at log index %d and the log holds it at %d; "+
				"the recorded index does not name the entry the record names",
			record.eventID, entry.UUID, record.logIndex, entry.LogIndex)
	default:
		return "", DriftFinding{}, false
	}
	return finding.Reason, finding, true
}

// artifactHashOf is the join Rekor indexes a gitsign commit signature under:
// the entry's artifact is sha256 of the commit's hex object id, which is what
// rekor.go's EntryForCommit searches by and what internal/signing proves an
// entry belongs to a commit with (ADR-0031 decision 6).
func artifactHashOf(commitSHA string) string {
	sum := sha256.Sum256([]byte(commitSHA))
	return hex.EncodeToString(sum[:])
}

// sweepLog is the LOG → CHAIN direction: REC-003.
func (r *Reconciler) sweepLog(ctx context.Context, view *ledgerView, result *DriftResult) {
	size, err := r.cfg.Drift.Sweep.TreeSize(ctx)
	if err != nil {
		r.unresolved(ctx, result, DriftFinding{
			Kind: DriftUnresolved,
			Detail: fmt.Sprintf("the transparency log's size could not be read, so no "+
				"unattributed signature can be established this cycle: %v", err),
		})
		return
	}
	if size <= 0 {
		return
	}
	window := r.cfg.Drift.window()
	from := max(size-window, 0)
	result.SweptFrom, result.SweptTo = from, size

	entries, err := r.cfg.Drift.Sweep.EntriesFrom(ctx, from, size-from)
	if err != nil {
		result.SweptFrom, result.SweptTo = 0, 0
		r.unresolved(ctx, result, DriftFinding{
			Kind: DriftUnresolved,
			Detail: fmt.Sprintf("log indexes %d..%d could not be read, so an entry with no "+
				"intent among them would go unreported this cycle: %v", from, size-1, err),
		})
		return
	}

	// A run holding an OPEN intent may have a signature the chain has not
	// recorded yet — that is REC-002's window, not a compromise.
	inflight := map[string]struct{}{}
	for _, intent := range view.open {
		inflight[intent.spiffeID] = struct{}{}
	}

	for _, entry := range entries {
		if !r.ours(entry.CertificateIdentity) {
			continue
		}
		result.Entries++
		if _, claimed := view.drift.claimed[entry.UUID]; claimed {
			continue
		}
		if _, open := inflight[entry.CertificateIdentity]; open {
			continue
		}
		if _, already := view.drift.reported[entry.UUID]; already {
			continue
		}
		finding := DriftFinding{
			Kind:                DriftUnattributedSignature,
			RekorEntryUUID:      entry.UUID,
			RekorLogIndex:       entry.LogIndex,
			CertificateIdentity: entry.CertificateIdentity,
			Detail: fmt.Sprintf("the transparency log holds entry %s at index %d, accepted at "+
				"%s under a certificate naming %s, and no commit_recorded on this chain claims "+
				"it and no intent of that run is open: a signature was made with one of this "+
				"deployment's identities and the ledger was never told",
				entry.UUID, entry.LogIndex, entry.IntegratedAt.Format(time.RFC3339),
				entry.CertificateIdentity),
		}
		result.Unattributed++
		r.appendDriftAlert(ctx, result, finding, event.Fields{
			event.FieldSchemaVersion:       event.SchemaVersion,
			event.FieldEventType:           event.EventTypeUnattributedSignatureDetected,
			event.FieldSource:              event.SourceReconciler,
			event.FieldIdempotencyKey:      UnattributedKey(entry.UUID),
			event.FieldRekorEntryUUID:      entry.UUID,
			event.FieldRekorLogIndex:       entry.LogIndex,
			event.FieldCertificateIdentity: entry.CertificateIdentity,
		})
	}
}

// unresolved records and alerts a finding that must never reach the chain.
func (r *Reconciler) unresolved(ctx context.Context, result *DriftResult, finding DriftFinding) {
	result.Unresolved++
	result.Findings = append(result.Findings, finding)
	r.cfg.Drift.alert(ctx, finding)
}

// appendDriftAlert writes one alert and records what happened.
//
// An append whose idempotency_key is already spent returns the earlier event
// and writes nothing (LED-008) — that is what makes two concurrent reconcilers
// harmless — and is reported as an empty AppendedEventID rather than counted as
// a write. A ledger that REFUSED the append is not allowed to silence the
// finding: I3 admits no action without a record, and an alert nobody can record
// is still an alert somebody must see, so the operator sink is told either way.
func (r *Reconciler) appendDriftAlert(
	ctx context.Context, result *DriftResult, finding DriftFinding, body event.Fields,
) {
	record, err := r.cfg.Appender.Append(ctx, body)
	switch {
	case err != nil:
		finding.Detail += fmt.Sprintf("; and this alert could not be appended to the chain: %v", err)
	case recordString(record, event.FieldEventType) != recordString(body, event.FieldEventType):
		finding.Detail += fmt.Sprintf("; and the idempotency key %q names a %s rather than this alert",
			recordString(body, event.FieldIdempotencyKey),
			recordString(record, event.FieldEventType))
	default:
		finding.AppendedEventID = recordString(record, event.FieldEventID)
	}
	result.Findings = append(result.Findings, finding)
	if finding.AppendedEventID != "" {
		result.Appended = append(result.Appended, finding.AppendedEventID)
	}
	r.cfg.Drift.alert(ctx, finding)
}

// defaultDriftAlert is the sink a deployment gets if it names none.
//
// Error level, unconditionally. doc 05 §4 lists reconciler drift alerts among
// the monitoring minimums, and both kinds here are IP §6.5's word for it:
// "that is either a bug or a compromise, and it must be loud".
func defaultDriftAlert(ctx context.Context, finding DriftFinding) {
	slog.ErrorContext(ctx, "transparency log cross-check: drift",
		"kind", string(finding.Kind),
		"rekor_entry_uuid", finding.RekorEntryUUID,
		"rekor_log_index", finding.RekorLogIndex,
		"certificate_identity", finding.CertificateIdentity,
		"subject_event_id", finding.SubjectEventID,
		"run_id", finding.RunID,
		"commit_sha", finding.CommitSHA,
		"appended_event_id", finding.AppendedEventID,
		"detail", finding.Detail)
}

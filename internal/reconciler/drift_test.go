// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// RM-036 (#44). The two test IDs this file drives, from doc 07:
//
//	REC-003  A Rekor entry for our trust domain with no intent, planted, raises
//	         `unattributed_signature_detected` within one reconciler cycle.
//	REC-004  A fabricated `commit_recorded` with no Rekor entry raises
//	         `ledger_drift_detected`. This is threat model AB-03 — "compromised
//	         MCP fabricates commit_recorded to frame an agent" — and it is the
//	         evidence for IP §6.10's claim that the worst case of a fully
//	         compromised MCP is fake EVENTS, "which the reconciler's Rekor
//	         cross-check surfaces as drift".
//
// The real signature, the real certificate, the real log entry and the real
// chain are in driftintegration_test.go: IP §2 — "a mocked Fulcio proves
// nothing about I5", and a mocked Rekor cannot prove REC-004. What is here is
// the decision logic, exercised over states a real stack cannot be driven into
// on demand: a log that cannot be read, an entry attesting another artifact, a
// certificate from another trust domain.
//
// # The negative control, and why it is the most important case in the file
//
// "Drift was detected" passes for a detector that alerts on everything, and an
// always-firing alert is the same as no alert. So
// TestDriftRaisesNothingOnALegitimateSignedCommit asserts the EMPTY finding
// set over a chain whose intent, signature and record are all real and all
// agree — and it bites: deleting the "some commit_recorded claims this entry"
// check in drift.go makes it fail, which was measured rather than assumed.

// ---------------------------------------------------------------------------
// The log-side fake. Replaced by a real Rekor in the integration case.
// ---------------------------------------------------------------------------

type fakeSweep struct {
	// entries is the log, in index order. Position i has LogIndex i.
	entries []reconciler.SweptEntry
	// treeErr, sweepErr and uuidErr make the log UNREADABLE, which is a
	// different answer from an empty log and must never become an alert.
	treeErr  error
	sweepErr error
	uuidErr  error

	treeCalls  int
	rangeCalls int
	uuidCalls  int
}

func (f *fakeSweep) TreeSize(context.Context) (int64, error) {
	f.treeCalls++
	if f.treeErr != nil {
		return 0, f.treeErr
	}
	return int64(len(f.entries)), nil
}

func (f *fakeSweep) EntriesFrom(_ context.Context, from, count int64) ([]reconciler.SweptEntry, error) {
	f.rangeCalls++
	if f.sweepErr != nil {
		return nil, f.sweepErr
	}
	var out []reconciler.SweptEntry
	for _, e := range f.entries {
		if e.LogIndex >= from && e.LogIndex < from+count {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeSweep) EntryByUUID(_ context.Context, uuid string) (reconciler.SweptEntry, error) {
	f.uuidCalls++
	if f.uuidErr != nil {
		return reconciler.SweptEntry{}, f.uuidErr
	}
	for _, e := range f.entries {
		if e.UUID == uuid {
			return e, nil
		}
	}
	return reconciler.SweptEntry{}, fmt.Errorf("%w: %s", reconciler.ErrNoEntry, uuid)
}

// ---------------------------------------------------------------------------
// A chain plus a log, seeded together.
// ---------------------------------------------------------------------------

const (
	driftRunID    = "run-drift"
	driftTree     = "3f2b1c8d4e5a6079182b3c4d5e6f708192a3b4c5"
	driftCommit   = "8ac0d2e4f6081a2b3c4d5e6f708192a3b4c5d6e7"
	plantedRunID  = "run-planted"
	plantedCommit = "1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e"
)

// artifactOf is the join Rekor indexes a gitsign commit signature under: the
// entry's artifact is sha256 of the commit's hex object id.
func artifactOf(commitSHA string) string {
	sum := sha256.Sum256([]byte(commitSHA))
	return hex.EncodeToString(sum[:])
}

// rekorUUIDOf is a syntactically valid Rekor entry uuid (64 hex) derived from
// a label, so a fixture's uuids are distinct and shaped like the real thing.
func rekorUUIDOf(label string) string {
	sum := sha256.Sum256([]byte("rekor-uuid/" + label))
	return hex.EncodeToString(sum[:])
}

type driftFixture struct {
	clock  *clock
	ledger *memLedger
	sweep  *fakeSweep
	// alerts collects every finding the sink saw, so an alert raised WITHOUT
	// an append is still observable.
	alerts []reconciler.DriftFinding
}

func newDriftFixture(t *testing.T) *driftFixture {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)}
	return &driftFixture{
		clock:  c,
		ledger: newMemLedger(c.now),
		sweep:  &fakeSweep{},
	}
}

// detector builds a FRESH reconciler with drift detection on. Every call
// returns a new one: the dedupe key must come back out of the chain, not out
// of a field this process happens to still hold (RM-019's standard, REC-005's).
func (f *driftFixture) detector(t *testing.T) *reconciler.Reconciler {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		// Long enough that no fixture's intent can expire; REC-001 is not this
		// file's subject and an expiry here would be noise in the diff.
		ExpireAfter: 24 * time.Hour,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Drift: &reconciler.DriftConfig{
			Sweep: f.sweep,
			Alert: func(_ context.Context, d reconciler.DriftFinding) {
				f.alerts = append(f.alerts, d)
			},
		},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	return r
}

func (f *driftFixture) cycle(t *testing.T) reconciler.Result {
	t.Helper()
	f.alerts = nil
	result, err := f.detector(t).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result
}

// plantEntry puts one entry in the log and nothing in the chain. That is
// REC-003's whole premise: a signature nobody claimed.
func (f *driftFixture) plantEntry(identity, commitSHA, label string) reconciler.SweptEntry {
	entry := reconciler.SweptEntry{
		UUID:                rekorUUIDOf(label),
		LogIndex:            int64(len(f.sweep.entries)),
		IntegratedAt:        f.clock.at,
		CertificateIdentity: identity,
		ArtifactHash:        artifactOf(commitSHA),
	}
	f.sweep.entries = append(f.sweep.entries, entry)
	return entry
}

// recordCommit appends a `commit_recorded` naming an intent, a commit and a
// log entry. Nothing here checks that any of the three exist — which is the
// point: this is the append a compromised MCP is free to make (IP §6.10).
func (f *driftFixture) recordCommit(t *testing.T, runID, intentID, commitSHA, uuid string, index int64) event.Fields {
	t.Helper()
	record, err := f.ledger.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/recorded/" + runID,
		event.FieldRepo:           testRepo,
		event.FieldTreeHash:       driftTree,
		event.FieldCommitSHA:      commitSHA,
		event.FieldRekorEntryUUID: uuid,
		event.FieldRekorLogIndex:  index,
		event.FieldIntentEventID:  intentID,
	})
	if err != nil {
		t.Fatalf("append commit_recorded: %v", err)
	}
	return record
}

// legitimate seeds the state a run that worked leaves behind: a registered
// run, an intent, a real log entry under that run's identity, and a
// `commit_recorded` naming that entry. It is the negative control's subject.
func (f *driftFixture) legitimate(t *testing.T) (record event.Fields, entry reconciler.SweptEntry) {
	t.Helper()
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	entry = f.plantEntry(spiffeIDFor(driftRunID), driftCommit, "legit")
	record = f.recordCommit(t, driftRunID,
		str(intent, event.FieldEventID), driftCommit, entry.UUID, entry.LogIndex)
	return record, entry
}

// ---------------------------------------------------------------------------
// Reading the alerts back off the chain.
// ---------------------------------------------------------------------------

func (f *driftFixture) eventsOf(t *testing.T, eventType string) []event.Fields {
	t.Helper()
	n, err := f.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	all, err := f.ledger.Events(context.Background(), 1, n)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	var out []event.Fields
	for _, rec := range all {
		if str(rec, event.FieldEventType) == eventType {
			out = append(out, rec)
		}
	}
	return out
}

func (f *driftFixture) onlyEventOf(t *testing.T, eventType string) event.Fields {
	t.Helper()
	got := f.eventsOf(t, eventType)
	if len(got) != 1 {
		t.Fatalf("the chain holds %d %s events, want exactly 1: %v",
			len(got), eventType, f.ledger.types())
	}
	return got[0]
}

// ---------------------------------------------------------------------------
// REC-003.
// ---------------------------------------------------------------------------

func TestREC003AnUnclaimedTrustDomainSignatureRaisesAnUnattributedAlert(t *testing.T) {
	f := newDriftFixture(t)
	// A signature under an identity of OUR trust domain, and a chain that has
	// never heard of the run. Nothing claims it: no intent, no record.
	planted := f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")

	result := f.cycle(t)

	if result.Drift.Unattributed != 1 {
		t.Fatalf("one cycle over a planted entry found %d unattributed signatures, want 1; findings %+v",
			result.Drift.Unattributed, result.Drift.Findings)
	}
	alert := f.onlyEventOf(t, event.EventTypeUnattributedSignatureDetected)
	if got := str(alert, event.FieldRekorEntryUUID); got != planted.UUID {
		t.Errorf("the alert names entry %q, want %q", got, planted.UUID)
	}
	if got := member[int64](t, alert, event.FieldRekorLogIndex); got != planted.LogIndex {
		t.Errorf("the alert names log index %d, want %d", got, planted.LogIndex)
	}
	if got := str(alert, event.FieldCertificateIdentity); got != planted.CertificateIdentity {
		t.Errorf("the alert names identity %q, want %q", got, planted.CertificateIdentity)
	}
	if got := str(alert, event.FieldSource); got != event.SourceReconciler {
		t.Errorf("the alert carries source %q, want %q", got, event.SourceReconciler)
	}
	// doc 02 §2: run_id and spiffe_id are omitted for "system-scope alerts that
	// reference no run". A signature nobody claimed references no run OF OURS,
	// and inventing one would put a false statement in an append-only chain.
	if _, present := alert[event.FieldRunID]; present {
		t.Errorf("the alert carries a run_id; the chain has never heard of this identity")
	}
	if _, present := alert[event.FieldSpiffeID]; present {
		t.Errorf("the alert carries a spiffe_id; the chain has never heard of this identity")
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != reconciler.DriftUnattributedSignature {
		t.Errorf("the operator sink saw %+v, want one unattributed-signature finding", f.alerts)
	}
}

func TestREC003IgnoresAnEntryFromAnotherTrustDomain(t *testing.T) {
	f := newDriftFixture(t)
	f.plantEntry("spiffe://example.org/agent/demo/rm-036/other", plantedCommit, "foreign")

	result := f.cycle(t)

	if result.Drift.Unattributed != 0 || len(f.eventsOf(t, event.EventTypeUnattributedSignatureDetected)) != 0 {
		t.Fatalf("a certificate from another trust domain raised %d alerts; IP §6.5 scopes "+
			"the sweep to OUR trust domain and an alert on every stranger's signature is "+
			"an alert nobody reads", result.Drift.Unattributed)
	}
}

func TestREC003LeavesAnEntryAloneWhileTheRunsIntentIsStillOpen(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	seedIntent(t, f.ledger, driftRunID, driftTree)
	// The B → C window: the signature exists and the record does not, YET.
	f.plantEntry(spiffeIDFor(driftRunID), driftCommit, "inflight")

	result := f.cycle(t)

	if result.Drift.Unattributed != 0 {
		t.Fatalf("an entry whose run still holds an OPEN intent was called unattributed; "+
			"that is REC-002's repair window, not a compromise: %+v", result.Drift.Findings)
	}
}

// ---------------------------------------------------------------------------
// REC-004 — threat model AB-03.
// ---------------------------------------------------------------------------

func TestREC004AFabricatedCommitRecordWithNoLogEntryRaisesLedgerDrift(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	// The compromised MCP's whole capability (E8: it holds no signing keys).
	// It writes a record. It cannot write a Rekor entry, and it did not.
	fabricated := f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, rekorUUIDOf("fabricated"), 41)

	result := f.cycle(t)

	if result.Drift.Fabricated != 1 {
		t.Fatalf("one cycle over a fabricated commit_recorded found %d fabricated records, "+
			"want 1; findings %+v", result.Drift.Fabricated, result.Drift.Findings)
	}
	drift := f.onlyEventOf(t, event.EventTypeLedgerDriftDetected)
	if got := str(drift, event.FieldSubjectEventID); got != str(fabricated, event.FieldEventID) {
		t.Errorf("the drift event names subject %q, want the fabricated record %q",
			got, str(fabricated, event.FieldEventID))
	}
	if got := str(drift, event.FieldReason); got == "" {
		t.Errorf("the drift event carries no reason")
	} else if got != "commit_recorded claims a Rekor entry that the log does not contain" {
		// doc 02 §6, golden fixture 10's own `reason` for this exact case.
		t.Errorf("the reason is %q, not doc 02 fixture 10's", got)
	}
	if got := str(drift, event.FieldSource); got != event.SourceReconciler {
		t.Errorf("the drift event carries source %q, want %q", got, event.SourceReconciler)
	}
	// The subject IS a run's record, so the alert carries that run — an
	// operator reading the drift feed learns which agent was framed.
	if got := str(drift, event.FieldRunID); got != driftRunID {
		t.Errorf("the drift event names run %q, want %q", got, driftRunID)
	}
	if got := str(drift, event.FieldSpiffeID); got != spiffeIDFor(driftRunID) {
		t.Errorf("the drift event names identity %q, want %q", got, spiffeIDFor(driftRunID))
	}
	if len(f.alerts) != 1 || f.alerts[0].Kind != reconciler.DriftFabricatedRecord {
		t.Errorf("the operator sink saw %+v, want one fabricated-record finding", f.alerts)
	}
}

func TestREC004FlagsARecordNamingAnEntryForAnotherArtifact(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	// A REAL entry, under this run's own certificate — for a different commit.
	// Pointing a fabricated record at somebody's real entry is the obvious
	// next move once "no entry at all" is detected.
	entry := f.plantEntry(spiffeIDFor(driftRunID), plantedCommit, "elsewhere")
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, entry.UUID, entry.LogIndex)

	result := f.cycle(t)

	if result.Drift.Fabricated != 1 {
		t.Fatalf("a record naming an entry for another commit found %d fabricated records, "+
			"want 1; findings %+v", result.Drift.Fabricated, result.Drift.Findings)
	}
	drift := f.onlyEventOf(t, event.EventTypeLedgerDriftDetected)
	if got := str(drift, event.FieldReason); !strings.Contains(got, "artifact") {
		t.Errorf("the reason %q does not name the artifact mismatch", got)
	}
}

func TestREC004FlagsARecordWhoseEntryAttributesAnotherIdentity(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	// The right commit, in the log, under SOMEBODY ELSE'S certificate: the
	// record claims this run signed what another identity signed.
	entry := f.plantEntry(spiffeIDFor(plantedRunID), driftCommit, "otherid")
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, entry.UUID, entry.LogIndex)

	result := f.cycle(t)

	if result.Drift.Fabricated != 1 {
		t.Fatalf("a record whose entry names another identity found %d fabricated records, "+
			"want 1; findings %+v", result.Drift.Fabricated, result.Drift.Findings)
	}
	drift := f.onlyEventOf(t, event.EventTypeLedgerDriftDetected)
	if got := str(drift, event.FieldReason); !strings.Contains(got, "identity") {
		t.Errorf("the reason %q does not name the identity mismatch", got)
	}
}

func TestREC004FlagsARecordWhoseEntryIsAtAnotherLogIndex(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	entry := f.plantEntry(spiffeIDFor(driftRunID), driftCommit, "index")
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, entry.UUID, entry.LogIndex+7)

	result := f.cycle(t)

	if result.Drift.Fabricated != 1 {
		t.Fatalf("a record naming the wrong log index found %d fabricated records, want 1; %+v",
			result.Drift.Fabricated, result.Drift.Findings)
	}
	drift := f.onlyEventOf(t, event.EventTypeLedgerDriftDetected)
	if got := str(drift, event.FieldReason); !strings.Contains(got, "index") {
		t.Errorf("the reason %q does not name the log index mismatch", got)
	}
}

func TestREC004FlagsARecordWhoseEntryUUIDCannotNameAnyEntry(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	// Rekor entry uuids are 64 or 80 hex characters. A record naming anything
	// else names nothing, and the log must not even be asked — Rekor answers a
	// malformed uuid with HTTP 422, which a reader could mistake for an outage.
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, "not-a-rekor-uuid", 3)

	result := f.cycle(t)

	if result.Drift.Fabricated != 1 {
		t.Fatalf("a record naming an impossible uuid found %d fabricated records, want 1; %+v",
			result.Drift.Fabricated, result.Drift.Findings)
	}
	if f.sweep.uuidCalls != 0 {
		t.Errorf("the log was asked about an impossible uuid %d times, want 0", f.sweep.uuidCalls)
	}
}

// ---------------------------------------------------------------------------
// THE NEGATIVE CONTROL. A detector that alerts on everything passes every case
// above; this is the one it cannot pass.
// ---------------------------------------------------------------------------

func TestDriftRaisesNothingOnALegitimateSignedCommit(t *testing.T) {
	f := newDriftFixture(t)
	record, entry := f.legitimate(t)

	before, err := f.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	result := f.cycle(t)
	after, err := f.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	// Everything real, everything agreeing: the entry is in the log under this
	// run's certificate, the record names that entry, and the record names the
	// commit the entry attests.
	if len(result.Drift.Findings) != 0 {
		t.Fatalf("drift detection raised %d findings about a legitimate signed commit "+
			"(record %s, entry %s): %+v — a detector that alerts on everything detects "+
			"nothing", len(result.Drift.Findings),
			str(record, event.FieldEventID), entry.UUID, result.Drift.Findings)
	}
	if len(result.Drift.Appended) != 0 || after != before {
		t.Fatalf("drift detection appended %v and grew the chain from %d to %d",
			result.Drift.Appended, before, after)
	}
	if len(f.alerts) != 0 {
		t.Fatalf("drift detection alerted an operator about a legitimate commit: %+v", f.alerts)
	}
	// And it did LOOK: an assertion about zero findings from a detector that
	// never ran would pass for the wrong reason.
	if result.Drift.Entries != 1 || result.Drift.Records != 1 {
		t.Fatalf("the cycle examined %d log entries and %d records, want 1 and 1 — "+
			"zero findings from a detector that examined nothing proves nothing",
			result.Drift.Entries, result.Drift.Records)
	}
	if !result.Drift.Enabled {
		t.Fatal("Result.Drift.Enabled is false with a DriftConfig configured")
	}
}

// ---------------------------------------------------------------------------
// Idempotency, across a FRESH process.
// ---------------------------------------------------------------------------

func TestDriftIsIdempotentAcrossAFreshReconciler(t *testing.T) {
	f := newDriftFixture(t)
	f.legitimate(t)
	f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")
	seedRun(t, f.ledger, "run-framed")
	framedIntent := seedIntent(t, f.ledger, "run-framed", driftTree)
	f.recordCommit(t, "run-framed", str(framedIntent, event.FieldEventID),
		"c0ffee0011223344556677889900aabbccddeeff", rekorUUIDOf("nothing"), 99)

	first := f.cycle(t)
	if first.Drift.Unattributed != 1 || first.Drift.Fabricated != 1 {
		t.Fatalf("the first cycle found %d unattributed and %d fabricated, want 1 and 1: %+v",
			first.Drift.Unattributed, first.Drift.Fabricated, first.Drift.Findings)
	}
	afterFirst, err := f.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	// A brand-new reconciler, over the same state. Nothing is remembered: the
	// dedupe key is read back out of the chain.
	second := f.cycle(t)
	afterSecond, err := f.ledger.Count(context.Background())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	if len(second.Drift.Appended) != 0 {
		t.Fatalf("a fresh second reconciler appended %v", second.Drift.Appended)
	}
	if afterSecond != afterFirst {
		t.Fatalf("the second cycle grew the chain from %d to %d", afterFirst, afterSecond)
	}
	if len(f.eventsOf(t, event.EventTypeUnattributedSignatureDetected)) != 1 {
		t.Fatalf("the chain holds %d unattributed_signature_detected events, want 1",
			len(f.eventsOf(t, event.EventTypeUnattributedSignatureDetected)))
	}
	if len(f.eventsOf(t, event.EventTypeLedgerDriftDetected)) != 1 {
		t.Fatalf("the chain holds %d ledger_drift_detected events, want 1",
			len(f.eventsOf(t, event.EventTypeLedgerDriftDetected)))
	}
	if len(second.Drift.Findings) != 0 {
		t.Fatalf("the second cycle re-reported %+v", second.Drift.Findings)
	}
}

// ---------------------------------------------------------------------------
// The two directions are different findings.
// ---------------------------------------------------------------------------

func TestDriftSaysWhichSideIsCompromised(t *testing.T) {
	f := newDriftFixture(t)
	f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, rekorUUIDOf("absent"), 12)

	result := f.cycle(t)

	if len(result.Drift.Findings) != 2 {
		t.Fatalf("want two findings, got %+v", result.Drift.Findings)
	}
	kinds := map[reconciler.DriftKind]bool{}
	for _, d := range result.Drift.Findings {
		kinds[d.Kind] = true
	}
	if !kinds[reconciler.DriftUnattributedSignature] || !kinds[reconciler.DriftFabricatedRecord] {
		t.Fatalf("the two findings are not distinguished: %+v", result.Drift.Findings)
	}
	// A signature nobody claimed is a possible compromise OF AN AGENT; a claim
	// nobody signed is a possible compromise OF THE MCP. Two event types, and
	// the chain says which.
	if n := len(f.eventsOf(t, event.EventTypeUnattributedSignatureDetected)); n != 1 {
		t.Errorf("the chain holds %d unattributed_signature_detected events, want 1", n)
	}
	if n := len(f.eventsOf(t, event.EventTypeLedgerDriftDetected)); n != 1 {
		t.Errorf("the chain holds %d ledger_drift_detected events, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// "We could not tell" is never recorded as "it did not happen".
// ---------------------------------------------------------------------------

func TestDriftRecordsNothingWhenTheLogCannotBeSwept(t *testing.T) {
	f := newDriftFixture(t)
	f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")
	f.sweep.sweepErr = errors.New("rekor is down")

	result := f.cycle(t)

	if len(result.Drift.Appended) != 0 {
		t.Fatalf("an unreadable log produced appends %v", result.Drift.Appended)
	}
	if result.Drift.Unresolved == 0 {
		t.Fatal("an unreadable log was not reported as unresolved")
	}
	if len(f.alerts) == 0 {
		t.Fatal("an unreadable log raised no operator alert")
	}
}

func TestDriftRecordsNothingWhenTheTreeSizeCannotBeRead(t *testing.T) {
	f := newDriftFixture(t)
	f.sweep.treeErr = errors.New("rekor is down")

	result := f.cycle(t)

	if len(result.Drift.Appended) != 0 {
		t.Fatalf("an unreadable log produced appends %v", result.Drift.Appended)
	}
	if result.Drift.Unresolved == 0 {
		t.Fatal("an unreadable tree size was not reported as unresolved")
	}
}

func TestDriftRecordsNothingWhenTheRecordsEntryCannotBeFetched(t *testing.T) {
	f := newDriftFixture(t)
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, rekorUUIDOf("unreachable"), 5)
	f.sweep.uuidErr = errors.New("rekor is down")

	result := f.cycle(t)

	if result.Drift.Fabricated != 0 {
		t.Fatalf("a log that could not be asked was recorded as a log that answered no: %+v",
			result.Drift.Findings)
	}
	if len(f.eventsOf(t, event.EventTypeLedgerDriftDetected)) != 0 {
		t.Fatal("a ledger_drift_detected was appended on an outage; I4 makes that permanent")
	}
	if result.Drift.Unresolved == 0 {
		t.Fatal("the outage was not reported as unresolved")
	}
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

func TestDriftIsOffAndSaysSoWhenNoSweeperIsConfigured(t *testing.T) {
	f := newDriftFixture(t)
	f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")

	r, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Drift.Enabled {
		t.Fatal("Result.Drift.Enabled is true with no DriftConfig; a reconciler that is not " +
			"watching for drift must not report that it is")
	}
	if len(result.Drift.Findings) != 0 {
		t.Fatalf("an unconfigured detector produced findings %+v", result.Drift.Findings)
	}
}

func TestDriftConfigWithoutASweeperIsRefused(t *testing.T) {
	f := newDriftFixture(t)
	_, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Drift:       &reconciler.DriftConfig{},
	})
	if err == nil {
		t.Fatal("a DriftConfig with no sweeper was accepted; a detector that cannot read " +
			"the log is one that reports agreement it never checked")
	}
}

// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// The three test IDs this file drives, from doc 07:
//
//	REC-001  Crash between Phase A and B → the dangling intent expires after
//	         the window and `commit_intent_expired` is appended.
//	REC-002  Crash between Phase B and C → the Rekor certificate is matched to
//	         the intent and `commit_recorded` is appended with source
//	         `reconciler`. The state-diff half runs against a real Fulcio,
//	         Rekor, Postgres and signed commit in integration_test.go: IP §2 —
//	         "a mocked Fulcio proves nothing about I5".
//	REC-005  A second run over the same state appends nothing, proved with a
//	         FRESH reconciler so the dedupe key comes out of the chain.

// clock is a settable time source shared by the ledger and the reconciler.
type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

// fixture is one seeded chain plus the two external halves.
type fixture struct {
	clock  *clock
	ledger *memLedger
	repos  *fakeRepos
	log    *fakeLog
	intent event.Fields
	runID  string
}

func newFixture(t *testing.T, runID, tree string) *fixture {
	t.Helper()
	c := &clock{at: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, runID)
	intent := seedIntent(t, m, runID, tree)
	return &fixture{
		clock:  c,
		ledger: m,
		repos:  &fakeRepos{commits: map[string]map[string][]string{}},
		log:    &fakeLog{entries: map[string]reconciler.LogEntry{}},
		intent: intent,
		runID:  runID,
	}
}

// reconciler builds a FRESH reconciler over the fixture's state. Every call
// returns a new one: REC-005 is only meaningful if the dedupe key is read back
// out of the chain rather than remembered between cycles.
func (f *fixture) reconciler(t *testing.T, expireAfter time.Duration) *reconciler.Reconciler {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       f.repos,
		Log:         f.log,
		TrustDomain: testTrustDomain,
		ExpireAfter: expireAfter,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	return r
}

func (f *fixture) reconcile(t *testing.T, expireAfter time.Duration) reconciler.Result {
	t.Helper()
	result, err := f.reconciler(t, expireAfter).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result
}

// signIt puts a signed commit in the repo and its entry in the log, under the
// run's own certificate identity — the B → C residue, in the two places the
// reconciler is allowed to look.
func (f *fixture) signIt(commitSHA, tree, certIdentity string) {
	if f.repos.commits[testRepo] == nil {
		f.repos.commits[testRepo] = map[string][]string{}
	}
	f.repos.commits[testRepo][tree] = append(f.repos.commits[testRepo][tree], commitSHA)
	f.log.entries[commitSHA] = reconciler.LogEntry{
		UUID:                "a8f225deef100e2a3cfd330abe728a747cdb5363e3d69433eda3930091c69909",
		LogIndex:            148203377,
		IntegratedAt:        f.clock.at,
		CertificateIdentity: certIdentity,
	}
}

// ---------------------------------------------------------------------------
// REC-001 — the A → B window.
// ---------------------------------------------------------------------------

func TestREC001ADanglingIntentExpiresOnlyAfterTheBoundedWindow(t *testing.T) {
	f := newFixture(t, "run-rec001", testTree)
	intentID := member[string](t, f.intent, event.FieldEventID)
	before := f.ledger.types()

	// Inside the window: an intent whose signature may still be in flight is
	// left alone. Expiring it would record "no signature exists" about a
	// signature that had not finished being made, and I4 makes that permanent.
	f.clock.at = f.clock.at.Add(time.Minute)
	early := f.reconcile(t, 15*time.Minute)
	if len(early.Appended) != 0 {
		t.Fatalf("inside the window the reconciler appended %v; the signature may still "+
			"be in flight", early.Appended)
	}
	if early.Open != 1 || early.Expired != 0 {
		t.Fatalf("inside the window: Open=%d Expired=%d, want 1 and 0", early.Open, early.Expired)
	}
	if got := f.ledger.types(); !slices.Equal(got, before) {
		t.Fatalf("the chain changed inside the window: %v -> %v", before, got)
	}

	// Past it: the intent is expired, and by the reconciler.
	f.clock.at = f.clock.at.Add(15 * time.Minute)
	late := f.reconcile(t, 15*time.Minute)
	if len(late.Appended) != 1 {
		t.Fatalf("past the window the reconciler appended %d events, want 1", len(late.Appended))
	}
	if late.Expired != 1 || late.Repaired != 0 {
		t.Fatalf("past the window: Expired=%d Repaired=%d, want 1 and 0", late.Expired, late.Repaired)
	}

	expired := f.ledger.last()
	if got := member[string](t, expired, event.FieldEventType); got != event.EventTypeCommitIntentExpired {
		t.Fatalf("the appended event is %s, want %s", got, event.EventTypeCommitIntentExpired)
	}
	if got := member[string](t, expired, event.FieldSource); got != event.SourceReconciler {
		t.Fatalf("the expiry carries source %q, want %q (doc 02 §3)", got, event.SourceReconciler)
	}
	if got := member[string](t, expired, event.FieldIntentEventID); got != intentID {
		t.Fatalf("the expiry names intent %s, want %s", got, intentID)
	}
	if got := member[string](t, expired, event.FieldRunID); got != f.runID {
		t.Fatalf("the expiry carries run_id %q, want %q", got, f.runID)
	}
	if got := member[string](t, expired, event.FieldSpiffeID); got != spiffeIDFor(f.runID) {
		t.Fatalf("the expiry carries spiffe_id %q, want %q", got, spiffeIDFor(f.runID))
	}
	// Nothing was fabricated: an expiry is not a commit_recorded.
	if _, present := expired[event.FieldCommitSHA]; present {
		t.Fatalf("the expiry carries a commit_sha: %#v", expired)
	}
}

func TestAnIntentIsNeverExpiredWhileTheTransparencyLogCannotBeAsked(t *testing.T) {
	f := newFixture(t, "run-recunres", testTree)
	// A commit with the intent's tree exists, so the log is the only thing
	// that can say whether it was signed — and the log is down.
	f.repos.commits[testRepo] = map[string][]string{testTree: {testCommit}}
	f.log.err = errors.New("rekor: connection refused")

	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if len(result.Appended) != 0 {
		t.Fatalf("a Rekor outage produced appends %v; expiry must never be recorded "+
			"on a negative nobody established", result.Appended)
	}
	if result.Unresolved != 1 {
		t.Fatalf("Unresolved=%d, want 1", result.Unresolved)
	}
}

func TestAnIntentIsNeverExpiredWhileItsRepositoryCannotBeRead(t *testing.T) {
	f := newFixture(t, "run-recnorepo", testTree)
	f.repos.err = errors.New("no working tree for github.com/innsegl/demo")

	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if len(result.Appended) != 0 {
		t.Fatalf("an unreadable repository produced appends %v", result.Appended)
	}
	if result.Unresolved != 1 {
		t.Fatalf("Unresolved=%d, want 1", result.Unresolved)
	}
}

// ---------------------------------------------------------------------------
// REC-002 — the B → C window, and the four ways the repair must refuse.
// ---------------------------------------------------------------------------

func TestREC002AnIntentWithARealLogEntryIsRepairedNotExpired(t *testing.T) {
	f := newFixture(t, "run-rec002", testTree)
	intentID := member[string](t, f.intent, event.FieldEventID)
	f.signIt(testCommit, testTree, spiffeIDFor(f.runID))

	// Well past the expiry window: the repair must win over the expiry, or a
	// signature that exists would be recorded as one that never happened.
	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)

	if result.Repaired != 1 || result.Expired != 0 {
		t.Fatalf("Repaired=%d Expired=%d, want 1 and 0", result.Repaired, result.Expired)
	}
	recorded := f.ledger.last()
	if got := member[string](t, recorded, event.FieldEventType); got != event.EventTypeCommitRecorded {
		t.Fatalf("the appended event is %s, want %s", got, event.EventTypeCommitRecorded)
	}
	if got := member[string](t, recorded, event.FieldSource); got != event.SourceReconciler {
		t.Fatalf("the repair carries source %q, want %q — a repair that looks identical "+
			"to an original is a lie by omission (doc 06 §3.3)", got, event.SourceReconciler)
	}
	for name, want := range map[string]any{
		event.FieldIntentEventID:  intentID,
		event.FieldRepo:           testRepo,
		event.FieldTreeHash:       testTree,
		event.FieldCommitSHA:      testCommit,
		event.FieldRekorEntryUUID: f.log.entries[testCommit].UUID,
		event.FieldRunID:          f.runID,
		event.FieldSpiffeID:       spiffeIDFor(f.runID),
	} {
		if got := recorded[name]; got != want {
			t.Errorf("the repair carries %s=%v, want %v", name, got, want)
		}
	}
	if got := member[int64](t, recorded, event.FieldRekorLogIndex); got != f.log.entries[testCommit].LogIndex {
		t.Errorf("the repair carries rekor_log_index=%d, want %d",
			got, f.log.entries[testCommit].LogIndex)
	}
}

// The vacuity this component is most able to commit: appending a
// commit_recorded for an intent that was never signed. That is fabricated
// attribution — precisely what RM-036's drift detection exists to catch — so
// each of the four ways a candidate can fail to be this intent's signature is
// its own case.
func TestTheRepairIsRefusedWhenTheLogHoldsNoEntryForTheCommit(t *testing.T) {
	f := newFixture(t, "run-nolog", testTree)
	// A commit with exactly the intent's tree exists in the repository — the
	// state an unsigned `git commit` leaves — and the log knows nothing of it.
	f.repos.commits[testRepo] = map[string][]string{testTree: {testCommit}}

	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if result.Repaired != 0 {
		t.Fatalf("the reconciler repaired an intent with no Rekor entry; that is a "+
			"fabricated commit_recorded: %+v", result.Findings)
	}
	if result.Expired != 1 {
		t.Fatalf("Expired=%d, want 1 — with no signature the intent is an A → B residue",
			result.Expired)
	}
	if got := member[string](t, f.ledger.last(), event.FieldEventType); got != event.EventTypeCommitIntentExpired {
		t.Fatalf("the appended event is %s, want %s", got, event.EventTypeCommitIntentExpired)
	}
}

func TestTheRepairIsRefusedWhenTheEntrysCertificateNamesAnotherRun(t *testing.T) {
	f := newFixture(t, "run-otherrun", testTree)
	f.signIt(testCommit, testTree, spiffeIDFor("run-somebody-else"))

	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if result.Repaired != 0 {
		t.Fatalf("the reconciler attributed another run's signature to this intent: %+v",
			result.Findings)
	}
	if result.Expired != 1 {
		t.Fatalf("Expired=%d, want 1", result.Expired)
	}
}

func TestTheRepairIsRefusedWhenTheEntrysCertificateIsOutsideOurTrustDomain(t *testing.T) {
	f := newFixture(t, "run-foreign", testTree)
	// The same run path under a trust domain that is not ours. IP §6.5 scopes
	// the scan to "certificates bearing our trust domain's identities".
	f.signIt(testCommit, testTree,
		"spiffe://evil.example/agent/demo/rm-035/run-foreign")

	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if result.Repaired != 0 {
		t.Fatalf("the reconciler accepted a certificate from another trust domain: %+v",
			result.Findings)
	}
}

// The trust-domain scope, isolated. IP §6.5 confines the repair to "our trust
// domain's identities", and the scope is enforced at the INTENT: an intent
// claiming an identity this deployment could not have issued is unresolvable,
// because no certificate the match would accept could ever name it. Without
// this case the scope is only enforced transitively and a mutation deleting it
// changes no test.
func TestAnIntentClaimingAnotherTrustDomainIsNeverActedOn(t *testing.T) {
	c := &clock{at: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	const runID = "run-foreigntd"
	const foreign = "spiffe://evil.example/agent/demo/rm-035/run-foreigntd"
	if _, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       foreign,
		event.FieldIdempotencyKey: "reg-" + runID,
		event.FieldAgentType:      "demo",
		event.FieldTaskRef:        "RM-035",
	}); err != nil {
		t.Fatalf("seed run_registered: %v", err)
	}
	intent, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       foreign,
		event.FieldIdempotencyKey: "sign_commit/intent/" + runID,
		event.FieldRepo:           testRepo,
		event.FieldTreeHash:       testTree,
	})
	if err != nil {
		t.Fatalf("seed commit_intent: %v", err)
	}
	f := &fixture{
		clock: c, ledger: m, intent: intent, runID: runID,
		repos: &fakeRepos{commits: map[string]map[string][]string{}},
		log:   &fakeLog{entries: map[string]reconciler.LogEntry{}},
	}
	// A signature really exists, under exactly the identity the intent claims.
	// It is still not ours to record.
	f.signIt(testCommit, testTree, foreign)

	c.at = c.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if len(result.Appended) != 0 {
		t.Fatalf("an intent outside %s produced appends %v; IP §6.5 scopes the repair "+
			"to our trust domain's identities", testTrustDomain, result.Appended)
	}
	if result.Unresolved != 1 {
		t.Fatalf("Unresolved=%d, want 1: %+v", result.Unresolved, result.Findings)
	}
	// And it never went looking: an identity we could not have issued is
	// decided from the intent alone.
	if f.repos.calls != 0 || f.log.calls != 0 {
		t.Fatalf("the cycle asked git %d times and the log %d times about an identity "+
			"outside the trust domain", f.repos.calls, f.log.calls)
	}
}

func TestARepairIsRefusedWhenTwoSignedCommitsClaimTheSameIntent(t *testing.T) {
	f := newFixture(t, "run-ambig", testTree)
	const second = "1c2f43cf5c69a41a4a55c3e0b0c1a5d3f7e2b6a9"
	f.signIt(testCommit, testTree, spiffeIDFor(f.runID))
	f.signIt(second, testTree, spiffeIDFor(f.runID))

	f.clock.at = f.clock.at.Add(time.Hour)
	result := f.reconcile(t, 15*time.Minute)
	if len(result.Appended) != 0 {
		t.Fatalf("two signatures for one intent produced %v; which commit the intent "+
			"names is not something this component may guess", result.Appended)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("the cycle produced %d findings, want 1: %+v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].Outcome != reconciler.OutcomeAmbiguous {
		t.Fatalf("outcome %q, want %q", result.Findings[0].Outcome, reconciler.OutcomeAmbiguous)
	}
}

// ---------------------------------------------------------------------------
// REC-005 — idempotency, across processes.
// ---------------------------------------------------------------------------

func TestREC005ASecondFreshReconcilerOverTheSameStateAppendsNothing(t *testing.T) {
	repaired := newFixture(t, "run-idem-b", testTree)
	repaired.signIt(testCommit, testTree, spiffeIDFor(repaired.runID))
	repaired.clock.at = repaired.clock.at.Add(time.Hour)

	expired := newFixture(t, "run-idem-a", testTree)
	expired.clock.at = expired.clock.at.Add(time.Hour)

	for name, f := range map[string]*fixture{"repaired": repaired, "expired": expired} {
		first := f.reconcile(t, 15*time.Minute)
		if len(first.Appended) != 1 {
			t.Fatalf("%s: the first cycle appended %d events, want 1", name, len(first.Appended))
		}
		after := f.ledger.types()
		repoCalls, logCalls := f.repos.calls, f.log.calls

		// A NEW reconciler, as a restarted process or a newly elected leader
		// would be: nothing it knows carries over from the cycle above.
		second := f.reconcile(t, 15*time.Minute)
		if len(second.Appended) != 0 {
			t.Fatalf("%s: a fresh second reconciler appended %v", name, second.Appended)
		}
		if got := f.ledger.types(); !slices.Equal(got, after) {
			t.Fatalf("%s: the chain changed on the second cycle:\n%v\n%v", name, after, got)
		}
		if second.Open != 0 {
			t.Fatalf("%s: the second cycle still sees %d open intents", name, second.Open)
		}
		// And it did not go back to git or to Rekor for an intent the chain
		// already answers — the answer is read out of the chain, not recomputed.
		if f.repos.calls != repoCalls || f.log.calls != logCalls {
			t.Fatalf("%s: the second cycle asked git %d more times and the log %d more times",
				name, f.repos.calls-repoCalls, f.log.calls-logCalls)
		}
	}
}

func TestASecondReconcilerRunningConcurrentlyCannotAppendASecondRepair(t *testing.T) {
	f := newFixture(t, "run-split", testTree)
	f.signIt(testCommit, testTree, spiffeIDFor(f.runID))
	f.clock.at = f.clock.at.Add(time.Hour)

	// Two reconcilers that both READ before either wrote — a split brain, the
	// state doc 05 §2's leader election exists to prevent and which failover
	// can still produce for one cycle.
	a := f.reconciler(t, 15*time.Minute)
	b := f.reconciler(t, 15*time.Minute)
	if _, err := a.Reconcile(context.Background()); err != nil {
		t.Fatalf("first reconciler: %v", err)
	}
	countBefore, cerr := f.ledger.Count(context.Background())
	if cerr != nil {
		t.Fatalf("Count: %v", cerr)
	}
	if _, err := b.Reconcile(context.Background()); err != nil {
		t.Fatalf("second reconciler: %v", err)
	}
	countAfter, cerr := f.ledger.Count(context.Background())
	if cerr != nil {
		t.Fatalf("Count: %v", cerr)
	}
	if countAfter != countBefore {
		t.Fatalf("the second reconciler grew the chain from %d to %d", countBefore, countAfter)
	}
}

func TestTheRepairKeyIsTheOneSignCommitWouldHaveUsed(t *testing.T) {
	f := newFixture(t, "run-key", testTree)
	f.signIt(testCommit, testTree, spiffeIDFor(f.runID))
	f.clock.at = f.clock.at.Add(time.Hour)
	f.reconcile(t, 15*time.Minute)

	key := member[string](t, f.ledger.last(), event.FieldIdempotencyKey)
	intentKey := member[string](t, f.intent, event.FieldIdempotencyKey)
	want := "sign_commit/recorded/" + strings.TrimPrefix(intentKey, "sign_commit/intent/")
	if key != want {
		t.Fatalf("the repair's idempotency_key is %q, want %q — Phase C's own key, so a "+
			"repaired chain and an uncrashed one are the same state", key, want)
	}
}

func TestAnIntentWhoseKeyIsNotSignCommitsFallsBackToTheReconcilersOwnNamespace(t *testing.T) {
	c := &clock{at: time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, "run-nokey")
	intent, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventType:     event.EventTypeCommitIntent,
		event.FieldSource:        event.SourceSystem,
		event.FieldRunID:         "run-nokey",
		event.FieldSpiffeID:      spiffeIDFor("run-nokey"),
		event.FieldRepo:          testRepo,
		event.FieldTreeHash:      testTree,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	f := &fixture{
		clock: c, ledger: m, intent: intent, runID: "run-nokey",
		repos: &fakeRepos{commits: map[string]map[string][]string{}},
		log:   &fakeLog{entries: map[string]reconciler.LogEntry{}},
	}
	f.signIt(testCommit, testTree, spiffeIDFor("run-nokey"))
	c.at = c.at.Add(time.Hour)
	f.reconcile(t, 15*time.Minute)

	key := member[string](t, m.last(), event.FieldIdempotencyKey)
	if !strings.HasPrefix(key, "reconciler:commit_recorded:") {
		t.Fatalf("the repair's idempotency_key is %q, want the reconciler namespace", key)
	}
}

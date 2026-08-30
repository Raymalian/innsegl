// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// The paths drift detection takes when something is wrong with the chain, the
// ledger or the configuration (RM-036, #44).
//
// Every one of them shares a rule: an alert this component cannot establish, or
// cannot record, is REPORTED and never invented. I4 makes a `ledger_drift_
// detected` permanent, and the subject of one is an accusation against a named
// run — so the only thing worse than missing drift is recording it wrongly.

// ---------------------------------------------------------------------------
// A chain the reader cannot make sense of.
// ---------------------------------------------------------------------------

// mangleLast mutates the record the chain most recently accepted. No production
// path can do this; the question is what a READER does with a record it cannot
// make sense of, which doc 02 §1 says it must tolerate rather than fail on.
func (f *driftFixture) mangleLast(mangle func(event.Fields)) {
	mangle(f.ledger.records[len(f.ledger.records)-1])
}

func TestDriftSkipsACommitRecordItCannotRead(t *testing.T) {
	for name, mangle := range map[string]func(event.Fields){
		"no event_id": func(r event.Fields) { delete(r, event.FieldEventID) },
		"no rekor_entry_uuid": func(r event.Fields) {
			delete(r, event.FieldRekorEntryUUID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDriftFixture(t)
			f.legitimate(t)
			f.mangleLast(mangle)

			result := f.cycle(t)

			// A record with no event_id names no subject, so no
			// `ledger_drift_detected` can be written about it — the schema
			// requires a real UUIDv7 there (ADR-0013's own reasoning). A record
			// with no uuid is judged: it names no entry, which is drift.
			for _, d := range result.Drift.Findings {
				if d.Kind == reconciler.DriftUnresolved {
					t.Fatalf("an unreadable record was reported as an outage: %+v", d)
				}
			}
			if name == "no event_id" && len(result.Drift.Findings) != 0 {
				t.Fatalf("a record with no event_id produced findings %+v; there is no "+
					"subject_event_id to write and doc 02 §1 admits no placeholder",
					result.Drift.Findings)
			}
			if name == "no rekor_entry_uuid" && result.Drift.Fabricated != 1 {
				t.Fatalf("a record naming no entry produced %d findings; a claim with no "+
					"proof is exactly what ledger_drift_detected is for",
					result.Drift.Fabricated)
			}
		})
	}
}

// A `rekor_log_index` that is not an int64 is still read where it honestly can
// be, and is otherwise a value no log index can equal — so a record carrying
// one is drift rather than a record that quietly agrees with everything.
func TestDriftReadsALogIndexWhateverShapeItArrivesIn(t *testing.T) {
	for name, tc := range map[string]struct {
		value    any
		wantSame bool
	}{
		"int64, as the store returns it":         {value: int64(0), wantSame: true},
		"int, from a record never round-tripped": {value: 0, wantSame: true},
		"a json.Number, from a decoder that kept the literal": {
			value: json.Number("0"), wantSame: true,
		},
		"a json.Number that is not an integer": {value: json.Number("1e9"), wantSame: false},
		"a string":                             {value: "0", wantSame: false},
		"absent":                               {value: nil, wantSame: false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDriftFixture(t)
			f.legitimate(t)
			f.mangleLast(func(r event.Fields) {
				if tc.value == nil {
					delete(r, event.FieldRekorLogIndex)
					return
				}
				r[event.FieldRekorLogIndex] = tc.value
			})

			result := f.cycle(t)

			if tc.wantSame && result.Drift.Fabricated != 0 {
				t.Fatalf("a legitimate record whose log index reads as %T was flagged: %+v",
					tc.value, result.Drift.Findings)
			}
			if !tc.wantSame && result.Drift.Fabricated != 1 {
				t.Fatalf("a record whose log index is %v was NOT flagged; an index nobody "+
					"can read is not an index that matches", tc.value)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A ledger that will not take the alert.
// ---------------------------------------------------------------------------

func TestAnAlertTheLedgerRefusesIsStillRaisedToAnOperator(t *testing.T) {
	for name, failOn := range map[string]string{
		"the unattributed signature": event.EventTypeUnattributedSignatureDetected,
		"the ledger drift":           event.EventTypeLedgerDriftDetected,
	} {
		t.Run(name, func(t *testing.T) {
			f := newDriftFixture(t)
			f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")
			seedRun(t, f.ledger, driftRunID)
			intent := seedIntent(t, f.ledger, driftRunID, driftTree)
			f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
				driftCommit, rekorUUIDOf("absent"), 12)
			f.ledger.failOn = failOn

			result := f.cycle(t)

			// The count still moves and the operator is still told. A drift
			// finding that disappears because Postgres was busy is the failure
			// mode this whole component exists to prevent.
			if result.Drift.Unattributed != 1 || result.Drift.Fabricated != 1 {
				t.Fatalf("a refused append lost a finding: %+v", result.Drift.Findings)
			}
			if len(f.alerts) != 2 {
				t.Fatalf("the operator sink saw %d alerts, want 2", len(f.alerts))
			}
			var refused reconciler.DriftFinding
			for _, d := range f.alerts {
				if d.AppendedEventID == "" {
					refused = d
				}
			}
			if refused.Kind == "" {
				t.Fatal("no finding reports a refused append")
			}
			if !strings.Contains(refused.Detail, "could not be appended") {
				t.Fatalf("the finding does not say the append was refused: %q", refused.Detail)
			}
			if len(result.Drift.Appended) != 1 {
				t.Fatalf("Appended = %v, want only the alert that was written",
					result.Drift.Appended)
			}
		})
	}
}

// wrongReply is a ledger that answers an append with something else, the way a
// chain another writer got to first would.
type wrongReply struct {
	mu    sync.Mutex
	reply event.Fields
}

func (w *wrongReply) Append(context.Context, event.Fields) (event.Fields, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reply, nil
}

func TestAnAlertThatComesBackAsAnotherEventIsReportedNotCounted(t *testing.T) {
	f := newDriftFixture(t)
	f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")

	r, err := reconciler.New(reconciler.Config{
		Ledger: f.ledger,
		Appender: &wrongReply{reply: event.Fields{
			event.FieldEventType:      event.EventTypeRunRetired,
			event.FieldEventID:        "01a05343-a4b4-748c-8b65-659c43a7a3d3",
			event.FieldIdempotencyKey: reconciler.UnattributedKey(rekorUUIDOf("planted")),
		}},
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Drift: &reconciler.DriftConfig{Sweep: f.sweep, Alert: func(_ context.Context, d reconciler.DriftFinding) {
			f.alerts = append(f.alerts, d)
		}},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	f.alerts = nil
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(result.Drift.Appended) != 0 {
		t.Fatalf("an append that came back as a run_retired was counted as written: %v",
			result.Drift.Appended)
	}
	if len(f.alerts) != 1 || !strings.Contains(f.alerts[0].Detail, "names a run_retired") {
		t.Fatalf("the finding does not say what came back: %+v", f.alerts)
	}
}

// ---------------------------------------------------------------------------
// Configuration and the default sink.
// ---------------------------------------------------------------------------

func TestADriftConfigWithANegativeWindowIsRefused(t *testing.T) {
	f := newDriftFixture(t)
	_, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Drift:       &reconciler.DriftConfig{Sweep: f.sweep, Window: -1},
	})
	if err == nil {
		t.Fatal("a negative sweep window was accepted")
	}
}

// The window is a TRAILING one: the newest entries, and no cursor. A fresh
// reconciler must sweep exactly the range a long-running one does, which is the
// property REC-005 and ADR-0013 both rest on.
func TestTheSweepWindowBoundsTheRangeToTheNewestEntries(t *testing.T) {
	f := newDriftFixture(t)
	for i := range 12 {
		f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, fmt.Sprintf("e%d", i))
	}

	r, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Drift: &reconciler.DriftConfig{Sweep: f.sweep, Window: 4,
			Alert: func(context.Context, reconciler.DriftFinding) {}},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Drift.SweptFrom != 8 || result.Drift.SweptTo != 12 {
		t.Fatalf("the cycle swept [%d, %d), want [8, 12)",
			result.Drift.SweptFrom, result.Drift.SweptTo)
	}
	if result.Drift.Unattributed != 4 {
		t.Fatalf("the cycle flagged %d of 12 entries with a window of 4, want 4",
			result.Drift.Unattributed)
	}
	if reconciler.DefaultSweepWindow <= 0 {
		t.Fatal("DefaultSweepWindow is not positive")
	}
}

func TestAnEmptyLogIsSweptWithoutAskingForEntries(t *testing.T) {
	f := newDriftFixture(t)
	result := f.cycle(t)
	if f.sweep.rangeCalls != 0 {
		t.Fatalf("an empty log was asked for %d ranges, want 0", f.sweep.rangeCalls)
	}
	if result.Drift.SweptFrom != 0 || result.Drift.SweptTo != 0 {
		t.Fatalf("an empty log was reported as swept [%d, %d)",
			result.Drift.SweptFrom, result.Drift.SweptTo)
	}
}

// The default sink is what a deployment that names none gets, and doc 05 §4
// lists reconciler drift alerts among the monitoring minimums — so it has to
// run rather than be assumed to.
func TestTheDefaultDriftSinkIsExercisedByEveryFindingShape(t *testing.T) {
	f := newDriftFixture(t)
	f.plantEntry(spiffeIDFor(plantedRunID), plantedCommit, "planted")
	seedRun(t, f.ledger, driftRunID)
	intent := seedIntent(t, f.ledger, driftRunID, driftTree)
	f.recordCommit(t, driftRunID, str(intent, event.FieldEventID),
		driftCommit, rekorUUIDOf("absent"), 12)

	r, err := reconciler.New(reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		// No Alert: the default sink.
		Drift: &reconciler.DriftConfig{Sweep: f.sweep},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Drift.Unattributed != 1 || result.Drift.Fabricated != 1 {
		t.Fatalf("the default-sink cycle found %d and %d, want 1 and 1",
			result.Drift.Unattributed, result.Drift.Fabricated)
	}

	// And the unresolved shape, which takes the same sink by another path.
	f.sweep.treeErr = errors.New("rekor is down")
	unresolved, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if unresolved.Drift.Unresolved != 1 {
		t.Fatalf("Unresolved = %d, want 1", unresolved.Drift.Unresolved)
	}
}

// ---------------------------------------------------------------------------
// A body whose public key is not even base64.
// ---------------------------------------------------------------------------

func TestSweepReadsAnEntryWhosePublicKeyIsNotBase64(t *testing.T) {
	raw := fmt.Sprintf(
		`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":`+
			`{"algorithm":"sha256","value":%q}},"signature":{"content":"c2ln",`+
			`"publicKey":{"content":"!!! not base64 !!!"}}}}`, artifactHash(testCommit))
	s := &sweepServer{}
	s.plant("aa", 0, base64.StdEncoding.EncodeToString([]byte(raw)))

	got, err := s.start(t).EntriesFrom(context.Background(), 0, 1)
	if err != nil {
		t.Fatalf("EntriesFrom: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("EntriesFrom returned %d entries, want 1", len(got))
	}
	if got[0].CertificateIdentity != "" {
		t.Errorf("identity = %q, want empty", got[0].CertificateIdentity)
	}
	if got[0].ArtifactHash != artifactHash(testCommit) {
		t.Errorf("artifact = %q, want %q; the artifact is readable even when the key is not",
			got[0].ArtifactHash, artifactHash(testCommit))
	}
	if got[0].IntegratedAt.IsZero() {
		t.Error("the entry carries no integration time")
	}
}

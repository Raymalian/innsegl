// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/reconciler"
)

// witnessintegration_test.go — #392 (RM-247), E18. The test ID this file
// drives, from doc 07:
//
//	OTW-002 (I)  A tool call the gateway relayed with no telemetry event past
//	             the window, and a telemetry event for a tool call the
//	             gateway never relayed, raise one alert each (or the honest
//	             equivalent for the second), and a second pass adds none.
//
// Against a REAL Postgres ledger (harness_test.go's freshStore, the same
// shared container every other integration case in this package uses) --
// idempotent-append across cycles (LED-008) is a claim about the real
// ledger's own unique index, and a map-backed fake proves nothing about it.
//
// # The honest equivalent for the second case
//
// doc 02 §3 defines `ledger_drift_detected` as needing `subject_event_id`
// (required, event-id grammar) and `reason`, and glosses it as "a ledger
// claim with no external proof". For the first case that fits exactly: the
// gateway's own tool_call event IS the ledger's claim that this call
// happened, and the harness's own telemetry is the external proof that
// never arrived. For the second case there is no ledger claim to be the
// subject of anything -- the gateway never relayed this tool_use_id at
// all, so no tool_call event names it, and inventing a subject_event_id
// (the run's run_registered? a made-up id?) would be exactly the kind of
// invented field #392's own task description forbids. So this pass reports
// the second case as a WitnessFinding (Kind: WitnessOrphanTelemetry) --
// counted, alerted, visible in Result.Witness -- and appends NOTHING. This
// is the intended, honest reading, not a shortfall: an alert nobody can
// record is still an alert somebody must see (the same standing this
// package's other passes already hold for a ledger that refuses an
// append), and here the alert exists BECAUSE there is nothing to record,
// not despite it.
//
// One consequence follows directly: an un-appendable finding cannot be
// deduped against the chain the way case one is (view.drift.subjects), so
// it recurs every cycle for as long as it stays true -- the SAME standing
// drift.go's own DriftUnresolved findings already hold (unresolved, in
// drift.go, re-alerts every cycle with no dedupe). "A second pass adds
// none" is proved here against the LEDGER (Result.Witness.Appended, and the
// chain's own event count), which is the property LED-008 and REC-005 are
// actually about; it is not a claim that the alert sink goes quiet, which
// nothing in this package promises for an unresolved finding of any kind.

const witnessIntegrationTimeout = 2 * time.Minute

// witnessIntegrationWindow is generous relative to what this test needs
// (a few hundred milliseconds of real work) on purpose: `call.at` comes
// from Postgres's own `clock_timestamp()` (internal/ledger/postgres.go's
// own Append) while a telemetry record's own receive time comes from this
// HOST's filesystem mtime (internal/gateway/witness.go's own atomic write)
// -- two different clocks, exactly the "disagreement two hosts' clocks may
// have" reconcile.go's own DefaultExpireAfter already budgets a full minute
// for. A window tight enough to leave no room for that skew makes this
// test flaky under load (measured: a few hundred milliseconds under a
// loaded Docker daemon) without proving anything sharper about the pass
// itself, which is validated at the unit level (witness_test.go's own
// OTW-003) against a single, fully-controlled clock instead.
const witnessIntegrationWindow = 3 * time.Second

func witnessSpiffeID(runID string) string {
	return fmt.Sprintf("spiffe://%s/agent/demo/rm-247/%s", testTrustDomain, runID)
}

func witnessSeedRun(ctx context.Context, t *testing.T, store *ledger.Store, runID string) {
	t.Helper()
	if _, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       witnessSpiffeID(runID),
		event.FieldIdempotencyKey: "register/" + runID,
		event.FieldAgentType:      "demo",
		event.FieldTaskRef:        "rm-247",
		event.FieldRepo:           "github.com/innsegl/otw002",
		event.FieldBranch:         "main",
	}); err != nil {
		t.Fatalf("seed run_registered: %v", err)
	}
}

// witnessSeedToolCall appends a tool_call event naming the digest of a body
// already planted on disk (plantCommitWatchBody, commitwatch_test.go).
func witnessSeedToolCall(ctx context.Context, t *testing.T, store *ledger.Store, runID, digest string) event.Fields {
	t.Helper()
	record, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       witnessSpiffeID(runID),
		event.FieldIdempotencyKey: "tool/" + runID + "/" + digest[7:19],
		event.FieldToolName:       "Bash",
		event.FieldPayloadDigest:  digest,
	})
	if err != nil {
		t.Fatalf("seed tool_call: %v", err)
	}
	return record
}

func witnessBody(toolUseID string) []byte {
	raw, err := json.Marshal(map[string]any{
		"tool":            "Bash",
		"tool_use_id":     toolUseID,
		"input":           map[string]any{"command": "echo hi"},
		"result_observed": true,
		"result":          "hi\n",
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func witnessPlantTelemetryFile(t *testing.T, dir, toolUseID string, success bool, receivedAt time.Time) {
	t.Helper()
	telDir := filepath.Join(dir, "telemetry")
	if err := os.MkdirAll(telDir, 0o755); err != nil {
		t.Fatalf("mkdir telemetry dir: %v", err)
	}
	raw, err := json.Marshal(map[string]any{
		"tool_use_id": toolUseID,
		"tool_name":   "Bash",
		"success":     success,
		"session_id":  "11111111-1111-1111-1111-111111111111",
		"time":        receivedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(telDir, toolUseID+".json"), raw, 0o644); err != nil {
		t.Fatalf("writing telemetry record: %v", err)
	}
}

// TestOTW002EachDirectionRaisesItsOwnFindingAndASecondPassAddsNone is
// OTW-002.
//
// cross-check told together: splitting them would separate each finding
// from the idempotency proof that is the whole point of the second cycle.
//
//nolint:gocyclo // one measured fact per block, both directions of one
func TestOTW002EachDirectionRaisesItsOwnFindingAndASecondPassAddsNone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), witnessIntegrationTimeout)
	defer cancel()

	store, _ := freshStore(t)
	const runID = "run-otw-002"
	witnessSeedRun(ctx, t, store, runID)

	logDir := t.TempDir()

	// A baseline pair, already corroborated, so telemetry reads as ACTIVE
	// since before the two cases below -- otherwise the missing-telemetry
	// case would be excluded as "telemetry not yet proven active" rather
	// than genuinely missing.
	baselineDigest := plantCommitWatchBody(t, logDir, runID, witnessBody("toolu_otw002_baseline"))
	witnessSeedToolCall(ctx, t, store, runID, baselineDigest)
	witnessPlantTelemetryFile(t, logDir, "toolu_otw002_baseline", true, time.Now().Add(-time.Hour))

	// Case 1: relayed, never corroborated.
	missingDigest := plantCommitWatchBody(t, logDir, runID, witnessBody("toolu_otw002_missing"))
	missingCall := witnessSeedToolCall(ctx, t, store, runID, missingDigest)
	missingCallID := str(missingCall, event.FieldEventID)

	// Case 2: telemetry for a tool_use_id the gateway never relayed at all.
	witnessPlantTelemetryFile(t, logDir, "toolu_otw002_orphan", false, time.Now())

	// Past the (short) window for both directions.
	time.Sleep(2 * witnessIntegrationWindow)

	var alerts []reconciler.WitnessFinding
	build := func() *reconciler.Reconciler {
		alerts = nil
		r, nerr := reconciler.New(reconciler.Config{
			Ledger: store, Appender: store,
			Repos: &fakeRepos{}, Log: &fakeLog{entries: map[string]reconciler.LogEntry{}},
			TrustDomain: testTrustDomain,
			Alert:       func(context.Context, reconciler.Finding) {},
			Observe:     func(reconciler.Result, error) {},
			Witness: &reconciler.WitnessConfig{
				LogDir: logDir,
				Window: witnessIntegrationWindow,
				Alert: func(_ context.Context, f reconciler.WitnessFinding) {
					alerts = append(alerts, f)
					t.Logf("witness alert: kind=%s reason=%q detail=%q", f.Kind, f.Reason, f.Detail)
				},
			},
		})
		if nerr != nil {
			t.Fatalf("reconciler.New: %v", nerr)
		}
		return r
	}

	// -----------------------------------------------------------------------
	// First cycle: one alert per direction.
	// -----------------------------------------------------------------------
	first, err := build().Reconcile(ctx)
	if err != nil {
		t.Fatalf("the first cycle failed: %v", err)
	}
	if !first.Witness.Enabled {
		t.Fatal("witness reported itself disabled with a WitnessConfig given")
	}
	if first.Witness.Missing != 1 {
		t.Fatalf("missing %d, want 1: %+v", first.Witness.Missing, first.Witness.Findings)
	}
	if first.Witness.Orphaned != 1 {
		t.Fatalf("orphaned %d, want 1: %+v", first.Witness.Orphaned, first.Witness.Findings)
	}
	if len(first.Witness.Appended) != 1 {
		t.Fatalf("appended %v, want exactly one (only the missing-telemetry case can be), "+
			"findings: %+v", first.Witness.Appended, first.Witness.Findings)
	}
	if len(alerts) != 2 {
		t.Fatalf("the operator sink saw %d alerts, want 2 (one per direction): %+v", len(alerts), alerts)
	}

	alert := onlyEvent(ctx, t, store, runID, event.EventTypeLedgerDriftDetected)
	if got := str(alert, event.FieldSubjectEventID); got != missingCallID {
		t.Fatalf("the alert names subject %s, want the missing tool_call %s", got, missingCallID)
	}
	if got := str(alert, event.FieldEventID); got != first.Witness.Appended[0] {
		t.Fatalf("the appended event id %s does not match the chain's %s",
			first.Witness.Appended[0], got)
	}

	var missingFinding, orphanFinding *reconciler.WitnessFinding
	for i := range first.Witness.Findings {
		f := &first.Witness.Findings[i]
		switch f.Kind {
		case reconciler.WitnessMissingTelemetry:
			missingFinding = f
		case reconciler.WitnessOrphanTelemetry:
			orphanFinding = f
		}
	}
	if missingFinding == nil {
		t.Fatal("no WitnessMissingTelemetry finding in the first cycle")
	}
	if missingFinding.AppendedEventID == "" {
		t.Error("the missing-telemetry finding's AppendedEventID is empty, want the ledger event")
	}
	if orphanFinding == nil {
		t.Fatal("no WitnessOrphanTelemetry finding in the first cycle")
	}
	if orphanFinding.AppendedEventID != "" {
		t.Errorf("the orphan-telemetry finding's AppendedEventID = %q, want empty: doc 02's "+
			"ledger_drift_detected has no honest subject for a tool_use_id the gateway never "+
			"relayed, so this case is reported and never appended", orphanFinding.AppendedEventID)
	}
	if orphanFinding.ToolUseID != "toolu_otw002_orphan" {
		t.Errorf("the orphan finding names tool_use_id %q, want %q",
			orphanFinding.ToolUseID, "toolu_otw002_orphan")
	}

	// -----------------------------------------------------------------------
	// Idempotency, proved against the LEDGER: a FRESH reconciler over the
	// same chain state appends nothing more. The orphan-telemetry finding
	// legitimately recurs (this file's own doc comment explains why -- the
	// same standing drift.go's own DriftUnresolved already holds), so it is
	// not asserted away here; what is asserted is that it never becomes a
	// SECOND ledger write.
	// -----------------------------------------------------------------------
	countBefore, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	second, err := build().Reconcile(ctx)
	if err != nil {
		t.Fatalf("the second cycle failed: %v", err)
	}
	if len(second.Witness.Appended) != 0 {
		t.Fatalf("a fresh second reconciler appended %v", second.Witness.Appended)
	}
	if second.Witness.Missing != 0 {
		t.Errorf("missing %d on the second cycle, want 0: the subject is already reported "+
			"(view.drift.subjects) and must not be re-judged", second.Witness.Missing)
	}
	countAfter, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if countAfter != countBefore {
		t.Fatalf("the second cycle grew the chain from %d to %d", countBefore, countAfter)
	}

	all, err := store.Events(ctx, 1, countAfter)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if _, verr := ledger.Verify(all); verr != nil {
		t.Fatalf("the chain does not verify after the alerts: %v", verr)
	}
	t.Logf("OTW-002: idempotent -- cycle two appended nothing; the chain is %d events and verifies",
		countAfter)
}

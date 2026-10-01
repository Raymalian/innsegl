// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// witness_test.go — #392 (RM-247), E18. The unit-level test ID this file
// drives, from doc 07:
//
//	OTW-003 (U)  Matching tool calls, and telemetry arriving late inside the
//	             window, raise no alert.
//
// Against an in-memory chain (memLedger, this package's own REAL hash-chain
// append and schema validation, per memledger_test.go's own doc comment) and
// a real body directory on disk, in the SAME layout the gateway's own
// TelemetryHandler and ToolCallRecorder write (internal/gateway/witness.go,
// internal/gateway/record.go). OTW-001 (I) is internal/gateway's own; OTW-002
// (I), needing a real ledger to prove idempotent appends, is
// witnessintegration_test.go's.

const witnessTestWindow = 5 * time.Minute

// witnessPlantToolCall seeds a tool_call event whose retained body carries
// toolUseID — record.go's own gatewayToolCallBody shape, restated (the SAME
// restatement commitwatch_test.go's own commitWatchPlant already holds
// itself to).
func witnessPlantToolCall(t *testing.T, m *memLedger, dir, runID, toolUseID string) event.Fields {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"tool":            "Bash",
		"tool_use_id":     toolUseID,
		"input":           map[string]any{"command": "echo hi"},
		"result_observed": true,
		"result":          "hi\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := plantCommitWatchBody(t, dir, runID, raw)
	record, aerr := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "tool/" + runID + "/" + toolUseID,
		event.FieldToolName:       "Bash",
		event.FieldPayloadDigest:  digest,
	})
	if aerr != nil {
		t.Fatalf("seed tool_call: %v", aerr)
	}
	return record
}

// witnessPlantTelemetry writes one telemetry record where TelemetryHandler
// itself would (internal/gateway/witness.go's own dir/telemetry/
// <tool_use_id>.json), so this pass reads the SAME on-disk shape the
// gateway actually produces rather than a hand-tuned stand-in for it.
func witnessPlantTelemetry(t *testing.T, dir, toolUseID string, success bool, receivedAt time.Time) {
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
	path := filepath.Join(telDir, toolUseID+".json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("writing telemetry record: %v", err)
	}
	// The pass reads a record's receive time from the file, as the gateway
	// leaves it; stamp it with the test's own clock.
	if err := os.Chtimes(path, receivedAt, receivedAt); err != nil {
		t.Fatalf("stamping telemetry record: %v", err)
	}
}

// runWitnessPass builds a reconciler with only Witness configured, over
// clock c, and runs one cycle.
func runWitnessPass(t *testing.T, m *memLedger, logDir string, c *clock, window time.Duration) reconciler.WitnessReport {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger:      m,
		Appender:    m,
		Repos:       &fakeRepos{},
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         c.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Witness:     &reconciler.WitnessConfig{LogDir: logDir, Window: window},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result.Witness
}

// ---------------------------------------------------------------------------
// OTW-003: matching tool calls raise no alert.
// ---------------------------------------------------------------------------

func TestOTW003MatchingToolCallsRaiseNoAlert(t *testing.T) {
	const runID = "run-otw-003-match"
	c := &clock{at: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, runID)
	logDir := t.TempDir()

	toolCall := witnessPlantToolCall(t, m, logDir, runID, "toolu_otw003_match")
	witnessPlantTelemetry(t, logDir, "toolu_otw003_match", true, c.at)

	report := runWitnessPass(t, m, logDir, c, witnessTestWindow)
	if !report.Enabled {
		t.Fatal("the pass reported itself disabled with a WitnessConfig given")
	}
	if !report.TelemetryActive {
		t.Error("TelemetryActive = false, want true (a telemetry record exists)")
	}
	if report.Checked != 1 {
		t.Errorf("checked %d, want 1", report.Checked)
	}
	if report.Matched != 1 {
		t.Errorf("matched %d, want 1", report.Matched)
	}
	if report.Missing != 0 {
		t.Errorf("missing %d, want 0: %+v", report.Missing, report.Findings)
	}
	if report.Orphaned != 0 {
		t.Errorf("orphaned %d, want 0: %+v", report.Orphaned, report.Findings)
	}
	if len(report.Appended) != 0 {
		t.Errorf("appended %v, want none", report.Appended)
	}
	_ = toolCall
}

// TestOTW003TelemetryArrivingLateInsideTheWindowRaisesNoAlert: the tool_call
// is relayed; telemetry for it has not arrived yet when the first cycle
// runs (well inside the window) -- no alert, and no ledger write. It then
// arrives, still inside the window, and a second cycle finds it matched --
// still no alert, ever, for this tool_use_id.
func TestOTW003TelemetryArrivingLateInsideTheWindowRaisesNoAlert(t *testing.T) {
	const runID = "run-otw-003-late"
	// A real wall-clock start, not an arbitrary fixed date: TelemetrySince
	// is derived from a telemetry file's own mtime (a REAL filesystem
	// timestamp, internal/gateway/witness.go's own atomic write — see
	// witness.go's own package doc comment, "Deriving telemetry active
	// since"), while every ledger timestamp in this test comes from this
	// clock. The two must agree on what "now" roughly is for the
	// TelemetrySince/call.at ordering below to mean anything.
	start := time.Now().UTC()
	c := &clock{at: start}
	m := newMemLedger(c.now)
	seedRun(t, m, runID)
	logDir := t.TempDir()

	// An older, already-corroborated call establishes that telemetry HAS
	// been active since before the call under test -- otherwise the call
	// under test would simply be excluded (telemetry not yet proven active)
	// rather than genuinely "pending", and this test would not be exercising
	// the window logic OTW-003 is about.
	witnessPlantToolCall(t, m, logDir, runID, "toolu_otw003_baseline")
	witnessPlantTelemetry(t, logDir, "toolu_otw003_baseline", true, start)

	// A clear margin past the baseline telemetry file's own (real) mtime,
	// so the call under test is unambiguously AFTER TelemetrySince however
	// many milliseconds the write above actually took.
	c.at = c.at.Add(1 * time.Second)
	toolCall := witnessPlantToolCall(t, m, logDir, runID, "toolu_otw003_late")
	toolCallID := str(toolCall, event.FieldEventID)

	// Cycle 1: well inside the window, no telemetry yet for this call.
	first := runWitnessPass(t, m, logDir, c, witnessTestWindow)
	if first.Pending == 0 {
		t.Errorf("pending %d, want at least 1 (telemetry has not arrived, window not yet passed)",
			first.Pending)
	}
	if first.Missing != 0 {
		t.Fatalf("missing %d, want 0: a call still inside its window must never alert: %+v",
			first.Missing, first.Findings)
	}
	if len(first.Appended) != 0 {
		t.Fatalf("appended %v, want none", first.Appended)
	}

	// The telemetry arrives, late but still inside the window.
	c.at = c.at.Add(1 * time.Minute)
	witnessPlantTelemetry(t, logDir, "toolu_otw003_late", true, c.at)

	// Cycle 2: still inside the window (2 minutes elapsed of a 5 minute
	// one), and now matched.
	second := runWitnessPass(t, m, logDir, c, witnessTestWindow)
	if second.Missing != 0 {
		t.Fatalf("missing %d, want 0: %+v", second.Missing, second.Findings)
	}
	if len(second.Appended) != 0 {
		t.Fatalf("appended %v, want none -- a late-but-in-window arrival is never an alert", second.Appended)
	}
	t.Logf("OTW-003: tool_call %s corroborated by telemetry that arrived %s after it, inside a %s window",
		toolCallID, 1*time.Minute, witnessTestWindow)
}

// TestWitnessReportsTelemetryInactiveWhenNoneEverArrived: a deployment that
// never enabled telemetry must not alert on every tool call it relays --
// the pass reports itself OFF (TelemetryActive=false) rather than treating
// silence as drift.
func TestWitnessReportsTelemetryInactiveWhenNoneEverArrived(t *testing.T) {
	const runID = "run-otw-003-off"
	c := &clock{at: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, runID)
	logDir := t.TempDir()

	witnessPlantToolCall(t, m, logDir, runID, "toolu_otw003_off")
	// Advance well past any reasonable window; still no alert, because
	// telemetry was never active.
	c.at = c.at.Add(24 * time.Hour)

	report := runWitnessPass(t, m, logDir, c, witnessTestWindow)
	if report.TelemetryActive {
		t.Error("TelemetryActive = true, want false: no telemetry record was ever written")
	}
	if report.Missing != 0 {
		t.Errorf("missing %d, want 0: a deployment with telemetry off must not alert on every "+
			"tool call it relays: %+v", report.Missing, report.Findings)
	}
	if len(report.Appended) != 0 {
		t.Errorf("appended %v, want none", report.Appended)
	}
}

// TestWitnessDisabledWithNoConfig: Result.Witness.Enabled is false, and
// nothing about this pass runs, when Config.Witness is nil.
func TestWitnessDisabledWithNoConfig(t *testing.T) {
	const runID = "run-otw-disabled"
	c := &clock{at: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, runID)

	r, err := reconciler.New(reconciler.Config{
		Ledger: m, Appender: m, Repos: &fakeRepos{}, Log: &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain, Now: c.now,
		Alert: func(context.Context, reconciler.Finding) {}, Observe: func(reconciler.Result, error) {},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Witness.Enabled {
		t.Error("Witness.Enabled = true with no Config.Witness given")
	}
}

// A tool call relayed long before telemetry began arriving can be neither
// matched nor missed, so it is not counted as checked and its body is not
// read: measured on a live chain, 38,551 calls were "checked" each cycle
// against 6 that telemetry could cover.
func TestWitnessSkipsToolCallsFromBeforeTelemetryWasActive(t *testing.T) {
	const runID = "run-witness-before"
	c := &clock{at: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, runID)
	logDir := t.TempDir()

	old := witnessPlantToolCall(t, m, logDir, runID, "toolu_witness_old")
	// Its body is gone: a pass that still read it would count it unchecked.
	if err := os.RemoveAll(filepath.Join(logDir, runID)); err != nil {
		t.Fatal(err)
	}
	c.at = c.at.Add(10 * witnessTestWindow)
	witnessPlantToolCall(t, m, logDir, runID, "toolu_witness_new")
	witnessPlantTelemetry(t, logDir, "toolu_witness_new", true, c.at)

	report := runWitnessPass(t, m, logDir, c, witnessTestWindow)
	if report.Checked != 1 || report.Unchecked != 0 || report.Matched != 1 {
		t.Fatalf("Witness = %+v, want only the call telemetry could cover counted", report)
	}
	_ = old
}

// TestWitnessJudgesARunOnlyOnceItsOwnTelemetryArrived — #434. Telemetry is a
// property of the harness that ran a session, not of the machine. Measured on
// 2026-10-01: one session exported telemetry, and from then on every tool
// call of every other session, none of which exported any, was appended as
// ledger_drift_detected (2076 of them in a day). A run whose own calls have
// never been matched by a telemetry record proves nothing by an absence.
func TestWitnessJudgesARunOnlyOnceItsOwnTelemetryArrived(t *testing.T) {
	const withTel, without = "run-witness-tel", "run-witness-notel"
	c := &clock{at: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	m := newMemLedger(c.now)
	seedRun(t, m, withTel)
	seedRun(t, m, without)
	logDir := t.TempDir()

	witnessPlantToolCall(t, m, logDir, withTel, "toolu_witness_tel_a")
	witnessPlantTelemetry(t, logDir, "toolu_witness_tel_a", true, c.at)
	witnessPlantToolCall(t, m, logDir, without, "toolu_witness_notel_a")
	c.at = c.at.Add(time.Minute)
	// The telemetry run then has a call its harness never reported: that one
	// is drift, and must still be found.
	witnessPlantToolCall(t, m, logDir, withTel, "toolu_witness_tel_b")
	c.at = c.at.Add(3 * witnessTestWindow)

	report := runWitnessPass(t, m, logDir, c, witnessTestWindow)
	if report.Missing != 1 {
		t.Fatalf("Witness = %+v, want exactly one missing call: the telemetry run's own", report)
	}
	for _, f := range report.Findings {
		if f.RunID == without {
			t.Errorf("a run that never exported telemetry was judged: %+v", f)
		}
	}
	if report.RunsWithoutTelemetry != 1 {
		t.Errorf("RunsWithoutTelemetry = %d, want 1 (reported, never appended)", report.RunsWithoutTelemetry)
	}
}

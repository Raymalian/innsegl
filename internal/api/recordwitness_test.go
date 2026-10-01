// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RPG-005: each witness state, and the whole-run summary.

func TestRPG005TelemetryWitnessStates(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	window := defaultRecordWitnessWindow

	cases := []struct {
		name    string
		active  bool
		matched bool
		callAt  time.Time
		want    string
	}{
		{"matched wins regardless of window", true, true, now, "matched"},
		{"inactive: telemetry never active", false, false, now, "inactive"},
		{"inactive: call predates telemetry", true, false, since.Add(-time.Minute), "inactive"},
		{"pending: inside the window", true, false, now.Add(-time.Second), "pending"},
		{"missing: past the window, no match", true, false, now.Add(-window - time.Minute), "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := telemetryWitness(c.active, since, c.matched, c.callAt, now, window)
			if got != c.want {
				t.Errorf("telemetryWitness(active=%v, matched=%v, callAt=%v) = %q, want %q",
					c.active, c.matched, c.callAt, got, c.want)
			}
		})
	}
}

func TestRPG005StepWitnessesGateway(t *testing.T) {
	now := time.Now().UTC()
	// Present: a verified body carrying a usable tool_use_id.
	w := stepWitnesses("", gatewayBody{ToolUseID: "toolu_1"}, true, "", "", false, time.Time{}, now, now, time.Minute)
	if w.Gateway != "present" {
		t.Errorf("Gateway = %q, want present", w.Gateway)
	}
	// Missing: no body at all.
	w = stepWitnesses("", gatewayBody{}, false, "", "", false, time.Time{}, now, now, time.Minute)
	if w.Gateway != "missing" {
		t.Errorf("Gateway = %q, want missing", w.Gateway)
	}
	// Missing: a body that parsed but named no tool_use_id at all (never
	// gateway-recorded).
	w = stepWitnesses("", gatewayBody{}, true, "", "", false, time.Time{}, now, now, time.Minute)
	if w.Gateway != "missing" {
		t.Errorf("Gateway = %q, want missing for a body with no tool_use_id", w.Gateway)
	}
}

func TestRPG005StepWitnessesSnapshot(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name, before, after, want string
	}{
		{"no snapshot taken", "aaaa", "", "none"},
		{"unchanged", "aaaa", "aaaa", "unchanged"},
		{"changed", "aaaa", "bbbb", "changed"},
		{"no baseline but a snapshot exists", "", "bbbb", "changed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := stepWitnesses("", gatewayBody{}, false, c.before, c.after, false, time.Time{}, now, now, time.Minute)
			if w.Snapshot != c.want {
				t.Errorf("Snapshot(before=%q,after=%q) = %q, want %q", c.before, c.after, w.Snapshot, c.want)
			}
		})
	}
}

func TestRPG005StepWitnessesTelemetryIntegration(t *testing.T) {
	dir := t.TempDir()
	telDir := filepath.Join(dir, "telemetry")
	if err := os.MkdirAll(telDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec, err := json.Marshal(struct {
		ToolUseID string `json:"tool_use_id"`
	}{"toolu_matched"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(telDir, "toolu_matched.json"), rec, 0o600); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	since := now.Add(-time.Hour)
	body := gatewayBody{ToolUseID: "toolu_matched"}
	w := stepWitnesses(dir, body, true, "", "", true, since, now, now, defaultRecordWitnessWindow)
	if w.Telemetry != "matched" {
		t.Errorf("Telemetry = %q, want matched", w.Telemetry)
	}

	body2 := gatewayBody{ToolUseID: "toolu_unmatched"}
	w2 := stepWitnesses(dir, body2, true, "", "", true, since,
		now.Add(-defaultRecordWitnessWindow-time.Minute), now, defaultRecordWitnessWindow)
	if w2.Telemetry != "missing" {
		t.Errorf("Telemetry = %q, want missing", w2.Telemetry)
	}
}

func TestRPG005SummarizeWitness(t *testing.T) {
	steps := []RecordStep{
		{Outcome: RecordOutcome{Kind: "ok"}, Witnesses: RecordWitnesses{Gateway: "present", Snapshot: "changed", Telemetry: "matched"}},
		{Outcome: RecordOutcome{Kind: "ok"}, Witnesses: RecordWitnesses{Gateway: "present", Snapshot: "unchanged", Telemetry: "inactive"}},
		{Outcome: RecordOutcome{Kind: "unknown"}, Witnesses: RecordWitnesses{Gateway: "missing", Snapshot: "none", Telemetry: "missing"}},
		{Outcome: RecordOutcome{Kind: "ok"}, Witnesses: RecordWitnesses{Gateway: "present", Snapshot: "changed", Telemetry: "pending"}},
		{Outcome: RecordOutcome{Kind: "ok"}, Witnesses: RecordWitnesses{Gateway: "missing", Snapshot: "changed", Telemetry: "matched"}},
	}
	w := summarizeWitness(steps, 3, 2)
	if w.Steps != 5 {
		t.Errorf("Steps = %d, want 5", w.Steps)
	}
	if w.Agree != 2 {
		t.Errorf("Agree = %d, want 2 (steps 1 and 2)", w.Agree)
	}
	if w.Unchecked != 2 {
		t.Errorf("Unchecked = %d, want 2 (unknown body, telemetry pending)", w.Unchecked)
	}
	if w.Disagree != 1 {
		t.Errorf("Disagree = %d, want 1 (gateway missing but body present)", w.Disagree)
	}
	if w.BodiesStored != 3 || w.BodiesVerified != 2 {
		t.Errorf("BodiesStored=%d BodiesVerified=%d, want 3, 2", w.BodiesStored, w.BodiesVerified)
	}
}

// TestSettleRunWitnessesJudgesEachWitnessPerRun — #438. A witness is judged
// only for a run where it was ever active. Measured on 2026-10-01: a run
// recorded through the hook, which never exported telemetry and never had a
// workspace snapshot, showed "1 of 3 witnesses" in red on every step.
func TestSettleRunWitnessesJudgesEachWitnessPerRun(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 4, 0, 0, 0, time.UTC)
	step := func(n int, at time.Time, snap, tel string) RecordStep {
		return RecordStep{N: n, At: at, Witnesses: RecordWitnesses{Gateway: "present", Snapshot: snap, Telemetry: tel}}
	}

	// A run with neither witness ever active: both are inactive, not failed.
	bare := []RecordStep{step(1, t0, "none", "missing"), step(2, t0.Add(time.Minute), "none", "pending")}
	settleRunWitnesses(bare)
	for _, st := range bare {
		if st.Witnesses.Snapshot != "inactive" || st.Witnesses.Telemetry != "inactive" {
			t.Errorf("step %d of a run with no snapshots and no telemetry = %+v, want both inactive", st.N, st.Witnesses)
		}
	}

	// A run whose telemetry started at step 2: step 1 is inactive, step 3's
	// absence is real. A step with no snapshot in a run that has them stays none.
	live := []RecordStep{
		step(1, t0, "changed", "missing"),
		step(2, t0.Add(time.Minute), "none", "matched"),
		step(3, t0.Add(2*time.Minute), "unchanged", "missing"),
	}
	settleRunWitnesses(live)
	if got := live[0].Witnesses.Telemetry; got != "inactive" {
		t.Errorf("step 1, before the run's telemetry began: telemetry = %q, want inactive", got)
	}
	if got := live[2].Witnesses.Telemetry; got != "missing" {
		t.Errorf("step 3, after the run's telemetry began: telemetry = %q, want missing", got)
	}
	if got := live[1].Witnesses.Snapshot; got != "none" {
		t.Errorf("step 2, no snapshot in a run that has them: snapshot = %q, want none", got)
	}
}

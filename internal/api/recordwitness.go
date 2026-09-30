// SPDX-License-Identifier: Apache-2.0

package api

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// recordwitness.go derives record.go's RecordWitnesses for one step — the
// SAME three witnesses ADR-0057 names and internal/reconciler already
// judges two of, reused here rather than reinvented so a step this page
// marks "matched" or "missing" can never disagree with a
// ledger_drift_detected the reconciler appended about the identical call.
//
// # Telemetry: internal/reconciler/witness.go's own rule, restated
//
// checkWitness (that file) is the one place this project decides whether a
// tool call's own telemetry is matched, missing, pending or the window
// simply had not started yet. Its helpers (listTelemetry,
// telemetryActiveSince, telemetryExists, telemetryDir, DefaultWitnessWindow)
// are unexported to the reconciler package, so this file restates the
// reading exactly — same directory layout, same window, same "active
// since" derivation from file mtimes — the same restatement discipline
// commitwatch.go and writes.go already hold each other to for
// gatewayToolCallBody.
//
// # Gateway and snapshot: this file's own reading of record.go's contract
//
// "Gateway: present (the gateway relayed and stored it) or missing" —
// present when this step's own body is available, verified, and parses as
// a gateway-recorded shape with a usable tool_use_id (the same "Checked"
// gate witness.go's own direction 1 holds its tool_call bodies to);
// missing for every other reason, including one this process simply cannot
// read right now.
//
// "Snapshot: changed, unchanged or none" — none when this step took no
// snapshot at all (TreeAfter == ""); unchanged when TreeBefore and
// TreeAfter are both known and equal; changed otherwise — which also
// covers a step whose TreeBefore is unknown (record.go's own "no earlier
// snapshot to compare against"): this process has evidence of the tree
// AFTER the step and none before it, and "changed" is the reading that
// does not claim more than that.

// defaultRecordWitnessWindow mirrors internal/reconciler's own
// DefaultWitnessWindow: the same few minutes, generous against the
// harness's own export interval and the gateway's own asynchronous
// recording, so a step this page shows seconds after it happened reads
// "pending" rather than "missing".
const defaultRecordWitnessWindow = 5 * time.Minute

func telemetryDirPath(logDir string) string { return filepath.Join(logDir, "telemetry") }

// telemetryEntry is one file under telemetryDir, read cheaply — a
// directory listing's own stat, never a body read, matching
// internal/reconciler/witness.go's own reasoning for why mtime IS the
// record's own receive time (the atomic rename in
// internal/gateway/witness.go).
type telemetryEntry struct {
	toolUseID  string
	receivedAt time.Time
}

func listTelemetryEntries(logDir string) ([]telemetryEntry, bool) {
	entries, err := os.ReadDir(telemetryDirPath(logDir))
	if err != nil {
		return nil, false
	}
	out := make([]telemetryEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		out = append(out, telemetryEntry{toolUseID: strings.TrimSuffix(name, ".json"), receivedAt: info.ModTime()})
	}
	return out, true
}

func telemetryActiveSinceEntries(entries []telemetryEntry) (time.Time, bool) {
	var since time.Time
	found := false
	for _, e := range entries {
		if !found || e.receivedAt.Before(since) {
			since = e.receivedAt
			found = true
		}
	}
	return since, found
}

func telemetryEntryExists(logDir, toolUseID string) bool {
	_, err := os.Stat(filepath.Join(telemetryDirPath(logDir), toolUseID+".json"))
	return err == nil
}

// telemetryWitness is the pure core internal/reconciler's own checkWitness
// direction 1 folds inline; split out here so RPG-005 can assert each of
// the four states directly, the same way commitwatch.go's commitShortSHA is
// split from its own caller.
func telemetryWitness(active bool, since time.Time, matched bool, callAt, now time.Time, window time.Duration) string {
	switch {
	case matched:
		return "matched"
	case !active || callAt.Before(since):
		return "inactive"
	case now.Sub(callAt) < window:
		return "pending"
	default:
		return "missing"
	}
}

// stepWitnesses derives RecordWitnesses for one step.
func stepWitnesses(
	logDir string, body gatewayBody, bodyAvailable bool,
	treeBefore, treeAfter string,
	telemetryActive bool, telemetrySince time.Time, callAt, now time.Time, window time.Duration,
) RecordWitnesses {
	// Telemetry defaults to "missing" rather than "inactive": the default
	// applies when this step's own tool_use_id could not be read at all (an
	// unavailable or unparseable body), and "inactive" is a specific claim
	// about the deployment's telemetry — this process simply has nothing to
	// check a match against, which "missing" states without asserting more
	// than that.
	w := RecordWitnesses{Gateway: "missing", Snapshot: "none", Telemetry: "missing"}

	if bodyAvailable && body.ToolUseID != "" {
		w.Gateway = "present"
	}

	switch {
	case treeAfter == "":
		w.Snapshot = "none"
	case treeBefore != "" && treeBefore == treeAfter:
		w.Snapshot = "unchanged"
	default:
		w.Snapshot = "changed"
	}

	if bodyAvailable && body.ToolUseID != "" {
		matched := logDir != "" && telemetryEntryExists(logDir, body.ToolUseID)
		w.Telemetry = telemetryWitness(telemetryActive, telemetrySince, matched, callAt, now, window)
	}

	return w
}

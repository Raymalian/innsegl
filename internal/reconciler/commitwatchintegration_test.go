// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/reconciler"
)

// RM-244 (#389). The test ID this file drives, from doc 07:
//
//	CMT-016  A git commit tool call whose result shows a new commit, with no
//	         commit_recorded for that commit on the run — signing disabled or
//	         bypassed — raises exactly one ledger_drift_detected whose
//	         subject is that tool_call and whose reason names an unsigned
//	         commit. A second pass over the same chain state adds none.
//
// Against a REAL Postgres ledger — harness_test.go's freshStore, the same
// shared container every other case in this package uses — and a REAL body
// on disk, in the SAME (run, digest) layout the gateway's own body store
// writes (internal/mcp/observe.go's observeWriteBody, read back by
// readRunBody in writes.go). This pass never asks Rekor or a repository
// anything — it reads the chain and a retained body — so *fakeRepos and
// *fakeLog stand in for those two exactly as they do in commitwatch_test.go's
// own unit cases; nothing here needs the Docker Compose SPIRE/Sigstore stack
// integration_test.go and driftintegration_test.go bring up for their own
// claims.
//
// The commit itself is real, made by an actual `git` subprocess with signing
// and hooks disabled in an isolated scratch repository — the SAME
// gitSignedCommit helper commitwatch_test.go's own "a commit that was
// signed" case uses, reused here for the opposite ledger state: this case
// never appends a commit_recorded for the sha it names, which is what makes
// the commit UNSIGNED as far as this pass is concerned. So the one line this
// pass parses is proven against git's own bytes end to end, never a
// hand-written stand-in for them.

const cmtIntegrationTimeout = 2 * time.Minute

func cmtSpiffeID(runID string) string {
	return fmt.Sprintf("spiffe://%s/agent/demo/rm-244/%s", testTrustDomain, runID)
}

func cmtSeedRun(ctx context.Context, t *testing.T, store *ledger.Store, runID string) {
	t.Helper()
	if _, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       cmtSpiffeID(runID),
		event.FieldIdempotencyKey: "register/" + runID,
		event.FieldAgentType:      "demo",
		event.FieldTaskRef:        "rm-244",
		event.FieldRepo:           "github.com/innsegl/cmt016",
		event.FieldBranch:         "main",
	}); err != nil {
		t.Fatalf("seed run_registered: %v", err)
	}
}

// cmtSeedToolCall appends the tool_call event a Bash `git commit` produces,
// naming the digest of a body already planted on disk by
// plantCommitWatchBody (commitwatch_test.go).
func cmtSeedToolCall(ctx context.Context, t *testing.T, store *ledger.Store, runID, digest string) event.Fields {
	t.Helper()
	record, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       cmtSpiffeID(runID),
		event.FieldIdempotencyKey: "tool/" + runID + "/" + digest[7:19],
		event.FieldToolName:       "Bash",
		event.FieldPayloadDigest:  digest,
	})
	if err != nil {
		t.Fatalf("seed tool_call: %v", err)
	}
	return record
}

// TestCMT016AnUnsignedCommitRaisesLedgerDrift is CMT-016.
//
//nolint:gocyclo // one measured fact per block; splitting the two cycles from what they assert would separate the evidence from what it proves.
func TestCMT016AnUnsignedCommitRaisesLedgerDrift(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), cmtIntegrationTimeout)
	defer cancel()

	store, _ := freshStore(t)
	const runID = "run-cmt-016"
	cmtSeedRun(ctx, t, store, runID)

	// The real commit. Signing is disabled on the subprocess itself, exactly
	// as an agent bypassing ADR-0059's hook would leave it — nothing about
	// THIS call is what makes the commit unsigned; what makes it unsigned is
	// that no commit_recorded is ever appended for the sha it produces.
	result, sha := gitSignedCommit(t)
	t.Logf("real git output, commit %s:\n%s", sha, result)

	logDir := t.TempDir()
	inputRaw, err := json.Marshal(map[string]any{"command": bypassCommand})
	if err != nil {
		t.Fatal(err)
	}
	resultRaw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	bodyRaw, err := json.Marshal(map[string]any{
		"tool": "Bash", "input": json.RawMessage(inputRaw),
		"result_observed": true, "result": json.RawMessage(resultRaw),
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := plantCommitWatchBody(t, logDir, runID, bodyRaw)
	toolCall := cmtSeedToolCall(ctx, t, store, runID, digest)
	toolCallID := str(toolCall, event.FieldEventID)

	var alerts []reconciler.CommitWatchFinding
	build := func() *reconciler.Reconciler {
		alerts = nil
		r, nerr := reconciler.New(reconciler.Config{
			Ledger: store, Appender: store,
			Repos: &fakeRepos{}, Log: &fakeLog{entries: map[string]reconciler.LogEntry{}},
			TrustDomain: testTrustDomain,
			Alert:       func(context.Context, reconciler.Finding) {},
			Observe:     func(reconciler.Result, error) {},
			CommitWatch: &reconciler.CommitWatchConfig{
				LogDir: logDir,
				Alert: func(_ context.Context, f reconciler.CommitWatchFinding) {
					alerts = append(alerts, f)
					t.Logf("commit watch alert: %s: %s", f.Reason, f.Detail)
				},
			},
		})
		if nerr != nil {
			t.Fatalf("reconciler.New: %v", nerr)
		}
		return r
	}

	// -----------------------------------------------------------------------
	// The first cycle: one alert, naming the tool call.
	// -----------------------------------------------------------------------
	first, err := build().Reconcile(ctx)
	if err != nil {
		t.Fatalf("the first cycle failed: %v", err)
	}
	if !first.CommitWatch.Enabled {
		t.Fatal("commit watch reported itself disabled with a CommitWatchConfig given")
	}
	if first.CommitWatch.Checked != 1 {
		t.Fatalf("checked %d, want 1", first.CommitWatch.Checked)
	}
	if first.CommitWatch.Unsigned != 1 {
		t.Fatalf("unsigned %d, want 1: %+v", first.CommitWatch.Unsigned, first.CommitWatch.Findings)
	}
	if len(first.CommitWatch.Appended) != 1 {
		t.Fatalf("appended %v, want exactly one alert", first.CommitWatch.Appended)
	}
	if len(alerts) != 1 {
		t.Fatalf("the operator sink saw %d alerts, want 1: %+v", len(alerts), alerts)
	}

	alert := onlyEvent(ctx, t, store, runID, event.EventTypeLedgerDriftDetected)
	if got := str(alert, event.FieldSubjectEventID); got != toolCallID {
		t.Fatalf("the alert names subject %s, want the tool_call %s", got, toolCallID)
	}
	if got := str(alert, event.FieldEventID); got != first.CommitWatch.Appended[0] {
		t.Fatalf("the appended event id %s does not match the one on the chain %s",
			first.CommitWatch.Appended[0], got)
	}
	reason := str(alert, event.FieldReason)
	if reason == "" || !strings.Contains(reason, "signature") {
		t.Fatalf("the alert's reason %q does not name an unsigned commit", reason)
	}
	if got := str(alert, event.FieldRunID); got != runID {
		t.Fatalf("the alert names run %q, want %q", got, runID)
	}
	t.Logf("CMT-016: ledger_drift_detected %s names subject %s, reason %q",
		str(alert, event.FieldEventID), toolCallID, reason)

	// -----------------------------------------------------------------------
	// Idempotency: a FRESH reconciler over the same chain state appends
	// nothing — REC-005's own property, held here for this pass.
	// -----------------------------------------------------------------------
	countBefore, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	second, err := build().Reconcile(ctx)
	if err != nil {
		t.Fatalf("the second cycle failed: %v", err)
	}
	if len(second.CommitWatch.Appended) != 0 {
		t.Fatalf("a fresh second reconciler appended %v", second.CommitWatch.Appended)
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
		t.Fatalf("the chain does not verify after the alert: %v", verr)
	}
	t.Logf("idempotent: cycle two appended nothing; the chain is %d events and verifies", countAfter)
}

// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// Pure-function unit coverage for recordagent.go, alongside the
// Postgres-backed assertions in recordagent_test.go.

func TestWriteStatusOfEditFamilyIsAlwaysM(t *testing.T) {
	for _, tool := range []string{"Edit", "MultiEdit", "NotebookEdit"} {
		if got := writeStatusOf(tool, gatewayBody{}, "anything"); got != "M" {
			t.Errorf("writeStatusOf(%s) = %q, want M", tool, got)
		}
	}
}

func TestWriteStatusOfHookWrite(t *testing.T) {
	create := gatewayBody{hookShape: true, hookWriteType: "create"}
	if got := writeStatusOf("Write", create, ""); got != "A" {
		t.Errorf("writeStatusOf(hook create) = %q, want A", got)
	}
	update := gatewayBody{hookShape: true, hookWriteType: "update"}
	if got := writeStatusOf("Write", update, ""); got != "M" {
		t.Errorf("writeStatusOf(hook update) = %q, want M", got)
	}
	unknown := gatewayBody{hookShape: true, hookWriteType: "something-else"}
	if got := writeStatusOf("Write", unknown, ""); got != "W" {
		t.Errorf("writeStatusOf(hook unrecognised type) = %q, want W", got)
	}
}

func TestWriteStatusOfGatewayWrite(t *testing.T) {
	if got := writeStatusOf("Write", gatewayBody{}, "File created successfully at: a.go"); got != "A" {
		t.Errorf("writeStatusOf(gateway create) = %q, want A", got)
	}
	if got := writeStatusOf("Write", gatewayBody{}, "The file a.go has been updated"); got != "M" {
		t.Errorf("writeStatusOf(gateway update) = %q, want M", got)
	}
	if got := writeStatusOf("Write", gatewayBody{}, "something unrecognised"); got != "W" {
		t.Errorf("writeStatusOf(gateway unrecognised) = %q, want W", got)
	}
}

func TestChildEndedAtRetiredWins(t *testing.T) {
	retiredAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	got := childEndedAt(ledger.RunFacts{}, ledger.RunRetired, retiredAt, true)
	if got == nil || !got.Equal(retiredAt) {
		t.Errorf("childEndedAt(retired) = %v, want %v", got, retiredAt)
	}
}

func TestChildEndedAtLapsedUsesLastActivity(t *testing.T) {
	lastActivity := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	got := childEndedAt(ledger.RunFacts{LastActivityAt: lastActivity}, ledger.RunLapsed, time.Time{}, false)
	if got == nil || !got.Equal(lastActivity) {
		t.Errorf("childEndedAt(lapsed) = %v, want %v", got, lastActivity)
	}
}

func TestChildEndedAtAbandonedUsesLastActivity(t *testing.T) {
	lastActivity := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	got := childEndedAt(ledger.RunFacts{LastActivityAt: lastActivity}, ledger.RunAbandoned, time.Time{}, false)
	if got == nil || !got.Equal(lastActivity) {
		t.Errorf("childEndedAt(abandoned) = %v, want %v", got, lastActivity)
	}
}

func TestChildEndedAtLapsedWithNoActivityYetIsNil(t *testing.T) {
	if got := childEndedAt(ledger.RunFacts{}, ledger.RunLapsed, time.Time{}, false); got != nil {
		t.Errorf("childEndedAt(lapsed, no activity recorded) = %v, want nil", got)
	}
}

func TestChildEndedAtActiveIsNil(t *testing.T) {
	if got := childEndedAt(ledger.RunFacts{}, ledger.RunActive, time.Time{}, false); got != nil {
		t.Errorf("childEndedAt(active) = %v, want nil", got)
	}
}

func TestReportedOfSubagentHandbackUnparseableMessageIsUnavailable(t *testing.T) {
	steps := []RecordStep{
		{N: 1, Tool: "SubagentHandback", Input: `not json`},
	}
	got := reportedOf(steps, []RecordMessage{{Text: "a reply", Available: true}})
	if got.Available {
		t.Errorf("reportedOf = %+v, want unavailable — the LAST SubagentHandback step's own message did not parse, never fall through", got)
	}
}

func TestReportedOfFallsBackToTheLastAvailableReply(t *testing.T) {
	replies := []RecordMessage{
		{Text: "first", Available: true},
		{Text: "unavailable", Available: false},
		{Text: "last available", Available: true},
	}
	got := reportedOf(nil, replies)
	if !got.Available || got.Text != "last available" || got.Step != 0 {
		t.Errorf("reportedOf = %+v, want the last AVAILABLE reply, step 0", got)
	}
}

func TestReportedOfNothingAtAllIsUnavailable(t *testing.T) {
	if got := reportedOf(nil, nil); got.Available {
		t.Errorf("reportedOf(nothing) = %+v, want unavailable", got)
	}
}

func TestSignedStepForTooShortShaAnswersZero(t *testing.T) {
	if got := signedStepFor([]RecordStep{{N: 1, Output: "signed abc"}}, "abc"); got != 0 {
		t.Errorf("signedStepFor(short sha) = %d, want 0", got)
	}
}

func TestSignedStepForNoMatchAnswersZero(t *testing.T) {
	sha := "deadbeef" + "0123456789abcdef0123456789abcdef0"
	if got := signedStepFor([]RecordStep{{N: 1, Output: "nothing relevant here"}}, sha); got != 0 {
		t.Errorf("signedStepFor(no match) = %d, want 0", got)
	}
}

func TestSignedStepForFirstMatchWins(t *testing.T) {
	sha := "abc1234" + "0123456789abcdef0123456789abcdef0"
	steps := []RecordStep{
		{N: 1, Output: "unrelated"},
		{N: 2, Output: "innsegl-commit: signed abc1234  rekor index 1"},
		{N: 3, Output: "innsegl-commit: signed abc1234  rekor index 1"},
	}
	if got := signedStepFor(steps, sha); got != 2 {
		t.Errorf("signedStepFor = %d, want 2 (the first step whose output names it)", got)
	}
}

func TestAncestorChainOfNoParentIsEmpty(t *testing.T) {
	if got := ancestorChainOf(nil, ""); got != nil {
		t.Errorf("ancestorChainOf(no parent) = %+v, want nil", got)
	}
}

func TestAncestorChainOfWalksToTheRootAndReverses(t *testing.T) {
	family := []familyNode{
		{RunID: "root"},
		{RunID: "mid", ParentRunID: "root"},
		{RunID: "parent", ParentRunID: "mid"},
	}
	got := ancestorChainOf(family, "parent")
	if len(got) != 3 {
		t.Fatalf("got %d ancestors, want 3: %+v", len(got), got)
	}
	if got[0].RunID != "root" || got[1].RunID != "mid" || got[2].RunID != "parent" {
		t.Errorf("ancestorChainOf order = %v, want root, mid, parent", []string{got[0].RunID, got[1].RunID, got[2].RunID})
	}
}

func TestAncestorChainOfCapsAtMaxLineageDepth(t *testing.T) {
	// A chain of 20 generations, deeper than maxLineageDepth (16).
	var family []familyNode
	prev := ""
	for i := 0; i < 20; i++ {
		id := string(rune('a' + i))
		family = append(family, familyNode{RunID: id, ParentRunID: prev})
		prev = id
	}
	got := ancestorChainOf(family, prev)
	if len(got) != maxLineageDepth {
		t.Fatalf("got %d ancestors, want the cap of %d", len(got), maxLineageDepth)
	}
}

func TestAncestorChainOfBreaksACycleRatherThanLoopingForever(t *testing.T) {
	family := []familyNode{
		{RunID: "a", ParentRunID: "b"},
		{RunID: "b", ParentRunID: "a"},
	}
	got := ancestorChainOf(family, "a")
	if len(got) > 2 {
		t.Fatalf("ancestorChainOf did not stop on a cycle: %+v", got)
	}
}

func TestIsSigningIdentity(t *testing.T) {
	if isSigningIdentity(childCounts{Steps: 0, Commits: 1}) != true {
		t.Error("zero steps, one commit should be a signing identity")
	}
	if isSigningIdentity(childCounts{Steps: 1, Commits: 1}) {
		t.Error("a run with its own tool_call is never a signing identity")
	}
	if isSigningIdentity(childCounts{Steps: 0, Commits: 0}) {
		t.Error("a run with neither is simply idle, not a signing identity")
	}
}

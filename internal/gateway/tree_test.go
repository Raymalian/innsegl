// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"
)

// GID-005 (docs/07-innsegl-test-catalog.md, TC-GID): a child whose brief
// equals a pending spawn's prompt links to that parent; containment never
// links; one spawn links one child; an agent never links to itself.

// TestTreeLinkerThreeLevelTree mirrors docs/decisions/model-gateway-spike.md
// spike 5 exactly: main -> LEAD -> WORKER, each child linked by the exact
// text of the spawning Agent tool call's prompt.
func TestTreeLinkerThreeLevelTree(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const session = "session-three-level"

	recordSpawn := func(parentRunID, prompt string) {
		t.Helper()
		if err := linker.RecordSpawn(ctx, PendingSpawn{
			ParentRunID: parentRunID,
			SessionID:   session,
			Prompt:      prompt,
		}); err != nil {
			t.Fatalf("RecordSpawn(%q -> %q): %v", parentRunID, prompt, err)
		}
	}

	// main spawns LEAD.
	recordSpawn("run-main", "lead the wave")

	leadParent, _, ok, err := linker.ResolveParent(ctx, session, "lead the wave")
	if err != nil {
		t.Fatalf("ResolveParent(LEAD): %v", err)
	}
	if !ok || leadParent != "run-main" {
		t.Fatalf("LEAD's parent = (%q, %v), want (%q, true)", leadParent, ok, "run-main")
	}

	// LEAD spawns WORKER.
	recordSpawn("run-lead", "build the widget")

	workerParent, _, ok, err := linker.ResolveParent(ctx, session, "build the widget")
	if err != nil {
		t.Fatalf("ResolveParent(WORKER): %v", err)
	}
	if !ok || workerParent != "run-lead" {
		t.Fatalf("WORKER's parent = (%q, %v), want (%q, true)", workerParent, ok, "run-lead")
	}

	// main itself has no parent: nothing was ever recorded for its own
	// brief, so it resolves as the root.
	mainParent, _, ok, err := linker.ResolveParent(ctx, session, "main's own root brief")
	if err != nil {
		t.Fatalf("ResolveParent(main): %v", err)
	}
	if ok {
		t.Fatalf("main resolved a parent (%q); the root must have none", mainParent)
	}
}

// TestTreeLinkerContainmentNeverLinks is the measured mislink itself
// (spike 5): a parent's own brief legitimately quotes a child's job text as
// a substring. Under containment this linked the parent to itself and left
// the real child unlinked; under exact equality the parent's own (longer,
// different) brief never matches, and only the child's own (identical)
// brief does.
func TestTreeLinkerContainmentNeverLinks(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const (
		session    = "session-containment"
		childJob   = "run the release checklist"
		mainsBrief = "You are the coordinator. Spawn a worker with exactly this job: " +
			"run the release checklist. Report back when it is done."
	)

	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: "run-main",
		SessionID:   session,
		Prompt:      childJob,
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}

	// mainsBrief CONTAINS childJob as a substring but does not EQUAL it.
	// A containment rule would match here; exact equality must not.
	if _, _, ok, err := linker.ResolveParent(ctx, session, mainsBrief); err != nil {
		t.Fatalf("ResolveParent(main's own brief): %v", err)
	} else if ok {
		t.Fatalf("main's own brief (which only CONTAINS the child's job text) matched a pending " +
			"spawn; containment must never link")
	}

	// The real child's brief, byte for byte the spawn's prompt, still links
	// correctly -- the spawn was not consumed by the containment attempt.
	parent, _, ok, err := linker.ResolveParent(ctx, session, childJob)
	if err != nil {
		t.Fatalf("ResolveParent(child): %v", err)
	}
	if !ok || parent != "run-main" {
		t.Fatalf("child's parent = (%q, %v), want (%q, true)", parent, ok, "run-main")
	}
}

// TestTreeLinkerNeverLinksAgentToItsOwnSpawn is ADR-0058 decision 3's own
// clause, isolated: "an agent is never linked to its own spawn". This is
// spike 5's actual observed failure -- "the first run ... linked main to
// itself" -- restated as its own assertion rather than folded into the
// containment test above.
func TestTreeLinkerNeverLinksAgentToItsOwnSpawn(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const session = "session-self-link"
	const parentRunID = "run-parent"
	const childPrompt = "do the delegated task"
	// parentBrief is the parent's OWN first-user-text: it quotes the exact
	// text it later hands to its child, but it is not, itself, that text.
	const parentBrief = "Delegate this to a subagent: do the delegated task"

	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: parentRunID,
		SessionID:   session,
		Prompt:      childPrompt,
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}

	// The parent asking about its OWN brief must never resolve to itself.
	if parent, _, ok, err := linker.ResolveParent(ctx, session, parentBrief); err != nil {
		t.Fatalf("ResolveParent(parent's own brief): %v", err)
	} else if ok {
		t.Fatalf("the parent (%q) resolved a parent for its OWN brief (got %q); "+
			"an agent must never be linked to its own spawn", parentRunID, parent)
	}
}

// TestTreeLinkerOneSpawnLinksOneChild: a matched spawn is consumed, so a
// second child (or the same child asking again) with the identical brief
// finds nothing.
func TestTreeLinkerOneSpawnLinksOneChild(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const session = "session-one-spawn"
	const prompt = "the one job"

	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: "run-parent",
		SessionID:   session,
		Prompt:      prompt,
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}

	if parent, _, ok, err := linker.ResolveParent(ctx, session, prompt); err != nil || !ok || parent != "run-parent" {
		t.Fatalf("first ResolveParent = (%q, %v, %v), want (%q, true, nil)", parent, ok, err, "run-parent")
	}

	if parent, _, ok, err := linker.ResolveParent(ctx, session, prompt); err != nil {
		t.Fatalf("second ResolveParent: %v", err)
	} else if ok {
		t.Fatalf("second ResolveParent matched an already-consumed spawn, parent %q", parent)
	}
}

// TestTreeLinkerParallelIdenticalPromptsLinkOnePerChild: two DIFFERENT
// parents in the same session each spawn a child with the identical
// prompt. Each of the two children must link to its OWN parent, oldest
// spawn first.
func TestTreeLinkerParallelIdenticalPromptsLinkOnePerChild(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const session = "session-parallel"
	const prompt = "run the same checklist"

	if err := linker.RecordSpawn(ctx, PendingSpawn{ParentRunID: "run-A", SessionID: session, Prompt: prompt}); err != nil {
		t.Fatalf("RecordSpawn(A): %v", err)
	}
	if err := linker.RecordSpawn(ctx, PendingSpawn{ParentRunID: "run-B", SessionID: session, Prompt: prompt}); err != nil {
		t.Fatalf("RecordSpawn(B): %v", err)
	}

	firstParent, _, ok, err := linker.ResolveParent(ctx, session, prompt)
	if err != nil || !ok {
		t.Fatalf("first ResolveParent = (%q, %v, %v)", firstParent, ok, err)
	}
	if firstParent != "run-A" {
		t.Fatalf("first child linked to %q, want the OLDEST spawn (run-A, FIFO)", firstParent)
	}

	secondParent, _, ok, err := linker.ResolveParent(ctx, session, prompt)
	if err != nil || !ok {
		t.Fatalf("second ResolveParent = (%q, %v, %v)", secondParent, ok, err)
	}
	if secondParent != "run-B" {
		t.Fatalf("second child linked to %q, want run-B", secondParent)
	}

	// A third child with the same prompt now finds nothing: both spawns
	// were consumed, one each.
	if _, _, ok, err := linker.ResolveParent(ctx, session, prompt); err != nil {
		t.Fatalf("third ResolveParent: %v", err)
	} else if ok {
		t.Fatal("third ResolveParent matched a spawn, but only two were ever recorded")
	}
}

// TestTreeLinkerEvictsSpawnsOlderThanWindow: a spawn older than the
// configured window is gone, whether or not it was ever matched -- memory
// tracks live spawns, not every spawn this process has ever seen.
func TestTreeLinkerEvictsSpawnsOlderThanWindow(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC))
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{
		Window: 10 * time.Minute,
		Now:    clock.Now,
	})

	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: "run-parent",
		SessionID:   "session-window",
		Prompt:      "a job that is never picked up",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	if got := linker.Stats().Pending; got != 1 {
		t.Fatalf("Pending = %d, want 1 right after recording", got)
	}

	clock.Advance(9 * time.Minute)
	if _, _, ok, err := linker.ResolveParent(ctx, "session-window", "a job that is never picked up"); err != nil {
		t.Fatalf("ResolveParent before the window elapsed: %v", err)
	} else if !ok {
		t.Fatal("the spawn was evicted before its window elapsed")
	}

	// Re-record, then advance PAST the window without ever resolving it.
	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: "run-parent",
		SessionID:   "session-window",
		Prompt:      "a second job that is never picked up",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	clock.Advance(11 * time.Minute)

	parent, _, ok, err := linker.ResolveParent(ctx, "session-window", "a second job that is never picked up")
	if err != nil {
		t.Fatalf("ResolveParent after the window elapsed: %v", err)
	}
	if ok {
		t.Fatalf("spawn older than the window still matched, parent %q", parent)
	}
	if got := linker.Stats().EvictedWindow; got == 0 {
		t.Fatal("Stats().EvictedWindow = 0, want at least one eviction recorded")
	}
}

// TestTreeLinkerCapsPendingSpawnCount: the table never grows past
// MaxPendingSpawns; at capacity, the OLDEST spawn is evicted to make room.
func TestTreeLinkerCapsPendingSpawnCount(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{MaxPendingSpawns: 3})

	prompts := []string{"job one", "job two", "job three", "job four"}
	for i, p := range prompts {
		if err := linker.RecordSpawn(ctx, PendingSpawn{
			ParentRunID: "run-parent",
			SessionID:   "session-cap",
			Prompt:      p,
		}); err != nil {
			t.Fatalf("RecordSpawn(%d): %v", i, err)
		}
	}

	stats := linker.Stats()
	if stats.Pending != 3 {
		t.Fatalf("Pending = %d, want 3 (capped)", stats.Pending)
	}
	if stats.EvictedCap != 1 {
		t.Fatalf("EvictedCap = %d, want 1", stats.EvictedCap)
	}

	// "job one" was the oldest and must have been evicted to make room.
	if _, _, ok, err := linker.ResolveParent(ctx, "session-cap", "job one"); err != nil {
		t.Fatalf("ResolveParent(job one): %v", err)
	} else if ok {
		t.Fatal("the oldest spawn (job one) should have been evicted at the cap, but it matched")
	}

	// The three most recent are still there.
	for _, p := range []string{"job two", "job three", "job four"} {
		if _, _, ok, err := linker.ResolveParent(ctx, "session-cap", p); err != nil {
			t.Fatalf("ResolveParent(%q): %v", p, err)
		} else if !ok {
			t.Fatalf("%q should still be pending", p)
		}
	}
}

// TestTreeLinkerResolveParentReturnsTheSpawnsAgentType (RM-263, #416): the
// matched spawn's own AgentType comes back alongside its parent run id, so
// a caller can register the child with the type it was actually spawned
// as, never the harness-asserted agent id ResolveParent's caller separately
// already has.
func TestTreeLinkerResolveParentReturnsTheSpawnsAgentType(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const session = "session-agent-type"

	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: "run-parent",
		SessionID:   session,
		Prompt:      "do the subtask",
		AgentType:   "code-reviewer",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}

	parent, agentType, ok, err := linker.ResolveParent(ctx, session, "do the subtask")
	if err != nil {
		t.Fatalf("ResolveParent: %v", err)
	}
	if !ok || parent != "run-parent" {
		t.Fatalf("ResolveParent = (%q, %q, %v), want parent %q", parent, agentType, ok, "run-parent")
	}
	if agentType != "code-reviewer" {
		t.Errorf("agentType = %q, want %q", agentType, "code-reviewer")
	}
}

// TestTreeLinkerResolveParentAgentTypeIsEmptyWhenTheSpawnCarriedNone: a spawn
// recorded with no AgentType at all answers an empty string, never a
// placeholder value of this linker's own invention -- deciding what an
// empty type falls back to belongs to the caller (identity.go's
// agentTypeFor), not this file.
func TestTreeLinkerResolveParentAgentTypeIsEmptyWhenTheSpawnCarriedNone(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	const session = "session-agent-type-absent"

	if err := linker.RecordSpawn(ctx, PendingSpawn{
		ParentRunID: "run-parent",
		SessionID:   session,
		Prompt:      "do the subtask",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}

	_, agentType, ok, err := linker.ResolveParent(ctx, session, "do the subtask")
	if err != nil || !ok {
		t.Fatalf("ResolveParent = (_, %q, %v, %v), want ok", agentType, ok, err)
	}
	if agentType != "" {
		t.Errorf("agentType = %q, want empty", agentType)
	}
}

// TestTreeLinkerRecordSpawnRefusesMalformedSpawns: a spawn missing its
// session id, its prompt or its parent run id is refused outright rather
// than recorded as something ResolveParent could later hand out.
func TestTreeLinkerRecordSpawnRefusesMalformedSpawns(t *testing.T) {
	ctx := context.Background()
	linker := NewInMemoryTreeLinker(TreeLinkerConfig{})

	cases := []struct {
		name  string
		spawn PendingSpawn
	}{
		{"no session id", PendingSpawn{ParentRunID: "run-parent", Prompt: "job"}},
		{"no prompt", PendingSpawn{ParentRunID: "run-parent", SessionID: "s1"}},
		{"no parent run id", PendingSpawn{SessionID: "s1", Prompt: "job"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := linker.RecordSpawn(ctx, tc.spawn); err == nil {
				t.Fatal("RecordSpawn accepted a malformed spawn, want an error")
			}
		})
	}

	if got := linker.Stats().Pending; got != 0 {
		t.Fatalf("Pending = %d, want 0: nothing malformed should have been recorded", got)
	}
}

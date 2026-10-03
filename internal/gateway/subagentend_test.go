// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sort"
	"testing"
	"time"
)

// Subagent runs ended only by the seven-day silence backstop: a session's
// end retired its main agent alone, and nothing signalled a subagent's end.
// Measured 2026-10-03: forty runs active, most of them finished subagents.

func seedSession(t *testing.T, m *fakeMappingStore) {
	t.Helper()
	for _, r := range []RunMapping{
		{RunID: "run-main", SessionID: "s1", AgentID: mainAgentID},
		{RunID: "run-sub-a", SessionID: "s1", AgentID: "a1"},
		{RunID: "run-sub-b", SessionID: "s1", AgentID: "b2"},
		{RunID: "run-other", SessionID: "s2", AgentID: mainAgentID},
	} {
		if err := m.Insert(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestASessionsEndRetiresItsSubagentsToo(t *testing.T) {
	mappings, reg := &fakeMappingStore{}, &fakeRegistrar{}
	seedSession(t, mappings)
	clock := newTestClock(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	ender := NewSessionEnder(NewSessionEndSignals(0), mappings, reg, time.Minute, clock.Now)
	if err := ender.SessionEnded(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	retired, err := ender.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(retired)
	if len(retired) != 3 || retired[0] != "run-main" || retired[1] != "run-sub-a" || retired[2] != "run-sub-b" {
		t.Fatalf("retired %v, want the main agent and both subagents of s1, nothing of s2", retired)
	}
}

func TestAFinishedSubagentIsRetiredOnItsOwn(t *testing.T) {
	mappings, reg := &fakeMappingStore{}, &fakeRegistrar{}
	seedSession(t, mappings)
	clock := newTestClock(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, mappings, reg, time.Minute, clock.Now)
	if err := ender.SubagentEnded(context.Background(), "s1", "a1"); err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute)
	retired, err := ender.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0] != "run-sub-a" {
		t.Fatalf("retired %v, want only run-sub-a", retired)
	}
}

// A subagent still talking cancels its own signal, exactly as the main
// agent does for the session's.
func TestASubagentStillTalkingCancelsItsSignal(t *testing.T) {
	mappings, reg := &fakeMappingStore{}, &fakeRegistrar{}
	seedSession(t, mappings)
	clock := newTestClock(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC))
	signals := NewSessionEndSignals(0)
	ender := NewSessionEnder(signals, mappings, reg, time.Minute, clock.Now)
	if err := ender.SubagentEnded(context.Background(), "s1", "a1"); err != nil {
		t.Fatal(err)
	}
	signals.CancelAgent("s1", "a1")
	clock.Advance(2 * time.Minute)
	if retired, err := ender.Sweep(context.Background()); err != nil || len(retired) != 0 {
		t.Fatalf("retired %v after the subagent spoke again", retired)
	}
}

// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"
)

// The Postgres store keeps marks across a restart, answers only a
// session's latest event, and is append-only (migration 0012).
func TestSessionEndStoreKeepsOpenMarksAcrossARestart(t *testing.T) {
	store, dsn := newMigratedMappingStore(t)
	ends := NewPostgresSessionEndStore(store.Pool())
	ctx := testCtx(t, 30*time.Second)
	t0 := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	for _, e := range []SessionEndEvent{
		{SessionID: "s-ended", Kind: SessionEndSignalled, At: t0},
		{SessionID: "s-resumed", Kind: SessionEndSignalled, At: t0},
		{SessionID: "s-resumed", Kind: SessionEndCancelled, At: t0.Add(time.Second)},
		{SessionID: "s-old", Kind: SessionEndSignalled, At: t0.Add(-48 * time.Hour)},
	} {
		if err := ends.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	open, err := ends.Open(ctx, t0.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].SessionID != "s-ended" || !open[0].At.Equal(t0) {
		t.Fatalf("open marks %+v, want only s-ended at %s", open, t0)
	}
	conn := rawMappingConn(t, dsn)
	if _, err := conn.Exec(context.Background(), `DELETE FROM innsegl.gateway_session_end`); err == nil {
		t.Fatal("a DELETE on the session-end table was allowed; it is append-only")
	}
}

// AgentsOfSession answers each agent's newest mapping in one session.
func TestAgentsOfSessionAnswersEachAgentsNewestRun(t *testing.T) {
	store, _ := newMigratedMappingStore(t)
	ctx := testCtx(t, 30*time.Second)
	for _, m := range []RunMapping{
		{RunID: "run-main", SessionID: "s1", AgentID: mainAgentID},
		{RunID: "run-a-old", SessionID: "s1", AgentID: "a1"},
		{RunID: "run-a-new", SessionID: "s1", AgentID: "a1"},
		{RunID: "run-other", SessionID: "s2", AgentID: mainAgentID},
	} {
		if err := store.Insert(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.AgentsOfSession(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	runs := map[string]string{}
	for _, m := range got {
		runs[m.AgentID] = m.RunID
	}
	if len(runs) != 2 || runs[mainAgentID] != "run-main" || runs["a1"] != "run-a-new" {
		t.Fatalf("agents of s1 %v, want main and a1's newest run", runs)
	}
}

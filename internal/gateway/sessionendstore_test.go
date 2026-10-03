// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"testing"
	"time"
)

// A session-end mark survives a restart of the core. Measured 2026-10-03:
// thirty-seven sessions were signalled ended, the core restarted inside the
// grace period, the marks were in memory only, and every run stayed active
// for the seven-day backstop. The table now writes each mark and each
// cancellation to an append-only store and reloads the open marks at start.

type fakeSessionEndStore struct {
	mu     sync.Mutex
	events []SessionEndEvent
	done   chan struct{}
}

func (f *fakeSessionEndStore) Record(_ context.Context, e SessionEndEvent) error {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
	if f.done != nil {
		f.done <- struct{}{}
	}
	return nil
}

func (f *fakeSessionEndStore) Open(_ context.Context, since time.Time) ([]SessionEndEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	latest := map[string]SessionEndEvent{}
	for _, e := range f.events {
		if prev, ok := latest[e.SessionID]; !ok || !e.At.Before(prev.At) {
			latest[e.SessionID] = e
		}
	}
	var open []SessionEndEvent
	for _, e := range latest {
		if e.Kind == SessionEndSignalled && !e.At.Before(since) {
			open = append(open, e)
		}
	}
	return open, nil
}

func (f *fakeSessionEndStore) wait(t *testing.T, n int) {
	t.Helper()
	for range n {
		select {
		case <-f.done:
		case <-time.After(2 * time.Second):
			t.Fatal("a session-end event was not written")
		}
	}
}

func TestSessionEndMarksAreWrittenAndReloaded(t *testing.T) {
	store := &fakeSessionEndStore{done: make(chan struct{}, 8)}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	before := NewSessionEndSignals(0)
	before.Persist(context.Background(), store, nil)
	before.Mark("s-ended", now)
	before.Mark("s-resumed", now)
	before.Cancel("s-resumed")
	before.Cancel("s-never-marked") // nothing to cancel: nothing written
	store.wait(t, 3)
	if len(store.events) != 3 {
		t.Fatalf("wrote %d events, want 3 (two marks, one cancel)", len(store.events))
	}

	// The core restarts: a new table, loaded from the store.
	after := NewSessionEndSignals(0)
	after.Persist(context.Background(), store, nil)
	if err := after.Load(context.Background(), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	due := after.Due(3*time.Minute, now.Add(5*time.Minute))
	if len(due) != 1 || due[0] != "s-ended" {
		t.Fatalf("after a restart the due sessions are %v, want [s-ended]", due)
	}
}

// Without a store the table is the in-memory one it always was.
func TestSessionEndSignalsWithoutAStoreStayInMemory(t *testing.T) {
	s := NewSessionEndSignals(0)
	s.Mark("s", time.Now())
	if err := s.Load(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("len %d", s.Len())
	}
}

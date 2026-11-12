// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/gateway"
)

type cleanupMappingStore struct{ noopMappingStore }

func (cleanupMappingStore) BySessionAgent(_ context.Context, session, agent string) (gateway.RunMapping, bool, error) {
	return gateway.RunMapping{SessionID: session, AgentID: agent, RunID: "run-finished"}, true, nil
}

type cleanupRegistrar struct {
	noopRegistrar
	retired chan string
}

func (r cleanupRegistrar) Retire(_ context.Context, run string) (string, error) {
	r.retired <- run
	return "ended", nil
}

// GID-011: a due session end must not wait for the silence backstop's timer.
func TestGID011SessionEndCleanupDoesNotWaitForBackstop(t *testing.T) {
	now := time.Now()
	signals := gateway.NewSessionEndSignals(0)
	signals.Mark("finished-session", now.Add(-4*time.Minute))
	retired := make(chan string, 1)
	g := &runningGateway{
		backstopInterval: time.Hour,
		sessionEnder: gateway.NewSessionEnder(signals, cleanupMappingStore{},
			cleanupRegistrar{retired: retired}, 3*time.Minute, func() time.Time { return now }),
		log: newServeLog(io.Discard),
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.runBackstop(ctx)
	}()
	select {
	case run := <-retired:
		if run != "run-finished" {
			t.Fatalf("retired %q, want the finished session's run", run)
		}
	case <-time.After(time.Second):
		t.Error("due session end waited for the silence backstop timer")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup scheduler did not stop on cancellation")
	}
}

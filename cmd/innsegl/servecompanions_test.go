// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// A stop waits for every companion to finish its own orderly stop. The
// gateway is one: it drains the model replies it is streaming. Measured
// 2026-10-03: the process returned as soon as the MCP listener stopped, the
// container ended, and a reply in flight reached Claude Code as "Connection
// lost mid-response".
func TestServeWaitsForEachCompanionToDrainOnStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var drained atomic.Bool
	failed, wait := startCompanions(ctx, []string{"gateway"}, func(string) int {
		<-ctx.Done()
		time.Sleep(150 * time.Millisecond) // a reply still streaming
		drained.Store(true)
		return exitOK
	}, newServeLog(io.Discard))
	cancel()
	wait()
	if !drained.Load() {
		t.Fatal("the stop returned before the companion had drained")
	}
	select {
	case <-failed:
		t.Fatal("a companion that stopped because the process is stopping was reported as a failure")
	default:
	}
}

// A companion that stops while the process is still running is a failure,
// as before: the replica can no longer do its whole job.
func TestServeReportsACompanionThatStopsOnItsOwn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	failed, _ := startCompanions(ctx, []string{"seal"}, func(string) int { return exitOK }, newServeLog(io.Discard))
	select {
	case <-failed:
	case <-time.After(2 * time.Second):
		t.Fatal("a companion that stopped on its own was not reported")
	}
}

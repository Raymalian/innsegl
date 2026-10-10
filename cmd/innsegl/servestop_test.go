// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/spire"
)

// OPS-177: `innsegl serve` stops within seconds of SIGTERM, every companion
// with it, and work in flight finishes first.
//
// Measured 2026-10-10: `docker stop` on innsegl-mcp took its whole
// stop_grace_period (2m30s) and ended in SIGKILL. The reap companion waited
// for a context.Background() that never ends, so serve's wait for its
// companions never returned. Every companion now runs on serve's own
// context: one signal, one cancellation, and no companion can miss it.

// stopBudget is how long a stop may take here. Seconds, not the grace period.
const stopBudget = 5 * time.Second

// holdSIGTERM keeps a SIGTERM registration for the whole test, as serve's
// own handler does in a deployment: the signal is then delivered to the
// handlers and never kills the test binary.
func holdSIGTERM(t *testing.T) {
	t.Helper()
	sink := make(chan os.Signal, 64)
	signal.Notify(sink, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(sink) })
}

// signalUntil sends SIGTERM every 50ms until done answers, and fails when
// that takes longer than stopBudget.
func signalUntil[T any](t *testing.T, done <-chan T, what string) T {
	t.Helper()
	deadline := time.After(stopBudget)
	for {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
			t.Fatalf("SIGTERM: %v", err)
		}
		select {
		case v := <-done:
			return v
		case <-time.After(50 * time.Millisecond):
		case <-deadline:
			t.Fatalf("%s did not stop within %s of SIGTERM", what, stopBudget)
		}
	}
}

// slowSweeper is a sweep in flight when the signal lands: it records
// whether its context was cancelled before it finished.
type slowSweeper struct {
	started  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	finished int
	cut      bool
}

func (s *slowSweeper) Sweep(ctx context.Context) (*spire.SweepReport, error) {
	s.once.Do(func() { close(s.started) })
	time.Sleep(300 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished++
	if ctx.Err() != nil {
		s.cut = true
	}
	return &spire.SweepReport{StartedAt: time.Now()}, nil
}

func TestOPS177ARepeatingReapStopsOnSIGTERMAfterItsSweep(t *testing.T) {
	holdSIGTERM(t)
	sw := &slowSweeper{started: make(chan struct{})}
	deps := reapDeps{open: func(context.Context, reapOptions) (sweeper, func(), error) {
		return sw, func() {}, nil
	}}
	done := make(chan int, 1)
	var out, errOut bytes.Buffer
	go func() {
		done <- runReapCommand(minimalReapArgs("-interval", "1h", "-quiet"), &out, &errOut, deps)
	}()
	<-sw.started
	code := signalUntil(t, done, "a repeating reap")
	if code != exitOK {
		t.Fatalf("exit = %d, want %d; stderr=%s", code, exitOK, errOut.String())
	}
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.finished != 1 || sw.cut {
		t.Fatalf("the sweep in flight finished %d time(s), cut=%v; want it finished once "+
			"with its context intact (a sweep records expiries in the ledger)", sw.finished, sw.cut)
	}
}

func TestOPS177ServeStopsEveryCompanionOnSIGTERM(t *testing.T) {
	clearServeEnv(t)
	holdSIGTERM(t)
	fake := &fakeServer{addr: "127.0.0.1:1"}
	deps := fakeDeps(fake, nil)

	// A companion that handles no signal of its own and stops only when the
	// context serve hands it ends: the reap companion's shape before the fix
	// never stopped at all.
	running := make(chan string, len(alsoCommands))
	deps.companions = map[string]companionFunc{}
	for name := range alsoCommands {
		deps.companions[name] = func(ctx context.Context, _ []string, _, _ io.Writer) int {
			running <- name
			<-ctx.Done()
			return exitOK
		}
	}

	done := make(chan int, 1)
	var stdout, stderr bytes.Buffer
	go func() {
		done <- runServeCommand(completeServeArgs("-also", "seal,reconcile,reap,gateway")[1:],
			&stdout, &stderr, deps)
	}()
	for range alsoCommands {
		select {
		case <-running:
		case <-time.After(stopBudget):
			t.Fatalf("not every companion started; stderr:\n%s", stderr.String())
		}
	}
	code := signalUntil(t, done, "serve with four companions")
	if code != exitOK {
		t.Fatalf("serve = %d, want %d; stderr:\n%s", code, exitOK, stderr.String())
	}
}

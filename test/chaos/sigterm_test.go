// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

// OPS-178 (#570): the SHIPPED `innsegl serve`, against a real Postgres and a
// real SPIRE (OPS-003's stack, its own containers, nothing of a running
// deployment), stops within seconds of SIGTERM while agents are calling it,
// exits 0, and leaves no call half done: no idempotency claim still in
// progress, and a chain that verifies end to end.
//
// Measured before #570: `docker stop` on innsegl-mcp took its whole 2m30s
// grace period and ended in SIGKILL. The cause was a companion (reap) that
// never saw the stop; cmd/innsegl/servestop_test.go holds the companions.
// This case holds the process: the MCP server itself, its listeners and its
// in-flight calls.
func TestOPS178ServeStopsOnSIGTERMWithinSecondsAndLeavesNoCallHalfDone(t *testing.T) {
	c := requireK9Campaign(t)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.work(ctx, i)
		}(i)
	}
	stopWork := func() {
		cancel()
		wg.Wait()
	}
	defer stopWork()

	// Wait until the agents are busy, so the signal lands on calls in flight.
	if !k9WaitFor(60*time.Second, func() bool { return c.dispatched.Load() >= 40 }) {
		t.Fatalf("the workload dispatched only %d calls in a minute", c.dispatched.Load())
	}

	c.mu.Lock()
	d := c.daemon
	c.mu.Unlock()
	inFlight := c.inFlight.Load()
	started := time.Now()
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- d.cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-exited:
	case <-time.After(20 * time.Second):
		t.Fatalf("`innsegl serve` was still running 20s after SIGTERM; stderr:\n%s", d.stderr.String())
	}
	elapsed := time.Since(started)
	d.dead = true
	stopWork()

	t.Logf("stopped %s after SIGTERM, %d call(s) in flight when it landed, %d dispatched in all",
		elapsed.Round(time.Millisecond), inFlight, c.dispatched.Load())
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		t.Errorf("`innsegl serve` exited %v on SIGTERM, want 0; stderr:\n%s", exitErr.ProcessState, d.stderr.String())
	} else if waitErr != nil {
		t.Fatalf("waiting for `innsegl serve`: %v", waitErr)
	}
	if elapsed > 5*time.Second {
		t.Errorf("`innsegl serve` took %s to stop after SIGTERM, want a few seconds", elapsed)
	}
	if claims := c.claims(t); claims.stranded != 0 {
		t.Errorf("%d idempotency claim(s) left in progress: a call the stop cut in half", claims.stranded)
	}
	c.requireNoViolations(t, "the chain after the stop", k9SweepChain(c.chainState(t)))
}

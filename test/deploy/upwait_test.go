// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// OPS-179 (PROPOSED for doc 07's TC-OPS) — a bring-up exits non-zero when a
// service it started does not come up (#573).
//
// MEASURED in the in-place update rehearsals: `make update` recreated the
// core, the new core failed its start, and the update exited 0. compose's
// `up -d` returns once the containers are started; nothing checked that they
// stayed up. scripts/compose-up.py, which every `up` in the Makefile goes
// through (OPS-165), now waits for each long-running service the `up` started
// or replaced: healthy where it has a health check, running and steady where
// it has none. One that is not exits non-zero, named, with its last log lines.
//
// The wait starts when compose has finished, so an old container that takes
// its whole stop grace period to stop (#570) is not counted against the new
// one, and a service the `up` left alone is not waited for.
// ---------------------------------------------------------------------------

func TestOPS179ABringUpFailsWhenAServiceItStartedDoesNotComeUp(t *testing.T) {
	ctx := t.Context()
	if err := dockertest.Usable(ctx); err != nil {
		skip, failure := dockertest.StartupOutcome(err)
		if failure != "" {
			t.Fatal(failure)
		}
		t.Skipf("skipping OPS-179: %s", skip)
	}
	root := repoRoot(t)
	dir := t.TempDir()
	project := uniqueName(t, "ops179")
	// good: healthy at once. slow: ignores SIGTERM, so replacing it takes its
	// whole grace period. bad: started only under the "bad" profile; prints a
	// line and exits 3 on every start. unchecked: no health check, crashes
	// once BREAK is set.
	compose := fmt.Sprintf(`name: %[1]s
services:
  good:
    image: %[2]s
    restart: unless-stopped
    network_mode: none
    command: ["sleep", "3600"]
    healthcheck:
      test: ["CMD", "true"]
      interval: 1s
      retries: 3
  slow:
    image: %[2]s
    restart: unless-stopped
    network_mode: none
    stop_grace_period: 8s
    environment:
      GENERATION: ${GENERATION:-one}
    command: ["sh", "-c", "trap '' TERM; while :; do sleep 1; done"]
    healthcheck:
      test: ["CMD", "true"]
      interval: 1s
      retries: 3
  unchecked:
    image: %[2]s
    restart: unless-stopped
    network_mode: none
    environment:
      BREAK: ${BREAK:-}
    command: ["sh", "-c", "if [ -n \"$$BREAK\" ]; then echo unchecked-broke; exit 4; fi; exec sleep 3600"]
  bad:
    image: %[2]s
    profiles: ["bad"]
    restart: unless-stopped
    network_mode: none
    command: ["sh", "-c", "echo ops179-the-start-failed; exit 3"]
`, project, opsInputsImage)
	file := filepath.Join(dir, "compose.yml")
	writeFile(t, file, compose)
	t.Cleanup(func() {
		if out, err := exec.CommandContext(context.Background(), "docker", "compose", "-f", file,
			"--profile", "bad", "down", "-v", "--remove-orphans", "-t", "1").CombinedOutput(); err != nil {
			t.Logf("removing the test project %s: %v\n%s", project, err, out)
		}
	})

	up := func(env []string, args ...string) (string, error) {
		t.Helper()
		full := append([]string{"-f", file}, args...)
		cmd := exec.CommandContext(ctx, filepath.Join(root, "scripts", "compose-up.py"), full...)
		cmd.Env = append(append(os.Environ(), "INNSEGL_UP_WAIT_TIMEOUT=60"), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := up(nil, "up", "-d", "--no-build"); err != nil {
		t.Fatalf("every service comes up, and the bring-up failed: %v\n%s", err, out)
	}

	// Nothing changed: nothing is started, nothing is waited for.
	start := time.Now()
	out, err := up(nil, "up", "-d", "--no-build")
	if err != nil {
		t.Fatalf("a bring-up that changed nothing failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "waiting for") {
		t.Errorf("a bring-up that started nothing waited for something:\n%s", out)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("a bring-up that changed nothing took %s", d)
	}

	// A slow stop is not a failure, even when it is longer than the wait.
	out, err = up([]string{"GENERATION=two", "INNSEGL_UP_WAIT_TIMEOUT=5"}, "up", "-d", "--no-build")
	if err != nil {
		t.Fatalf("replacing a service whose old container stops slowly failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "slow: healthy") {
		t.Errorf("the replaced service was not waited for:\n%s", out)
	}

	// A service that exits on every start fails the bring-up, by name, with
	// its own last words.
	out, err = up(nil, "--profile", "bad", "up", "-d", "--no-build")
	if err == nil {
		t.Fatalf("a service that fails on start, and the bring-up exited 0 — the rehearsal's failure:\n%s", out)
	}
	if !strings.Contains(out, "bad") || !strings.Contains(out, "ops179-the-start-failed") {
		t.Errorf("the failure does not name the service and show its log:\n%s", out)
	}

	// A service with no health check that crashes on start fails it too.
	out, err = up([]string{"BREAK=1"}, "up", "-d", "--no-build", "unchecked")
	if err == nil {
		t.Fatalf("a service with no health check crashed on start, and the bring-up exited 0:\n%s", out)
	}
	if !strings.Contains(out, "unchecked") || !strings.Contains(out, "unchecked-broke") {
		t.Errorf("the failure does not name the service and show its log:\n%s", out)
	}
}

// SPDX-License-Identifier: Apache-2.0

// Package dockertest holds the Docker and container-start-up helpers that
// the integration-test harnesses used to carry a copy of each (#555).
//
// It is for this project's own tests only and is never linked into a binary;
// TestDockertestIsNotLinkedIntoAnyBinary pins that.
//
// The shared rule (#101, HAR-003): a missing dependency is a skip and
// anything else that goes wrong while standing one up is a failure. A
// harness decides per package what "up" means (ADR-0015/ADR-0022 give some
// packages one stack per test process); this package only supplies the
// routing and the plumbing underneath it.
package dockertest

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// DefaultPostgresImage is the Postgres the harnesses start unless
// INNSEGL_TEST_POSTGRES_IMAGE names another.
const DefaultPostgresImage = "postgres:16"

// ErrDependencyAbsent marks the ONLY conditions under which skipping is
// honest: there is no Docker daemon, or INNSEGL_TEST_NO_DOCKER asks for none.
// Nothing else wraps it.
var ErrDependencyAbsent = errors.New("a required dependency is absent")

// StartupOutcome routes a start-up error to exactly one of two results. An
// absent dependency is a skip; anything else is a failure. There is no third
// answer, and the third answer is how a package once reported ok with nothing
// having run (#101).
func StartupOutcome(err error) (skip, failure string) {
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, ErrDependencyAbsent):
		return err.Error(), ""
	default:
		return "", err.Error()
	}
}

// Requirement is what a require-function must do for the calling test.
type Requirement int

// The three outcomes of Need.
const (
	Proceed Requirement = iota
	SkipTest
	FailTest
)

// Need decides between the three. A failure outranks a skip: if the
// dependency broke, the reason it broke is what the developer needs to read.
func Need(up bool, _, failure string) Requirement {
	switch {
	case failure != "":
		return FailTest
	case !up:
		return SkipTest
	default:
		return Proceed
	}
}

// OneLine collapses a multi-line subprocess error into a single line.
//
// docker and `docker compose` report progress on stderr, so a failure arrives
// as several lines of which only the last usually names the cause, and Go's
// test JSON stream emits each line as its own event.
func OneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// PostgresImage is the image to run: INNSEGL_TEST_POSTGRES_IMAGE, or the
// default.
func PostgresImage() string {
	if v := os.Getenv("INNSEGL_TEST_POSTGRES_IMAGE"); v != "" {
		return v
	}
	return DefaultPostgresImage
}

// Docker runs one docker command and returns its trimmed stdout. A failure
// carries the command and its stderr on one line.
func Docker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(args, " "), err, OneLine(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// Usable reports whether a docker daemon is reachable. Its errors are the
// ONLY ones a harness should wrap as an absent dependency.
func Usable(ctx context.Context) error {
	if os.Getenv("INNSEGL_TEST_NO_DOCKER") != "" {
		return fmt.Errorf("%w: INNSEGL_TEST_NO_DOCKER is set", ErrDependencyAbsent)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%w: docker is not on PATH: %w", ErrDependencyAbsent, err)
	}
	if _, err := Docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		return fmt.Errorf("%w: no reachable docker daemon: %w", ErrDependencyAbsent, err)
	}
	return nil
}

// FreePortLow and FreePortHigh bound the ports FreeHostPort hands out.
//
// A harness releases the port before Docker binds it, so the port must not
// come from the kernel's ephemeral range (Linux 32768-60999, macOS
// 49152-65535): there, the same allocator gives it to the next outgoing
// connection, or to Docker's own published ports, inside that gap. Measured
// in CI on 2026-10-09: INIT-008's Rekor failed with "Bind for
// 127.0.0.1:46659 failed: port is already allocated", a port net.Listen(":0")
// had handed out and released minutes before. This band is below every
// default ephemeral range and clear of the ports innsegl's stack publishes
// (5555, 8082, 23000, 28080-28095, 28195, 28443).
const (
	FreePortLow   = 24000
	FreePortHigh  = 27999
	freePortTries = 200
)

// FreeHostPort finds a loopback port in FreePortLow..FreePortHigh that
// nothing holds, and hands it back released. Two picks can still meet only
// when two processes draw the same random port in the same moment; the
// kernel's own allocations never land here.
func FreeHostPort(ctx context.Context) (string, error) {
	span := FreePortHigh - FreePortLow + 1
	for range freePortTries {
		port := strconv.Itoa(FreePortLow + rand.IntN(span)) //nolint:gosec // G404: spreads picks across a band; nothing secret depends on it
		var lc net.ListenConfig
		l, err := lc.Listen(ctx, "tcp", "127.0.0.1:"+port)
		if err != nil {
			continue
		}
		if err := l.Close(); err != nil {
			return "", err
		}
		return port, nil
	}
	return "", fmt.Errorf("no free loopback port in %d-%d after %d tries", FreePortLow, FreePortHigh, freePortTries)
}

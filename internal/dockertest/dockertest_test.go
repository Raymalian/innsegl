// SPDX-License-Identifier: Apache-2.0

package dockertest

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// HAR-003 — #101. Both branches of the routing rule, exercised once for every
// harness that now shares it.
func TestHAR003AnAbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
	t.Run("no docker is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_TEST_NO_DOCKER", "1")
		err := Usable(t.Context())
		if err == nil {
			t.Fatal("Usable answered nil with INNSEGL_TEST_NO_DOCKER set")
		}
		if !errors.Is(err, ErrDependencyAbsent) {
			t.Fatalf("%v does not wrap ErrDependencyAbsent, so it would be routed to a "+
				"FAILURE and a developer with no Docker could not run the package", err)
		}
		skip, failure := StartupOutcome(err)
		if skip == "" || failure != "" {
			t.Fatalf("StartupOutcome(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("a dependency that did not start is a failure", func(t *testing.T) {
		// Docker is present, working, and refuses to create the network
		// because its address pools are used up: the shape #101 produced.
		err := fmt.Errorf("could not start the stack: %w",
			errors.New("Error response from daemon: could not find an available, "+
				"non-overlapping IPv4 address pool among the defaults to assign "+
				"to the network"))
		if errors.Is(err, ErrDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps ErrDependencyAbsent; it would " +
				"be reported as a skip and the cases would silently not run")
		}
		skip, failure := StartupOutcome(err)
		if failure == "" || skip != "" {
			t.Fatalf("StartupOutcome(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("a healthy start-up is neither", func(t *testing.T) {
		if skip, failure := StartupOutcome(nil); skip != "" || failure != "" {
			t.Fatalf("StartupOutcome(nil) = (%q, %q), want both empty", skip, failure)
		}
	})

	t.Run("a failure outranks a skip", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			up            bool
			skip, failure string
			want          Requirement
		}{
			{"a failure outranks everything", false, "no docker", "boom", FailTest},
			{"a failure outranks a live dependency", true, "", "boom", FailTest},
			{"nothing up and no failure is a skip", false, "no docker", "", SkipTest},
			{"a live dependency proceeds", true, "", "", Proceed},
		} {
			if got := Need(tc.up, tc.skip, tc.failure); got != tc.want {
				t.Errorf("%s: Need(%v, %q, %q) = %d, want %d",
					tc.name, tc.up, tc.skip, tc.failure, got, tc.want)
			}
		}
	})
}

func TestOneLineCollapsesAMultiLineError(t *testing.T) {
	if got := OneLine(" Network x  Creating\n\terror: pool\nexhausted "); got != "Network x Creating error: pool exhausted" {
		t.Fatalf("OneLine = %q", got)
	}
}

func TestPostgresImageHonoursTheOverride(t *testing.T) {
	t.Setenv("INNSEGL_TEST_POSTGRES_IMAGE", "")
	if got := PostgresImage(); got != DefaultPostgresImage {
		t.Fatalf("PostgresImage() = %q, want the default %q", got, DefaultPostgresImage)
	}
	t.Setenv("INNSEGL_TEST_POSTGRES_IMAGE", "postgres:17")
	if got := PostgresImage(); got != "postgres:17" {
		t.Fatalf("PostgresImage() = %q, want the override", got)
	}
}

func TestFreeHostPortReturnsAUsablePort(t *testing.T) {
	port, err := FreeHostPort(t.Context())
	if err != nil || port == "" || port == "0" {
		t.Fatalf("FreeHostPort = (%q, %v)", port, err)
	}
}

// A port handed to `docker compose` is released before Docker binds it. Drawn
// from the kernel's ephemeral range (Linux 32768-60999, macOS 49152-65535),
// the same allocator hands it to the next outgoing connection or to Docker's
// own published ports in that gap: CI's INIT-008 failed 2026-10-09 with
// "Bind for 127.0.0.1:46659 failed: port is already allocated". So a port
// comes from FreePortLow..FreePortHigh, below every default ephemeral range
// and clear of the ports innsegl's own stack publishes.
func TestFreeHostPortAvoidsTheEphemeralRangeAndTheStacksOwnPorts(t *testing.T) {
	if FreePortLow < 1024 || FreePortHigh >= 32768 || FreePortLow > FreePortHigh {
		t.Fatalf("band %d-%d is not below the ephemeral ranges", FreePortLow, FreePortHigh)
	}
	for _, stack := range []int{5555, 8082, 23000, 28080, 28081, 28090, 28095, 28195, 28443} {
		if stack >= FreePortLow && stack <= FreePortHigh {
			t.Errorf("the band %d-%d holds %d, a port the stack publishes", FreePortLow, FreePortHigh, stack)
		}
	}
	for range 50 {
		port, err := FreeHostPort(t.Context())
		if err != nil {
			t.Fatalf("FreeHostPort: %v", err)
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < FreePortLow || n > FreePortHigh {
			t.Fatalf("FreeHostPort = %q, want a port in %d-%d", port, FreePortLow, FreePortHigh)
		}
	}
}

// A port something already holds is never handed out.
func TestFreeHostPortSkipsAPortInUse(t *testing.T) {
	var held []net.Listener
	t.Cleanup(func() {
		for _, l := range held {
			_ = l.Close()
		}
	})
	for p := FreePortLow; p <= FreePortLow+20; p++ {
		if l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:"+strconv.Itoa(p)); err == nil {
			held = append(held, l)
		}
	}
	for range 50 {
		port, err := FreeHostPort(t.Context())
		if err != nil {
			t.Fatalf("FreeHostPort: %v", err)
		}
		for _, l := range held {
			if strings.HasSuffix(l.Addr().String(), ":"+port) {
				t.Fatalf("FreeHostPort handed out %s, which is held", port)
			}
		}
	}
}

func TestDockerNamesTheCommandOnFailure(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker binary; the error shape needs one to fail")
	}
	_, err := Docker(t.Context(), "no-such-subcommand-555")
	if err == nil || !strings.Contains(err.Error(), "docker no-such-subcommand-555:") {
		t.Fatalf("Docker error = %v, want it to name the command", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("Docker error spans lines: %q", err)
	}
}

// This package is test support. If a production package imports it, the
// helpers (and the os/exec calls to docker) ship in a binary.
func TestDockertestIsNotLinkedIntoAnyBinary(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "../../cmd/...").Output()
	if err != nil {
		t.Fatalf("go list -deps ./cmd/...: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasSuffix(pkg, "/internal/dockertest") {
			t.Fatalf("%s is linked into a cmd/ binary", pkg)
		}
	}
}

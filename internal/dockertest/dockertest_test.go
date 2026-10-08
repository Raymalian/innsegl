// SPDX-License-Identifier: Apache-2.0

package dockertest

import (
	"errors"
	"fmt"
	"os/exec"
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

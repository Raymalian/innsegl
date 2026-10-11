// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/hostdeps"
)

// CLI-027 (PROPOSED for doc 07, #592) — connect names every missing
// dependency before it acts, and refuses before it writes anything when one
// it cannot work without is missing; doctor's first line says the same.

// hostWithout is a Debian machine on which none of names is installed.
func hostWithout(names ...string) *hostdeps.Env {
	gone := map[string]bool{}
	for _, n := range names {
		gone[n] = true
	}
	return &hostdeps.Env{
		GOOS: "linux", OSRelease: "ID=debian\n",
		LookPath: func(n string) (string, error) {
			if gone[n] {
				return "", exec.ErrNotFound
			}
			return "/usr/bin/" + n, nil
		},
		Output: func(string, ...string) (string, error) { return "git version 2.39.5", nil },
	}
}

func TestCLI027ConnectWithoutGitRefusesBeforeWritingAnything(t *testing.T) {
	f := newConnectFixture(t)
	f.deps.host = hostWithout("git")
	code, _, stderr := f.connect(f.core.URL(), "--token", clienttest.Token, "--ca", f.caFile,
		"--managed-settings", f.settings)
	if code != exitConnectFailed {
		t.Fatalf("connect without git = %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "missing git") || !strings.Contains(stderr, "sudo apt-get install -y git") {
		t.Fatalf("git and its install line are not named:\n%s", stderr)
	}
	if _, err := os.Stat(client.ClientPaths(f.home).Dir); !os.IsNotExist(err) {
		t.Fatalf("connect wrote %s before refusing", client.ClientPaths(f.home).Dir)
	}
	if _, err := os.Stat(f.settings); !os.IsNotExist(err) {
		t.Fatal("connect wrote the managed settings before refusing")
	}
	if n, _ := f.core.Counts(); n != 0 {
		t.Fatal("connect spent the token before refusing")
	}
	if len(f.calls) != 0 {
		t.Fatalf("connect ran %q before refusing", f.calls)
	}
}

func TestCLI027DoctorsFirstLineIsTheHost(t *testing.T) {
	d := newDoctorRun(t, healthyDoctorCore())
	deps := d.deps(t)
	deps.host = hostWithout()
	var out strings.Builder
	runDoctor(t.Context(), []string{"--wait", "5s"}, &out, &out, deps)
	if first, _, _ := strings.Cut(out.String(), "\n"); first != "host: ok" {
		t.Fatalf("doctor's first line is %q, want host: ok\n%s", first, out.String())
	}

	deps.host = hostWithout("git")
	out.Reset()
	runDoctor(t.Context(), []string{"--wait", "5s"}, &out, &out, deps)
	if first, _, _ := strings.Cut(out.String(), "\n"); !strings.HasPrefix(first, "host: MISSING — git") ||
		!strings.Contains(first, "sudo apt-get install -y git") {
		t.Fatalf("doctor's first line does not name git:\n%s", out.String())
	}
}

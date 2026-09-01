// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-005 (PROPOSED for doc 07's TC-OPS) — the README is the smoke command's
// source, and the two cannot drift.
//
// doc 08's versioning policy: "The compose reference stack and the documented
// smoke command are part of the compatibility surface: if `make smoke` from
// the previous minor's README fails on the new minor, that is a breaking
// change misfiled as minor — release is blocked."
//
// A compatibility surface nothing checks is a promise, not a surface. OPS-004
// proves the stack works; this proves that what OPS-004 runs is what the
// README tells an adopter to run, and that `make smoke` is the command that
// runs it. It needs no Docker and takes microseconds, so the pin holds on
// every CI run rather than only on the ones that reach the containers.
//
// A change here is a change to the compatibility surface. If this test wants
// editing, the question is whether a release is being blocked, not whether the
// assertion is inconvenient.
// ---------------------------------------------------------------------------

func TestOPS005TheREADMEIsWhatTheSmokeCommandRuns(t *testing.T) {
	root := repoRoot(t)

	readmePath := filepath.Join(root, "deploy", "compose", "README.md")
	readme, err := os.ReadFile(readmePath) //nolint:gosec // a fixed path under the repo root
	if err != nil {
		t.Fatalf("deploy/compose/README.md is the front door of the project and the "+
			"document doc 08 measures a release against; it must exist: %v", err)
	}
	text := string(readme)

	// Every command the harness issues against the shipped stack, verbatim.
	// documentedCommands is the single place both this test and the harness
	// read, so a command cannot be added to the smoke without appearing in the
	// README — which is what "the README must be executable as written" means
	// mechanically.
	for _, cmd := range documentedCommands {
		if !strings.Contains(text, cmd) {
			t.Errorf("deploy/compose/README.md does not contain %q.\n"+
				"OPS-004 runs it. An adopter following the README would not, and "+
				"the first-run experience is then something nobody has tested.", cmd)
		}
	}

	makefile, err := os.ReadFile(filepath.Join(root, "Makefile")) //nolint:gosec // a fixed path under the repo root
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	make := string(makefile)

	if !strings.Contains(make, "\nsmoke:") {
		t.Error("the Makefile declares no `smoke` target. doc 08 names `make smoke` " +
			"as the compatibility surface by that exact spelling.")
	}
	// The target must run OPS-004 and nothing renamed. `make smoke` and
	// TestOPS004FreshCloneBootstrap are two names for one thing; if they ever
	// stop being, the release gate is measuring a command nobody runs.
	for _, want := range []string{"./test/smoke", "TestOPS004"} {
		if !strings.Contains(make, want) {
			t.Errorf("the Makefile's smoke target does not mention %q; `make smoke` "+
				"must run OPS-004 itself", want)
		}
	}
	if !strings.Contains(text, "make smoke") {
		t.Error("deploy/compose/README.md never names `make smoke`; doc 08 blocks a " +
			"release on the previous minor's README naming a command that still works")
	}
}

// ---------------------------------------------------------------------------
// OPS-006 (PROPOSED for doc 07's TC-OPS) — the harness reports an absent
// dependency and a broken one differently.
//
// #101: eight harnesses sent "no Docker" and "the stack did not start" to the
// same variable, and the second silently became a skip — `go test` exits zero,
// the package reports ok, and the case that proves the invariant did not run.
// internal/verify/verifyharness_test.go's corrected shape is copied here; this
// is the test that makes the copy real, because a fix nothing exercises is a
// fix until the next refactor.
//
// Both branches must bite, so both are asserted.
// ---------------------------------------------------------------------------

func TestOPS006AnAbsentDockerIsASkipAndABrokenStackIsAFailure(t *testing.T) {
	absent := errors.New("no reachable docker daemon: " + errDependencyAbsent.Error())
	absent = wrapDependencyAbsent(absent)
	skip, failure := startupOutcome(absent)
	if skip == "" || failure != "" {
		t.Fatalf("an absent dependency is a skip and nothing else; got skip=%q failure=%q",
			skip, failure)
	}

	broke := errors.New("bringing up the SPIRE stack: network innsegl-spire-node: " +
		"all predefined address pools have been fully subnetted")
	skip, failure = startupOutcome(broke)
	if failure == "" || skip != "" {
		t.Fatalf("a stack that did not come up on a machine WITH Docker is a FAILURE, "+
			"never a skip — that is #101, and OPS-004 is the one case that measures "+
			"the adopter's first-run experience. got skip=%q failure=%q", skip, failure)
	}

	if skip, failure := startupOutcome(nil); skip != "" || failure != "" {
		t.Fatalf("a clean start-up is neither: got skip=%q failure=%q", skip, failure)
	}

	for _, tc := range []struct {
		name    string
		up      bool
		skip    string
		failure string
		want    requirement
	}{
		{"stack up", true, "", "", proceed},
		{"docker absent", false, "docker is not on PATH", "", skipTest},
		{"stack did not start", false, "", "address pools exhausted", failTest},
		{"a failure outranks a stale skip", false, "docker absent", "port allocated", failTest},
	} {
		if got := stackRequirement(tc.up, tc.skip, tc.failure); got != tc.want {
			t.Errorf("%s: stackRequirement = %v, want %v", tc.name, got, tc.want)
		}
	}
}

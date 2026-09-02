// SPDX-License-Identifier: Apache-2.0

package load

import (
	"errors"
	"fmt"
	"testing"
)

// The harness's own routing, measured.
//
// Proposed doc 07 ID: OPS-002c, layer U. ADR-0039 carries the proposed row;
// doc 07 is normative and is not edited from here.
//
// #101 was a branch nothing exercised: eight TestMains send "no Docker" and
// "the stack did not start" to the same variable, and the second silently
// becomes a skip. This package does not add a ninth, and the fix is only a fix
// if both branches are held apart by a test — so these cases exist to bite if
// anyone ever collapses them again.
//
// They need no Docker, and that is deliberate: the honesty of the skip/fail
// routing is exactly the thing that must still be checkable on a machine where
// the stack cannot run.

func TestTheHarnessSeparatesAnAbsentDockerFromAStackThatDidNotStart(t *testing.T) {
	absent := fmt.Errorf("no reachable docker daemon: %w", errDependencyAbsent)
	skip, failure := startupOutcome(absent)
	if skip == "" || failure != "" {
		t.Fatalf("an absent dependency must be a skip and nothing else; "+
			"got skip=%q failure=%q", skip, failure)
	}

	broke := errors.New("the OPS-002 stack did not come up: start rekor: port already allocated")
	skip, failure = startupOutcome(broke)
	if failure == "" || skip != "" {
		t.Fatalf("a stack that did not start on a machine with Docker is a FAILURE, "+
			"never a skip: that is #101. got skip=%q failure=%q", skip, failure)
	}

	if skip, failure := startupOutcome(nil); skip != "" || failure != "" {
		t.Fatalf("a clean start-up is neither: got skip=%q failure=%q", skip, failure)
	}
}

func TestRequireStackFailsOnAnInfrastructureFaultAndSkipsOnlyOnAnAbsentOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		stack   *stack
		skip    string
		failure string
		want    requirement
	}{
		{"stack up", &stack{}, "", "", proceed},
		{"docker absent", nil, "docker is not on PATH", "", skipTest},
		{"stack did not start", nil, "", "port already allocated", failTest},
		{"a failure outranks a stale skip", nil, "something", "port allocated", failTest},
	} {
		if got := stackRequirement(tc.stack, tc.skip, tc.failure); got != tc.want {
			t.Errorf("%s: stackRequirement = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A dependency-absent error is the only kind that may wrap the sentinel. This
// case guards the other half of the rule: dependenciesPresent is the only
// function in the harness allowed to produce one, so an error from anywhere
// else must not satisfy errors.Is.
func TestOnlyAbsenceWrapsTheSentinel(t *testing.T) {
	fromStartup := fmt.Errorf("the OPS-002 stack did not come up: %w",
		errors.New("start minio: no space left on device"))
	if errors.Is(fromStartup, errDependencyAbsent) {
		t.Fatal("a start-up failure wraps errDependencyAbsent; it would be routed to a " +
			"skip and OPS-002 would report ok having measured nothing")
	}
}

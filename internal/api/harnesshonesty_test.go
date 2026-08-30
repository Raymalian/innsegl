// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"fmt"
	"testing"
)

// The harness's own routing, measured.
//
// #101 was a branch nothing exercised: TestMain sent "no Docker" and "the
// stack did not start" to the same variable, and the second silently became a
// skip. The fix is only a fix if both branches are held apart by a test, so
// these two cases exist to bite if anyone ever collapses them again.

func TestTheHarnessSeparatesAnAbsentDockerFromAContainerThatDidNotStart(t *testing.T) {
	absent := fmt.Errorf("no reachable docker daemon: %w", errDependencyAbsent)
	skip, failure := startupOutcome(absent)
	if skip == "" || failure != "" {
		t.Fatalf("an absent dependency must be a skip and nothing else; "+
			"got skip=%q failure=%q", skip, failure)
	}

	broke := errors.New("could not start postgres:16: port already allocated")
	skip, failure = startupOutcome(broke)
	if failure == "" || skip != "" {
		t.Fatalf("a container that did not start on a machine with Docker is a "+
			"FAILURE, never a skip: that is #101. got skip=%q failure=%q", skip, failure)
	}

	if skip, failure := startupOutcome(nil); skip != "" || failure != "" {
		t.Fatalf("a clean start-up is neither: got skip=%q failure=%q", skip, failure)
	}
}

func TestRequirePGFailsOnAnInfrastructureFaultAndSkipsOnlyOnAnAbsentOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pg      *pgContainer
		skip    string
		failure string
		want    requirement
	}{
		{"container up", &pgContainer{}, "", "", proceed},
		{"docker absent", nil, "docker is not on PATH", "", skipTest},
		{"container did not start", nil, "", "port already allocated", failTest},
		{"a failure outranks a stale skip", nil, "something", "port allocated", failTest},
	} {
		if got := pgRequirement(tc.pg, tc.skip, tc.failure); got != tc.want {
			t.Errorf("%s: pgRequirement = %v, want %v", tc.name, got, tc.want)
		}
	}
}

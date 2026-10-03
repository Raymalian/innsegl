// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// RM-330 (#506), ADR-0044's 2026-10-03 amendment: `innsegl api` may hold a
// resolver credential, and resolves alerts from the dashboard only if it
// does. It is optional, so a deployment that has not provisioned the role
// keeps starting exactly as before, and it reads its DSN from the
// environment, since a DSN carries a password.

func TestRM330TheResolverDSNIsOptional(t *testing.T) {
	t.Setenv(envAPIResolverDSN, "")
	var seen apiOptions
	code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), &seen))
	if code != exitOK {
		t.Fatalf("exit = %d, want %d with no resolver DSN. stderr: %s", code, exitOK, stderr)
	}
	if seen.resolverDSN != "" {
		t.Errorf("resolverDSN = %q, want empty", seen.resolverDSN)
	}
}

func TestRM330TheResolverDSNFallsBackToItsEnvironmentVariable(t *testing.T) {
	t.Setenv(envAPIResolverDSN, "postgres://innsegl_resolver:secret@ledger/innsegl")
	var seen apiOptions
	code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), &seen))
	if code != exitOK {
		t.Fatalf("exit = %d. stderr: %s", code, stderr)
	}
	if seen.resolverDSN != "postgres://innsegl_resolver:secret@ledger/innsegl" {
		t.Errorf("-resolver-dsn did not fall back to $%s: %q", envAPIResolverDSN, seen.resolverDSN)
	}
	if strings.Contains(stderr, "secret") {
		t.Errorf("the resolver DSN's password was logged:\n%s", stderr)
	}
}

func TestRM330TheUsageNamesTheResolutionRoutes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runAPICommand([]string{"-h"}, &stdout, &stderr, stubAPIDeps(healthyStub(), nil))
	for _, want := range []string{
		"POST /api/v1/alert-resolutions/begin",
		"POST /api/v1/alert-resolutions/finish",
		"-resolver-dsn",
		envAPIResolverDSN,
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the usage does not name %q", want)
		}
	}
}

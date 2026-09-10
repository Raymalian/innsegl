// SPDX-License-Identifier: Apache-2.0

package mcp

import "testing"

// A run id is public — it is in every commit's Agent-Run trailer — so it must
// not be enough to obtain that run's credential.
func TestRunTokenIsNotDerivableFromThePublicRunID(t *testing.T) {
	const secret = "server-held"
	const run = "run-72b6665addd7409d8b1bf62e54754ecd"

	tok := RunToken(secret, run)
	if tok == "" {
		t.Fatal("no token derived for a run under a configured secret")
	}
	if tok == run {
		t.Fatal("the token is the run id")
	}
	if len(tok) != 64 {
		t.Errorf("token is %d chars, want 64 hex", len(tok))
	}
	if RunToken("another-secret", run) == tok {
		t.Error("the same run under a different secret produced the same token")
	}
	if RunToken(secret, "run-other") == tok {
		t.Error("two different runs produced the same token")
	}
}

func TestRunTokenValidRejectsAnythingButTheToken(t *testing.T) {
	const secret = "server-held"
	const run = "run-a"
	good := RunToken(secret, run)

	if !RunTokenValid(secret, run, good) {
		t.Fatal("the correct token was refused")
	}
	for name, bad := range map[string]string{
		"the run id itself":      run,
		"another run's token":    RunToken(secret, "run-b"),
		"another secret's token": RunToken("other", run),
		"empty":                  "",
		"truncated":              good[:len(good)-1],
	} {
		if RunTokenValid(secret, run, bad) {
			t.Errorf("%s was accepted as the token", name)
		}
	}
}

// With no secret configured nothing validates, so a deployment cannot drift
// into "authenticated" by accident: the decision to require tokens is made once
// at wiring, never by a comparison that happens to pass.
func TestRunTokenValidIsFalseWithoutASecret(t *testing.T) {
	if RunTokenValid("", "run-a", "") {
		t.Fatal("an empty token validated against an empty secret")
	}
	if RunTokenValid("", "run-a", "anything") {
		t.Fatal("a token validated with no secret configured")
	}
}

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

// RM-212. A deployment that sets no -run-token-secret derives one from the
// identity secret it already loads, so get_credential, sign_commit and
// observe_tool_call are enforced with no new configuration.
func TestDeriveRunTokenSecretIsNonEmptyForANonEmptyIdentitySecret(t *testing.T) {
	const identitySecret = "a-32-byte-identity-secret-abcdef"
	got := DeriveRunTokenSecret(identitySecret)
	if got == "" {
		t.Fatal("no run-token secret derived from a configured identity secret")
	}
	if len(got) != 64 {
		t.Errorf("derived secret is %d chars, want 64 hex", len(got))
	}
}

// An empty identity secret derives nothing: there is nothing to derive FROM,
// and the caller (cmd/innsegl) reads that as "keep the loud warning" rather
// than as a derived empty-string secret that would validate nothing anyway.
func TestDeriveRunTokenSecretIsEmptyWithNoIdentitySecret(t *testing.T) {
	if got := DeriveRunTokenSecret(""); got != "" {
		t.Fatalf("DeriveRunTokenSecret(\"\") = %q, want empty", got)
	}
}

// The derivation is domain-separated from every other use of the identity
// secret: it must not equal the identity secret itself, and it must not equal
// RunToken's own output over that same secret. Either equality would mean the
// run-token secret is not its own key -- exactly the "one key with two
// purposes" risk domain separation exists to close.
func TestDeriveRunTokenSecretIsDomainSeparatedFromTheIdentitySecretAndFromARunToken(t *testing.T) {
	const identitySecret = "a-32-byte-identity-secret-abcdef"
	const run = "run-rm212"

	derived := DeriveRunTokenSecret(identitySecret)
	if derived == identitySecret {
		t.Fatal("the derived run-token secret equals the identity secret it was derived from")
	}
	if derived == RunToken(identitySecret, run) {
		t.Fatal("the derived run-token secret equals a run token computed over the identity secret")
	}

	// Deterministic: the same identity secret always derives the same
	// run-token secret, or a rolling replica would each mint a different one
	// for a secret loaded from the same file.
	if again := DeriveRunTokenSecret(identitySecret); again != derived {
		t.Fatalf("DeriveRunTokenSecret(%q) = %q then %q; it must be deterministic",
			identitySecret, derived, again)
	}

	// Depends on the whole secret, not a prefix of it or a constant.
	if other := DeriveRunTokenSecret("a different identity secret entirely"); other == derived {
		t.Fatal("two different identity secrets derived the same run-token secret")
	}
}

// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// agentmessagekey_test.go — GREC-006 (doc 07 TC-GREC, unit): "The key is
// derived from the identity secret with a fixed label; a new key id after
// rotation; an old digest verifies with its own key id."

const (
	amkSecret  = "test-deployment-identity-secret-rm-237"
	amkOtherKS = "a-completely-different-deployment-secret"
	amkKeyID   = "core-2026-09"
	amkKeyID2  = "core-2026-10"
)

// TestGREC006KeyDerivationIsFixedAndDeterministic: the same (secret, key id)
// always derives the same key, and either input changing derives a
// different one — the property a verifier depends on ("re-derives the key
// for any recorded key id") and the property that makes the derivation safe
// to use as a key at all (two different messages must not end up keyed
// identically by accident of the derivation itself).
func TestGREC006KeyDerivationIsFixedAndDeterministic(t *testing.T) {
	k1, err := DeriveAgentMessageKey(amkSecret, amkKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey: %v", err)
	}
	k2, err := DeriveAgentMessageKey(amkSecret, amkKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey (second call): %v", err)
	}
	if k1 != k2 {
		t.Errorf("the same secret and key id derived two different keys: %q vs %q", k1, k2)
	}
	if k1 == "" {
		t.Fatal("a derived key is empty with a real secret and a valid key id")
	}

	byOtherSecret, err := DeriveAgentMessageKey(amkOtherKS, amkKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey (other secret): %v", err)
	}
	if byOtherSecret == k1 {
		t.Error("two different identity secrets derived the same agent-message key")
	}

	byOtherKeyID, err := DeriveAgentMessageKey(amkSecret, amkKeyID2)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey (other key id): %v", err)
	}
	if byOtherKeyID == k1 {
		t.Error("two different key ids derived the same agent-message key from the same secret")
	}
}

// TestGREC006RotationKeepsAnOldDigestVerifiable: "an old digest verifies
// with its own key id." A message keyed under an id BEFORE a rotation
// verifies correctly by re-deriving that SAME id's key, even once a
// deployment has moved its current key id on to something else — the whole
// point of naming the key id inside the digest rather than tracking a
// current epoch out of band (ADR-0061 Consequences).
func TestGREC006RotationKeepsAnOldDigestVerifiable(t *testing.T) {
	oldKey, err := DeriveAgentMessageKey(amkSecret, amkKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey (pre-rotation): %v", err)
	}

	// The deployment rotates: a NEW key id is now current. This must not
	// change what the OLD id derives to.
	newKey, err := DeriveAgentMessageKey(amkSecret, amkKeyID2)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey (post-rotation, new id): %v", err)
	}
	if newKey == oldKey {
		t.Fatal("the new key id derived the same key as the old one; rotation would key nothing new")
	}

	// A verifier holding the identity secret and the OLD key id — read off
	// an event appended before the rotation — re-derives the identical key
	// the recorder used at the time, independent of whatever is current now.
	rederived, err := DeriveAgentMessageKey(amkSecret, amkKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey (re-derive old id after rotation): %v", err)
	}
	if rederived != oldKey {
		t.Errorf("re-deriving the old key id after rotation gave %q, want the original %q", rederived, oldKey)
	}
}

// TestDeriveAgentMessageKeyRefusesAnEmptySecret: ADR-0061 gives this member
// no unkeyed fallback, so a recorder with nothing to derive from must
// refuse loudly rather than key a digest with an empty or default value.
func TestDeriveAgentMessageKeyRefusesAnEmptySecret(t *testing.T) {
	_, err := DeriveAgentMessageKey("", amkKeyID)
	if !errors.Is(err, ErrNoIdentitySecretForAgentMessageKey) {
		t.Fatalf("DeriveAgentMessageKey(\"\", ...) = %v, want ErrNoIdentitySecretForAgentMessageKey", err)
	}
}

// TestDeriveAgentMessageKeyRefusesAMalformedKeyID: the 2026-09-28 amendment's
// grammar, [a-z0-9][a-z0-9-]{0,62}, held exactly — the same grammar
// event.ValidateIdentifier already enforces for run_id, agent_type and
// task_id, reused rather than re-specified (see agentmessagekey.go's own
// doc comment).
func TestDeriveAgentMessageKeyRefusesAMalformedKeyID(t *testing.T) {
	cases := []struct {
		name  string
		keyID string
	}{
		{"empty", ""},
		{"uppercase", "Core-2026-09"},
		{"leading hyphen", "-core-2026-09"},
		{"underscore", "core_2026_09"},
		{"space", "core 2026 09"},
		{"too long", strings.Repeat("a", 64)}, // 64 valid characters, one over the 63-byte bound
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DeriveAgentMessageKey(amkSecret, tc.keyID); !errors.Is(err, ErrAgentMessageKeyID) {
				t.Errorf("DeriveAgentMessageKey(secret, %q) = %v, want ErrAgentMessageKeyID", tc.keyID, err)
			}
			if err := ValidateAgentMessageKeyID(tc.keyID); !errors.Is(err, ErrAgentMessageKeyID) {
				t.Errorf("ValidateAgentMessageKeyID(%q) = %v, want ErrAgentMessageKeyID", tc.keyID, err)
			}
		})
	}
}

// TestValidateAgentMessageKeyIDAcceptsTheADRExample: ADR-0061's own example,
// "core-2026-09", is exactly what the amendment's grammar was written to
// accept — a stable prefix and a rotation date, hyphen-joined.
func TestValidateAgentMessageKeyIDAcceptsTheADRExample(t *testing.T) {
	if err := ValidateAgentMessageKeyID("core-2026-09"); err != nil {
		t.Errorf("ValidateAgentMessageKeyID(%q): %v, want no error", "core-2026-09", err)
	}
}

// agentMessageKeyedDigestPattern mirrors internal/event's own private
// keyedDigestPattern (validate.go) so this file can assert the SHAPE of a
// full digest it builds by hand, independent of internal/event's own
// unexported regexp. Kept identical to ADR-0061's grammar deliberately:
// this is a second CHECK of the same rule, not a second DEFINITION of it —
// event.ValidateKeyedDigest is what agentmessage.go's own production code
// and its tests hold every real digest to.
var agentMessageKeyedDigestPattern = regexp.MustCompile(`^hmac-sha256:[a-z0-9][a-z0-9-]{0,62}:[0-9a-f]{64}$`)

// TestDeriveAgentMessageKeyReturnsHexNotADigest: the derived KEY is a plain
// hex string (an HMAC key), never the `hmac-sha256:<id>:<hex>` digest
// grammar itself — the two are easy to conflate since both are hex-shaped.
// agentmessage.go's own keyedDigest method is what builds the actual
// digest, over this value; this file checks the two are not confused at
// their boundary.
func TestDeriveAgentMessageKeyReturnsHexNotADigest(t *testing.T) {
	key, err := DeriveAgentMessageKey(amkSecret, amkKeyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey: %v", err)
	}
	if agentMessageKeyedDigestPattern.MatchString(key) {
		t.Errorf("the derived key %q matches the keyed-digest grammar; it must be a bare hex key", key)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(key) {
		t.Errorf("the derived key %q is not 64 lowercase hex characters (a SHA-256 in hex)", key)
	}
}

// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"innsegl.dev/innsegl/internal/event"
)

// agentmessagekey.go — RM-237 (#382), ADR-0061 decision 2 and its 2026-09-28
// amendment: the HMAC key behind agent_message.payload_digest's keyed
// grammar, `hmac-sha256:<key-id>:<64 lowercase hex>`.
//
// # Derived, not stored — the same argument runtoken.go already made
//
// DeriveRunTokenSecret (runtoken.go) derives the run-token secret from the
// one deployment-wide secret this process already loads (RM-212), rather
// than requiring a SECOND provisioned, mounted, rotated secret: "Requiring
// an operator to provision, mount and rotate a SECOND one ... is exactly the
// friction that shipped every deployment ... unauthenticated by default."
// The identical argument applies here: ADR-0061 requires the digest to be
// keyed from the start, and deriving the key from the identity secret this
// process already has is what makes that cost zero rather than a second
// secret store nobody provisions. Nothing here is persisted, so there is no
// table to migrate, no row to leak, and no schema change to a protected
// surface (doc 02) — a verifier recomputes the key it needs from the
// identity secret and the key id an event already names.
//
// # Domain separation, twice over
//
// agentMessageKeyDerivationLabel separates this derivation from every other
// use of the identity secret this codebase already makes (a pseudonym,
// internal/identity; a run token, runTokenLabel; a run-token secret,
// runTokenSecretDerivationLabel). The key id is mixed in as a second,
// independent separator, so EVERY key id derives its own key from the same
// secret: rotation is minting a new id and getting an independent key with
// nothing to revoke and nothing to persist, and an old id's key is exactly
// as recoverable after a rotation as before it, because the derivation never
// changes — only the id a caller names does.
//
// # Why this is not runtoken.go's derivation, reused
//
// A run-token secret and an agent-message key answer different questions
// under the same identity secret, and are read by different parties: a run
// token by whichever gateway/MCP process needs to authenticate a run, a
// keyed digest by anyone who can hold the identity secret and a message
// body and wants to confirm one against the chain. Sharing one derived value
// between the two would mean a party entitled to verify an agent_message
// digest could also recompute this deployment's run-token secret — a
// capability ADR-0061 never grants. A separating label, mixed in before any
// caller-supplied byte, is what keeps the two from ever producing the same
// bytes, and RM-212's own DeriveRunTokenSecret already relies on the
// identical property one derivation up.
const agentMessageKeyDerivationLabel = "innsegl/agent-message-key/v1"

// agentMessageKeyDerivationSep separates the label from the key id inside
// the MAC input. Without it, label "ab" + id "c" and label "a" + id "bc"
// would hash identically; HMAC's own key (identitySecret) already stops
// that class of confusion between callers using DIFFERENT secrets, but this
// domain stays exact even for two key ids that happen to concatenate the
// same way against one label.
var agentMessageKeyDerivationSep = []byte{0}

// ErrAgentMessageKeyID rejects a key id that does not match ADR-0061's
// grammar.
var ErrAgentMessageKeyID = errors.New("invalid agent-message key id")

// ErrNoIdentitySecretForAgentMessageKey rejects a request to derive an
// agent-message key with no identity secret to derive it from.
var ErrNoIdentitySecretForAgentMessageKey = errors.New("no identity secret configured: an agent-message key cannot be derived from nothing")

// ValidateAgentMessageKeyID checks keyID against ADR-0061's 2026-09-28
// amendment: "<key-id> follows doc 02 §5's identifier grammar:
// [a-z0-9][a-z0-9-]{0,62}." Reused outright from internal/event rather than
// duplicated — the ADR names doc 02 §5's grammar by reference and gives
// <key-id> no shape of its own beyond that reuse, so a second regexp here
// would be a second place the two could drift apart.
func ValidateAgentMessageKeyID(keyID string) error {
	if err := event.ValidateIdentifier(keyID); err != nil {
		return fmt.Errorf("%w: %w", ErrAgentMessageKeyID, err)
	}
	return nil
}

// DeriveAgentMessageKey derives the HMAC-SHA256 key for keyID from
// identitySecret: the same per-deployment secret DeriveRunTokenSecret
// already derives the run-token secret from, under a fixed label of this
// derivation's own and the key id mixed in as a second separator (see this
// file's doc comment for why the two derivations must never collapse into
// one, and why the key id is part of the domain separation rather than
// appended to the secret afterwards).
//
// Returned hex-encoded, the same shape DeriveRunTokenSecret returns its own
// derived secret in: a caller HMACs a message body with []byte(the
// returned string) exactly as RunToken already HMACs a run id with
// []byte(secret).
//
// Refused, rather than returning an empty key, when identitySecret is empty
// or keyID does not match ADR-0061's grammar — unlike
// DeriveRunTokenSecret's "empty secret yields an empty token" reading. A
// run token's empty case is deliberately absorbable (RunTokenValid treats
// an empty want as "never valid," which is exactly "no auth configured");
// ADR-0061 gives agent_message.payload_digest no equivalent unkeyed
// fallback — "never shipped plain and hardened later" — so a key that
// cannot be derived here has to stop the write it would key, loudly, rather
// than hand back a value that would key nothing.
func DeriveAgentMessageKey(identitySecret, keyID string) (string, error) {
	if identitySecret == "" {
		return "", ErrNoIdentitySecretForAgentMessageKey
	}
	if err := ValidateAgentMessageKeyID(keyID); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(identitySecret))
	mac.Write([]byte(agentMessageKeyDerivationLabel))
	mac.Write(agentMessageKeyDerivationSep)
	mac.Write([]byte(keyID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// SPDX-License-Identifier: Apache-2.0

package event

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ADR-0061 -- schema 4, #407 (RM-258).
//
// Schema 4 adds one event type and two optional members, and nothing else:
//
//	run_registered  forked_from_run_id, optional (run_id grammar)
//	agent_message   role (required, brief | assistant) and payload_digest
//	                (required, the KEYED grammar -- not the envelope's
//	                default)
//	tool_call       workspace_tree_hash, optional (git object id grammar)
//
// Each case starts from a committed v4 vector, so it differs from a known-good
// event in exactly the one way under test.

func briefEvent(t *testing.T) Fields {
	t.Helper()
	return fixtureFor(t, EventTypeAgentMessage)
}

// TestADP007AgentMessageIsASchema4EventAndNothingLooser is the agent_message
// half of ADR-0061 decision 2: role is a closed enum and payload_digest is the
// keyed grammar, required, not the envelope's plain default.
func TestADP007AgentMessageIsASchema4EventAndNothingLooser(t *testing.T) {
	if err := ValidateEvent(briefEvent(t)); err != nil {
		t.Fatalf("the committed agent_message vector does not validate: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(Fields)
		want   error
	}{
		{"no role", func(f Fields) { delete(f, FieldRole) }, ErrMissingMember},
		{"an empty role", func(f Fields) { f[FieldRole] = "" }, ErrEmptyValue},
		{"a role in the wrong case", func(f Fields) { f[FieldRole] = "Brief" }, ErrInvalidField},
		{"a role naming a tool, not a message", func(f Fields) { f[FieldRole] = "tool" }, ErrInvalidField},
		{"a role this ledger never speaks", func(f Fields) { f[FieldRole] = "system" }, ErrInvalidField},
		{"no claim digest", func(f Fields) { delete(f, FieldPayloadDigest) }, ErrMissingMember},
		{"a claim digest that is not a digest at all", func(f Fields) { f[FieldPayloadDigest] = "claim.txt" }, ErrInvalidKeyedDigest},
		{
			"a claim digest in the PLAIN envelope grammar -- rejected on this type",
			func(f Fields) { f[FieldPayloadDigest] = HashPrefix + strings.Repeat("a", 64) },
			ErrInvalidKeyedDigest,
		},
		{
			"a key id with an uppercase character",
			func(f Fields) {
				f[FieldPayloadDigest] = "hmac-sha256:Core-2026-09:" + strings.Repeat("a", 64)
			},
			ErrInvalidKeyedDigest,
		},
		{
			"63 hex digits instead of 64",
			func(f Fields) { f[FieldPayloadDigest] = "hmac-sha256:core-2026-09:" + strings.Repeat("a", 63) },
			ErrInvalidKeyedDigest,
		},
		{
			"uppercase hex",
			func(f Fields) { f[FieldPayloadDigest] = "hmac-sha256:core-2026-09:" + strings.Repeat("A", 64) },
			ErrInvalidKeyedDigest,
		},
		{
			"missing the hmac-sha256 tag",
			func(f Fields) { f[FieldPayloadDigest] = "core-2026-09:" + strings.Repeat("a", 64) },
			ErrInvalidKeyedDigest,
		},
		// ValidateEvent (the append path) refuses any schema_version but the
		// current one before it ever looks up the type, so this is
		// ErrInvalidField rather than ErrUnknownEventType -- proved
		// separately, on the verification path, below.
		{"the same event relabelled schema 3", func(f Fields) { f[FieldSchemaVersion] = "3" }, ErrInvalidField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := briefEvent(t)
			tc.mutate(f)
			err := ValidateEvent(f)
			if err == nil {
				t.Fatal("accepted")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("ValidateEvent = %v, want %v", err, tc.want)
			}
		})
	}

	for _, role := range []string{"brief", "assistant"} {
		t.Run("the role "+role, func(t *testing.T) {
			f := briefEvent(t)
			f[FieldRole] = role
			if err := ValidateEvent(f); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}

	// agent_message is not merely optional under schema 3 -- under 3 it is
	// NOT A TYPE, the same rule memberSpec.since states for a member. A
	// verifier that predates schema 4 refuses it outright rather than
	// validating it against a table it never had.
	t.Run("agent_message does not exist under schema 3", func(t *testing.T) {
		f := briefEvent(t)
		f[FieldSchemaVersion] = "3"
		if err := ValidateEventForVerification(f); !errors.Is(err, ErrUnknownEventType) {
			t.Errorf("ValidateEventForVerification = %v, want %v", err, ErrUnknownEventType)
		}
	})
}

// TestADP008TheKeyedGrammarIsExclusiveToAgentMessage is the grammar
// cross-rejection ADR-0061 decision 2 requires: the keyed form belongs to
// agent_message ALONE. Every other type's payload_digest keeps the plain
// envelope grammar, unchanged, and refuses a keyed value exactly as it would
// refuse any other malformed digest.
func TestADP008TheKeyedGrammarIsExclusiveToAgentMessage(t *testing.T) {
	keyed := "hmac-sha256:" + v4KeyID + ":" + strings.Repeat("a", 64)

	for _, et := range []string{EventTypeToolCall, EventTypeRunAdopted, EventTypeCommitIntentExpired} {
		t.Run(et, func(t *testing.T) {
			f := fixtureFor(t, et)
			f[FieldPayloadDigest] = keyed
			if err := ValidateEvent(f); !errors.Is(err, ErrInvalidDigest) {
				t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidDigest)
			}
		})
	}

	// And the reverse, directly against the two grammar functions: neither
	// accepts what the other is for.
	plain := HashPrefix + strings.Repeat("a", 64)
	if err := ValidateKeyedDigest(plain); !errors.Is(err, ErrInvalidKeyedDigest) {
		t.Errorf("ValidateKeyedDigest(%q) = %v, want %v", plain, err, ErrInvalidKeyedDigest)
	}
	if err := ValidateDigest(keyed); !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("ValidateDigest(%q) = %v, want %v", keyed, err, ErrInvalidDigest)
	}
}

// TestADP009ForkedFromRunIDIsOptionalOnRunRegisteredFromSchema4 covers
// ADR-0061 decision 1: forked_from_run_id is the run_id grammar, optional, and
// independent of parent_run_id -- a run may carry either, both, or neither.
func TestADP009ForkedFromRunIDIsOptionalOnRunRegisteredFromSchema4(t *testing.T) {
	plain := fixtureFor(t, EventTypeRunRegistered)
	if _, ok := plain[FieldForkedFromRunID]; ok {
		t.Fatal("the plain run_registered vector carries forked_from_run_id; want the one without")
	}
	if err := ValidateEvent(plain); err != nil {
		t.Fatalf("a run_registered with no fork origin refused: %v", err)
	}

	fork := loadFixture(t, v4ForkFixture).input.Clone()
	if _, ok := fork[FieldForkedFromRunID]; !ok {
		t.Fatal("the fork vector does not carry forked_from_run_id")
	}
	if err := ValidateEvent(fork); err != nil {
		t.Errorf("a run_registered naming its fork origin refused: %v", err)
	}

	// Independent of parent_run_id: a fixture can carry both without either
	// being read as an answer to the other's question (ADR-0061 decision 1).
	both := fork.Clone()
	both[FieldParentRunID] = "run-45"
	if err := ValidateEvent(both); err != nil {
		t.Errorf("a run_registered carrying both parent_run_id and "+
			"forked_from_run_id refused: %v", err)
	}

	bad := fork.Clone()
	bad[FieldForkedFromRunID] = "run 41"
	if err := ValidateEvent(bad); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidIdentifier)
	}

	older := fork.Clone()
	older[FieldSchemaVersion] = "3"
	if err := ValidateEventForVerification(older); !errors.Is(err, ErrUnknownMember) {
		t.Error("forked_from_run_id accepted under schema 3, which has no such member")
	}
}

// TestADP010WorkspaceTreeHashIsOptionalOnToolCallFromSchema4 covers ADR-0061
// decision 3: the same git object id grammar commit_intent.tree_hash already
// uses, optional, and not a duplicate of it.
func TestADP010WorkspaceTreeHashIsOptionalOnToolCallFromSchema4(t *testing.T) {
	plain := fixtureFor(t, EventTypeToolCall)
	if _, ok := plain[FieldWorkspaceTreeHash]; ok {
		t.Fatal("the plain tool_call vector carries workspace_tree_hash; want the one without")
	}
	if err := ValidateEvent(plain); err != nil {
		t.Fatalf("a tool_call with no workspace snapshot refused: %v", err)
	}

	withTree := loadFixture(t, v4WorkspaceTreeFixture).input.Clone()
	if _, ok := withTree[FieldWorkspaceTreeHash]; !ok {
		t.Fatal("the workspace-tree vector does not carry workspace_tree_hash")
	}
	if err := ValidateEvent(withTree); err != nil {
		t.Errorf("a tool_call naming its workspace tree refused: %v", err)
	}

	bad := withTree.Clone()
	bad[FieldWorkspaceTreeHash] = "abc1234"
	if err := ValidateEvent(bad); !errors.Is(err, ErrInvalidGitObjectID) {
		t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidGitObjectID)
	}

	older := withTree.Clone()
	older[FieldSchemaVersion] = "3"
	if err := ValidateEventForVerification(older); !errors.Is(err, ErrUnknownMember) {
		t.Error("workspace_tree_hash accepted under schema 3, which has no such member")
	}
}

// TestADP011TheV4SetAddsOnlyWhatADR0061Specifies holds the generator to its
// word: every vector carried over from v3 (minus v3's own migration
// attestation) differs from its original in the version and the chain link and
// nothing else, and the only vectors v3 has no counterpart for are the five
// ADR-0061 adds.
func TestADP011TheV4SetAddsOnlyWhatADR0061Specifies(t *testing.T) {
	v3 := "testdata/fixtures/v3"
	v4 := "testdata/fixtures/v4"
	carried := map[string]bool{}
	for _, name := range fixtureNamesIn(t, v3) {
		carried[name] = true
	}
	added := []string{
		v4ForkFixture, v4WorkspaceTreeFixture,
		v4AgentMessageBriefFixture, v4AgentMessageAssistant,
		v4MigrationFixture,
	}
	for _, name := range fixtureNamesIn(t, v4) {
		if name == "format-probe" {
			continue
		}
		if !carried[name] || name == v3MigrationFixture {
			if !slices.Contains(added, name) {
				t.Errorf("v4 carries %q, which neither v3 nor ADR-0061 has", name)
			}
			continue
		}
		was := loadFixtureFrom(t, v3, name).input
		now := loadFixtureFrom(t, v4, name).input
		for member := range now {
			if member == FieldSchemaVersion || member == FieldPrevEventHash {
				continue
			}
			if fmt.Sprint(now[member]) != fmt.Sprint(was[member]) {
				t.Errorf("%s: %s changed from %v to %v", name, member, was[member], now[member])
			}
		}
		if len(now) != len(was) {
			t.Errorf("%s: v4 has %d members, v3 had %d", name, len(now), len(was))
		}
	}
}

// TestValidateKeyedDigestGrammar exercises ValidateKeyedDigest directly,
// including the states ValidateEvent's callers cannot reach but a direct
// caller can.
func TestValidateKeyedDigestGrammar(t *testing.T) {
	good := "hmac-sha256:" + v4KeyID + ":" + strings.Repeat("a", 64)
	if err := ValidateKeyedDigest(good); err != nil {
		t.Errorf("ValidateKeyedDigest(%q) = %v, want nil", good, err)
	}
	for _, bad := range []string{
		"",
		"hmac-sha256::" + strings.Repeat("a", 64),
		"hmac-sha256:core:" + strings.Repeat("a", 63),
		"hmac-sha256:core:" + strings.Repeat("a", 65),
		"hmac-sha256:core:" + strings.Repeat("A", 64),
		"hmac-sha256:-core:" + strings.Repeat("a", 64),
		"hmac-sha1:core:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 64),
	} {
		if err := ValidateKeyedDigest(bad); !errors.Is(err, ErrInvalidKeyedDigest) {
			t.Errorf("ValidateKeyedDigest(%q) = %v, want %v", bad, err, ErrInvalidKeyedDigest)
		}
	}
}

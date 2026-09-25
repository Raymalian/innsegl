// SPDX-License-Identifier: Apache-2.0

package event

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// ADP-004 and ADP-005 — schema 3, ADR-0051 decision 3, #298 (RM-187).
//
// Schema 3 adds one event type and one member, and nothing else:
//
//	run_adopted        adopted_run_id, adopted_run_state, and payload_digest
//	                   (the claim, stored as a body under that digest: E4)
//	commit_intent      adoption_event_id, optional
//
// Each case starts from a committed v3 vector, so it differs from a known-good
// event in exactly the one way under test.

func adoptedEvent(t *testing.T) Fields {
	t.Helper()
	return fixtureFor(t, EventTypeRunAdopted)
}

func TestADP004RunAdoptedIsASchema3EventAndNothingLooser(t *testing.T) {
	if err := ValidateEvent(adoptedEvent(t)); err != nil {
		t.Fatalf("the committed run_adopted vector does not validate: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(Fields)
	}{
		{"a state the ledger does not call dead: active", func(f Fields) { f[FieldAdoptedRunState] = "active" }},
		{"an empty state", func(f Fields) { f[FieldAdoptedRunState] = "" }},
		{"a state in the wrong case", func(f Fields) { f[FieldAdoptedRunState] = "Retired" }},
		{"no adopted run", func(f Fields) { delete(f, FieldAdoptedRunID) }},
		{"an adopted run that is not a run id", func(f Fields) { f[FieldAdoptedRunID] = "run 42" }},
		{"no claim digest", func(f Fields) { delete(f, FieldPayloadDigest) }},
		{"a claim digest that is not a digest", func(f Fields) { f[FieldPayloadDigest] = "claim.txt" }},
		{"the same event under schema 2", func(f Fields) { f[FieldSchemaVersion] = "2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := adoptedEvent(t)
			tc.mutate(f)
			if err := ValidateEvent(f); err == nil {
				t.Error("accepted")
			}
		})
	}

	for _, state := range []string{"retired", "lapsed", "abandoned"} {
		t.Run("the dead state "+state, func(t *testing.T) {
			f := adoptedEvent(t)
			f[FieldAdoptedRunState] = state
			if err := ValidateEvent(f); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

func TestADP005AdoptionEventIDIsOptionalOnCommitIntentFromSchema3(t *testing.T) {
	plain := fixtureFor(t, EventTypeCommitIntent)
	if _, ok := plain[FieldAdoptionEventID]; ok {
		t.Fatal("the plain commit_intent vector carries adoption_event_id; want the one without")
	}
	if err := ValidateEvent(plain); err != nil {
		t.Fatalf("a commit_intent with no adoption refused: %v", err)
	}

	adopted := plain.Clone()
	adopted[FieldAdoptionEventID] = adoptedEvent(t)[FieldEventID]
	if err := ValidateEvent(adopted); err != nil {
		t.Errorf("a commit_intent naming its adoption refused: %v", err)
	}

	bad := plain.Clone()
	bad[FieldAdoptionEventID] = "not-an-event-id"
	if err := ValidateEvent(bad); err == nil {
		t.Error("a malformed adoption_event_id accepted")
	}

	older := adopted.Clone()
	older[FieldSchemaVersion] = "2"
	delete(older, FieldAdoptionEventID)
	if err := ValidateEventForVerification(older); err != nil {
		t.Fatalf("control: the v2 form of the intent refused: %v", err)
	}
	older[FieldAdoptionEventID] = adopted[FieldAdoptionEventID]
	if err := ValidateEventForVerification(older); !errors.Is(err, ErrUnknownMember) {
		t.Error("adoption_event_id accepted under schema 2, which has no such member")
	}
}

// TestADP006TheV3SetAddsOnlyWhatADR0051Specifies holds the generator to its
// word: every vector carried over from v2 differs from its original in the
// version and the chain link and nothing else, and the only vectors v2 has no
// counterpart for are the three ADR-0051 adds.
func TestADP006TheV3SetAddsOnlyWhatADR0051Specifies(t *testing.T) {
	v2 := "testdata/fixtures/v2"
	v3 := "testdata/fixtures/v3"
	carried := map[string]bool{}
	for _, name := range fixtureNamesIn(t, v2) {
		carried[name] = true
	}
	added := []string{v3AdoptedFixture, v3AdoptedIntent, v3MigrationFixture}
	for _, name := range fixtureNamesIn(t, v3) {
		if name == "format-probe" {
			continue
		}
		if !carried[name] || name == "16-schema_migrated" {
			if !slices.Contains(added, name) {
				t.Errorf("v3 carries %q, which neither v2 nor ADR-0051 has", name)
			}
			continue
		}
		was := loadFixtureFrom(t, v2, name).input
		now := loadFixtureFrom(t, v3, name).input
		for member := range now {
			if member == FieldSchemaVersion || member == FieldPrevEventHash {
				continue
			}
			if fmt.Sprint(now[member]) != fmt.Sprint(was[member]) {
				t.Errorf("%s: %s changed from %v to %v", name, member, was[member], now[member])
			}
		}
		if len(now) != len(was) {
			t.Errorf("%s: v3 has %d members, v2 had %d", name, len(now), len(was))
		}
	}
}

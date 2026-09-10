// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// LED-037 (proposed for doc 07; doc 07 is not modified here) — RM-116, #188.
//
// The E9 epic's exit criterion, in its own words: "a verifier refuses to start
// if it cannot read both."
//
// # The failure this closes
//
// A build knows every version up to its own and nothing about the ones after
// it. That asymmetry is deliberate — doc 02 §1 has a verifier TOLERATE unknown
// members from a newer schema rather than refuse them, because the alternative
// is that every old verifier breaks on the day a new version ships.
//
// Tolerating them per-event is right. Starting up and serving verdicts over a
// chain that has been migrated past this build is not: every answer it gives
// about an event after the cutover is an answer it cannot fully check, and it
// would give them silently and confidently. The chain says so itself —
// `schema_migrated` names the version and the position — so a verifier can ask
// once at startup instead of guessing forever.
func TestLED037AVerifierRefusesAChainMigratedPastIt(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	t.Run("an unmigrated chain is readable", func(t *testing.T) {
		if err := s.AssertReadableSchema(ctx); err != nil {
			t.Errorf("AssertReadableSchema on a chain with no attestation: %v", err)
		}
	})

	t.Run("a chain migrated to this build's own version is readable", func(t *testing.T) {
		if _, err := s.Append(ctx, attestation("1", event.SchemaVersion, 1, "to-current")); err != nil {
			t.Fatalf("append the attestation: %v", err)
		}
		if err := s.AssertReadableSchema(ctx); err != nil {
			t.Errorf("AssertReadableSchema after migrating to %s, which this build "+
				"emits: %v", event.SchemaVersion, err)
		}
	})

	t.Run("a chain migrated past this build is refused, by name", func(t *testing.T) {
		if _, err := s.Append(ctx, attestation(event.SchemaVersion, "99", 2, "to-future")); err != nil {
			t.Fatalf("append the attestation: %v", err)
		}
		err := s.AssertReadableSchema(ctx)
		if err == nil {
			t.Fatal("a chain migrated to schema 99 was accepted; every verdict this " +
				"verifier gives about an event after the cutover is one it cannot " +
				"fully check, and it would give them silently")
		}
		for _, want := range []string{"99", event.SchemaVersion} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("said %q, which does not name %q", err, want)
			}
		}
	})
}

// attestation builds a `schema_migrated` body.
func attestation(from, to string, cutover int64, key string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:     event.SchemaVersion,
		event.FieldEventType:         event.EventTypeSchemaMigrated,
		event.FieldSource:            event.SourceSystem,
		event.FieldIdempotencyKey:    key,
		event.FieldFromSchemaVersion: from,
		event.FieldToSchemaVersion:   to,
		event.FieldCutoverPosition:   cutover,
	}
}

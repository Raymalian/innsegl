// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"

	"innsegl.dev/innsegl/internal/event"
)

// valueRunes is the alphabet generated string values are drawn from: ASCII,
// the two characters JSON must escape, a control character, and multi-byte
// UTF-8 so that a single-byte flip can land mid-sequence.
var valueRunes = []rune{
	'a', 'Z', '0', '-', '_', ' ', '/', '"', '\\', '\n', 0x7f,
	0x00e9, 0x20ac, 0x4e2d, 0x1f600,
}

// genBody generates one event body: the caller-supplied half of an event, with
// none of the three members the ledger assigns.
func genBody(n int) *rapid.Generator[event.Fields] {
	return rapid.Custom(func(t *rapid.T) event.Fields {
		f := event.Fields{
			event.FieldSchemaVersion: event.SchemaVersion,
			event.FieldEventID:       testEventID(n),
			event.FieldEventType:     "tool_call",
			event.FieldTS:            "2026-08-28T09:14:03.201Z",
			event.FieldSource:        event.SourceMCP,
			"tool_name": string(rapid.SliceOfN(rapid.SampledFrom(valueRunes), 1, 8).
				Draw(t, fmt.Sprintf("tool_name_%d", n))),
			"attempt": rapid.Int64Range(0, 1<<40).Draw(t, fmt.Sprintf("attempt_%d", n)),
			"retried": rapid.Bool().Draw(t, fmt.Sprintf("retried_%d", n)),
		}
		return f
	})
}

// genChain generates a valid chain of between minLen and maxLen events, built
// through Append itself so the chain under test is the chain the ledger writes.
func genChain(t *rapid.T, minLen, maxLen int) ([]event.Fields, Head) {
	n := rapid.IntRange(minLen, maxLen).Draw(t, "chain_length")
	var (
		head    Head
		records []event.Fields
	)
	for i := 1; i <= n; i++ {
		rec, next, err := Append(head, genBody(i).Draw(t, fmt.Sprintf("body_%d", i)))
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
		records = append(records, rec)
		head = next
	}
	// Guard against a vacuous property: if the chain under test is not a real
	// chain of n linked events, every mutation below would "pass" by proving
	// nothing at all.
	if len(records) != n {
		t.Fatalf("generated %d records, want %d", len(records), n)
	}
	if head.Position != int64(n) {
		t.Fatalf("generated chain head is at position %d, want %d", head.Position, n)
	}
	if err := VerifyTip(records, head); err != nil {
		t.Fatalf("generated chain does not verify: %v", err)
	}
	return records, head
}

// assertBreaksFrom is the LED-005 assertion in full: every prefix that stops
// before position `pos` still verifies, and every prefix that reaches it fails
// there — "from that event onward", not merely "somewhere".
func assertBreaksFrom(t require, records []event.Fields, pos int) {
	for k := 0; k < pos-1; k++ {
		if _, err := Verify(records[:k+1]); err != nil {
			t.Fatalf("prefix of %d records (before the damage at position %d) failed: %v",
				k+1, pos, err)
		}
	}
	for k := pos - 1; k < len(records); k++ {
		_, err := Verify(records[:k+1])
		if err == nil {
			t.Fatalf("prefix of %d records verified despite damage at position %d", k+1, pos)
		}
		var verr *VerificationError
		if !errors.As(err, &verr) {
			t.Fatalf("error %v is not a *VerificationError", err)
		}
		if verr.Position != int64(pos) {
			t.Fatalf("prefix of %d records failed at position %d, want %d",
				k+1, verr.Position, pos)
		}
	}
}

// require is the slice of *testing.T and *rapid.T the assertions need, so one
// assertion body serves both the property tests and the exhaustive ones.
type require interface {
	Fatalf(format string, args ...any)
	Helper()
}

// mutateByte flips one byte of a record's canonical serialization and reparses
// it. It reports false when the mutation makes the record unparseable, which
// is detection by a stricter route than chain verification.
func mutateByte(t *rapid.T, rec event.Fields, label string) (event.Fields, bool) {
	raw, err := event.Canonicalize(rec)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	i := rapid.IntRange(0, len(raw)-1).Draw(t, label+"_offset")
	delta := rapid.IntRange(1, 255).Draw(t, label+"_delta")

	mutated := make([]byte, len(raw))
	copy(mutated, raw)
	mutated[i] = byte((int(mutated[i]) + delta) % 256)

	parsed, err := event.ParseFields(mutated)
	if err != nil {
		return nil, false
	}
	return parsed, true
}

// TestLED005MutateAnyByteBreaksTheChain is LED-005: flipping any single byte of
// any historical event breaks verification from that event onward (I4, IP §6.4).
func TestLED005MutateAnyByteBreaksTheChain(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		records, _ := genChain(t, 2, 8)
		i := rapid.IntRange(0, len(records)-1).Draw(t, "victim_index")

		parsed, ok := mutateByte(t, records[i], "flip")
		if !ok {
			// The mutation destroyed the record's syntax. It is rejected before
			// the chain walk ever sees it, which is still detection.
			return
		}
		before, err := event.Canonicalize(records[i])
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}
		after, err := event.Canonicalize(parsed)
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}
		if bytes.Equal(before, after) {
			t.Fatalf("the byte flip was a no-op; the mutation must change the record")
		}

		damaged := make([]event.Fields, len(records))
		copy(damaged, records)
		damaged[i] = parsed
		assertBreaksFrom(t, damaged, i+1)
	})
}

// TestLED005MutateAnyMemberBreaksTheChain is LED-005 at the member level: a
// semantically valid edit to any member of any historical event, including its
// own event_hash, breaks verification from that event onward.
func TestLED005MutateAnyMemberBreaksTheChain(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		records, _ := genChain(t, 2, 8)
		i := rapid.IntRange(0, len(records)-1).Draw(t, "victim_index")

		victim := records[i]
		names := make([]string, 0, len(victim))
		for name := range victim {
			names = append(names, name)
		}
		// Sorted so the draw is reproducible from the rapid seed alone.
		slices.Sort(names)
		name := rapid.SampledFrom(names).Draw(t, "victim_member")

		edited := victim.Clone()
		switch v := victim[name].(type) {
		case string:
			edited[name] = v + "x"
		case int64:
			edited[name] = v + 1
		case bool:
			edited[name] = !v
		default:
			t.Fatalf("member %q is %T; events are flat objects of string, bool and integer", name, v)
		}

		damaged := make([]event.Fields, len(records))
		copy(damaged, records)
		damaged[i] = edited
		assertBreaksFrom(t, damaged, i+1)
	})
}

// TestLED005EveryPositionMutated is the exhaustive companion to the property
// tests: it walks every position of a fixed chain rather than sampling, so the
// coverage of positions beyond the first is a fact and not a probability.
func TestLED005EveryPositionMutated(t *testing.T) {
	const n = 6
	records, _ := appendChain(t, n)

	for i := range records {
		t.Run(fmt.Sprintf("position_%d", i+1), func(t *testing.T) {
			edited := records[i].Clone()
			edited["tool_name"] = memberString(t, records[i], "tool_name") + "-tampered"

			damaged := make([]event.Fields, len(records))
			copy(damaged, records)
			damaged[i] = edited
			assertBreaksFrom(t, damaged, i+1)
		})
	}
}

// TestLED006RemoveAnyEventBreaksTheChain is LED-006: removing any event breaks
// verification at the gap. Removing the tail leaves no gap — a prefix of a
// valid chain is a valid chain — so that case is caught by the expected tip
// instead, which is the only thing that can catch it.
func TestLED006RemoveAnyEventBreaksTheChain(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		records, tip := genChain(t, 2, 8)
		i := rapid.IntRange(0, len(records)-1).Draw(t, "removed_index")
		assertRemovalDetected(t, records, tip, i)
	})
}

// TestLED006EveryPositionRemoved is the exhaustive companion: every position of
// a fixed chain is removed in turn, first to last.
func TestLED006EveryPositionRemoved(t *testing.T) {
	const n = 6
	records, tip := appendChain(t, n)

	for i := range records {
		t.Run(fmt.Sprintf("position_%d", i+1), func(t *testing.T) {
			assertRemovalDetected(t, records, tip, i)
		})
	}
}

// assertRemovalDetected holds the LED-006 expectation for removing index i.
func assertRemovalDetected(t require, records []event.Fields, tip Head, i int) {
	t.Helper()

	gapped := make([]event.Fields, 0, len(records)-1)
	gapped = append(gapped, records[:i]...)
	gapped = append(gapped, records[i+1:]...)

	if i == len(records)-1 {
		// Tail removal: the walk itself is green, and only the expected tip
		// exposes it.
		if _, err := Verify(gapped); err != nil {
			t.Fatalf("removing the tail should leave a walkable chain, got %v", err)
		}
		if err := VerifyTip(gapped, tip); !errors.Is(err, ErrTipMismatch) {
			t.Fatalf("VerifyTip after truncation = %v, want %v", err, ErrTipMismatch)
		}
		return
	}

	_, err := Verify(gapped)
	if err == nil {
		t.Fatalf("a chain missing position %d verified", i+1)
	}
	var verr *VerificationError
	if !errors.As(err, &verr) {
		t.Fatalf("error %v is not a *VerificationError", err)
	}
	if verr.Position != int64(i+1) {
		t.Fatalf("failed at position %d, want the gap at %d", verr.Position, i+1)
	}
	if !errors.Is(err, ErrPositionMismatch) {
		t.Fatalf("error %v does not wrap %v", err, ErrPositionMismatch)
	}
	if err := VerifyTip(gapped, tip); err == nil {
		t.Fatalf("VerifyTip accepted a chain with a gap at %d", i+1)
	}
}

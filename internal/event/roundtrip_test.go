// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// valueRunes is the alphabet generated string values are drawn from. It is
// deliberately weighted towards the characters that break serializers: the two
// characters JSON must escape, the C0 range, DEL, the two characters Go's
// encoding/json escapes and RFC 8785 does not, a combining mark, and an astral
// code point. Surrogate halves are excluded because they are not valid runes.
var valueRunes = []rune{
	'a', 'Z', '0', '-', '_', ' ', '/', '<', '&', '>', '"', '\\',
	0x00, 0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x1F, 0x7F,
	0x00A9, 0x00E9, 0x0301, 0x05D0, 0x20AC, 0x2028, 0x2029, 0x4E2D,
	0xFFFD, 0xFFFF, 0x1F600, 0x10FFFF,
}

// nameRunes is the alphabet generated member names are drawn from. Real member
// names are a protected surface and always ASCII (doc 02 §2), so the generator
// stays there too.
var nameRunes = []rune{'a', 'b', 'z', 'A', 'Z', '0', '9', '_', '-', '.', '~'}

func genString(runes []rune, maxLen int) *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		rs := rapid.SliceOfN(rapid.SampledFrom(runes), 1, maxLen).Draw(t, "runes")
		return string(rs)
	})
}

func genValue() *rapid.Generator[any] {
	return rapid.Custom(func(t *rapid.T) any {
		switch rapid.IntRange(0, 2).Draw(t, "kind") {
		case 0:
			return any(genString(valueRunes, 12).Draw(t, "string"))
		case 1:
			return any(rapid.Int64Range(MinSafeInteger, MaxSafeInteger).Draw(t, "int"))
		default:
			return any(rapid.Bool().Draw(t, "bool"))
		}
	})
}

func genFields() *rapid.Generator[Fields] {
	return rapid.Custom(func(t *rapid.T) Fields {
		m := rapid.MapOfN(genString(nameRunes, 10), genValue(), 1, 10).Draw(t, "members")
		f := make(Fields, len(m))
		for k, v := range m {
			f[k] = v
		}
		return f
	})
}

// TestSER004RoundTrip is SER-004: parse(serialize(e)) == e for generated
// events.
func TestSER004RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := genFields().Draw(t, "fields")

		canonical, err := Canonicalize(f)
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}

		got, err := ParseFields(canonical)
		if err != nil {
			t.Fatalf("ParseFields(%s): %v", canonical, err)
		}
		if !reflect.DeepEqual(map[string]any(got), map[string]any(f)) {
			t.Fatalf("round-trip lost information\n in  %#v\n out %#v", f, got)
		}

		// Serializing the parse must land on the identical bytes, so the
		// canonical form is a fixed point.
		again, err := Canonicalize(got)
		if err != nil {
			t.Fatalf("Canonicalize (second pass): %v", err)
		}
		if !bytes.Equal(canonical, again) {
			t.Fatalf("canonicalization is not idempotent\n first  %s\n second %s",
				canonical, again)
		}
	})
}

// TestSER004MemberOrderNeverMatters is SER-004 crossed with SER-002: however
// the members are ordered on the wire, the canonical bytes are the same.
func TestSER004MemberOrderNeverMatters(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := genFields().Draw(t, "fields")

		want, err := Canonicalize(f)
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}

		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		order := rapid.Permutation(keys).Draw(t, "order")

		var b strings.Builder
		b.WriteByte('{')
		for i, k := range order {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, kerr := json.Marshal(k)
			if kerr != nil {
				t.Fatalf("marshal key: %v", kerr)
			}
			vb, verr := json.Marshal(f[k])
			if verr != nil {
				t.Fatalf("marshal value: %v", verr)
			}
			b.Write(kb)
			b.WriteByte(':')
			b.Write(vb)
		}
		b.WriteByte('}')

		var m map[string]any
		dec := json.NewDecoder(strings.NewReader(b.String()))
		dec.UseNumber()
		if derr := dec.Decode(&m); derr != nil {
			t.Fatalf("decode: %v", derr)
		}
		got, err := Canonicalize(m)
		if err != nil {
			t.Fatalf("Canonicalize (permuted): %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("member order changed the canonical bytes\n got  %s\n want %s", got, want)
		}
	})
}

// TestSER004EventHashIsExcludedFromItsOwnPreimage is SER-004 over doc 02 §4.1:
// whatever event_hash a record carries, the preimage is the record without it.
func TestSER004EventHashIsExcludedFromItsOwnPreimage(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := genFields().Draw(t, "fields")
		delete(f, EventHashField)
		if len(f) == 0 {
			t.Skip("no members left")
		}

		want, err := f.Preimage()
		if err != nil {
			t.Fatalf("Preimage: %v", err)
		}

		sealed, err := f.Finalize()
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		if verr := sealed.Verify(); verr != nil {
			t.Fatalf("Verify: %v", verr)
		}
		got, err := sealed.Preimage()
		if err != nil {
			t.Fatalf("Preimage (sealed): %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("attaching event_hash changed the preimage\n got  %s\n want %s", got, want)
		}

		// Any other event_hash value must also leave the preimage alone, and
		// must fail verification.
		other := sealed.Clone()
		other[EventHashField] = HashPrefix + strings.Repeat("f", 64)
		got, err = other.Preimage()
		if err != nil {
			t.Fatalf("Preimage (tampered): %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("a different event_hash changed the preimage")
		}
		if err := other.Verify(); err == nil {
			t.Fatal("Verify accepted a tampered event_hash")
		}
	})
}

// TestSER004AnyChangeMovesTheEventHash is SER-004: the hash has to be a
// function of the whole record, so no member can be edited invisibly.
func TestSER004AnyChangeMovesTheEventHash(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := genFields().Draw(t, "fields")

		before, err := f.EventHash()
		if err != nil {
			t.Fatalf("EventHash: %v", err)
		}

		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		victim := rapid.SampledFrom(keys).Draw(t, "victim")

		mutated := f.Clone()
		switch v := f[victim].(type) {
		case string:
			mutated[victim] = v + "."
		case int64:
			// Step towards the interior so the mutation stays inside the
			// JCS-safe range whatever value was drawn.
			if v == MaxSafeInteger {
				mutated[victim] = v - 1
			} else {
				mutated[victim] = v + 1
			}
		case bool:
			mutated[victim] = !v
		default:
			t.Fatalf("unexpected value type %T", v)
		}

		after, err := mutated.EventHash()
		if err != nil {
			t.Fatalf("EventHash (mutated): %v", err)
		}
		if after == before {
			t.Fatalf("mutating %q did not move the event_hash", victim)
		}

		// Dropping a member must move it too.
		dropped := f.Clone()
		delete(dropped, victim)
		if len(dropped) > 0 {
			h, err := dropped.EventHash()
			if err != nil {
				t.Fatalf("EventHash (dropped): %v", err)
			}
			if h == before {
				t.Fatalf("dropping %q did not move the event_hash", victim)
			}
		}
	})
}

// TestSER004TimestampRoundTrip is SER-004 over doc 02 §1: every server clock
// reading renders to exactly one string, and that string parses back to the
// same instant.
func TestSER004TimestampRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// A wide but realistic range: 1970 through the year 9999, at
		// nanosecond resolution, in an arbitrary zone offset.
		sec := rapid.Int64Range(0, 253_402_300_799).Draw(t, "unix_seconds")
		nsec := rapid.Int64Range(0, 999_999_999).Draw(t, "nanoseconds")
		offset := rapid.IntRange(-14*3600, 14*3600).Draw(t, "offset")
		in := time.Unix(sec, nsec).In(time.FixedZone("z", offset))

		ts := NewTimestamp(in)
		s := ts.String()

		back, err := ParseTimestamp(s)
		if err != nil {
			t.Fatalf("ParseTimestamp(%q): %v", s, err)
		}
		if back != ts {
			t.Fatalf("round-trip: %q -> %v, want %v", s, back.Time(), ts.Time())
		}
		if back.String() != s {
			t.Fatalf("re-render: %q, want %q", back.String(), s)
		}
		if got := ts.Time().Nanosecond() % 1_000_000; got != 0 {
			t.Fatalf("timestamp is not truncated to milliseconds: %v", ts.Time())
		}
		if ts.Time().Location() != time.UTC {
			t.Fatalf("timestamp is not UTC: %v", ts.Time())
		}
	})
}

// TestSER004ValidateAcceptsWhatParseProduces closes the loop between the two
// directions: anything that parses is something the serializer will accept.
func TestSER004ValidateAcceptsWhatParseProduces(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		f := genFields().Draw(t, "fields")
		canonical, err := Canonicalize(f)
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}
		parsed, err := ParseFields(canonical)
		if err != nil {
			t.Fatalf("ParseFields: %v", err)
		}
		if err := parsed.Validate(); err != nil {
			t.Fatalf("Validate rejected a parsed record: %v", err)
		}
	})
}

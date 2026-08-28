// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// doc02Section6Example is the run_registered example in doc 02 §6, quoted
// verbatim, ellipsis and all. The spec shows it JCS-ordered, so reproducing it
// byte for byte is the tightest possible tie between this package and the
// normative document.
const doc02Section6Example = `{"agent_type":"fix-ci","chain_position":412,` +
	`"event_id":"01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e6f","event_type":"run_registered",` +
	`"idempotency_key":"reg-8f21c","prev_event_hash":"sha256:…","run_id":"run-42",` +
	`"schema_version":"1","source":"mcp",` +
	`"spiffe_id":"spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",` +
	`"task_ref":"JIRA-118","ts":"2026-08-28T09:14:03.201Z"}`

// TestSER001GoldenVectors is SER-001: serialize each event type and compare
// byte-exact against the committed fixtures.
func TestSER001GoldenVectors(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			f := loadFixture(t, name)

			if _, ok := f.input[EventHashField]; ok {
				t.Fatalf("fixture input contains %s: it must be excluded from its own preimage",
					EventHashField)
			}

			// The committed .hash must be the SHA-256 of the committed
			// canonical bytes. Checked here with crypto/sha256 directly, so
			// the two committed files are held together without this
			// package's help.
			sum := sha256.Sum256(f.canonical)
			if want := HashPrefix + hex.EncodeToString(sum[:]); want != f.hash {
				t.Errorf("committed fixture is internally inconsistent:\n .hash            = %s\n sha256(canonical) = %s",
					f.hash, want)
			}

			got, err := Canonicalize(f.input)
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if !bytes.Equal(got, f.canonical) {
				t.Errorf("canonical bytes differ\n got  %s\n want %s", got, f.canonical)
			}

			pre, err := f.input.Preimage()
			if err != nil {
				t.Fatalf("Preimage: %v", err)
			}
			if !bytes.Equal(pre, f.canonical) {
				t.Errorf("preimage differs\n got  %s\n want %s", pre, f.canonical)
			}

			h, err := f.input.EventHash()
			if err != nil {
				t.Fatalf("EventHash: %v", err)
			}
			if h != f.hash {
				t.Errorf("event_hash = %s, want %s", h, f.hash)
			}
		})
	}
}

// TestSER001EventHashExcludedFromItsOwnPreimage is SER-001, doc 02 §4.1 and
// §4.3: the object is constructed without event_hash, hashed, and only then is
// event_hash attached.
func TestSER001EventHashExcludedFromItsOwnPreimage(t *testing.T) {
	f := loadFixture(t, "01-run_registered")

	sealed, err := f.input.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if sealed[EventHashField] != f.hash {
		t.Errorf("Finalize set %s = %v, want %s", EventHashField, sealed[EventHashField], f.hash)
	}
	if _, ok := f.input[EventHashField]; ok {
		t.Error("Finalize mutated its receiver")
	}

	// Re-deriving from the sealed event must strip event_hash again and land
	// on the identical preimage.
	pre, err := sealed.Preimage()
	if err != nil {
		t.Fatalf("Preimage of sealed event: %v", err)
	}
	if !bytes.Equal(pre, f.canonical) {
		t.Errorf("sealed preimage differs\n got  %s\n want %s", pre, f.canonical)
	}
	if err := sealed.Verify(); err != nil {
		t.Errorf("Verify: %v", err)
	}

	// A tampered event_hash must not verify.
	bad := sealed.Clone()
	bad[EventHashField] = HashPrefix + strings.Repeat("0", 64)
	if err := bad.Verify(); err == nil {
		t.Error("Verify accepted a tampered event_hash")
	}

	// An unsealed event has nothing to verify against.
	if err := f.input.Verify(); !errors.Is(err, ErrEventHashMissing) {
		t.Errorf("Verify on an unsealed event: err = %v, want %v", err, ErrEventHashMissing)
	}

	// Re-sealing would hash over the previous hash, which is how a chain
	// quietly stops meaning anything.
	if _, err := sealed.Finalize(); !errors.Is(err, ErrEventHashPresent) {
		t.Errorf("Finalize on a sealed event: err = %v, want %v", err, ErrEventHashPresent)
	}

	// A non-string event_hash is not an event_hash.
	wrongType := f.input.Clone()
	wrongType[EventHashField] = int64(1)
	if err := wrongType.Verify(); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Verify with a non-string event_hash: err = %v, want %v", err, ErrUnsupportedType)
	}
}

// TestSER001CanonicalizeErrors covers the serializer's own failure returns.
func TestSER001CanonicalizeErrors(t *testing.T) {
	if _, err := Canonicalize(make(chan int)); err == nil {
		t.Error("Canonicalize accepted a value JSON cannot represent")
	}

	// The JCS stage has its own failure return. It is unreachable from
	// encoding/json output, so it is exercised through the seam rather than
	// left as an untested error path.
	saved := canonicalTransform
	defer func() { canonicalTransform = saved }()
	canonicalTransform = func([]byte) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := Canonicalize(Fields{"a": "b"}); err == nil {
		t.Error("Canonicalize swallowed a canonicalization failure")
	}

	canonicalTransform = saved
	if _, err := Canonicalize(Fields{"a": "b"}); err != nil {
		t.Errorf("seam not restored: %v", err)
	}
}

// TestSER001EmptyFields is the degenerate record: no members at all.
func TestSER001EmptyFields(t *testing.T) {
	got, err := Canonicalize(Fields{})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("Canonicalize(empty) = %s, want {}", got)
	}
	sealed, err := Fields(nil).Finalize()
	if err != nil {
		t.Fatalf("Finalize(nil): %v", err)
	}
	if err := sealed.Verify(); err != nil {
		t.Errorf("Verify(sealed nil): %v", err)
	}
	if got, err := ParseFields([]byte("{}")); err != nil || len(got) != 0 {
		t.Errorf("ParseFields({}) = %v, %v", got, err)
	}
	if _, err := ParseFields([]byte(`{"a":"b"} trailing`)); err == nil {
		t.Error("ParseFields accepted trailing content")
	}
	if _, err := ParseFields([]byte(`{`)); err == nil {
		t.Error("ParseFields accepted a truncated object")
	}
	if _, err := ParseFields(nil); err == nil {
		t.Error("ParseFields accepted no input")
	}
}

// TestSER001Doc02Section6 is SER-001: the canonical form must reproduce the
// example in doc 02 §6 exactly.
func TestSER001Doc02Section6(t *testing.T) {
	genesis := string(readFixtureFile(t, "genesis.hash"))
	want := strings.Replace(doc02Section6Example, HashPrefix+"…", genesis, 1)
	if want == doc02Section6Example {
		t.Fatal("doc 02 §6 substitution did not apply")
	}

	// The committed fixture is the spec's own bytes.
	if got := string(readFixtureFile(t, "00-doc02-example.canonical.json")); got != want {
		t.Errorf("fixture 00 has drifted from doc 02 §6\n got  %s\n want %s", got, want)
	}

	// And the serializer reproduces them from the parsed object.
	f := loadFixture(t, "00-doc02-example")
	got, err := Canonicalize(f.input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("serializer output differs from doc 02 §6\n got  %s\n want %s", got, want)
	}
}

// TestSER001FixtureChain is SER-001: fixtures 01..14 are one valid hash chain,
// so the vectors also pin doc 02 §4.4 and §4.5.
func TestSER001FixtureChain(t *testing.T) {
	prev := GenesisPrevEventHash()
	if want := string(readFixtureFile(t, "genesis.hash")); prev != want {
		t.Fatalf("GenesisPrevEventHash() = %s, want %s", prev, want)
	}

	for _, name := range fixtureNames(t) {
		if !isChainFixture(name) {
			continue
		}
		f := loadFixture(t, name)
		if got := f.input[FieldPrevEventHash]; got != prev {
			t.Errorf("%s: %s = %v, want %s", name, FieldPrevEventHash, got, prev)
		}
		prev = f.hash
	}
}

// TestSER001FixturesCoverEveryEventType is SER-001: "serialize each event
// type". Deleting a vector must fail rather than silently shrink the corpus.
func TestSER001FixturesCoverEveryEventType(t *testing.T) {
	// doc 02 §3, in document order. Protected strings.
	want := []string{
		"run_registered", "credential_issued", "tool_call", "commit_intent",
		"commit_recorded", "commit_intent_expired", "run_retired", "run_expired",
		"unattributed_signature_detected", "ledger_drift_detected", "segment_sealed",
	}

	seen := map[string]bool{}
	for _, name := range fixtureNames(t) {
		if !isChainFixture(name) {
			continue
		}
		f := loadFixture(t, name)
		if et, ok := f.input[FieldEventType].(string); ok {
			seen[et] = true
		}
	}
	for _, et := range want {
		if !seen[et] {
			t.Errorf("no golden fixture for event_type %q", et)
		}
	}
}

// isChainFixture reports whether a fixture belongs to the 01..14 hash chain.
// Fixture 00 reproduces doc 02 §6 at its own chain position, and the format
// probe is not an event at all.
func isChainFixture(name string) bool {
	return !strings.HasPrefix(name, "00-") && !strings.HasPrefix(name, "format-probe")
}

// TestSER002MemberOrderIndependence is SER-002: the canonical bytes depend on
// the member set, never on the order the members arrived in.
func TestSER002MemberOrderIndependence(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			f := loadFixture(t, name)

			// Every .input.json is stored reverse-sorted, so parsing it and
			// canonicalizing already crosses the ordering. Re-serialize the
			// object into several different member orders and confirm each
			// canonicalizes identically.
			for i, text := range permuteMembers(t, f.input) {
				var m map[string]any
				dec := json.NewDecoder(strings.NewReader(text))
				dec.UseNumber()
				if err := dec.Decode(&m); err != nil {
					t.Fatalf("permutation %d: decode: %v", i, err)
				}
				got, err := Canonicalize(m)
				if err != nil {
					t.Fatalf("permutation %d: Canonicalize: %v", i, err)
				}
				if !bytes.Equal(got, f.canonical) {
					t.Fatalf("permutation %d changed the canonical bytes\n got  %s\n want %s",
						i, got, f.canonical)
				}
			}
		})
	}
}

// permuteMembers renders f as several JSON texts whose members appear in
// different orders.
func permuteMembers(t *testing.T, f Fields) []string {
	t.Helper()

	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}

	orders := [][]string{append([]string(nil), keys...)}
	rev := append([]string(nil), keys...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	orders = append(orders, rev)
	if len(keys) > 2 {
		rot := append(append([]string(nil), keys[1:]...), keys[0])
		orders = append(orders, rot)
	}

	texts := make([]string, 0, len(orders))
	for _, order := range orders {
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range order {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("marshal key: %v", err)
			}
			vb, err := json.Marshal(f[k])
			if err != nil {
				t.Fatalf("marshal value: %v", err)
			}
			b.Write(kb)
			b.WriteByte(':')
			b.Write(vb)
		}
		b.WriteByte('}')
		texts = append(texts, b.String())
	}
	return texts
}

// TestSER002MemberSortIsUTF16 is SER-002: RFC 8785 §3.2.3 sorts member names
// by UTF-16 code unit, not by code point. The two orders disagree above
// U+FFFF, and this is the case that tells them apart.
func TestSER002MemberSortIsUTF16(t *testing.T) {
	// U+FFFF is one UTF-16 unit, 0xFFFF. U+1F600 is the surrogate pair
	// 0xD83D 0xDE00. 0xD83D < 0xFFFF, so the astral name sorts FIRST under
	// UTF-16 and LAST under code point.
	in := map[string]any{"\uffff": "bmp", "\U0001f600": "astral"}
	want := "{\"\U0001f600\":\"astral\",\"\uffff\":\"bmp\"}"

	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("member sort is not UTF-16\n got  %q\n want %q", got, want)
	}
}

// TestSER002SortsNestedAndAsciiRange is SER-002: sorting is recursive, and the
// ASCII ordering is by code unit rather than anything locale-aware.
func TestSER002SortsNestedAndAsciiRange(t *testing.T) {
	in := map[string]any{
		"b": map[string]any{"z": 1, "a": 2, "~": 3, "A": 4, "0": 5, "": 6},
		"a": []any{map[string]any{"y": 1, "x": 2}},
	}
	want := `{"a":[{"x":2,"y":1}],"b":{"":6,"0":5,"A":4,"a":2,"z":1,"~":3}}`

	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != want {
		t.Errorf("nested sort\n got  %s\n want %s", got, want)
	}
}

// TestSER002ArrayOrderIsPreserved is SER-002: JCS sorts object members and
// leaves array element order untouched.
func TestSER002ArrayOrderIsPreserved(t *testing.T) {
	got, err := Canonicalize(map[string]any{"a": []any{"z", "y", "x"}})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if want := `{"a":["z","y","x"]}`; string(got) != want {
		t.Errorf("array order\n got  %s\n want %s", got, want)
	}
}

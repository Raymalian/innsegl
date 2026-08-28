// SPDX-License-Identifier: Apache-2.0

package event

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func mustTimestamp(t *testing.T, s string) Timestamp {
	t.Helper()
	ts, err := ParseTimestamp(s)
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", s, err)
	}
	return ts
}

// validEnvelope is the envelope of golden fixture 01.
func validEnvelope(t *testing.T) Envelope {
	t.Helper()
	return Envelope{
		SchemaVersion:  SchemaVersion,
		EventID:        "01a047a3-8b7c-7d1e-9f20-3a4b5c6d7e8f",
		ChainPosition:  1,
		EventType:      "run_registered",
		TS:             mustTimestamp(t, "2026-08-28T09:14:03.201Z"),
		RunID:          Optional("run-42"),
		SpiffeID:       Optional("spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"),
		Source:         SourceMCP,
		IdempotencyKey: Optional("reg-8f21c"),
		PrevEventHash:  GenesisPrevEventHash(),
	}
}

// TestSER003AbsentIsNotEmpty is SER-003: absent and empty are distinct states
// and only absent is legal for a missing value (doc 02 §1). An optional member
// that is present must carry a value; an empty string is a rejected input, not
// a quieter way of spelling "absent".
func TestSER003AbsentIsNotEmpty(t *testing.T) {
	absent := validEnvelope(t)
	absent.IdempotencyKey = nil
	absent.Source = SourceReconciler // idempotency_key is only required of mcp

	f, err := absent.Fields()
	if err != nil {
		t.Fatalf("Fields with absent optional: %v", err)
	}
	if _, ok := f[FieldIdempotencyKey]; ok {
		t.Errorf("absent optional was emitted: %v", f[FieldIdempotencyKey])
	}
	got, err := Canonicalize(f)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if bytes.Contains(got, []byte(FieldIdempotencyKey)) {
		t.Errorf("absent optional appears in the canonical bytes: %s", got)
	}
	if bytes.Contains(got, []byte("null")) {
		t.Errorf("canonical bytes contain null: %s", got)
	}

	empty := absent
	empty.IdempotencyKey = Optional("")
	if _, err := empty.Fields(); !errors.Is(err, ErrEmptyValue) {
		t.Errorf("empty-string optional: err = %v, want %v", err, ErrEmptyValue)
	}

	for _, tc := range []struct {
		name string
		mut  func(*Envelope)
	}{
		{FieldRunID, func(e *Envelope) { e.RunID = Optional("") }},
		{FieldSpiffeID, func(e *Envelope) { e.SpiffeID = Optional("") }},
		{FieldPayloadDigest, func(e *Envelope) { e.PayloadDigest = Optional("") }},
		{FieldSupersedes, func(e *Envelope) { e.Supersedes = Optional("") }},
	} {
		t.Run("empty/"+tc.name, func(t *testing.T) {
			e := validEnvelope(t)
			tc.mut(&e)
			if _, err := e.Fields(); !errors.Is(err, ErrEmptyValue) {
				t.Errorf("err = %v, want %v", err, ErrEmptyValue)
			}
		})
	}
}

// TestSER003NoNullAndNoEmptyInFields is SER-003 at the Fields level: nil and
// empty-string values never reach the serializer.
func TestSER003NoNullAndNoEmptyInFields(t *testing.T) {
	base := loadFixture(t, "01-run_registered").input

	nilled := base.Clone()
	nilled["extra"] = nil
	if err := nilled.Validate(); !errors.Is(err, ErrNilValue) {
		t.Errorf("nil value: err = %v, want %v", err, ErrNilValue)
	}
	if _, err := nilled.Preimage(); !errors.Is(err, ErrNilValue) {
		t.Errorf("nil value reached the preimage: err = %v", err)
	}

	emptied := base.Clone()
	emptied["extra"] = ""
	if err := emptied.Validate(); !errors.Is(err, ErrEmptyValue) {
		t.Errorf("empty value: err = %v, want %v", err, ErrEmptyValue)
	}

	unnamed := base.Clone()
	unnamed[""] = "x"
	if err := unnamed.Validate(); !errors.Is(err, ErrEmptyMemberName) {
		t.Errorf("empty member name: err = %v, want %v", err, ErrEmptyMemberName)
	}

	typed := base.Clone()
	typed["extra"] = 1.5
	if err := typed.Validate(); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("float value: err = %v, want %v", err, ErrUnsupportedType)
	}

	nested := base.Clone()
	nested["extra"] = map[string]any{"a": 1}
	if err := nested.Validate(); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("nested value: err = %v, want %v", err, ErrUnsupportedType)
	}
}

// TestSER003ParseRejectsNullAndEmpty is SER-003 on the reading side: an event
// that arrives with a null or empty-string member is not an event.
func TestSER003ParseRejectsNullAndEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		json string
		want error
	}{
		{"null", `{"a":"x","b":null}`, ErrNilValue},
		{"empty string", `{"a":"x","b":""}`, ErrEmptyValue},
		{"empty member name", `{"":"x"}`, ErrEmptyMemberName},
		{"duplicate member", `{"a":"x","a":"y"}`, ErrDuplicateMember},
		{"float", `{"a":1.5}`, ErrUnsupportedType},
		{"nested object", `{"a":{"b":"c"}}`, ErrUnsupportedType},
		{"array", `{"a":["b"]}`, ErrUnsupportedType},
		{"not an object", `["a"]`, ErrNotAnObject},
		{"integer above the JCS-safe range", `{"a":9007199254740992}`, ErrIntegerOutOfRange},
		{"integer below the JCS-safe range", `{"a":-9007199254740992}`, ErrIntegerOutOfRange},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFields([]byte(tc.json)); !errors.Is(err, tc.want) {
				t.Errorf("ParseFields(%s): err = %v, want %v", tc.json, err, tc.want)
			}
		})
	}
}

// TestSER003MaxLengthFields is SER-003: doc 02 §2 caps idempotency_key at 128.
// The cap is on bytes, because bytes are what the canonical form and the store
// both measure.
func TestSER003MaxLengthFields(t *testing.T) {
	at := strings.Repeat("k", MaxIdempotencyKeyBytes)
	e := validEnvelope(t)
	e.IdempotencyKey = Optional(at)
	if _, err := e.Fields(); err != nil {
		t.Errorf("idempotency_key of exactly %d bytes rejected: %v", MaxIdempotencyKeyBytes, err)
	}

	over := validEnvelope(t)
	over.IdempotencyKey = Optional(at + "k")
	if _, err := over.Fields(); !errors.Is(err, ErrInvalidField) {
		t.Errorf("idempotency_key of %d bytes: err = %v, want %v",
			MaxIdempotencyKeyBytes+1, err, ErrInvalidField)
	}

	// 128 runes but 256 bytes: the cap is bytes, so this is over.
	multibyte := strings.Repeat("é", MaxIdempotencyKeyBytes)
	if utf8.RuneCountInString(multibyte) != MaxIdempotencyKeyBytes {
		t.Fatalf("test input is %d runes", utf8.RuneCountInString(multibyte))
	}
	wide := validEnvelope(t)
	wide.IdempotencyKey = Optional(multibyte)
	if _, err := wide.Fields(); !errors.Is(err, ErrInvalidField) {
		t.Errorf("multibyte idempotency_key of %d bytes: err = %v, want %v",
			len(multibyte), err, ErrInvalidField)
	}
}

// TestSER003UnicodeIsDeterministic is SER-003: the escaping rules are fixed and
// repeated serialization of the same input is byte-identical.
func TestSER003UnicodeIsDeterministic(t *testing.T) {
	f := loadFixture(t, "13-unicode_and_escapes")

	first, err := Canonicalize(f.input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	for i := 0; i < 64; i++ {
		again, err := Canonicalize(f.input)
		if err != nil {
			t.Fatalf("Canonicalize (run %d): %v", i, err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("Canonicalize is not deterministic at run %d", i)
		}
	}
}

// TestSER003EscapingRules is SER-003: RFC 8785 escapes only the two structural
// characters and C0, and emits everything else — U+2028 and U+2029 included —
// as raw UTF-8. Go's encoding/json escapes more than that, so this is where a
// naive marshal-and-hash would have diverged.
func TestSER003EscapingRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"quote", `"`, `{"a":"\""}`},
		{"backslash", `\`, `{"a":"\\"}`},
		{"solidus is not escaped", `/`, `{"a":"/"}`},
		{"html is not escaped", `<&>`, `{"a":"<&>"}`},
		{"short escapes", "\b\t\n\f\r", `{"a":"\b\t\n\f\r"}`},
		{"other C0 is \\u lower hex", "\x00\x1f", `{"a":"\u0000\u001f"}`},
		{"DEL is raw", "\x7f", "{\"a\":\"\x7f\"}"},
		{"U+2028 and U+2029 are raw", "\u2028\u2029", "{\"a\":\"\u2028\u2029\"}"},
		{"astral is raw", "\U0001f600", "{\"a\":\"\U0001f600\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(map[string]any{"a": tc.in})
			if err != nil {
				t.Fatalf("Canonicalize: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSER003RejectsInvalidUTF8 is SER-003: doc 02 §1 says all strings are
// UTF-8. Go would silently substitute U+FFFD for an invalid byte and hash the
// substitute, which is a hash over something the caller never wrote.
func TestSER003RejectsInvalidUTF8(t *testing.T) {
	f := Fields{"a": "\xff\xfe"}
	if err := f.Validate(); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("invalid UTF-8 value: err = %v, want %v", err, ErrInvalidUTF8)
	}
	f = Fields{"\xff": "a"}
	if err := f.Validate(); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("invalid UTF-8 member name: err = %v, want %v", err, ErrInvalidUTF8)
	}
}

// TestSER003IntegerBounds is SER-003 and doc 02 §4.2: integers must stay inside
// the range RFC 8785's number canonicalization reproduces exactly.
func TestSER003IntegerBounds(t *testing.T) {
	for _, v := range []int64{0, 1, -1, MaxSafeInteger, MinSafeInteger} {
		if err := (Fields{"a": v}).Validate(); err != nil {
			t.Errorf("Validate(%d) = %v, want nil", v, err)
		}
	}
	for _, v := range []int64{MaxSafeInteger + 1, MinSafeInteger - 1} {
		if err := (Fields{"a": v}).Validate(); !errors.Is(err, ErrIntegerOutOfRange) {
			t.Errorf("Validate(%d) = %v, want %v", v, err, ErrIntegerOutOfRange)
		}
	}
	if err := (Fields{"a": uint64(1) << 63}).Validate(); !errors.Is(err, ErrIntegerOutOfRange) {
		t.Errorf("Validate(1<<63) = %v, want %v", err, ErrIntegerOutOfRange)
	}
	got, err := Canonicalize(Fields{"a": MaxSafeInteger})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if want := `{"a":9007199254740991}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestSER003EnvelopeShape covers the envelope's own constraints (doc 02 §2 and
// §5) and every error return it has.
func TestSER003EnvelopeShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*Envelope)
		want error
	}{
		{"wrong schema_version", func(e *Envelope) { e.SchemaVersion = "2" }, ErrInvalidField},
		{"missing schema_version", func(e *Envelope) { e.SchemaVersion = "" }, ErrInvalidField},
		{"upper-case event_id", func(e *Envelope) {
			e.EventID = strings.ToUpper(e.EventID)
		}, ErrInvalidEventID},
		{"uuidv4 event_id", func(e *Envelope) {
			e.EventID = "01a047a3-8b7c-4d1e-9f20-3a4b5c6d7e8f"
		}, ErrInvalidEventID},
		{"bad uuid variant", func(e *Envelope) {
			e.EventID = "01a047a3-8b7c-7d1e-2f20-3a4b5c6d7e8f"
		}, ErrInvalidEventID},
		{"malformed event_id", func(e *Envelope) { e.EventID = "not-a-uuid" }, ErrInvalidEventID},
		{"chain_position 0", func(e *Envelope) { e.ChainPosition = 0 }, ErrInvalidField},
		{"chain_position negative", func(e *Envelope) { e.ChainPosition = -1 }, ErrInvalidField},
		{"chain_position beyond JCS-safe", func(e *Envelope) {
			e.ChainPosition = MaxSafeInteger + 1
		}, ErrIntegerOutOfRange},
		{"missing event_type", func(e *Envelope) { e.EventType = "" }, ErrInvalidField},
		{"zero ts", func(e *Envelope) { e.TS = Timestamp{} }, ErrInvalidTimestamp},
		{"unknown source", func(e *Envelope) { e.Source = "cron" }, ErrInvalidSource},
		{"missing source", func(e *Envelope) { e.Source = "" }, ErrInvalidSource},
		{"run_id without spiffe_id", func(e *Envelope) { e.SpiffeID = nil }, ErrInvalidField},
		{"spiffe_id without run_id", func(e *Envelope) { e.RunID = nil }, ErrInvalidField},
		{"run_id with an upper-case character", func(e *Envelope) {
			e.RunID = Optional("Run-42")
		}, ErrInvalidIdentifier},
		{"run_id starting with a hyphen", func(e *Envelope) {
			e.RunID = Optional("-run")
		}, ErrInvalidIdentifier},
		{"run_id too long", func(e *Envelope) {
			e.RunID = Optional("r" + strings.Repeat("a", 63))
		}, ErrInvalidIdentifier},
		{"spiffe_id with the wrong scheme", func(e *Envelope) {
			e.SpiffeID = Optional("https://innsegl.dev/agent/fix-ci/jira-118/run-42")
		}, ErrInvalidSpiffeID},
		{"spiffe_id without the agent segment", func(e *Envelope) {
			e.SpiffeID = Optional("spiffe://innsegl.dev/fix-ci/jira-118/run-42")
		}, ErrInvalidSpiffeID},
		{"spiffe_id with too few segments", func(e *Envelope) {
			e.SpiffeID = Optional("spiffe://innsegl.dev/agent/fix-ci/run-42")
		}, ErrInvalidSpiffeID},
		{"spiffe_id with an empty trust domain", func(e *Envelope) {
			e.SpiffeID = Optional("spiffe:///agent/fix-ci/jira-118/run-42")
		}, ErrInvalidSpiffeID},
		{"spiffe_id with an invalid agent_type", func(e *Envelope) {
			e.SpiffeID = Optional("spiffe://innsegl.dev/agent/FixCI/jira-118/run-42")
		}, ErrInvalidSpiffeID},
		{"mcp source without idempotency_key", func(e *Envelope) {
			e.IdempotencyKey = nil
		}, ErrInvalidField},
		{"payload_digest without the algorithm prefix", func(e *Envelope) {
			e.PayloadDigest = Optional(strings.Repeat("a", 64))
		}, ErrInvalidDigest},
		{"payload_digest with upper-case hex", func(e *Envelope) {
			e.PayloadDigest = Optional(HashPrefix + strings.Repeat("A", 64))
		}, ErrInvalidDigest},
		{"payload_digest of the wrong width", func(e *Envelope) {
			e.PayloadDigest = Optional(HashPrefix + strings.Repeat("a", 63))
		}, ErrInvalidDigest},
		{"supersedes is not a uuidv7", func(e *Envelope) {
			e.Supersedes = Optional("run-42")
		}, ErrInvalidEventID},
		{"missing prev_event_hash", func(e *Envelope) { e.PrevEventHash = "" }, ErrInvalidDigest},
		{"malformed prev_event_hash", func(e *Envelope) {
			e.PrevEventHash = "sha512:" + strings.Repeat("a", 64)
		}, ErrInvalidDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := validEnvelope(t)
			tc.mut(&e)
			if _, err := e.Fields(); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestSER003EnvelopeAcceptsSystemScope is doc 02 §2: run_id and spiffe_id are
// omitted together for segment_sealed and for system-scope alerts.
func TestSER003EnvelopeAcceptsSystemScope(t *testing.T) {
	e := validEnvelope(t)
	e.EventType = "segment_sealed"
	e.Source = SourceSystem
	e.RunID = nil
	e.SpiffeID = nil
	e.IdempotencyKey = nil

	f, err := e.Fields()
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	for _, name := range []string{FieldRunID, FieldSpiffeID, FieldIdempotencyKey} {
		if _, ok := f[name]; ok {
			t.Errorf("%s was emitted for a system-scope event", name)
		}
	}
}

// TestSER003FieldsWithRejectsReservedNames keeps type-specific fields from
// shadowing the envelope or smuggling in an event_hash.
func TestSER003FieldsWithRejectsReservedNames(t *testing.T) {
	e := validEnvelope(t)

	for _, name := range append(EnvelopeFieldNames(), EventHashField) {
		if _, err := e.FieldsWith(Fields{name: "x"}); !errors.Is(err, ErrReservedMemberName) {
			t.Errorf("FieldsWith(%q): err = %v, want %v", name, err, ErrReservedMemberName)
		}
	}

	f, err := e.FieldsWith(Fields{"agent_type": "fix-ci", "task_ref": "JIRA-118"})
	if err != nil {
		t.Fatalf("FieldsWith: %v", err)
	}
	if f["agent_type"] != "fix-ci" || f["task_ref"] != "JIRA-118" {
		t.Errorf("type-specific fields were not merged: %v", f)
	}
	if f[FieldEventID] != e.EventID {
		t.Errorf("envelope fields were not merged: %v", f)
	}
}

// TestSER003Timestamps is doc 02 §1: RFC 3339 UTC, exactly millisecond
// precision, literal Z.
func TestSER003Timestamps(t *testing.T) {
	ok := "2026-08-28T09:14:03.201Z"
	ts, err := ParseTimestamp(ok)
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", ok, err)
	}
	if ts.String() != ok {
		t.Errorf("round-trip: %q, want %q", ts.String(), ok)
	}
	if ts.IsZero() {
		t.Error("IsZero on a set timestamp")
	}
	if !ts.Time().Equal(time.Date(2026, 8, 28, 9, 14, 3, 201e6, time.UTC)) {
		t.Errorf("Time() = %v", ts.Time())
	}
	if !(Timestamp{}).IsZero() {
		t.Error("zero Timestamp is not zero")
	}
	if s := (Timestamp{}).String(); s != "" {
		t.Errorf("zero Timestamp renders as %q", s)
	}

	for _, bad := range []string{
		"",
		"2026-08-28T09:14:03Z",          // no milliseconds
		"2026-08-28T09:14:03.2Z",        // one digit
		"2026-08-28T09:14:03.20Z",       // two digits
		"2026-08-28T09:14:03.2011Z",     // microseconds
		"2026-08-28T09:14:03.201z",      // lower-case z
		"2026-08-28T09:14:03.201+00:00", // offset rather than Z
		"2026-08-28T10:14:03.201+01:00", // offset rather than Z
		"2026-08-28 09:14:03.201Z",      // space separator
		"2026-13-28T09:14:03.201Z",      // month 13
		"2026-08-32T09:14:03.201Z",      // day 32
		"2026-08-28T25:14:03.201Z",      // hour 25
		"28/08/2026 09:14:03.201",       // not RFC 3339 at all
		" 2026-08-28T09:14:03.201Z",     // leading space
		"2026-08-28T09:14:03.201Z ",     // trailing space
		"2026-08-28T09:14:03.201Zjunk",  // trailing junk
		"+2026-08-28T09:14:03.201Z",     // signed year
		"2026-08-28T09:14:03.201Z\x00",  // embedded NUL
	} {
		if _, err := ParseTimestamp(bad); !errors.Is(err, ErrInvalidTimestamp) {
			t.Errorf("ParseTimestamp(%q): err = %v, want %v", bad, err, ErrInvalidTimestamp)
		}
	}

	// NewTimestamp normalizes to UTC and truncates to milliseconds, so a
	// server clock with nanosecond resolution still renders one exact form.
	loc := time.FixedZone("CEST", 2*3600)
	got := NewTimestamp(time.Date(2026, 8, 28, 11, 14, 3, 201_999_999, loc))
	if got.String() != ok {
		t.Errorf("NewTimestamp = %q, want %q", got.String(), ok)
	}
	if NewTimestamp(time.Time{}).IsZero() != true {
		t.Error("NewTimestamp(zero) is not zero")
	}
}

// TestSER003Validators covers the exported shape checks directly, including
// every rejection path.
func TestSER003Validators(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		if err := ValidateDigest(HashPrefix + strings.Repeat("0", 64)); err != nil {
			t.Errorf("valid digest rejected: %v", err)
		}
		for _, bad := range []string{
			"", "sha256:", strings.Repeat("a", 64),
			HashPrefix + strings.Repeat("a", 63),
			HashPrefix + strings.Repeat("a", 65),
			HashPrefix + strings.Repeat("A", 64),
			HashPrefix + strings.Repeat("g", 64),
			"sha1:" + strings.Repeat("a", 64),
		} {
			if err := ValidateDigest(bad); !errors.Is(err, ErrInvalidDigest) {
				t.Errorf("ValidateDigest(%q): err = %v", bad, err)
			}
		}
	})

	t.Run("event id", func(t *testing.T) {
		if err := ValidateEventID("01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e6f"); err != nil {
			t.Errorf("valid uuidv7 rejected: %v", err)
		}
		for _, bad := range []string{
			"", "01919f2e8c1a7d3b9e4f1a2b3c4d5e6f",
			"01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e6",
			"01919f2e-8c1a-1d3b-9e4f-1a2b3c4d5e6f",
			"01919f2e-8c1a-7d3b-ce4f-1a2b3c4d5e6f",
			"01919f2e-8c1a-7d3b-9e4f-1a2b3c4d5e6F",
			"01919f2e_8c1a_7d3b_9e4f_1a2b3c4d5e6f",
		} {
			if err := ValidateEventID(bad); !errors.Is(err, ErrInvalidEventID) {
				t.Errorf("ValidateEventID(%q): err = %v", bad, err)
			}
		}
	})

	t.Run("identifier", func(t *testing.T) {
		for _, ok := range []string{"a", "0", "run-42", "r" + strings.Repeat("a", 62)} {
			if err := ValidateIdentifier(ok); err != nil {
				t.Errorf("ValidateIdentifier(%q): %v", ok, err)
			}
		}
		for _, bad := range []string{
			"", "-a", "A", "a_b", "a.b", "é", "r" + strings.Repeat("a", 63),
		} {
			if err := ValidateIdentifier(bad); !errors.Is(err, ErrInvalidIdentifier) {
				t.Errorf("ValidateIdentifier(%q): err = %v", bad, err)
			}
		}
	})

	t.Run("spiffe id", func(t *testing.T) {
		if err := ValidateSPIFFEID("spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"); err != nil {
			t.Errorf("valid SPIFFE ID rejected: %v", err)
		}
		for _, bad := range []string{
			"",
			"spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42/extra",
			"spiffe://innsegl.dev/agent/fix-ci/jira-118/",
			"spiffe://innsegl.dev/agent//jira-118/run-42",
			"spiffe://INNSEGL.dev/agent/fix-ci/jira-118/run-42",
			"spiffe://innsegl.dev/agent/fix-ci/JIRA-118/run-42",
		} {
			if err := ValidateSPIFFEID(bad); !errors.Is(err, ErrInvalidSpiffeID) {
				t.Errorf("ValidateSPIFFEID(%q): err = %v", bad, err)
			}
		}
	})

	t.Run("source", func(t *testing.T) {
		for _, ok := range []string{SourceMCP, SourceReconciler, SourceReaper, SourceSystem} {
			if err := ValidateSource(ok); err != nil {
				t.Errorf("ValidateSource(%q): %v", ok, err)
			}
		}
		for _, bad := range []string{"", "MCP", "cron", "mcp "} {
			if err := ValidateSource(bad); !errors.Is(err, ErrInvalidSource) {
				t.Errorf("ValidateSource(%q): err = %v", bad, err)
			}
		}
	})
}

// TestSER003EnvelopeMatchesGoldenFixture ties the envelope to the vectors: the
// struct path and the map path must produce the same bytes.
func TestSER003EnvelopeMatchesGoldenFixture(t *testing.T) {
	golden := loadFixture(t, "01-run_registered")

	e := Envelope{
		SchemaVersion:  SchemaVersion,
		EventID:        fixtureString(t, golden.input, FieldEventID),
		ChainPosition:  fixtureInt(t, golden.input, FieldChainPosition),
		EventType:      fixtureString(t, golden.input, FieldEventType),
		TS:             mustTimestamp(t, fixtureString(t, golden.input, FieldTS)),
		RunID:          Optional(fixtureString(t, golden.input, FieldRunID)),
		SpiffeID:       Optional(fixtureString(t, golden.input, FieldSpiffeID)),
		Source:         fixtureString(t, golden.input, FieldSource),
		IdempotencyKey: Optional(fixtureString(t, golden.input, FieldIdempotencyKey)),
		PrevEventHash:  fixtureString(t, golden.input, FieldPrevEventHash),
	}

	f, err := e.FieldsWith(Fields{
		"agent_type": golden.input["agent_type"],
		"task_ref":   golden.input["task_ref"],
	})
	if err != nil {
		t.Fatalf("FieldsWith: %v", err)
	}
	got, err := f.Preimage()
	if err != nil {
		t.Fatalf("Preimage: %v", err)
	}
	if !bytes.Equal(got, golden.canonical) {
		t.Errorf("envelope bytes differ from the golden fixture\n got  %s\n want %s",
			got, golden.canonical)
	}
	h, err := f.EventHash()
	if err != nil {
		t.Fatalf("EventHash: %v", err)
	}
	if h != golden.hash {
		t.Errorf("event_hash = %s, want %s", h, golden.hash)
	}
}

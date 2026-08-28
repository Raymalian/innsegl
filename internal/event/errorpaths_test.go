// SPDX-License-Identifier: Apache-2.0

package event

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestValueDomain walks every branch of the value-domain check. This package
// will carry a 100% branch floor on hash construction, and every one of these
// is a way a record could otherwise reach the hash in a form the canonical
// serializer does not reproduce faithfully.
func TestValueDomain(t *testing.T) {
	accepted := []any{
		"x", true, false,
		int(1), int8(1), int16(1), int32(1), int64(1),
		uint(1), uint8(1), uint16(1), uint32(1), uint64(1),
		json.Number("1"), json.Number("-1"), json.Number("0"),
		json.Number("9007199254740991"),
	}
	for _, v := range accepted {
		if err := (Fields{"a": v}).Validate(); err != nil {
			t.Errorf("Validate(%T %v) = %v, want nil", v, v, err)
		}
	}

	rejected := []struct {
		value any
		want  error
	}{
		{nil, ErrNilValue},
		{"", ErrEmptyValue},
		{"\xff", ErrInvalidUTF8},
		{1.5, ErrUnsupportedType},
		{float32(1.5), ErrUnsupportedType},
		{[]string{"a"}, ErrUnsupportedType},
		{map[string]any{"a": "b"}, ErrUnsupportedType},
		{struct{}{}, ErrUnsupportedType},
		{MaxSafeInteger + 1, ErrIntegerOutOfRange},
		{MinSafeInteger - 1, ErrIntegerOutOfRange},
		{int(MaxSafeInteger + 1), ErrIntegerOutOfRange},
		{uint(MaxSafeInteger + 1), ErrIntegerOutOfRange},
		{uint64(MaxSafeInteger + 1), ErrIntegerOutOfRange},
		{json.Number("1.5"), ErrUnsupportedType},
		{json.Number("1e3"), ErrUnsupportedType},
		{json.Number("1E3"), ErrUnsupportedType},
		{json.Number("99999999999999999999"), ErrIntegerOutOfRange},
		{json.Number("9007199254740992"), ErrIntegerOutOfRange},
	}
	for _, tc := range rejected {
		if err := (Fields{"a": tc.value}).Validate(); !errors.Is(err, tc.want) {
			t.Errorf("Validate(%T %v) = %v, want %v", tc.value, tc.value, err, tc.want)
		}
	}
}

// TestParseFieldsMalformedInput covers the parser's failure returns.
func TestParseFieldsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty input", ``},
		{"truncated object", `{`},
		{"truncated after a comma", `{"a":"b",`},
		{"missing value", `{"a":}`},
		{"unterminated value", `{"a":"b`},
		{"no closing brace", `{"a":"b"`},
		{"trailing content", `{"a":"b"}{}`},
		{"trailing garbage", `{"a":"b"} nope`},
		{"a bare string", `"a"`},
		{"a bare number", `1`},
		{"null", `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFields([]byte(tc.in)); err == nil {
				t.Errorf("ParseFields(%q) accepted malformed input", tc.in)
			}
		})
	}
}

// TestVerifyPropagatesPreimageFailure: a record that cannot be serialized
// cannot be verified either, and must say so rather than report a mismatch.
func TestVerifyPropagatesPreimageFailure(t *testing.T) {
	f := Fields{
		EventHashField: HashPrefix + strings.Repeat("0", 64),
		"broken":       nil,
	}
	if err := f.Verify(); !errors.Is(err, ErrNilValue) {
		t.Errorf("Verify: err = %v, want %v", err, ErrNilValue)
	}
	if _, err := f.EventHash(); !errors.Is(err, ErrNilValue) {
		t.Errorf("EventHash: err = %v, want %v", err, ErrNilValue)
	}

	unsealable := Fields{"broken": nil}
	if _, err := unsealable.Finalize(); !errors.Is(err, ErrNilValue) {
		t.Errorf("Finalize: err = %v, want %v", err, ErrNilValue)
	}
}

// TestFieldsWithRejectsBadExtras: type-specific members are held to the same
// value domain as the envelope's own.
func TestFieldsWithRejectsBadExtras(t *testing.T) {
	e := validEnvelope(t)
	for _, tc := range []struct {
		name  string
		extra Fields
		want  error
	}{
		{"nil value", Fields{"agent_type": nil}, ErrNilValue},
		{"empty value", Fields{"agent_type": ""}, ErrEmptyValue},
		{"float value", Fields{"agent_type": 1.5}, ErrUnsupportedType},
		{"empty member name", Fields{"": "x"}, ErrEmptyMemberName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.FieldsWith(tc.extra); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}

	broken := e
	broken.Source = "cron"
	if _, err := broken.FieldsWith(nil); !errors.Is(err, ErrInvalidSource) {
		t.Errorf("FieldsWith on an invalid envelope: err = %v, want %v", err, ErrInvalidSource)
	}
}

// TestIdempotencyKeyMustBeUTF8 is doc 02 §1: all strings are UTF-8.
func TestIdempotencyKeyMustBeUTF8(t *testing.T) {
	e := validEnvelope(t)
	e.IdempotencyKey = Optional("\xff\xfe")
	if _, err := e.Fields(); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("err = %v, want %v", err, ErrInvalidUTF8)
	}
}

// TestSER005FormatChecksSurviveASerializerFailure: the format gate reports a
// serializer that cannot run, rather than reporting drift it did not measure.
func TestSER005FormatChecksSurviveASerializerFailure(t *testing.T) {
	saved := canonicalTransform
	defer func() { canonicalTransform = saved }()
	canonicalTransform = func([]byte) ([]byte, error) { return nil, errors.New("boom") }

	if _, err := FormatFingerprint(); err == nil {
		t.Error("FormatFingerprint reported success with a broken serializer")
	}
	if err := VerifyFormat(); err == nil {
		t.Error("VerifyFormat reported success with a broken serializer")
	} else if errors.Is(err, ErrFormatDrift) {
		t.Errorf("a serializer failure was reported as drift: %v", err)
	}
}

// TestSER005FormatSpecMismatches: the frozen spec pins the schema version and
// the genesis seed as well as the byte-level fingerprint, because either one
// changing changes what a verifier re-derives.
func TestSER005FormatSpecMismatches(t *testing.T) {
	spec, err := CurrentFormat()
	if err != nil {
		t.Fatalf("CurrentFormat: %v", err)
	}

	wrongSchema := spec
	wrongSchema.SchemaVersion = "99"
	if err := verifyFormatAgainst(wrongSchema); !errors.Is(err, ErrFormatDrift) {
		t.Errorf("schema version mismatch: err = %v, want %v", err, ErrFormatDrift)
	}

	wrongSeed := spec
	wrongSeed.GenesisSeed = "innsegl-genesis-v2"
	if err := verifyFormatAgainst(wrongSeed); !errors.Is(err, ErrFormatDrift) {
		t.Errorf("genesis seed mismatch: err = %v, want %v", err, ErrFormatDrift)
	}
}

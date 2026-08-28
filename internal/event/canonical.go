// SPDX-License-Identifier: Apache-2.0

// Package event defines the innsegl event envelope, its canonical
// serialization and its hash construction.
//
// # Protected surface
//
// Everything in this file is a protected surface (VERSIONING.md §1). The
// canonical byte sequence a given event serializes to, and the event_hash
// derived from it, can never change retroactively: a verifier run in ten years
// re-derives today's hashes from today's bytes, or invariant I4 is broken.
// Changing any of it is a major schema version, released with a new
// schema_version accepted alongside every previous one, a new golden fixture
// set with the old one retained and still asserted, a signed migration
// attestation marking the cutover chain position, and a superseding ADR
// (doc 02 §7).
//
// The normative definition is not this file. It is the golden fixtures under
// testdata/fixtures — "where a document and a fixture disagree, the fixture
// wins, because the fixture is what verifiers actually re-derive". Two things
// hold this code to them: the fixtures were derived by an oracle that is not
// this code (see their README), and the format fingerprint below freezes the
// serializer's observable behaviour to a constant.
//
// # Shape of an event
//
// An event is a flat object of scalars: doc 02 §2 and §3 define no nested or
// repeated member, and adding one would be a major version anyway. Fields
// therefore admits strings, booleans and integers inside the range RFC 8785's
// ECMAScript number canonicalization reproduces exactly, and nothing else. A
// float would serialize to a form that depends on how it was computed, which
// is exactly the property a content hash must not have.
package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	// SchemaVersion is the schema_version this package emits (doc 02 §2).
	SchemaVersion = "1"

	// SerializerVersion is the version tag of the canonical serializer. It is
	// the same number as SchemaVersion by construction: the serialization is
	// part of the schema, so there is no such thing as a new serializer under
	// an unchanged schema version.
	SerializerVersion = "1"

	// HashPrefix is the algorithm prefix on every hash string (doc 02 §1).
	HashPrefix = "sha256:"

	// EventHashField is the member excluded from its own preimage (doc 02 §4.1).
	EventHashField = "event_hash"
)

// Compile-time gate (SER-005). A duplicate constant key in a map literal is a
// compile error, so bumping one version constant without the other fails
// `go build ./...` rather than shipping a silently different format.
var _ = map[bool]struct{}{false: {}, SerializerVersion == SchemaVersion: {}}

// MaxSafeInteger and MinSafeInteger bound integers that survive RFC 8785's
// ECMAScript number canonicalization without loss (doc 02 §4.2). Outside them
// a JSON number is no longer a faithful record of the value that was hashed.
const (
	MaxSafeInteger int64 = 1<<53 - 1
	MinSafeInteger int64 = -MaxSafeInteger
)

var (
	ErrNilValue               = errors.New("nil member value")
	ErrEmptyValue             = errors.New("empty-string member value")
	ErrEmptyMemberName        = errors.New("empty member name")
	ErrUnsupportedType        = errors.New("unsupported member type")
	ErrIntegerOutOfRange      = errors.New("integer outside the JCS-safe range")
	ErrEventHashPresent       = errors.New("event_hash present")
	ErrEventHashMissing       = errors.New("event_hash missing")
	ErrEventHashMismatch      = errors.New("event_hash does not match its preimage")
	ErrDuplicateMember        = errors.New("duplicate member name")
	ErrNotAnObject            = errors.New("not a JSON object")
	ErrInvalidUTF8            = errors.New("invalid UTF-8")
	ErrUnregisteredSerializer = errors.New("unregistered serializer version")
	ErrFormatDrift            = errors.New("serializer format fingerprint drift")
)

// Fields is one event as member names and values. Absence is expressed by the
// member not being in the map; there is no other spelling of it, because
// doc 02 §1 makes null and the empty string illegal rather than synonymous.
type Fields map[string]any

// Clone returns a copy. Values are scalars, so a shallow copy is a deep one.
func (f Fields) Clone() Fields { return maps.Clone(f) }

// Validate reports whether f is inside the value domain the canonical form
// admits. Members are checked in sorted order so a given record always
// produces the same error.
func (f Fields) Validate() error {
	for _, name := range slices.Sorted(maps.Keys(f)) {
		if err := validateMemberName(name); err != nil {
			return err
		}
		if err := validateValue(name, f[name]); err != nil {
			return err
		}
	}
	return nil
}

// validateMemberName holds a member name to doc 02 §1: a name, and UTF-8.
func validateMemberName(name string) error {
	if name == "" {
		return ErrEmptyMemberName
	}
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: member name %q", ErrInvalidUTF8, name)
	}
	return nil
}

// validateValue admits exactly the scalars doc 02 §2 and §3 use.
func validateValue(name string, v any) error {
	switch t := v.(type) {
	case nil:
		return fmt.Errorf("%w: %q; omit the member instead", ErrNilValue, name)
	case string:
		if t == "" {
			return fmt.Errorf("%w: %q; omit the member instead", ErrEmptyValue, name)
		}
		if !utf8.ValidString(t) {
			return fmt.Errorf("%w: value of %q", ErrInvalidUTF8, name)
		}
		return nil
	case bool:
		return nil
	case int:
		return checkSafeInteger(name, int64(t))
	case int8:
		return checkSafeInteger(name, int64(t))
	case int16:
		return checkSafeInteger(name, int64(t))
	case int32:
		return checkSafeInteger(name, int64(t))
	case int64:
		return checkSafeInteger(name, t)
	case uint8:
		return checkSafeInteger(name, int64(t))
	case uint16:
		return checkSafeInteger(name, int64(t))
	case uint32:
		return checkSafeInteger(name, int64(t))
	case uint:
		return checkSafeUnsigned(name, uint64(t))
	case uint64:
		return checkSafeUnsigned(name, t)
	case json.Number:
		_, err := parseNumberLiteral(name, t)
		return err
	default:
		return fmt.Errorf("%w: %q is %T; events are flat objects of string, bool and integer",
			ErrUnsupportedType, name, v)
	}
}

func checkSafeInteger(name string, v int64) error {
	if v > MaxSafeInteger || v < MinSafeInteger {
		return fmt.Errorf("%w: %q = %d, limit ±%d", ErrIntegerOutOfRange, name, v, MaxSafeInteger)
	}
	return nil
}

func checkSafeUnsigned(name string, v uint64) error {
	if v > uint64(MaxSafeInteger) {
		return fmt.Errorf("%w: %q = %d, limit %d", ErrIntegerOutOfRange, name, v, MaxSafeInteger)
	}
	return nil
}

// parseNumberLiteral converts a JSON number, rejecting anything that is not an
// integer inside the safe range. A literal with a fraction or an exponent is a
// different kind of value, not an out-of-range one, and is reported as such.
func parseNumberLiteral(name string, n json.Number) (int64, error) {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return 0, fmt.Errorf("%w: %q = %s is not an integer", ErrUnsupportedType, name, s)
	}
	v, err := n.Int64()
	if err != nil {
		return 0, fmt.Errorf("%w: %q = %s", ErrIntegerOutOfRange, name, s)
	}
	return v, checkSafeInteger(name, v)
}

// Preimage returns the canonical bytes an event_hash is taken over: the record
// canonicalized with event_hash removed (doc 02 §4.1).
func (f Fields) Preimage() ([]byte, error) {
	if _, err := CurrentFormat(); err != nil {
		return nil, err
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	pre := f
	if pre == nil {
		// A record with no members is an object with no members, never null.
		pre = Fields{}
	}
	if _, ok := pre[EventHashField]; ok {
		pre = pre.Clone()
		delete(pre, EventHashField)
	}
	return Canonicalize(pre)
}

// EventHash computes the event's event_hash (doc 02 §4.3).
func (f Fields) EventHash() (string, error) {
	pre, err := f.Preimage()
	if err != nil {
		return "", err
	}
	return Digest(pre), nil
}

// Finalize returns a copy of f with event_hash attached. The receiver is left
// alone: what was hashed and what carries the hash are separate objects, which
// is the whole reason the member is excluded from its own preimage.
func (f Fields) Finalize() (Fields, error) {
	if _, ok := f[EventHashField]; ok {
		return nil, fmt.Errorf("%w: refusing to hash over a previous %s",
			ErrEventHashPresent, EventHashField)
	}
	h, err := f.EventHash()
	if err != nil {
		return nil, err
	}
	out := f.Clone()
	if out == nil {
		out = Fields{}
	}
	out[EventHashField] = h
	return out, nil
}

// Verify recomputes the event's hash and compares it with the one it carries.
func (f Fields) Verify() error {
	raw, ok := f[EventHashField]
	if !ok {
		return fmt.Errorf("%w: nothing to verify against", ErrEventHashMissing)
	}
	have, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%w: %s is %T, want string", ErrUnsupportedType, EventHashField, raw)
	}
	want, err := f.EventHash()
	if err != nil {
		return err
	}
	if have != want {
		return fmt.Errorf("%w: record carries %s, preimage yields %s",
			ErrEventHashMismatch, have, want)
	}
	return nil
}

// canonicalTransform is the RFC 8785 stage, behind a seam so that its error
// return is reachable from a test. It is never reassigned outside tests.
var canonicalTransform = jcs.Transform

// Canonicalize returns the RFC 8785 JCS form of v (doc 02 §4.2).
//
// The JSON encoder is only a first pass: encoding/json escapes <, >, &,
// U+2028 and U+2029, none of which RFC 8785 escapes. jcs.Transform re-parses
// and re-serializes, so the output is whatever RFC 8785 says regardless of how
// the intermediate JSON was produced — which also makes it immune to future
// changes in encoding/json's escaping.
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: encode: %w", err)
	}
	out, err := canonicalTransform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return out, nil
}

// ParseFields decodes a serialized event.
//
// It is stricter than encoding/json on purpose. A duplicate member name is
// rejected rather than resolved to the last occurrence, because a parser that
// silently picks one of two values for event_hash is a parser two verifiers
// can disagree through. Numbers stay integers, and every value is held to the
// same domain Validate enforces on the way out.
func ParseFields(b []byte) (Fields, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAnObject, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%w: starts with %v", ErrNotAnObject, tok)
	}

	// json.Decoder.More reports true forever once the input is truncated, so
	// the loop is driven by the token stream itself and every read is checked.
	f := Fields{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrNotAnObject, err)
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			break
		}
		// Inside an object encoding/json only ever yields a string here, so
		// this is unreachable today. It is kept so that a change in the
		// decoder fails loudly rather than silently.
		name, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: member name is %T", ErrNotAnObject, tok)
		}
		if err := validateMemberName(name); err != nil {
			return nil, err
		}
		if _, dup := f[name]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateMember, name)
		}

		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("member %q: %w", name, err)
		}
		if n, ok := v.(json.Number); ok {
			i, err := parseNumberLiteral(name, n)
			if err != nil {
				return nil, err
			}
			v = i
		} else if err := validateValue(name, v); err != nil {
			return nil, err
		}
		f[name] = v
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing content after the object", ErrNotAnObject)
	}
	return f, nil
}

// FormatSpec is what one serializer version tag promises. Every field is
// spelled out in the registry rather than referenced from the constants above,
// so that changing a constant makes the registry disagree with the code
// instead of travelling along with it.
type FormatSpec struct {
	Version       string
	SchemaVersion string
	GenesisSeed   string
	Fingerprint   string
}

// formatFingerprintV1 is the digest of the canonical form of formatProbe under
// serializer version 1. It is frozen twice: here, and as the committed fixture
// testdata/fixtures/v1/format-probe.hash, which CI diffs against the previous
// tag. Do not update it to make a test pass — a mismatch means the serializer
// changed, and the serializer is what must be reverted.
const formatFingerprintV1 = "sha256:c7b107b02fd51e19e85e08d3c91c98fbb60ba501211ac7fb6249dcf0bf3d4f44"

// serializerRegistry holds one entry per serializer version that has ever
// existed. Entries are never removed: verification of old records is supported
// forever, without exception (VERSIONING.md).
var serializerRegistry = map[string]FormatSpec{
	"1": {
		Version:       "1",
		SchemaVersion: "1",
		GenesisSeed:   "innsegl-genesis-v1",
		Fingerprint:   formatFingerprintV1,
	},
}

// LookupFormat returns the format frozen for a serializer version tag.
func LookupFormat(version string) (FormatSpec, error) {
	spec, ok := serializerRegistry[version]
	if !ok {
		return FormatSpec{}, fmt.Errorf(
			"%w: %q has no frozen format; a version bump needs a registered spec, "+
				"new golden fixtures and a migration attestation (doc 02 §7)",
			ErrUnregisteredSerializer, version)
	}
	return spec, nil
}

// CurrentFormat returns the format frozen for SerializerVersion.
func CurrentFormat() (FormatSpec, error) { return LookupFormat(SerializerVersion) }

// formatProbeEscapes exercises every string rule RFC 8785 fixes: the two
// characters JSON must escape, the solidus and the HTML characters it must
// not, every short escape, \u-escaped control characters, DEL, the two
// separators encoding/json escapes and RFC 8785 does not, Latin-1, a combining
// sequence, BMP CJK, an astral code point and RTL text.
const formatProbeEscapes = "quote:\" backslash:\\\\ solidus:/ html:<&> " +
	"nul:\x00 bs:\b tab:\t lf:\n ff:\f cr:\r us:\x1f del:\x7f " +
	"lsep:\u2028 psep:\u2029 " +
	"latin1:\u00e9 combining:e\u0301 euro:\u20ac han:\u4e2d " +
	"nonbmp:\U0001f600 rtl:\u05d0\u05d1"

// formatProbe is the fixed object whose canonical form fingerprints the
// serializer. Member names span the ASCII sort range so a change in ordering
// moves the fingerprint; values span the escaping and number rules so a change
// in either does too.
func formatProbe() Fields {
	return Fields{
		"bool_false":         false,
		"bool_true":          true,
		"escapes":            formatProbeEscapes,
		"genesis":            GenesisPrevEventHash(),
		"int_max":            MaxSafeInteger,
		"int_min":            MinSafeInteger,
		"int_zero":           int64(0),
		"schema_version":     SchemaVersion,
		"serializer_version": SerializerVersion,
		"sort_0":             "digit",
		"sort_A":             "upper",
		"sort_a":             "lower",
		"sort_~":             "tilde",
	}
}

// FormatFingerprint returns the digest of the live serializer's output over the
// format probe.
func FormatFingerprint() (string, error) {
	b, err := Canonicalize(formatProbe())
	if err != nil {
		return "", err
	}
	return Digest(b), nil
}

// VerifyFormat reports whether the live serializer still behaves the way
// SerializerVersion promises. Call it at process start: an event_hash produced
// by a drifted serializer is a record nobody can re-derive.
func VerifyFormat() error {
	spec, err := CurrentFormat()
	if err != nil {
		return err
	}
	return verifyFormatAgainst(spec)
}

func verifyFormatAgainst(spec FormatSpec) error {
	if spec.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: version %q is frozen at schema_version %q, code emits %q",
			ErrFormatDrift, spec.Version, spec.SchemaVersion, SchemaVersion)
	}
	if spec.GenesisSeed != GenesisSeed {
		return fmt.Errorf("%w: version %q is frozen at genesis seed %q, code uses %q",
			ErrFormatDrift, spec.Version, spec.GenesisSeed, GenesisSeed)
	}
	got, err := FormatFingerprint()
	if err != nil {
		return err
	}
	if got != spec.Fingerprint {
		return fmt.Errorf(
			"%w: version %q is frozen at %s, the serializer now emits %s; "+
				"revert the serializer rather than the fingerprint (doc 02 §7)",
			ErrFormatDrift, spec.Version, spec.Fingerprint, got)
	}
	return nil
}

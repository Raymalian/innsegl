// SPDX-License-Identifier: Apache-2.0

package event

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Envelope member names (doc 02 §2). Protected strings: a rename here is a new
// major schema version with a migration attestation, not a tidy-up.
const (
	FieldSchemaVersion  = "schema_version"
	FieldEventID        = "event_id"
	FieldChainPosition  = "chain_position"
	FieldEventType      = "event_type"
	FieldTS             = "ts"
	FieldRunID          = "run_id"
	FieldSpiffeID       = "spiffe_id"
	FieldSource         = "source"
	FieldIdempotencyKey = "idempotency_key"
	FieldPayloadDigest  = "payload_digest"
	FieldSupersedes     = "supersedes"
	FieldPrevEventHash  = "prev_event_hash"
)

// The source enum (doc 02 §2): who appended the event. Protected strings.
const (
	SourceMCP        = "mcp"
	SourceReconciler = "reconciler"
	SourceReaper     = "reaper"
	SourceSystem     = "system"
)

// MaxIdempotencyKeyBytes is doc 02 §2's "string ≤128". The document does not
// say whether the limit counts characters or bytes; bytes is the reading taken
// here, because bytes are what the canonical form and the store both measure,
// and it is the stricter of the two.
const MaxIdempotencyKeyBytes = 128

var (
	ErrReservedMemberName = errors.New("member name is reserved by the envelope")
	ErrInvalidTimestamp   = errors.New("invalid timestamp")
	ErrInvalidDigest      = errors.New("invalid digest")
	ErrInvalidEventID     = errors.New("invalid event_id")
	ErrInvalidIdentifier  = errors.New("invalid identifier")
	ErrInvalidSpiffeID    = errors.New("invalid SPIFFE ID")
	ErrInvalidSource      = errors.New("invalid source")
	ErrInvalidField       = errors.New("invalid envelope field")
)

// timestampLayout renders and parses doc 02 §1's timestamp: RFC 3339 UTC at
// exactly millisecond precision with a literal Z.
const timestampLayout = "2006-01-02T15:04:05.000Z"

// timestampPattern pins the rendered shape before time.Parse ever sees it, so
// that "…03Z", "…03.2011Z", "…03.201z" and "…03.201+00:00" are rejected rather
// than quietly accepted as the same instant in a different spelling.
var timestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

// Timestamp is an RFC 3339 UTC instant at exactly millisecond precision. It is
// a distinct type so that a server clock reading is normalized once, at the
// boundary, rather than every time an event is serialized.
type Timestamp struct{ t time.Time }

// NewTimestamp normalizes a clock reading: UTC, truncated to the millisecond.
// Truncation rather than rounding, so a timestamp never names an instant that
// had not happened when the event was appended.
func NewTimestamp(t time.Time) Timestamp {
	return Timestamp{t: t.UTC().Truncate(time.Millisecond)}
}

// ParseTimestamp reads a timestamp in exactly the one legal form.
func ParseTimestamp(s string) (Timestamp, error) {
	if !timestampPattern.MatchString(s) {
		return Timestamp{}, fmt.Errorf(
			"%w: %q is not RFC 3339 UTC at exactly millisecond precision with a literal Z",
			ErrInvalidTimestamp, s)
	}
	t, err := time.Parse(timestampLayout, s)
	if err != nil {
		return Timestamp{}, fmt.Errorf("%w: %q: %w", ErrInvalidTimestamp, s, err)
	}
	return Timestamp{t: t.UTC()}, nil
}

// String renders the timestamp, or "" for the zero value.
func (ts Timestamp) String() string {
	if ts.t.IsZero() {
		return ""
	}
	return ts.t.UTC().Format(timestampLayout)
}

// Time returns the instant.
func (ts Timestamp) Time() time.Time { return ts.t }

// IsZero reports whether the timestamp is unset.
func (ts Timestamp) IsZero() bool { return ts.t.IsZero() }

// Envelope is the common envelope every event carries (doc 02 §2).
//
// The optional members are pointers rather than strings, so that "absent" and
// "present and empty" are different states in the type system and not only in
// a validator. Doc 02 §1 allows only the first, and a *string makes the second
// something the caller has to write on purpose — where it is then rejected.
type Envelope struct {
	SchemaVersion string
	EventID       string
	ChainPosition int64
	EventType     string
	TS            Timestamp

	// RunID and SpiffeID are omitted together, and only for segment_sealed and
	// system-scope alerts that reference no run (doc 02 §2).
	RunID    *string
	SpiffeID *string

	Source string

	// IdempotencyKey is required on events created by MCP tool calls, which is
	// to say on every event with source "mcp" (doc 02 §2).
	IdempotencyKey *string

	// PayloadDigest is present if and only if an out-of-band payload exists.
	// Only its shape can be checked here; whether a payload exists cannot.
	PayloadDigest *string

	// Supersedes names the event this correction refers to. The referenced
	// event is never modified.
	Supersedes *string

	PrevEventHash string
}

// envelopeFieldNames is the envelope's member set, sorted. Protected.
var envelopeFieldNames = []string{
	FieldChainPosition, FieldEventID, FieldEventType, FieldIdempotencyKey,
	FieldPayloadDigest, FieldPrevEventHash, FieldRunID, FieldSchemaVersion,
	FieldSource, FieldSpiffeID, FieldSupersedes, FieldTS,
}

// EnvelopeFieldNames returns the envelope's member names, sorted.
func EnvelopeFieldNames() []string { return slices.Clone(envelopeFieldNames) }

// Optional returns a pointer to s, for an optional envelope member that is
// present. A nil pointer means the member is absent; a pointer to "" is a
// rejected input, because doc 02 §1 has no empty-string placeholders.
func Optional(s string) *string { return &s }

// Fields renders the envelope as members, omitting every absent optional.
func (e Envelope) Fields() (Fields, error) {
	if e.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: %s must be %q, got %q",
			ErrInvalidField, FieldSchemaVersion, SchemaVersion, e.SchemaVersion)
	}
	if err := ValidateEventID(e.EventID); err != nil {
		return nil, fmt.Errorf("%s: %w", FieldEventID, err)
	}
	if e.ChainPosition < 1 {
		return nil, fmt.Errorf("%w: %s is 1-based, got %d",
			ErrInvalidField, FieldChainPosition, e.ChainPosition)
	}
	if err := checkSafeInteger(FieldChainPosition, e.ChainPosition); err != nil {
		return nil, err
	}
	if e.EventType == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidField, FieldEventType)
	}
	if e.TS.IsZero() {
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidTimestamp, FieldTS)
	}
	if err := ValidateSource(e.Source); err != nil {
		return nil, err
	}
	if err := ValidateDigest(e.PrevEventHash); err != nil {
		return nil, fmt.Errorf("%s: %w", FieldPrevEventHash, err)
	}

	optionals := []struct {
		name     string
		value    *string
		validate func(string) error
	}{
		{FieldRunID, e.RunID, ValidateIdentifier},
		{FieldSpiffeID, e.SpiffeID, ValidateSPIFFEID},
		{FieldIdempotencyKey, e.IdempotencyKey, validateIdempotencyKey},
		{FieldPayloadDigest, e.PayloadDigest, ValidateDigest},
		{FieldSupersedes, e.Supersedes, ValidateEventID},
	}

	f := Fields{
		FieldSchemaVersion: e.SchemaVersion,
		FieldEventID:       e.EventID,
		FieldChainPosition: e.ChainPosition,
		FieldEventType:     e.EventType,
		FieldTS:            e.TS.String(),
		FieldSource:        e.Source,
		FieldPrevEventHash: e.PrevEventHash,
	}
	for _, o := range optionals {
		if o.value == nil {
			continue
		}
		if *o.value == "" {
			return nil, fmt.Errorf("%w: %s is present but empty; omit it instead",
				ErrEmptyValue, o.name)
		}
		if err := o.validate(*o.value); err != nil {
			return nil, fmt.Errorf("%s: %w", o.name, err)
		}
		f[o.name] = *o.value
	}

	if (e.RunID == nil) != (e.SpiffeID == nil) {
		return nil, fmt.Errorf(
			"%w: %s and %s are omitted together, and only for events that reference no run",
			ErrInvalidField, FieldRunID, FieldSpiffeID)
	}
	if e.Source == SourceMCP && e.IdempotencyKey == nil {
		return nil, fmt.Errorf("%w: %s is required on events created by MCP tool calls",
			ErrInvalidField, FieldIdempotencyKey)
	}
	return f, nil
}

// FieldsWith renders the envelope together with an event type's own members
// (doc 02 §3). A type-specific member may not shadow an envelope member, and
// may not be event_hash: both would let a caller change what gets hashed
// without changing what the envelope says.
func (e Envelope) FieldsWith(extra Fields) (Fields, error) {
	f, err := e.Fields()
	if err != nil {
		return nil, err
	}
	reserved := append(EnvelopeFieldNames(), EventHashField)
	for _, name := range slices.Sorted(maps.Keys(extra)) {
		if slices.Contains(reserved, name) {
			return nil, fmt.Errorf("%w: %q", ErrReservedMemberName, name)
		}
		f[name] = extra[name]
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	return f, nil
}

var (
	digestPattern     = regexp.MustCompile(`^` + regexp.QuoteMeta(HashPrefix) + `[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

	// UUIDv7, lowercase (doc 02 §1): version nibble 7, variant bits 10.
	eventIDPattern = regexp.MustCompile(
		`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// ValidateDigest checks doc 02 §1's hash form: lowercase hex with an algorithm
// prefix.
func ValidateDigest(s string) error {
	if !digestPattern.MatchString(s) {
		return fmt.Errorf("%w: %q is not %s followed by 64 lowercase hex digits",
			ErrInvalidDigest, s, HashPrefix)
	}
	return nil
}

// ValidateEventID checks doc 02 §1's event_id form: a lowercase UUIDv7.
func ValidateEventID(s string) error {
	if !eventIDPattern.MatchString(s) {
		return fmt.Errorf("%w: %q is not a lowercase UUIDv7", ErrInvalidEventID, s)
	}
	return nil
}

// ValidateIdentifier checks the agent_type / task_id / run_id grammar in
// doc 02 §5.
func ValidateIdentifier(s string) error {
	if !identifierPattern.MatchString(s) {
		return fmt.Errorf("%w: %q does not match [a-z0-9][a-z0-9-]{0,62}",
			ErrInvalidIdentifier, s)
	}
	return nil
}

// ValidateSPIFFEID checks the SPIFFE ID grammar in doc 02 §5:
// spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}.
//
// It checks shape only. Whether the trust domain is one this deployment
// accepts is a policy question and belongs with the workload API, not here.
func ValidateSPIFFEID(s string) error {
	const scheme = "spiffe://"
	bad := func() error {
		return fmt.Errorf(
			"%w: %q is not spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}",
			ErrInvalidSpiffeID, s)
	}

	rest, ok := strings.CutPrefix(s, scheme)
	if !ok {
		return bad()
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 5 {
		return bad()
	}
	trustDomain, agent := parts[0], parts[1]
	if trustDomain == "" || trustDomain != strings.ToLower(trustDomain) || agent != "agent" {
		return bad()
	}
	for _, p := range parts[2:] {
		if err := ValidateIdentifier(p); err != nil {
			return bad()
		}
	}
	return nil
}

// ValidateSource checks the source enum in doc 02 §2.
func ValidateSource(s string) error {
	switch s {
	case SourceMCP, SourceReconciler, SourceReaper, SourceSystem:
		return nil
	default:
		return fmt.Errorf("%w: %q is not one of %s, %s, %s, %s",
			ErrInvalidSource, s, SourceMCP, SourceReconciler, SourceReaper, SourceSystem)
	}
}

func validateIdempotencyKey(s string) error {
	if len(s) > MaxIdempotencyKeyBytes {
		return fmt.Errorf("%w: %s is %d bytes, limit %d",
			ErrInvalidField, FieldIdempotencyKey, len(s), MaxIdempotencyKeyBytes)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s", ErrInvalidUTF8, FieldIdempotencyKey)
	}
	return nil
}

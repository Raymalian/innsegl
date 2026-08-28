// SPDX-License-Identifier: Apache-2.0

package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Closed-schema validation: doc 02 §1 ("Unknown fields are rejected at append
// time"), §3 (the eleven types and their members) and §5 (identifier and size
// constraints).
//
// # Why a closed schema is the payload guard
//
// IP E4 — events are references, never payloads — is not a convention here. It
// is enforced by construction, at three layers:
//
//  1. The member set of every event type is fixed (doc 02 §3). A body has no
//     member to live in: `payload`, `body`, `diff`, `stdout` are all unknown
//     members and are refused at append.
//  2. Every member that does exist is bounded. A body cannot be smuggled into
//     `reason` or `tool_name`, because a reference is at most
//     MaxReferenceBytes and free text at most MaxTextBytes.
//  3. The whole canonical record is capped at MaxEventBytes (doc 02 §5),
//     the backstop behind the first two rather than the first line of defence.
//
// Layer 1 is what LED-011 names: "rejected at schema validation; only
// digests/references pass".

const (
	// TargetEventBytes is doc 02 §5's target canonical size. It is a budget for
	// the per-member bounds below, not a limit: an event over it is a design
	// smell, not an error.
	TargetEventBytes = 1024

	// MaxEventBytes is doc 02 §5's hard cap, enforced at append.
	MaxEventBytes = 4096

	// MaxReferenceBytes bounds a member that names something — an audience, a
	// tool, a Rekor entry, a segment. Doc 02 gives these no grammar, so the
	// bound is what keeps them references: a quarter of the 1 KB target, so no
	// single reference can consume the budget doc 02 §5 sets for a whole event.
	MaxReferenceBytes = 256

	// MaxTextBytes bounds the one free-text member in the schema,
	// ledger_drift_detected's `reason`. Half the 1 KB target: enough for a
	// sentence naming what drifted, far short of anything that could carry the
	// evidence itself rather than a reference to it (IP E4).
	MaxTextBytes = 512
)

var (
	ErrUnknownEventType   = errors.New("unknown event_type")
	ErrUnknownMember      = errors.New("unknown member; the schema is closed")
	ErrMissingMember      = errors.New("missing required member")
	ErrValueTooLong       = errors.New("member value too long")
	ErrEventTooLarge      = errors.New("event exceeds the canonical size cap")
	ErrInvalidRepo        = errors.New("invalid repo")
	ErrInvalidGitObjectID = errors.New("invalid git object id")
)

// CanonicalSize returns the size in bytes of the event's canonical form
// (doc 02 §4.2) — the preimage, with event_hash excluded.
//
// Measuring the preimage rather than the stored record means an event's size
// does not change when it is hashed. A finalized event carries event_hash as
// well, which is a fixed 74 bytes of canonical JSON on top of what is measured
// here.
func CanonicalSize(f Fields) (int, error) {
	b, err := f.Preimage()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// ValidateEvent is the append-time gate: the schema is closed, every required
// member is present, every value is inside its grammar and its bound, and the
// whole record is inside doc 02 §5's hard cap.
func ValidateEvent(f Fields) error { return validateEvent(f, false) }

// ValidateEventForVerification is the verifier-side gate for an event read back
// out of history.
//
// It differs from ValidateEvent in exactly one way, and it is the one doc 02 §1
// allows: "Verifiers reading historical events tolerate unknown fields only if
// the event's schema_version is newer than the verifier." At the same version
// an unknown member is not a member from the future; it is corruption or a
// forgery, and is refused here as it is at append.
func ValidateEventForVerification(f Fields) error { return validateEvent(f, true) }

func validateEvent(f Fields, verifying bool) error {
	// The value domain first (canonical.go): nulls, empty strings, floats and
	// out-of-range integers are not schema questions, and nothing below can be
	// trusted until they are gone.
	if err := f.Validate(); err != nil {
		return err
	}

	// doc 02 §5's hard cap, before any structural work: an oversized record is
	// refused on its size, whatever else is wrong with it.
	size, err := CanonicalSize(f)
	if err != nil {
		return err
	}
	if size > MaxEventBytes {
		return fmt.Errorf("%w: %d bytes canonical, hard cap %d (doc 02 §5)",
			ErrEventTooLarge, size, MaxEventBytes)
	}

	tolerateUnknown, err := resolveSchemaVersion(f, verifying)
	if err != nil {
		return err
	}

	eventType, err := memberString(f, FieldEventType)
	if err != nil {
		return err
	}
	spec, err := lookupType(eventType)
	if err != nil {
		return err
	}
	allowed := allowedFor(spec)

	if !tolerateUnknown {
		for _, name := range slices.Sorted(maps.Keys(f)) {
			if _, ok := allowed[name]; !ok {
				return fmt.Errorf(
					"%w: %q is not a member of %s; events are references, never "+
						"payloads (doc 02 §1, §3, IP E4)",
					ErrUnknownMember, name, eventType)
			}
		}
	}

	for _, name := range requiredFor(spec) {
		if _, ok := f[name]; !ok {
			return fmt.Errorf("%w: %s requires %q (doc 02 §2, §3)",
				ErrMissingMember, eventType, name)
		}
	}

	// Members are checked in sorted order so a given record always produces the
	// same error, the way Fields.Validate does.
	for _, name := range slices.Sorted(maps.Keys(f)) {
		member, ok := allowed[name]
		if !ok {
			// Only reachable when tolerating a newer schema_version, where the
			// member's constraint is by definition unknown to this verifier.
			continue
		}
		if err := member.check(name, f[name]); err != nil {
			return err
		}
	}

	return checkCrossMemberRules(f, spec)
}

// resolveSchemaVersion checks schema_version and reports whether unknown
// members are to be tolerated (doc 02 §1).
func resolveSchemaVersion(f Fields, verifying bool) (bool, error) {
	got, err := memberString(f, FieldSchemaVersion)
	if err != nil {
		return false, err
	}
	if !verifying {
		if got != SchemaVersion {
			return false, fmt.Errorf("%w: %s must be %q at append, got %q",
				ErrInvalidField, FieldSchemaVersion, SchemaVersion, got)
		}
		return false, nil
	}

	theirs, err := parseSchemaVersion(got)
	if err != nil {
		return false, err
	}
	// An older version is verified strictly, not refused: every version ever
	// released stays verifiable (VERSIONING.md), and this verifier knows that
	// version's whole member set. Only a newer one can carry a member this
	// verifier has no way to know about.
	return theirs > currentSchemaVersion, nil
}

// currentSchemaVersion is SchemaVersion as the number doc 02 §7's major
// versioning makes it. It is spelled out rather than parsed: SchemaVersion is a
// constant of this package, not an input, and a parse of it would be an error
// path no test could ever reach. The two are held together by
// TestSchemaVersionConstantsAgree, in the same spirit as the SER-005 gate.
const currentSchemaVersion = 1

// parseSchemaVersion reads a schema_version as the integer doc 02 §7's major
// versioning makes it. "1.0" is not a spelling of "1": it is not a version.
func parseSchemaVersion(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || strconv.Itoa(n) != s {
		return 0, fmt.Errorf("%w: %s %q is not a major version number",
			ErrInvalidField, FieldSchemaVersion, s)
	}
	return n, nil
}

// checkCrossMemberRules holds the rules that relate members to one another, and
// so cannot be checked one member at a time.
func checkCrossMemberRules(f Fields, spec typeSpec) error {
	if err := checkRunScope(f); err != nil {
		return err
	}
	if err := checkIdempotencyKeyScope(f, spec); err != nil {
		return err
	}
	return checkSegmentRules(f, spec)
}

// checkRunScope is doc 02 §2: run_id and spiffe_id are omitted together, and
// only for the event types that may reference no run. The required half is
// already covered by requiredFor; what is left is the pairing.
func checkRunScope(f Fields) error {
	_, hasRun := f[FieldRunID]
	_, hasSpiffe := f[FieldSpiffeID]
	if hasRun != hasSpiffe {
		return fmt.Errorf(
			"%w: %s and %s are omitted together, and only for events that reference "+
				"no run (doc 02 §2)",
			ErrInvalidField, FieldRunID, FieldSpiffeID)
	}
	return nil
}

// checkIdempotencyKeyScope is ADR-0004, applied to a record rather than to an
// Envelope. Envelope.Fields enforces the same rule on the way in; this is the
// gate for anything that reaches the ledger by another route, and the two read
// from the same two sets so they cannot drift apart.
func checkIdempotencyKeyScope(f Fields, spec typeSpec) error {
	_, present := f[FieldIdempotencyKey]
	switch {
	case idempotencyKeyForbiddenOn[spec.eventType] && present:
		return fmt.Errorf(
			"%w: %s must be absent on %s; the MCP tool that emits it takes no "+
				"idempotency key (ADR-0004)",
			ErrInvalidField, FieldIdempotencyKey, spec.eventType)
	case idempotencyKeyAcceptedBy[spec.eventType] && !present:
		// source has already been through checkSourceValue by the time the
		// cross-member rules run, so this read cannot be anything but a string.
		source, ok := f[FieldSource].(string)
		if ok && source == SourceMCP {
			return fmt.Errorf(
				"%w: %s is required on %s appended by the MCP server (ADR-0004)",
				ErrMissingMember, FieldIdempotencyKey, spec.eventType)
		}
	}
	return nil
}

// checkSegmentRules is doc 02 §3's segment_sealed row: the two anchoring
// members are absent until Rekor confirms and then arrive together in a
// superseding event, and the sealed range runs forwards.
func checkSegmentRules(f Fields, spec typeSpec) error {
	if spec.eventType != EventTypeSegmentSealed {
		return nil
	}

	_, hasIndex := f[FieldAnchorRekorLogIndex]
	_, hasUUID := f[FieldAnchorRekorEntryUUID]
	if hasIndex != hasUUID {
		return fmt.Errorf(
			"%w: %s and %s arrive together in the superseding event once Rekor "+
				"confirms; half an anchor is not an anchor (doc 02 §3)",
			ErrInvalidField, FieldAnchorRekorLogIndex, FieldAnchorRekorEntryUUID)
	}

	// Both members are required and have already been through
	// checkChainPositionValue, so the reads below cannot fail.
	first, okFirst := toInteger(f[FieldFirstPosition])
	last, okLast := toInteger(f[FieldLastPosition])
	if okFirst && okLast && last < first {
		return fmt.Errorf("%w: %s %d is before %s %d",
			ErrInvalidField, FieldLastPosition, last, FieldFirstPosition, first)
	}
	return nil
}

// memberString reads a required string member.
func memberString(f Fields, name string) (string, error) {
	v, ok := f[name]
	if !ok {
		return "", fmt.Errorf("%w: %q (doc 02 §2)", ErrMissingMember, name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is %T, want string", ErrUnsupportedType, name, v)
	}
	return s, nil
}

// toInteger accepts the integer spellings Fields admits (canonical.go), so that
// a record built by hand, decoded by ParseFields or rendered from an Envelope
// is validated identically.
func toInteger(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int8:
		return int64(t), true
	case int16:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint8:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint32:
		return int64(t), true
	case uint:
		if uint64(t) > uint64(MaxSafeInteger) {
			return 0, false
		}
		return int64(t), true
	case uint64:
		if t > uint64(MaxSafeInteger) {
			return 0, false
		}
		return int64(t), true
	case json.Number:
		n, err := t.Int64()
		if err != nil || strings.ContainsAny(t.String(), ".eE") {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// checkBoundedString is the shape every string member shares: a string, not
// empty, and inside its bound. The bound is what stops a member being used as a
// payload channel (IP E4).
func checkBoundedString(name string, v any, limit int) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %q is %T, want string", ErrUnsupportedType, name, v)
	}
	if s == "" {
		return "", fmt.Errorf("%w: %q; omit the member instead", ErrEmptyValue, name)
	}
	if len(s) > limit {
		return "", fmt.Errorf(
			"%w: %q is %d bytes, limit %d; events are references, never payloads (IP E4)",
			ErrValueTooLong, name, len(s), limit)
	}
	return s, nil
}

// checkInteger is the shape every integer member shares.
func checkInteger(name string, v any, minimum int64) error {
	n, ok := toInteger(v)
	if !ok {
		return fmt.Errorf("%w: %q is %T, want an integer", ErrUnsupportedType, name, v)
	}
	if n < minimum {
		return fmt.Errorf("%w: %q is %d, minimum %d", ErrInvalidField, name, n, minimum)
	}
	return checkSafeInteger(name, n)
}

func checkReference(name string, v any) error {
	_, err := checkBoundedString(name, v, MaxReferenceBytes)
	return err
}

func checkText(name string, v any) error {
	_, err := checkBoundedString(name, v, MaxTextBytes)
	return err
}

func checkIdentifier(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateIdentifier(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkSPIFFEIDValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateSPIFFEID(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkDigestValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateDigest(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkEventIDValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateEventID(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkTimestampValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if _, err := ParseTimestamp(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkSourceValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateSource(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkEventTypeValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateEventType(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkIdempotencyKeyValue(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxIdempotencyKeyBytes)
	if err != nil {
		return err
	}
	return validateIdempotencyKey(s)
}

func checkRepo(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateRepo(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func checkGitObjectID(name string, v any) error {
	s, err := checkBoundedString(name, v, MaxReferenceBytes)
	if err != nil {
		return err
	}
	if err := ValidateGitObjectID(s); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// checkLogIndex bounds a transparency-log index. Rekor indices are 0-based.
func checkLogIndex(name string, v any) error { return checkInteger(name, v, 0) }

// checkChainPositionValue bounds a chain position. doc 02 §2: 1-based.
func checkChainPositionValue(name string, v any) error { return checkInteger(name, v, 1) }

var (
	// repoHostPattern is a lowercase DNS name: doc 02 §5's "lowercase host".
	// It admits a single label so that a self-hosted forge reachable by short
	// name is expressible; it does not admit a port, a scheme or a userinfo,
	// none of which are part of host/org/name.
	repoHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

	// repoPathPattern bounds the org and name segments. doc 02 §5 constrains
	// only the host's case, so these keep theirs — forge org names are
	// case-sensitive, and lowercasing one here would name a different repo.
	repoPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

	// gitObjectIDPattern is doc 02 §5: "full 40-hex (SHA-1) or 64-hex
	// (SHA-256 repos); never abbreviated". No algorithm prefix: unlike the
	// digests of doc 02 §1, these are git object ids as git spells them.
	gitObjectIDPattern = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ValidateRepo checks doc 02 §5's repo form: host/org/name, lowercase host.
func ValidateRepo(s string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: %q %s; doc 02 §5 requires host/org/name with a lowercase host",
			ErrInvalidRepo, s, why)
	}

	parts := strings.Split(s, "/")
	if len(parts) != 3 {
		return bad("is not three slash-separated segments")
	}
	host, org, name := parts[0], parts[1], parts[2]
	if host != strings.ToLower(host) {
		return bad("has an uppercase host")
	}
	if !repoHostPattern.MatchString(host) {
		return bad("has a host that is not a DNS name")
	}
	if !repoPathPattern.MatchString(org) {
		return bad("has an org segment outside [A-Za-z0-9][A-Za-z0-9._-]*")
	}
	if !repoPathPattern.MatchString(name) {
		return bad("has a name segment outside [A-Za-z0-9][A-Za-z0-9._-]*")
	}
	return nil
}

// ValidateGitObjectID checks doc 02 §5's commit_sha and tree_hash form: a full
// 40-hex or 64-hex lowercase object id, never abbreviated.
//
// Abbreviation is refused rather than expanded. An abbreviated hash is a
// prefix, and a prefix names whatever repository state happens to be unique
// under it today — which is not a property a record kept for ten years can
// rely on.
func ValidateGitObjectID(s string) error {
	if !gitObjectIDPattern.MatchString(s) {
		return fmt.Errorf(
			"%w: %q is not a full 40-hex or 64-hex lowercase object id (doc 02 §5)",
			ErrInvalidGitObjectID, s)
	}
	return nil
}

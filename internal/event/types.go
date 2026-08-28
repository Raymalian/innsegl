// SPDX-License-Identifier: Apache-2.0

package event

import (
	"fmt"
	"slices"
)

// This file is doc 02 §3: the eleven event types and the members each one adds
// to the common envelope.
//
// # Protected surface
//
// Every string constant below is a protected string (doc 02 §3, IP §2):
// "Enum values, field names, and the trailer keys Agent-Identity / Agent-Run /
// Agent-Task are protected strings." A value here changes only in a new major
// schema_version, released with everything doc 02 §7 requires. The Go
// identifiers are ours; the string literals are not.
//
// The `source` enum (doc 02 §2) and the envelope member names live in
// envelope.go, where they landed with the canonical serializer (RM-006). They
// are referenced from here rather than restated: one definition of a protected
// string, or the two copies eventually disagree.

// The event_type enum, doc 02 §3, in document order.
const (
	// EventTypeRunRegistered: identity created; SPIRE entry exists.
	EventTypeRunRegistered = "run_registered"
	// EventTypeCredentialIssued: a JWT/X.509-SVID was released to the run.
	// G101 reads "credential_" as a secret; it is a protected event_type enum
	// value from doc 02 §3, and there is no secret anywhere near this package.
	EventTypeCredentialIssued = "credential_issued" //nolint:gosec // protected enum value, not a credential
	// EventTypeToolCall: one agent tool invocation; body only as payload_digest.
	EventTypeToolCall = "tool_call"
	// EventTypeCommitIntent: phase A of two-phase signing (IP §6.5).
	EventTypeCommitIntent = "commit_intent"
	// EventTypeCommitRecorded: phase C; source reconciler when repaired.
	EventTypeCommitRecorded = "commit_recorded"
	// EventTypeCommitIntentExpired: phase A with no signature inside the window.
	EventTypeCommitIntentExpired = "commit_intent_expired"
	// EventTypeRunRetired: clean retirement; SPIRE entry deleted.
	EventTypeRunRetired = "run_retired"
	// EventTypeRunExpired: TTL expiry of an unretired run.
	EventTypeRunExpired = "run_expired"
	// EventTypeUnattributedSignatureDetected: alert, a trust-domain signature
	// with no intent.
	EventTypeUnattributedSignatureDetected = "unattributed_signature_detected"
	// EventTypeLedgerDriftDetected: alert, a ledger claim with no external proof.
	EventTypeLedgerDriftDetected = "ledger_drift_detected"
	// EventTypeSegmentSealed: segment closed, and — via a superseding event —
	// anchored.
	EventTypeSegmentSealed = "segment_sealed"
)

// Type-specific member names, doc 02 §3. Protected strings.
const (
	FieldAgentType = "agent_type"
	FieldTaskRef   = "task_ref"
	FieldAudience  = "audience"
	// Same G101 false positive as EventTypeCredentialIssued above.
	FieldCredentialExpiry     = "credential_expiry" //nolint:gosec // protected member name, not a credential
	FieldToolName             = "tool_name"
	FieldRepo                 = "repo"
	FieldTreeHash             = "tree_hash"
	FieldCommitSHA            = "commit_sha"
	FieldRekorLogIndex        = "rekor_log_index"
	FieldRekorEntryUUID       = "rekor_entry_uuid"
	FieldIntentEventID        = "intent_event_id"
	FieldCertificateIdentity  = "certificate_identity"
	FieldSubjectEventID       = "subject_event_id"
	FieldReason               = "reason"
	FieldSegmentID            = "segment_id"
	FieldSegmentMerkleRoot    = "segment_merkle_root"
	FieldFirstPosition        = "first_position"
	FieldLastPosition         = "last_position"
	FieldAnchorRekorLogIndex  = "anchor_rekor_log_index"
	FieldAnchorRekorEntryUUID = "anchor_rekor_entry_uuid"
)

// runScope says whether an event type must name the run it belongs to.
//
// doc 02 §2: run_id and spiffe_id are "Omitted only for segment_sealed and
// system-scope alerts that reference no run." The two rows doc 02 §3 labels
// "Alert:" are the system-scope alerts, and golden fixture 09 is the committed
// example of one appended with neither member.
type runScope int

const (
	// runRequired: the event belongs to a run and must name it.
	runRequired runScope = iota
	// runOptional: the event may reference no run, in which case run_id and
	// spiffe_id are both omitted. Never one without the other.
	runOptional
)

// memberSpec is one member of one event type: its name, whether doc 02 §3
// requires it, and the constraint its value is held to.
type memberSpec struct {
	name     string
	required bool
	check    func(name string, v any) error
}

// typeSpec is one row of doc 02 §3.
type typeSpec struct {
	eventType string
	runScope  runScope
	// members are the type-specific ones only, sorted by name so that
	// RequiredFields and AllowedFields are deterministic.
	members []memberSpec
}

func required(name string, check func(string, any) error) memberSpec {
	return memberSpec{name: name, required: true, check: check}
}

func optional(name string, check func(string, any) error) memberSpec {
	return memberSpec{name: name, required: false, check: check}
}

// typeSpecOrder is the enum in doc 02 §3's order. Order is part of what is
// pinned: a reader comparing this file against the document reads them
// side by side.
var typeSpecOrder = []string{
	EventTypeRunRegistered,
	EventTypeCredentialIssued,
	EventTypeToolCall,
	EventTypeCommitIntent,
	EventTypeCommitRecorded,
	EventTypeCommitIntentExpired,
	EventTypeRunRetired,
	EventTypeRunExpired,
	EventTypeUnattributedSignatureDetected,
	EventTypeLedgerDriftDetected,
	EventTypeSegmentSealed,
}

// typeSpecs is doc 02 §3's table.
//
// Members are listed sorted by name, not in the document's column order, so
// that a validator walking them reports the same error for the same record
// every time. The document's own order is preserved by typeSpecOrder above.
var typeSpecs = map[string]typeSpec{
	EventTypeRunRegistered: {
		eventType: EventTypeRunRegistered,
		runScope:  runRequired,
		members: []memberSpec{
			// agent_type is the same value that appears as {agent_type} in the
			// run's SPIFFE ID, so it is held to the same grammar (doc 02 §5).
			required(FieldAgentType, checkIdentifier),
			// task_ref is an external reference — golden fixture 01 carries
			// "JIRA-118" — and is deliberately NOT the {task_id} of the SPIFFE
			// ID, which is the lowercased "jira-118". doc 02 gives it no
			// grammar, so it is a bounded reference and nothing more.
			required(FieldTaskRef, checkReference),
		},
	},
	EventTypeCredentialIssued: {
		eventType: EventTypeCredentialIssued,
		runScope:  runRequired,
		members: []memberSpec{
			required(FieldAudience, checkReference),
			required(FieldCredentialExpiry, checkTimestampValue),
		},
	},
	EventTypeToolCall: {
		eventType: EventTypeToolCall,
		runScope:  runRequired,
		members: []memberSpec{
			// doc 02 §3: "body only as payload_digest". The body has no member
			// to live in, which is IP E4 made mechanical.
			required(FieldToolName, checkReference),
		},
	},
	EventTypeCommitIntent: {
		eventType: EventTypeCommitIntent,
		runScope:  runRequired,
		members: []memberSpec{
			required(FieldRepo, checkRepo),
			required(FieldTreeHash, checkGitObjectID),
		},
	},
	EventTypeCommitRecorded: {
		eventType: EventTypeCommitRecorded,
		runScope:  runRequired,
		members: []memberSpec{
			required(FieldCommitSHA, checkGitObjectID),
			required(FieldIntentEventID, checkEventIDValue),
			required(FieldRekorEntryUUID, checkReference),
			required(FieldRekorLogIndex, checkLogIndex),
			required(FieldRepo, checkRepo),
			required(FieldTreeHash, checkGitObjectID),
		},
	},
	EventTypeCommitIntentExpired: {
		eventType: EventTypeCommitIntentExpired,
		runScope:  runRequired,
		members: []memberSpec{
			required(FieldIntentEventID, checkEventIDValue),
		},
	},
	EventTypeRunRetired: {
		eventType: EventTypeRunRetired,
		runScope:  runRequired,
	},
	EventTypeRunExpired: {
		eventType: EventTypeRunExpired,
		runScope:  runRequired,
	},
	EventTypeUnattributedSignatureDetected: {
		eventType: EventTypeUnattributedSignatureDetected,
		runScope:  runOptional,
		members: []memberSpec{
			// certificate_identity is read out of a certificate this deployment
			// did not issue and does not trust. It is bounded, and otherwise
			// left alone: an alert about an identity too malformed to parse is
			// exactly the alert that must still be recordable (I3).
			required(FieldCertificateIdentity, checkReference),
			required(FieldRekorEntryUUID, checkReference),
			required(FieldRekorLogIndex, checkLogIndex),
		},
	},
	EventTypeLedgerDriftDetected: {
		eventType: EventTypeLedgerDriftDetected,
		runScope:  runOptional,
		members: []memberSpec{
			required(FieldReason, checkText),
			required(FieldSubjectEventID, checkEventIDValue),
		},
	},
	EventTypeSegmentSealed: {
		eventType: EventTypeSegmentSealed,
		runScope:  runOptional,
		members: []memberSpec{
			// "opt until anchored": absent in the sealing event, present in the
			// superseding one once Rekor confirms. Golden fixtures 11 and 12
			// are the two sides of it.
			optional(FieldAnchorRekorEntryUUID, checkReference),
			optional(FieldAnchorRekorLogIndex, checkLogIndex),
			required(FieldFirstPosition, checkChainPositionValue),
			required(FieldLastPosition, checkChainPositionValue),
			required(FieldSegmentID, checkReference),
			required(FieldSegmentMerkleRoot, checkDigestValue),
		},
	},
}

// envelopeSpecs is doc 02 §2's table, as members.
//
// Requiredness here is the unconditional kind. run_id, spiffe_id and
// idempotency_key are conditional (doc 02 §2, ADR-0004) and are resolved
// against the event type and source in requiredFor and checkCrossMemberRules.
var envelopeSpecs = []memberSpec{
	optional(EventHashField, checkDigestValue),
	required(FieldChainPosition, checkChainPositionValue),
	required(FieldEventID, checkEventIDValue),
	required(FieldEventType, checkEventTypeValue),
	optional(FieldIdempotencyKey, checkIdempotencyKeyValue),
	optional(FieldPayloadDigest, checkDigestValue),
	required(FieldPrevEventHash, checkDigestValue),
	optional(FieldRunID, checkIdentifier),
	required(FieldSchemaVersion, checkReference),
	required(FieldSource, checkSourceValue),
	optional(FieldSpiffeID, checkSPIFFEIDValue),
	optional(FieldSupersedes, checkEventIDValue),
	required(FieldTS, checkTimestampValue),
}

// EventTypes returns the eleven event_type values of doc 02 §3, in document
// order.
func EventTypes() []string { return slices.Clone(typeSpecOrder) }

// IsEventType reports whether s is one of the eleven.
func IsEventType(s string) bool {
	_, ok := typeSpecs[s]
	return ok
}

// ValidateEventType checks the event_type enum (doc 02 §3).
func ValidateEventType(s string) error {
	if !IsEventType(s) {
		return fmt.Errorf("%w: %q is not one of %v", ErrUnknownEventType, s, typeSpecOrder)
	}
	return nil
}

// lookupType returns the row of doc 02 §3 for an event type.
func lookupType(eventType string) (typeSpec, error) {
	spec, ok := typeSpecs[eventType]
	if !ok {
		return typeSpec{}, fmt.Errorf("%w: %q is not one of %v",
			ErrUnknownEventType, eventType, typeSpecOrder)
	}
	return spec, nil
}

// requiredFor returns the members an event of this type must carry, sorted.
//
// idempotency_key is deliberately absent: doc 02 §2 makes it conditional and
// ADR-0004 resolves the condition against the event's `source` as well as its
// type, so it is not a property of the type alone. checkCrossMemberRules
// enforces it.
func requiredFor(spec typeSpec) []string {
	names := make([]string, 0, len(envelopeSpecs)+len(spec.members))
	for _, m := range envelopeSpecs {
		if m.required {
			names = append(names, m.name)
		}
	}
	if spec.runScope == runRequired {
		names = append(names, FieldRunID, FieldSpiffeID)
	}
	for _, m := range spec.members {
		if m.required {
			names = append(names, m.name)
		}
	}
	slices.Sort(names)
	return names
}

// allowedFor returns every member an event of this type may carry, by name.
func allowedFor(spec typeSpec) map[string]memberSpec {
	allowed := make(map[string]memberSpec, len(envelopeSpecs)+len(spec.members))
	for _, m := range envelopeSpecs {
		allowed[m.name] = m
	}
	for _, m := range spec.members {
		allowed[m.name] = m
	}
	return allowed
}

// RequiredFields returns the members an event of the given type must carry,
// sorted. See requiredFor for why idempotency_key is not among them.
func RequiredFields(eventType string) ([]string, error) {
	spec, err := lookupType(eventType)
	if err != nil {
		return nil, err
	}
	return requiredFor(spec), nil
}

// AllowedFields returns every member an event of the given type may carry,
// sorted. Anything outside this set is rejected at append: the schema is closed
// (doc 02 §1).
func AllowedFields(eventType string) ([]string, error) {
	spec, err := lookupType(eventType)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(envelopeSpecs)+len(spec.members))
	for name := range allowedFor(spec) {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

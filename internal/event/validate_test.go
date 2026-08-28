// SPDX-License-Identifier: Apache-2.0

package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// doc02EventTypes transcribes the `event_type` column of doc 02 §3, in document
// order. These are protected strings: the literals are written out here rather
// than referenced from the production constants, so that a change to a constant
// makes this test disagree with the document instead of travelling along with
// the code.
var doc02EventTypes = []string{
	"run_registered",
	"credential_issued",
	"tool_call",
	"commit_intent",
	"commit_recorded",
	"commit_intent_expired",
	"run_retired",
	"run_expired",
	"unattributed_signature_detected",
	"ledger_drift_detected",
	"segment_sealed",
}

// doc02TypeSpecificRequired transcribes doc 02 §3's "Extra required fields"
// column. Fields the table marks optional (`segment_sealed`'s two anchoring
// members, "opt until anchored") are not required and appear below in
// doc02TypeSpecificOptional instead.
var doc02TypeSpecificRequired = map[string][]string{
	"run_registered":                  {"agent_type", "task_ref"},
	"credential_issued":               {"audience", "credential_expiry"},
	"tool_call":                       {"tool_name"},
	"commit_intent":                   {"repo", "tree_hash"},
	"commit_recorded":                 {"commit_sha", "intent_event_id", "rekor_entry_uuid", "rekor_log_index", "repo", "tree_hash"},
	"commit_intent_expired":           {"intent_event_id"},
	"run_retired":                     {},
	"run_expired":                     {},
	"unattributed_signature_detected": {"certificate_identity", "rekor_entry_uuid", "rekor_log_index"},
	"ledger_drift_detected":           {"reason", "subject_event_id"},
	"segment_sealed":                  {"first_position", "last_position", "segment_id", "segment_merkle_root"},
}

// doc02TypeSpecificOptional is the rest of doc 02 §3's per-type membership: the
// anchoring fields a `segment_sealed` gains in its superseding update event.
var doc02TypeSpecificOptional = map[string][]string{
	"segment_sealed": {"anchor_rekor_entry_uuid", "anchor_rekor_log_index"},
}

// eventFixtures returns every golden fixture that is an event. The format probe
// is excluded: it is a serializer vector, not an event (fixtures README).
func eventFixtures(t *testing.T) []goldenFixture {
	t.Helper()

	var out []goldenFixture
	for _, name := range fixtureNames(t) {
		if strings.HasPrefix(name, "format-probe") {
			continue
		}
		out = append(out, loadFixture(t, name))
	}
	if len(out) == 0 {
		t.Fatal("no event fixtures")
	}
	return out
}

// fixtureFor returns a mutable copy of the first golden fixture carrying the
// given event_type. Starting from a committed vector means every negative case
// below differs from a known-good event in exactly the one way under test.
func fixtureFor(t *testing.T, eventType string) Fields {
	t.Helper()

	for _, f := range eventFixtures(t) {
		if et, ok := f.input[FieldEventType].(string); ok && et == eventType {
			return f.input.Clone()
		}
	}
	t.Fatalf("no golden fixture with event_type %q", eventType)
	return nil
}

// TestEventTypeEnumMatchesDoc02 pins the enum to doc 02 §3, value for value and
// in document order.
func TestEventTypeEnumMatchesDoc02(t *testing.T) {
	if got := EventTypes(); !slices.Equal(got, doc02EventTypes) {
		t.Errorf("EventTypes() = %q\nwant %q", got, doc02EventTypes)
	}
	for _, et := range doc02EventTypes {
		if !IsEventType(et) {
			t.Errorf("IsEventType(%q) = false, want true", et)
		}
		if err := ValidateEventType(et); err != nil {
			t.Errorf("ValidateEventType(%q) = %v, want nil", et, err)
		}
	}
	for _, bad := range []string{"", "Run_Registered", "run_registered ", "commit_signed", "segment_anchored"} {
		if IsEventType(bad) {
			t.Errorf("IsEventType(%q) = true, want false", bad)
		}
		if err := ValidateEventType(bad); !errors.Is(err, ErrUnknownEventType) {
			t.Errorf("ValidateEventType(%q) = %v, want %v", bad, err, ErrUnknownEventType)
		}
	}
}

// TestTypeSpecificFieldsMatchDoc02 pins each type's own membership to doc 02
// §3's table: everything in the "Extra required fields" column is required, the
// two anchoring members are allowed but not required, and nothing else exists.
func TestTypeSpecificFieldsMatchDoc02(t *testing.T) {
	envelope := EnvelopeFieldNames()

	for _, et := range doc02EventTypes {
		t.Run(et, func(t *testing.T) {
			required, err := RequiredFields(et)
			if err != nil {
				t.Fatalf("RequiredFields: %v", err)
			}
			var typeSpecific []string
			for _, name := range required {
				if !slices.Contains(envelope, name) {
					typeSpecific = append(typeSpecific, name)
				}
			}
			want := doc02TypeSpecificRequired[et]
			if len(want) == 0 && len(typeSpecific) == 0 {
				typeSpecific, want = nil, nil
			}
			if !slices.Equal(typeSpecific, want) {
				t.Errorf("type-specific required = %q\nwant %q", typeSpecific, want)
			}

			allowed, err := AllowedFields(et)
			if err != nil {
				t.Fatalf("AllowedFields: %v", err)
			}
			for _, name := range append(slices.Clone(want), doc02TypeSpecificOptional[et]...) {
				if !slices.Contains(allowed, name) {
					t.Errorf("AllowedFields(%q) omits %q", et, name)
				}
			}
			for _, name := range allowed {
				if slices.Contains(envelope, name) || name == EventHashField {
					continue
				}
				if slices.Contains(want, name) || slices.Contains(doc02TypeSpecificOptional[et], name) {
					continue
				}
				t.Errorf("AllowedFields(%q) admits %q, which doc 02 §3 does not list", et, name)
			}
		})
	}
}

// TestLED011EventSizeGuard is LED-011: "Event size guard: event type embedding a
// payload body — rejected at schema validation; only digests/references pass"
// (IP E4, doc 02 §5). E4 says events are references, never payloads; this is
// that rule made mechanical, at three layers.
func TestLED011EventSizeGuard(t *testing.T) {
	// Layer 0: what E4 permits. Every committed vector is references and
	// digests only, so every one of them validates and sits inside both the
	// 1 KB target and the 4 KB hard cap of doc 02 §5.
	t.Run("digests and references pass", func(t *testing.T) {
		for _, f := range eventFixtures(t) {
			if err := ValidateEvent(f.input); err != nil {
				t.Errorf("%s: ValidateEvent = %v, want nil", f.name, err)
				continue
			}
			n, err := CanonicalSize(f.input)
			if err != nil {
				t.Errorf("%s: CanonicalSize: %v", f.name, err)
				continue
			}
			if n != len(f.canonical) {
				t.Errorf("%s: CanonicalSize = %d, canonical fixture is %d bytes", f.name, n, len(f.canonical))
			}
			if n > MaxEventBytes {
				t.Errorf("%s: %d bytes exceeds the %d byte hard cap", f.name, n, MaxEventBytes)
			}
			if n > TargetEventBytes {
				t.Errorf("%s: %d bytes exceeds the %d byte target", f.name, n, TargetEventBytes)
			}
		}
	})

	// doc 02 §3, tool_call: "One agent tool invocation; body only as
	// payload_digest". The digest form is the one that passes.
	toolCall := fixtureFor(t, EventTypeToolCall)
	if _, ok := toolCall[FieldPayloadDigest]; !ok {
		t.Fatalf("the tool_call fixture is expected to carry %s", FieldPayloadDigest)
	}
	if err := ValidateEvent(toolCall); err != nil {
		t.Fatalf("tool_call carrying only a payload_digest: %v", err)
	}

	// Layer 1: the schema is closed, so there is nowhere to put a body. An
	// event type that embeds one is rejected at schema validation, whatever it
	// calls the member and however small the body is.
	t.Run("an embedded payload body is rejected", func(t *testing.T) {
		for _, member := range []string{"payload", "body", "content", "stdout", "diff"} {
			withBody := toolCall.Clone()
			withBody[member] = "the body the digest already refers to"
			if err := ValidateEvent(withBody); !errors.Is(err, ErrUnknownMember) {
				t.Errorf("member %q: ValidateEvent = %v, want %v", member, err, ErrUnknownMember)
			}
		}
	})

	// Layer 2: a body smuggled into a member that does exist. Every member has
	// a bound, so free text cannot become a payload channel.
	t.Run("a body smuggled into a free-text member is rejected", func(t *testing.T) {
		drift := fixtureFor(t, EventTypeLedgerDriftDetected)
		drift[FieldReason] = strings.Repeat("x", MaxTextBytes+1)
		if err := ValidateEvent(drift); !errors.Is(err, ErrValueTooLong) {
			t.Errorf("oversized %s: ValidateEvent = %v, want %v", FieldReason, err, ErrValueTooLong)
		}

		call := toolCall.Clone()
		call[FieldToolName] = strings.Repeat("x", MaxReferenceBytes+1)
		if err := ValidateEvent(call); !errors.Is(err, ErrValueTooLong) {
			t.Errorf("oversized %s: ValidateEvent = %v, want %v", FieldToolName, err, ErrValueTooLong)
		}
	})

	// Layer 3: the hard cap of doc 02 §5, enforced at append. It is the
	// backstop behind the other two, not the first line of defence.
	t.Run("the 4 KB hard cap is enforced", func(t *testing.T) {
		if MaxEventBytes != 4096 || TargetEventBytes != 1024 {
			t.Fatalf("doc 02 §5: target %d want 1024, hard cap %d want 4096",
				TargetEventBytes, MaxEventBytes)
		}
		drift := fixtureFor(t, EventTypeLedgerDriftDetected)
		drift[FieldReason] = strings.Repeat("x", MaxEventBytes)
		if err := ValidateEvent(drift); !errors.Is(err, ErrEventTooLarge) {
			t.Errorf("ValidateEvent = %v, want %v", err, ErrEventTooLarge)
		}
	})
}

// TestLED011EveryEventTypeRefusesAnEmbeddedBody is LED-011 across the whole
// enum: no event type has a seam a payload body can be poured into.
func TestLED011EveryEventTypeRefusesAnEmbeddedBody(t *testing.T) {
	for _, et := range doc02EventTypes {
		t.Run(et, func(t *testing.T) {
			f := fixtureFor(t, et)
			if err := ValidateEvent(f); err != nil {
				t.Fatalf("the unmodified fixture must validate: %v", err)
			}
			f["payload"] = "an inlined body"
			if err := ValidateEvent(f); !errors.Is(err, ErrUnknownMember) {
				t.Errorf("ValidateEvent = %v, want %v", err, ErrUnknownMember)
			}
		})
	}
}

// TestClosedSchemaRejectsUnknownMembers is doc 02 §1: unknown fields are
// rejected at append time. A member that belongs to another event type is
// unknown here, which is what makes the schema closed rather than merely
// spell-checked.
func TestClosedSchemaRejectsUnknownMembers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType string
		member    string
		value     any
	}{
		{"a member of no type at all", EventTypeRunRetired, "note", "hello"},
		{"a member of another type", EventTypeRunRetired, FieldToolName, "run_tests"},
		{"an anchoring member outside segment_sealed", EventTypeToolCall, FieldAnchorRekorLogIndex, int64(1)},
		{"a near-miss spelling", EventTypeCommitIntent, "tree-hash", "5dda8fd290f4d08d527bbe82c310a27fc0cddadb"},
		{"a future member", EventTypeSegmentSealed, "segment_size_bytes", int64(4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureFor(t, tc.eventType)
			f[tc.member] = tc.value
			if err := ValidateEvent(f); !errors.Is(err, ErrUnknownMember) {
				t.Errorf("ValidateEvent = %v, want %v", err, ErrUnknownMember)
			}
		})
	}
}

// TestVerifiersTolerateUnknownMembersOnlyForANewerSchema is the second half of
// doc 02 §1: a verifier reading history tolerates unknown fields only when the
// event's schema_version is newer than its own. At the same version it does
// not, because at the same version there is nothing an unknown field can be
// except corruption or a forgery.
func TestVerifiersTolerateUnknownMembersOnlyForANewerSchema(t *testing.T) {
	base := fixtureFor(t, EventTypeRunRegistered)

	t.Run("same version", func(t *testing.T) {
		f := base.Clone()
		f["future_member"] = "x"
		if err := ValidateEventForVerification(f); !errors.Is(err, ErrUnknownMember) {
			t.Errorf("ValidateEventForVerification = %v, want %v", err, ErrUnknownMember)
		}
	})

	t.Run("newer version", func(t *testing.T) {
		f := base.Clone()
		f[FieldSchemaVersion] = "2"
		f["future_member"] = "x"
		if err := ValidateEventForVerification(f); err != nil {
			t.Errorf("ValidateEventForVerification = %v, want nil", err)
		}
		// Appending one is still refused: this process emits version 1.
		if err := ValidateEvent(f); err == nil {
			t.Error("ValidateEvent accepted a newer schema_version at append time")
		}
	})

	t.Run("not a version at all", func(t *testing.T) {
		f := base.Clone()
		f[FieldSchemaVersion] = "1.0"
		f["future_member"] = "x"
		if err := ValidateEventForVerification(f); !errors.Is(err, ErrInvalidField) {
			t.Errorf("ValidateEventForVerification = %v, want %v", err, ErrInvalidField)
		}
	})
}

// TestValidateEventRequiresEveryRequiredMember drops each required member of
// each type in turn.
func TestValidateEventRequiresEveryRequiredMember(t *testing.T) {
	for _, et := range doc02EventTypes {
		required, err := RequiredFields(et)
		if err != nil {
			t.Fatalf("RequiredFields(%q): %v", et, err)
		}
		for _, name := range required {
			t.Run(fmt.Sprintf("%s/%s", et, name), func(t *testing.T) {
				f := fixtureFor(t, et)
				if _, ok := f[name]; !ok {
					t.Fatalf("the %s fixture does not carry required member %q", et, name)
				}
				delete(f, name)
				if err := ValidateEvent(f); !errors.Is(err, ErrMissingMember) {
					t.Errorf("ValidateEvent = %v, want %v", err, ErrMissingMember)
				}
			})
		}
	}
}

// TestValidateEventIdentifierConstraints is doc 02 §5's identifier grammar,
// applied through the validator rather than to the helpers directly.
func TestValidateEventIdentifierConstraints(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType string
		member    string
		value     any
		want      error
	}{
		{"repo host/org/name", EventTypeCommitIntent, FieldRepo, "github.com/acme/api", nil},
		{"repo with an uppercase host", EventTypeCommitIntent, FieldRepo, "GitHub.com/acme/api", ErrInvalidRepo},
		{"repo with a mixed-case org", EventTypeCommitIntent, FieldRepo, "github.com/Acme/API", nil},
		{"repo missing the host", EventTypeCommitIntent, FieldRepo, "acme/api", ErrInvalidRepo},
		{"repo with a fourth segment", EventTypeCommitIntent, FieldRepo, "github.com/acme/api/extra", ErrInvalidRepo},
		{"repo with an empty segment", EventTypeCommitIntent, FieldRepo, "github.com//api", ErrInvalidRepo},
		{"repo with a scheme", EventTypeCommitIntent, FieldRepo, "https://github.com/acme/api", ErrInvalidRepo},

		{"40-hex tree_hash", EventTypeCommitIntent, FieldTreeHash, "5dda8fd290f4d08d527bbe82c310a27fc0cddadb", nil},
		{"64-hex tree_hash", EventTypeCommitIntent, FieldTreeHash, strings.Repeat("ab", 32), nil},
		{"abbreviated tree_hash", EventTypeCommitIntent, FieldTreeHash, "5dda8fd", ErrInvalidGitObjectID},
		{"uppercase tree_hash", EventTypeCommitIntent, FieldTreeHash, strings.ToUpper("5dda8fd290f4d08d527bbe82c310a27fc0cddadb"), ErrInvalidGitObjectID},
		{"48-hex tree_hash", EventTypeCommitIntent, FieldTreeHash, strings.Repeat("ab", 24), ErrInvalidGitObjectID},
		{"prefixed commit_sha", EventTypeCommitRecorded, FieldCommitSHA, "sha256:" + strings.Repeat("ab", 32), ErrInvalidGitObjectID},

		{"spiffe_id", EventTypeToolCall, FieldSpiffeID, "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42", nil},
		{"spiffe_id with an uppercase segment", EventTypeToolCall, FieldSpiffeID, "spiffe://innsegl.dev/agent/Fix-CI/jira-118/run-42", ErrInvalidSpiffeID},
		{"spiffe_id with a segment starting in a dash", EventTypeToolCall, FieldSpiffeID, "spiffe://innsegl.dev/agent/-fix/jira-118/run-42", ErrInvalidSpiffeID},
		{"spiffe_id outside the agent subtree", EventTypeToolCall, FieldSpiffeID, "spiffe://innsegl.dev/other/fix-ci/jira-118/run-42", ErrInvalidSpiffeID},
		{"spiffe_id with a 64-character segment", EventTypeToolCall, FieldSpiffeID, "spiffe://innsegl.dev/agent/" + strings.Repeat("a", 64) + "/jira-118/run-42", ErrInvalidSpiffeID},

		{"agent_type", EventTypeRunRegistered, FieldAgentType, "fix-ci", nil},
		{"agent_type with an underscore", EventTypeRunRegistered, FieldAgentType, "fix_ci", ErrInvalidIdentifier},
		{"run_id", EventTypeRunRegistered, FieldRunID, "run-42", nil},
		{"run_id with a slash", EventTypeRunRegistered, FieldRunID, "run/42", ErrInvalidIdentifier},

		{"credential_expiry", EventTypeCredentialIssued, FieldCredentialExpiry, "2026-08-28T09:19:03.874Z", nil},
		{"credential_expiry without milliseconds", EventTypeCredentialIssued, FieldCredentialExpiry, "2026-08-28T09:19:03Z", ErrInvalidTimestamp},
		{"credential_expiry with an offset", EventTypeCredentialIssued, FieldCredentialExpiry, "2026-08-28T09:19:03.874+00:00", ErrInvalidTimestamp},

		{"intent_event_id", EventTypeCommitIntentExpired, FieldIntentEventID, "01a047a7-62f6-7ca8-b29c-ffd68aa542e3", nil},
		{"intent_event_id as a UUIDv4", EventTypeCommitIntentExpired, FieldIntentEventID, "01a047a7-62f6-4ca8-b29c-ffd68aa542e3", ErrInvalidEventID},

		{"rekor_log_index", EventTypeCommitRecorded, FieldRekorLogIndex, int64(0), nil},
		{"negative rekor_log_index", EventTypeCommitRecorded, FieldRekorLogIndex, int64(-1), ErrInvalidField},
		{"rekor_log_index as a string", EventTypeCommitRecorded, FieldRekorLogIndex, "148203377", ErrUnsupportedType},

		{"segment_merkle_root", EventTypeSegmentSealed, FieldSegmentMerkleRoot, "sha256:" + strings.Repeat("ab", 32), nil},
		{"unprefixed segment_merkle_root", EventTypeSegmentSealed, FieldSegmentMerkleRoot, strings.Repeat("ab", 32), ErrInvalidDigest},
		{"first_position below 1", EventTypeSegmentSealed, FieldFirstPosition, int64(0), ErrInvalidField},
		{"last_position before first_position", EventTypeSegmentSealed, FieldLastPosition, int64(0), ErrInvalidField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureFor(t, tc.eventType)
			f[tc.member] = tc.value
			err := ValidateEvent(f)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("ValidateEvent = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("ValidateEvent = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestValidateEventRunScope is doc 02 §2's run scope: run_id and spiffe_id are
// omitted together, and only for segment_sealed and the system-scope alerts
// that reference no run. Fixture 09 is the committed example.
func TestValidateEventRunScope(t *testing.T) {
	runless := map[string]bool{
		EventTypeSegmentSealed:                 true,
		EventTypeUnattributedSignatureDetected: true,
		EventTypeLedgerDriftDetected:           true,
	}

	for _, et := range doc02EventTypes {
		t.Run(et, func(t *testing.T) {
			f := fixtureFor(t, et)
			delete(f, FieldRunID)
			delete(f, FieldSpiffeID)
			err := ValidateEvent(f)
			if runless[et] {
				if err != nil {
					t.Errorf("ValidateEvent without a run = %v, want nil", err)
				}
			} else if !errors.Is(err, ErrMissingMember) {
				t.Errorf("ValidateEvent without a run = %v, want %v", err, ErrMissingMember)
			}
		})
	}

	t.Run("half a run scope", func(t *testing.T) {
		f := fixtureFor(t, EventTypeUnattributedSignatureDetected)
		f[FieldRunID] = "run-42"
		if err := ValidateEvent(f); !errors.Is(err, ErrInvalidField) {
			t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidField)
		}
	})
}

// TestValidateEventKeepsADR0004 holds the append-time validator to the same
// idempotency_key rule the envelope enforces, so the two cannot drift.
func TestValidateEventKeepsADR0004(t *testing.T) {
	t.Run("required where the tool takes one", func(t *testing.T) {
		f := fixtureFor(t, EventTypeRunRegistered)
		delete(f, FieldIdempotencyKey)
		if err := ValidateEvent(f); !errors.Is(err, ErrMissingMember) {
			t.Errorf("ValidateEvent = %v, want %v", err, ErrMissingMember)
		}
	})
	t.Run("forbidden where it does not", func(t *testing.T) {
		f := fixtureFor(t, EventTypeRunRetired)
		f[FieldIdempotencyKey] = "ret-9004f"
		if err := ValidateEvent(f); !errors.Is(err, ErrInvalidField) {
			t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidField)
		}
	})
	t.Run("unconstrained for a repaired commit_recorded", func(t *testing.T) {
		f := fixtureFor(t, EventTypeCommitRecorded)
		f[FieldSource] = SourceReconciler
		delete(f, FieldIdempotencyKey)
		if err := ValidateEvent(f); err != nil {
			t.Errorf("ValidateEvent = %v, want nil", err)
		}
	})
}

// TestValidateEventAnchoringFieldsArriveTogether is doc 02 §3's segment_sealed
// rule: the anchoring members are absent until Rekor confirms, and then arrive
// together in a superseding event. Fixtures 11 and 12 are the two sides of it.
func TestValidateEventAnchoringFieldsArriveTogether(t *testing.T) {
	anchored := fixtureFor(t, EventTypeSegmentSealed)
	for _, name := range []string{FieldAnchorRekorLogIndex, FieldAnchorRekorEntryUUID} {
		t.Run("only "+name, func(t *testing.T) {
			f := anchored.Clone()
			delete(f, FieldAnchorRekorLogIndex)
			delete(f, FieldAnchorRekorEntryUUID)
			switch name {
			case FieldAnchorRekorLogIndex:
				f[name] = int64(148204190)
			default:
				f[name] = strings.Repeat("ab", 32)
			}
			if err := ValidateEvent(f); !errors.Is(err, ErrInvalidField) {
				t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidField)
			}
		})
	}
}

// TestValidateEventRejectsTheFormatProbe guards the one committed vector that
// is deliberately not an event: it has no envelope at all, and a validator that
// accepted it would be accepting arbitrary objects.
func TestValidateEventRejectsTheFormatProbe(t *testing.T) {
	probe := loadFixture(t, "format-probe")
	if err := ValidateEvent(probe.input); err == nil {
		t.Fatal("ValidateEvent accepted the format probe, which is not an event")
	}
}

// TestValidateEventAcceptsAFinalizedEvent: event_hash is a legal member of a
// stored event, and its presence does not change the event's measured size —
// what an event weighs cannot depend on whether it has been hashed yet.
func TestValidateEventAcceptsAFinalizedEvent(t *testing.T) {
	f := fixtureFor(t, EventTypeRunRegistered)
	before, err := CanonicalSize(f)
	if err != nil {
		t.Fatalf("CanonicalSize: %v", err)
	}
	final, err := f.Finalize()
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if verr := ValidateEvent(final); verr != nil {
		t.Fatalf("ValidateEvent on a finalized event: %v", verr)
	}
	after, err := CanonicalSize(final)
	if err != nil {
		t.Fatalf("CanonicalSize: %v", err)
	}
	if before != after {
		t.Errorf("CanonicalSize changed on finalize: %d then %d", before, after)
	}

	final[EventHashField] = "not-a-digest"
	if err := ValidateEvent(final); !errors.Is(err, ErrInvalidDigest) {
		t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidDigest)
	}
}

// TestValidateEventAcceptsEveryIntegerSpelling: Fields admits every integer
// type canonical.go lists, so the schema validator has to read every one of
// them. A record built by hand must be validated exactly as one decoded by
// ParseFields or rendered from an Envelope.
func TestValidateEventAcceptsEveryIntegerSpelling(t *testing.T) {
	for _, v := range []any{
		int(1), int8(1), int16(1), int32(1), int64(1),
		uint(1), uint8(1), uint16(1), uint32(1), uint64(1),
		json.Number("1"),
	} {
		f := fixtureFor(t, EventTypeRunRegistered)
		f[FieldChainPosition] = v
		if err := ValidateEvent(f); err != nil {
			t.Errorf("chain_position as %T: ValidateEvent = %v, want nil", v, err)
		}
	}
}

// TestToInteger covers the reads the schema validator makes of a number,
// including the ones no valid record can reach.
func TestToInteger(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want int64
		ok   bool
	}{
		{int(7), 7, true},
		{int8(7), 7, true},
		{int16(7), 7, true},
		{int32(7), 7, true},
		{int64(7), 7, true},
		{uint(7), 7, true},
		{uint8(7), 7, true},
		{uint16(7), 7, true},
		{uint32(7), 7, true},
		{uint64(7), 7, true},
		{json.Number("7"), 7, true},
		{uint(1) << 62, 0, false},
		{uint64(1) << 62, 0, false},
		{json.Number("7.5"), 0, false},
		{json.Number("1e3"), 0, false},
		{json.Number("banana"), 0, false},
		{"7", 0, false},
		{true, 0, false},
	} {
		got, ok := toInteger(tc.v)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("toInteger(%#v) = %d, %v; want %d, %v", tc.v, got, ok, tc.want, tc.ok)
		}
	}
}

// TestUnknownEventTypeHasNoSchema: the type table is the only source of an
// event's member set, so a type outside the enum has no member set at all.
func TestUnknownEventTypeHasNoSchema(t *testing.T) {
	if _, err := RequiredFields("commit_signed"); !errors.Is(err, ErrUnknownEventType) {
		t.Errorf("RequiredFields = %v, want %v", err, ErrUnknownEventType)
	}
	if _, err := AllowedFields("commit_signed"); !errors.Is(err, ErrUnknownEventType) {
		t.Errorf("AllowedFields = %v, want %v", err, ErrUnknownEventType)
	}
	f := fixtureFor(t, EventTypeRunRegistered)
	f[FieldEventType] = "commit_signed"
	if err := ValidateEvent(f); !errors.Is(err, ErrUnknownEventType) {
		t.Errorf("ValidateEvent = %v, want %v", err, ErrUnknownEventType)
	}
}

// TestCanonicalSizeRejectsAnUnserializableRecord: a size that cannot be
// measured is not reported as zero.
func TestCanonicalSizeRejectsAnUnserializableRecord(t *testing.T) {
	if n, err := CanonicalSize(Fields{"a": nil}); err == nil {
		t.Errorf("CanonicalSize = %d, nil; want an error", n)
	}
}

// TestValidateEventRejectsNonStringEnvelopeMembers: schema_version and
// event_type steer everything else, so they are read before anything trusts
// them to be strings.
func TestValidateEventRejectsNonStringEnvelopeMembers(t *testing.T) {
	for _, name := range []string{FieldSchemaVersion, FieldEventType} {
		t.Run(name, func(t *testing.T) {
			f := fixtureFor(t, EventTypeRunRegistered)
			f[name] = int64(1)
			if err := ValidateEvent(f); !errors.Is(err, ErrUnsupportedType) {
				t.Errorf("ValidateEvent = %v, want %v", err, ErrUnsupportedType)
			}
			delete(f, name)
			if err := ValidateEvent(f); !errors.Is(err, ErrMissingMember) {
				t.Errorf("ValidateEvent without %s = %v, want %v", name, err, ErrMissingMember)
			}
		})
	}
}

// TestParseSchemaVersion: doc 02 §7 versions are major numbers. "1.0", "01"
// and "v1" are not other spellings of 1; they are not versions.
func TestParseSchemaVersion(t *testing.T) {
	if n, err := parseSchemaVersion("2"); err != nil || n != 2 {
		t.Errorf(`parseSchemaVersion("2") = %d, %v; want 2, nil`, n, err)
	}
	for _, s := range []string{"", "0", "-1", "01", "1.0", "v1", " 1", "1 ", "one"} {
		if _, err := parseSchemaVersion(s); !errors.Is(err, ErrInvalidField) {
			t.Errorf("parseSchemaVersion(%q) = %v, want %v", s, err, ErrInvalidField)
		}
	}
}

// TestCheckBoundedString covers the shape every string member shares, including
// the states a well-formed record cannot reach but a direct caller can.
func TestCheckBoundedString(t *testing.T) {
	if _, err := checkBoundedString("m", int64(1), 8); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("non-string: %v, want %v", err, ErrUnsupportedType)
	}
	if _, err := checkBoundedString("m", "", 8); !errors.Is(err, ErrEmptyValue) {
		t.Errorf("empty: %v, want %v", err, ErrEmptyValue)
	}
	if _, err := checkBoundedString("m", "123456789", 8); !errors.Is(err, ErrValueTooLong) {
		t.Errorf("over the bound: %v, want %v", err, ErrValueTooLong)
	}
	if s, err := checkBoundedString("m", "12345678", 8); err != nil || s != "12345678" {
		t.Errorf("at the bound: %q, %v", s, err)
	}
	// The bound is bytes, not characters — doc 04 residual risk #4, the same
	// reading ADR-0004 fixes for idempotency_key.
	if _, err := checkBoundedString("m", strings.Repeat("\U0001d11e", 3), 8); !errors.Is(err, ErrValueTooLong) {
		t.Errorf("three astral runes in a bound of 8 bytes: %v, want %v", err, ErrValueTooLong)
	}
}

// TestValidateRepo is doc 02 §5's repo grammar, exercised directly.
func TestValidateRepo(t *testing.T) {
	for _, s := range []string{
		"github.com/acme/api",
		"github.com/Acme/API",
		"git.internal/team/repo.git",
		"localhost/org/name",
		"gitlab.example.co.uk/group/sub-project_1",
	} {
		if err := ValidateRepo(s); err != nil {
			t.Errorf("ValidateRepo(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{
		"", "acme/api", "github.com/acme", "github.com/acme/api/extra",
		"github.com//api", "github.com/acme/", "/acme/api",
		"GitHub.com/acme/api", "github.com:443/acme/api", "-github.com/acme/api",
		"github..com/acme/api", "https://github.com/acme/api",
		"github.com/.acme/api", "github.com/acme/..",
	} {
		if err := ValidateRepo(s); !errors.Is(err, ErrInvalidRepo) {
			t.Errorf("ValidateRepo(%q) = %v, want %v", s, err, ErrInvalidRepo)
		}
	}
}

// TestValidateGitObjectID is doc 02 §5: full 40-hex or 64-hex, never
// abbreviated.
func TestValidateGitObjectID(t *testing.T) {
	for _, s := range []string{strings.Repeat("a", 40), strings.Repeat("0", 64)} {
		if err := ValidateGitObjectID(s); err != nil {
			t.Errorf("ValidateGitObjectID(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{
		"", "abc1234", strings.Repeat("a", 39), strings.Repeat("a", 41),
		strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("A", 40), "sha256:" + strings.Repeat("a", 64),
		strings.Repeat("g", 40),
	} {
		if err := ValidateGitObjectID(s); !errors.Is(err, ErrInvalidGitObjectID) {
			t.Errorf("ValidateGitObjectID(%q) = %v, want %v", s, err, ErrInvalidGitObjectID)
		}
	}
}

// TestValidateEventForVerificationAcceptsTheCurrentVersion: the verifier path
// is the append path plus one tolerance, and nothing else.
func TestValidateEventForVerificationAcceptsTheCurrentVersion(t *testing.T) {
	for _, f := range eventFixtures(t) {
		if err := ValidateEventForVerification(f.input); err != nil {
			t.Errorf("%s: ValidateEventForVerification = %v, want nil", f.name, err)
		}
	}
}

// TestMemberChecks exercises each member constraint directly. Several of them
// are unreachable through ValidateEvent — a bad event_type is caught by the
// type lookup before the member loop runs, and Fields.Validate strips empty
// strings before either — but the constraint is what the table in types.go
// promises, so it is proved here rather than assumed.
func TestMemberChecks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(string, any) error
		good  any
		bad   any
		want  error
	}{
		{"identifier", checkIdentifier, "run-42", "Run-42", ErrInvalidIdentifier},
		{"spiffe_id", checkSPIFFEIDValue, "spiffe://innsegl.dev/agent/a/b/c", "spiffe://innsegl.dev/agent/a/b", ErrInvalidSpiffeID},
		{"digest", checkDigestValue, GenesisPrevEventHash(), "sha1:abc", ErrInvalidDigest},
		{"event_id", checkEventIDValue, "01a047a5-cc41-7c45-86fd-a88c8c2b5320", "not-a-uuid", ErrInvalidEventID},
		{"timestamp", checkTimestampValue, "2026-08-28T09:14:03.201Z", "2026-08-28", ErrInvalidTimestamp},
		{"source", checkSourceValue, SourceMCP, "operator", ErrInvalidSource},
		{"event_type", checkEventTypeValue, EventTypeRunRetired, "commit_signed", ErrUnknownEventType},
		{"idempotency_key", checkIdempotencyKeyValue, "reg-8f21c", strings.Repeat("k", MaxIdempotencyKeyBytes+1), ErrValueTooLong},
		{"repo", checkRepo, "github.com/acme/api", "acme/api", ErrInvalidRepo},
		{"git object id", checkGitObjectID, strings.Repeat("a", 40), "abc1234", ErrInvalidGitObjectID},
		{"reference", checkReference, "sigstore", strings.Repeat("r", MaxReferenceBytes+1), ErrValueTooLong},
		{"text", checkText, "a reason", strings.Repeat("t", MaxTextBytes+1), ErrValueTooLong},
		{"log index", checkLogIndex, int64(0), int64(-1), ErrInvalidField},
		{"chain position", checkChainPositionValue, int64(1), int64(0), ErrInvalidField},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check("m", tc.good); err != nil {
				t.Errorf("check(%v) = %v, want nil", tc.good, err)
			}
			if err := tc.check("m", tc.bad); !errors.Is(err, tc.want) {
				t.Errorf("check(%v) = %v, want %v", tc.bad, err, tc.want)
			}
			// Every member is read out of a decoded record, so every check has
			// to survive a value of the wrong Go type.
			if err := tc.check("m", true); !errors.Is(err, ErrUnsupportedType) {
				t.Errorf("check(true) = %v, want %v", err, ErrUnsupportedType)
			}
		})
	}
}

// TestSchemaVersionConstantsAgree keeps the numeric schema version and the
// string one from drifting apart, the way the SER-005 gate keeps
// SerializerVersion and SchemaVersion together.
func TestSchemaVersionConstantsAgree(t *testing.T) {
	if got := strconv.Itoa(currentSchemaVersion); got != SchemaVersion {
		t.Fatalf("currentSchemaVersion renders as %q, SchemaVersion is %q", got, SchemaVersion)
	}
}

// TestValidateEventRejectsValuesOutsideTheCanonicalDomain: the value domain of
// canonical.go is checked before anything structural, because a member that
// cannot be canonicalized cannot be measured, hashed or stored.
func TestValidateEventRejectsValuesOutsideTheCanonicalDomain(t *testing.T) {
	f := fixtureFor(t, EventTypeRunRegistered)
	f[FieldTaskRef] = nil
	if err := ValidateEvent(f); !errors.Is(err, ErrNilValue) {
		t.Errorf("ValidateEvent = %v, want %v", err, ErrNilValue)
	}
}

// TestValidateEventNeedsAFrozenFormat: an event cannot be admitted by a
// serializer whose format is not frozen, because its size — and then its hash —
// would be whatever today's build happens to emit.
func TestValidateEventNeedsAFrozenFormat(t *testing.T) {
	f := fixtureFor(t, EventTypeRunRegistered)
	withoutCurrentSpec(t, func() {
		if err := ValidateEvent(f); !errors.Is(err, ErrUnregisteredSerializer) {
			t.Errorf("ValidateEvent = %v, want %v", err, ErrUnregisteredSerializer)
		}
	})
}

// TestValidateEventSegmentRangeRunsForwards: a sealed segment covers positions
// first..last, so last cannot precede first.
func TestValidateEventSegmentRangeRunsForwards(t *testing.T) {
	f := fixtureFor(t, EventTypeSegmentSealed)
	f[FieldFirstPosition] = int64(5)
	f[FieldLastPosition] = int64(1)
	if err := ValidateEvent(f); !errors.Is(err, ErrInvalidField) {
		t.Errorf("ValidateEvent = %v, want %v", err, ErrInvalidField)
	}
	f[FieldLastPosition] = int64(5)
	if err := ValidateEvent(f); err != nil {
		t.Errorf("a single-position segment: ValidateEvent = %v, want nil", err)
	}
}

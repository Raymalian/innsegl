// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// ip4Classes is the error-class vocabulary transcribed from IP §4, in the
// order IP §4 lists it, with the retryability each class carries.
//
// This literal table is the specification, not a mirror of the production
// table: it is written out by hand here so that a change to the production
// vocabulary shows up as a diff against IP §4 rather than agreeing with
// itself. RM-013's protected-surfaces gate holds the same eleven spellings.
//
// Where IP states retryability verbatim it is quoted below. Where it does not,
// the value follows ADR-0016: a class is retryable exactly when it names a
// dependency outage — a condition outside the request that may clear on its
// own. Everything else describes the request or durable state, which retrying
// cannot change.
var ip4Classes = []struct {
	class     Class
	retryable bool
	why       string
}{
	{ClassAttestationFailed, false, `IP §6.1 verbatim: "ATTESTATION_FAILED, not retryable"`},
	{ClassIdentityUnavailable, true, `IP §6.1 verbatim: "IDENTITY_UNAVAILABLE, retryable"`},
	{ClassCredentialExpired, false, "ADR-0016: a dead credential is a property of the request; IP §6.2 forbids extending TTLs to help"},
	{ClassAudienceMismatch, false, "ADR-0016: the allowlist does not change between two identical calls"},
	{ClassLedgerUnavailable, true, "ADR-0016: IP §6.4 Postgres down is a dependency outage"},
	{ClassSigningUnavailable, true, `IP §6.3 verbatim: "Fulcio down → SIGNING_UNAVAILABLE, retryable"`},
	{ClassTransparencyUnavailable, true, "ADR-0016: IP §6.3 Rekor down is the same shape as Fulcio down"},
	{ClassRunNotFound, false, "ADR-0016: an absent run does not appear by being asked for twice"},
	{ClassRunAlreadyRetired, false, "ADR-0016: IP §6.2 retirement is immediate and terminal"},
	{ClassDuplicateRequest, false, "ADR-0016: the second answer to a duplicate is the same duplicate"},
	{ClassInvariantViolation, false, "ADR-0016: IP §6.2 alert-level; a retry repeats the violation"},
}

// TestIP4ClassVocabularyIsExactlyTheEleven pins the spelling and the order.
// The vocabulary is a protected surface (doc 08 §3, VERSIONING.md surface 4).
func TestIP4ClassVocabularyIsExactlyTheEleven(t *testing.T) {
	want := []string{
		"ATTESTATION_FAILED",
		"IDENTITY_UNAVAILABLE",
		"CREDENTIAL_EXPIRED",
		"AUDIENCE_MISMATCH",
		"LEDGER_UNAVAILABLE",
		"SIGNING_UNAVAILABLE",
		"TRANSPARENCY_UNAVAILABLE",
		"RUN_NOT_FOUND",
		"RUN_ALREADY_RETIRED",
		"DUPLICATE_REQUEST",
		"INVARIANT_VIOLATION",
	}
	got := Classes()
	if len(got) != len(want) {
		t.Fatalf("Classes() has %d members, IP §4 lists %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("Classes()[%d] = %q, IP §4 says %q", i, got[i], want[i])
		}
	}
	if len(ip4Classes) != len(want) {
		t.Fatalf("this test's own table has %d rows, IP §4 lists %d", len(ip4Classes), len(want))
	}
	for i, row := range ip4Classes {
		if string(row.class) != want[i] {
			t.Errorf("this test's table row %d is %q, IP §4 says %q", i, row.class, want[i])
		}
	}
}

// TestIP4RetryabilityPerClass asserts the flag each class carries, one
// assertion per class, against the literal table above.
func TestIP4RetryabilityPerClass(t *testing.T) {
	for _, row := range ip4Classes {
		t.Run(string(row.class), func(t *testing.T) {
			if got := row.class.Retryable(); got != row.retryable {
				t.Errorf("Class(%s).Retryable() = %v, want %v — %s",
					row.class, got, row.retryable, row.why)
			}
		})
	}
}

// TestClassValidRejectsAnythingOutsideTheVocabulary keeps an invented class
// from ever reaching the wire.
func TestClassValidRejectsAnythingOutsideTheVocabulary(t *testing.T) {
	for _, row := range ip4Classes {
		if !row.class.Valid() {
			t.Errorf("Class(%s).Valid() = false; it is one of the eleven", row.class)
		}
	}
	for _, bad := range []Class{"", "attestation_failed", "ATTESTATION FAILED", "INTERNAL", "LEDGER_UNAVAILABLE "} {
		if bad.Valid() {
			t.Errorf("Class(%q).Valid() = true; it is not one of the eleven", string(bad))
		}
	}
}

// wireKeys returns the JSON object keys of b, in the order they appear.
func wireKeys(t *testing.T, b []byte) []string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(string(b)))
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("decoding %s: %v", b, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		t.Fatalf("wire error is not a JSON object: %s", b)
	}
	var keys []string
	depth := 0
	for dec.More() || depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("decoding %s: %v", b, err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth < 0 {
					return keys
				}
			}
			continue
		}
		if depth == 0 {
			if s, ok := tok.(string); ok {
				keys = append(keys, s)
				// Skip the value.
				if _, err := dec.Token(); err != nil {
					t.Fatalf("decoding %s: %v", b, err)
				}
			}
		}
	}
	return keys
}

// TestIP4WireShapeIsExactlyTheFourFields is the shape contract of IP §4:
// {error_class, message, retryable, run_id?}. Nothing else may appear — a
// fifth field is how a credential or a token leaks to a caller (IP §1, E8).
func TestIP4WireShapeIsExactlyTheFourFields(t *testing.T) {
	withRun := Errorf(ClassRunAlreadyRetired, "run-abc", "run is retired")
	b, err := json.Marshal(withRun)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if got, want := wireKeys(t, b), []string{"error_class", "message", "retryable", "run_id"}; !equalStrings(got, want) {
		t.Errorf("wire keys = %v, IP §4 says %v (%s)", got, want, b)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshalling %s: %v", b, err)
	}
	if decoded["error_class"] != "RUN_ALREADY_RETIRED" {
		t.Errorf("error_class = %v, want RUN_ALREADY_RETIRED (%s)", decoded["error_class"], b)
	}
	if decoded["message"] != "run is retired" {
		t.Errorf("message = %v, want %q (%s)", decoded["message"], "run is retired", b)
	}
	if decoded["retryable"] != false {
		t.Errorf("retryable = %v, want false (%s)", decoded["retryable"], b)
	}
	if decoded["run_id"] != "run-abc" {
		t.Errorf("run_id = %v, want run-abc (%s)", decoded["run_id"], b)
	}
}

// TestIP4WireOmitsAbsentRunIDNeverEmptyString is doc 02 §1's absent-vs-empty
// rule applied to the wire: a failure not scoped to a run carries no `run_id`
// key at all, rather than a key whose value is "".
func TestIP4WireOmitsAbsentRunIDNeverEmptyString(t *testing.T) {
	b, err := json.Marshal(Errorf(ClassLedgerUnavailable, "", "postgres is unreachable"))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if got, want := wireKeys(t, b), []string{"error_class", "message", "retryable"}; !equalStrings(got, want) {
		t.Errorf("wire keys = %v, want %v — run_id must be absent, not empty (%s)", got, want, b)
	}
	if strings.Contains(string(b), "run_id") {
		t.Errorf("wire carries a run_id key with no run: %s", b)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshalling %s: %v", b, err)
	}
	if _, present := decoded["run_id"]; present {
		t.Errorf("run_id present with no run: %s", b)
	}
	if decoded["retryable"] != true {
		t.Errorf("retryable = %v, want true for LEDGER_UNAVAILABLE (%s)", decoded["retryable"], b)
	}
}

// TestErrorfDefaultsRetryableFromTheClass: a tool never chooses retryability;
// it chooses a class, and the class carries the flag.
func TestErrorfDefaultsRetryableFromTheClass(t *testing.T) {
	for _, row := range ip4Classes {
		e := Errorf(row.class, "run-1", "boom")
		if e.Retryable != row.retryable {
			t.Errorf("Errorf(%s).Retryable = %v, want %v", row.class, e.Retryable, row.retryable)
		}
		if e.Class != row.class {
			t.Errorf("Errorf(%s).Class = %s", row.class, e.Class)
		}
		if e.RunID != "run-1" {
			t.Errorf("Errorf(%s).RunID = %q, want run-1", row.class, e.RunID)
		}
	}
}

// TestErrorfWrapsWithPercentW keeps errors.Is/As working through the taxonomy.
func TestErrorfWrapsWithPercentW(t *testing.T) {
	sentinel := errors.New("underlying cause")
	e := Errorf(ClassLedgerUnavailable, "run-1", "append failed: %w", sentinel)
	if !errors.Is(e, sentinel) {
		t.Errorf("errors.Is(e, sentinel) = false; the cause chain was dropped")
	}
	if e.Message != "append failed: underlying cause" {
		t.Errorf("Message = %q", e.Message)
	}
	if !errors.Is(e.Unwrap(), sentinel) {
		t.Errorf("Unwrap() = %v, want the sentinel", e.Unwrap())
	}
	plain := Errorf(ClassRunNotFound, "", "no such run")
	if plain.Unwrap() != nil {
		t.Errorf("Unwrap() = %v with no %%w, want nil", plain.Unwrap())
	}
}

// TestErrorStringNamesClassRunAndRetryability keeps the log line useful.
func TestErrorStringNamesClassRunAndRetryability(t *testing.T) {
	s := Errorf(ClassIdentityUnavailable, "run-9", "spire-server is down").Error()
	for _, want := range []string{"IDENTITY_UNAVAILABLE", "run-9", "spire-server is down", "retryable"} {
		if !strings.Contains(s, want) {
			t.Errorf("Error() = %q, missing %q", s, want)
		}
	}
	s2 := Errorf(ClassAttestationFailed, "", "selector mismatch").Error()
	if !strings.Contains(s2, "not retryable") {
		t.Errorf("Error() = %q, want it to say the failure is not retryable", s2)
	}
	if strings.Contains(s2, "[run ") {
		t.Errorf("Error() = %q, want no run marker when there is no run", s2)
	}
	bare := (&Error{Class: ClassDuplicateRequest}).Error()
	if bare != "DUPLICATE_REQUEST (not retryable)" {
		t.Errorf("Error() with no message or run = %q, want %q", bare, "DUPLICATE_REQUEST (not retryable)")
	}
}

// TestClassifyReturnsTheErrorItAlreadyIs.
func TestClassifyReturnsTheErrorItAlreadyIs(t *testing.T) {
	e := Errorf(ClassAudienceMismatch, "run-2", "audience %q is not allowlisted", "github")
	if got := Classify(e); got != e {
		t.Errorf("Classify(*Error) = %v, want the same value back", got)
	}
	wrapped := fmt.Errorf("record_event: %w", e)
	if got := Classify(wrapped); got != e {
		t.Errorf("Classify(wrapped) = %v, want the wrapped *Error", got)
	}
	if Classify(nil) != nil {
		t.Errorf("Classify(nil) = %v, want nil", Classify(nil))
	}
}

// TestClassifyUnclassifiedFailsClosedAsInvariantViolation. IP §4 has no
// "internal error" class. A failure this package cannot name is a defect, and
// a defect is alert-level, not a retryable hiccup.
func TestClassifyUnclassifiedFailsClosedAsInvariantViolation(t *testing.T) {
	got := Classify(errors.New("something nobody classified"))
	if got.Class != ClassInvariantViolation {
		t.Errorf("Classify(plain).Class = %s, want INVARIANT_VIOLATION", got.Class)
	}
	if got.Retryable {
		t.Errorf("Classify(plain).Retryable = true, want false")
	}
	if !strings.Contains(got.Message, "something nobody classified") {
		t.Errorf("Classify(plain).Message = %q, want it to carry the cause", got.Message)
	}
}

// spireInterop is every class internal/spire can produce (RM-015), with the
// class this package must map it to. The two schemes are one vocabulary; a
// second, incompatible one would make the wire depend on which layer failed.
var spireInterop = []struct {
	from spire.Class
	to   Class
}{
	{spire.ClassAttestationFailed, ClassAttestationFailed},
	{spire.ClassIdentityUnavailable, ClassIdentityUnavailable},
	{spire.ClassInvariantViolation, ClassInvariantViolation},
	{spire.ClassRunNotFound, ClassRunNotFound},
	{spire.ClassDuplicateRequest, ClassDuplicateRequest},
}

// TestClassifyMapsEverySPIREClass.
func TestClassifyMapsEverySPIREClass(t *testing.T) {
	for _, row := range spireInterop {
		t.Run(string(row.from), func(t *testing.T) {
			se := &spire.Error{
				Class:     row.from,
				Op:        "register_agent",
				Message:   "from spire",
				Retryable: row.to.Retryable(),
				RunID:     "run-7",
			}
			got := Classify(fmt.Errorf("register_agent: %w", se))
			if got.Class != row.to {
				t.Errorf("Classify(spire %s).Class = %s, want %s", row.from, got.Class, row.to)
			}
			if got.RunID != "run-7" {
				t.Errorf("Classify(spire %s).RunID = %q, want run-7", row.from, got.RunID)
			}
			if got.Retryable != row.to.Retryable() {
				t.Errorf("Classify(spire %s).Retryable = %v, want %v", row.from, got.Retryable, row.to.Retryable())
			}
			if !errors.Is(got, se) {
				t.Errorf("Classify(spire %s) dropped the spire error from the chain", row.from)
			}
			if !strings.Contains(got.Message, "from spire") {
				t.Errorf("Classify(spire %s).Message = %q, want the spire message", row.from, got.Message)
			}
		})
	}
}

// TestClassifyCarriesTheLedgersOwnClassification (RM-067, #87): a raw,
// unwrapped *ledger.StoreError that reaches Classify — never funnelled
// through register_agent.go's or runs.go's own carrying helper first — is
// classified from the field internal/ledger already measured, not defaulted
// to INVARIANT_VIOLATION. *ledger.StoreError cannot implement Classified
// (ErrorClass's signature names this package's own Class type, and
// internal/ledger importing internal/mcp back would cycle), so Classify names
// the type explicitly, the same move it already makes for *spire.Error.
func TestClassifyCarriesTheLedgersOwnClassification(t *testing.T) {
	cases := []struct {
		name          string
		storeErr      *ledger.StoreError
		wantClass     Class
		wantRetryable bool
	}{
		{
			"a dependency outage carries across retryable",
			&ledger.StoreError{Class: string(ClassLedgerUnavailable), Op: "head", Retryable: true, Err: errors.New("connection exception")},
			ClassLedgerUnavailable, true,
		},
		{
			"a schema refusal carries across not retryable",
			&ledger.StoreError{Class: string(ClassInvariantViolation), Op: "append", Retryable: false, Err: errors.New("chain link refused")},
			ClassInvariantViolation, false,
		},
		{
			"the ledger's own narrowing is honoured, never widened",
			&ledger.StoreError{Class: string(ClassLedgerUnavailable), Op: "append", Retryable: false, Err: errors.New("syntax error")},
			ClassLedgerUnavailable, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(fmt.Errorf("wrapped: %w", tc.storeErr))
			if got.Class != tc.wantClass {
				t.Errorf("Classify(%v).Class = %s, want %s", tc.storeErr, got.Class, tc.wantClass)
			}
			if got.Retryable != tc.wantRetryable {
				t.Errorf("Classify(%v).Retryable = %v, want %v", tc.storeErr, got.Retryable, tc.wantRetryable)
			}
			if got.RunID != "" {
				t.Errorf("Classify(%v).RunID = %q, want empty: *ledger.StoreError carries no run_id of its own", tc.storeErr, got.RunID)
			}
			if !errors.Is(got, tc.storeErr) {
				t.Errorf("Classify(%v) dropped the ledger error from the chain", tc.storeErr)
			}
		})
	}
}

// TestClassifyNarrowsRetryableAndNeverWidensIt. internal/spire deliberately
// carries retryability as a field rather than deriving it: IP §6.1 makes
// IDENTITY_UNAVAILABLE retryable when SPIRE is unreachable and not retryable
// when SPIRE answered something the client cannot act on. A lower layer that
// knows better may narrow the class default from true to false. It may never
// widen it, or a caller would be told to retry a refusal.
func TestClassifyNarrowsRetryableAndNeverWidensIt(t *testing.T) {
	narrowed := Classify(&spire.Error{
		Class:     spire.ClassIdentityUnavailable,
		Message:   "spire answered something this client cannot act on",
		Retryable: false,
	})
	if narrowed.Class != ClassIdentityUnavailable {
		t.Fatalf("class = %s", narrowed.Class)
	}
	if narrowed.Retryable {
		t.Errorf("Retryable = true; internal/spire said false and narrowing must be honoured")
	}

	widened := Classify(&spire.Error{
		Class:     spire.ClassAttestationFailed,
		Message:   "a lower layer claiming a refusal is retryable",
		Retryable: true,
	})
	if widened.Retryable {
		t.Errorf("Retryable = true for ATTESTATION_FAILED; IP §6.1 says not retryable and no layer may widen it")
	}
}

// classifiedProbe is a failure carrier outside this package's own *Error that
// names its class, the way RM-021's idempotency store and the five tools do.
type classifiedProbe struct {
	class     Class
	runID     string
	retryable bool
}

func (p classifiedProbe) Error() string { return "probe: " + string(p.class) }

func (p classifiedProbe) ErrorClass() (Class, string, bool) { return p.class, p.runID, p.retryable }

// TestClassifyHonoursAClassifiedError proves the extension point: a carrier
// that is not *Error and is not *spire.Error reaches the wire through the one
// taxonomy, under its own class, with retryability narrowed the same way.
func TestClassifyHonoursAClassifiedError(t *testing.T) {
	for _, row := range ip4Classes {
		t.Run(string(row.class), func(t *testing.T) {
			got := Classify(fmt.Errorf("record_event: %w",
				classifiedProbe{class: row.class, runID: "run-8", retryable: true}))
			if got.Class != row.class {
				t.Errorf("Class = %s, want %s", got.Class, row.class)
			}
			if got.Retryable != row.retryable {
				t.Errorf("Retryable = %v, want %v — a Classified error may not widen the class default",
					got.Retryable, row.retryable)
			}
			if got.RunID != "run-8" {
				t.Errorf("RunID = %q, want run-8", got.RunID)
			}
		})
	}
	narrowed := Classify(classifiedProbe{class: ClassLedgerUnavailable, retryable: false})
	if narrowed.Retryable {
		t.Errorf("Retryable = true; a Classified error that narrows to false must be honoured")
	}
	unknown := Classify(classifiedProbe{class: "NOT_A_CLASS", runID: "run-8", retryable: true})
	if unknown.Class != ClassInvariantViolation || unknown.Retryable {
		t.Errorf("Classify(unknown Classified class) = %s retryable=%v, want INVARIANT_VIOLATION not retryable",
			unknown.Class, unknown.Retryable)
	}
	if !strings.Contains(unknown.Message, "NOT_A_CLASS") {
		t.Errorf("Message = %q, want it to name the rejected class", unknown.Message)
	}
}

// TestClassifyUnknownSPIREClassFailsClosed: a class this package does not know
// is not passed through to the wire under an invented name.
func TestClassifyUnknownSPIREClassFailsClosed(t *testing.T) {
	got := Classify(&spire.Error{Class: "SOMETHING_NEW", Message: "unknown", RunID: "run-3", Retryable: true})
	if got.Class != ClassInvariantViolation {
		t.Errorf("Class = %s, want INVARIANT_VIOLATION", got.Class)
	}
	if got.Retryable {
		t.Errorf("Retryable = true, want false")
	}
	if got.RunID != "run-3" {
		t.Errorf("RunID = %q, want run-3", got.RunID)
	}
}

// TestMarshalCoercesAnInventedClassToInvariantViolation. The vocabulary is
// closed (doc 08 §3). A value outside it must never appear as an error_class
// on the wire, whatever a caller constructed by hand.
func TestMarshalCoercesAnInventedClassToInvariantViolation(t *testing.T) {
	b, err := json.Marshal(&Error{Class: "TEAPOT", Message: "invented", Retryable: true, RunID: "run-4"})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshalling %s: %v", b, err)
	}
	if decoded["error_class"] != "INVARIANT_VIOLATION" {
		t.Errorf("error_class = %v, want INVARIANT_VIOLATION (%s)", decoded["error_class"], b)
	}
	if decoded["retryable"] != false {
		t.Errorf("retryable = %v, want false (%s)", decoded["retryable"], b)
	}
	coerced, ok := decoded["message"].(string)
	if !ok {
		t.Fatalf("message is %T, want a string (%s)", decoded["message"], b)
	}
	if !strings.Contains(coerced, "TEAPOT") {
		t.Errorf("message = %v, want it to name the rejected class (%s)", decoded["message"], b)
	}
}

// TestMarshalNeverEmitsAnEmptyMessage keeps an operator from receiving an
// error whose only content is a class.
func TestMarshalNeverEmitsAnEmptyMessage(t *testing.T) {
	b, err := json.Marshal(&Error{Class: ClassSigningUnavailable, Retryable: true})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshalling %s: %v", b, err)
	}
	if decoded["message"] == "" || decoded["message"] == nil {
		t.Errorf("message is empty: %s", b)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

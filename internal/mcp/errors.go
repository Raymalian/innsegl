// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"innsegl.dev/innsegl/internal/spire"
)

// Class is one member of the error-class vocabulary of IP §4.
//
// The string values are a PROTECTED SURFACE (VERSIONING.md surface 4,
// doc 08 §3): they are the `error_class` an agent reads off the wire, they are
// enumerated in scripts/protected-surfaces.sh, and they change only in a major
// release with a migration attestation.
//
// internal/spire.Class carries the same spellings for the subset a SPIRE
// client can produce. That is one vocabulary in two packages, not two schemes:
// Classify maps a *spire.Error across by string identity, so a class renamed
// in either place fails the mapping rather than inventing a new name.
type Class string

// The eleven classes of IP §4, in the order IP §4 lists them.
const (
	// ClassAttestationFailed: SPIRE refused to issue an identity to the
	// calling workload. IP §6.1: "Attestation selector mismatch →
	// ATTESTATION_FAILED, not retryable."
	ClassAttestationFailed Class = "ATTESTATION_FAILED"

	// ClassIdentityUnavailable: SPIRE could not be reached or could not
	// answer. IP §6.1: "spire-server down at register_agent →
	// IDENTITY_UNAVAILABLE, retryable."
	ClassIdentityUnavailable Class = "IDENTITY_UNAVAILABLE"

	// ClassCredentialExpired: the credential presented is outside its validity
	// window. IP §6.2 forbids signing with it and forbids extending a TTL to
	// help; the caller needs a new credential, which is a different request.
	//nolint:gosec // G101: this is a protected IP §4 error-class name, not a credential.
	ClassCredentialExpired Class = "CREDENTIAL_EXPIRED"

	// ClassAudienceMismatch: the requested or presented audience is not in the
	// allowlist (IP §4: `sigstore` initially; IP §6.2).
	ClassAudienceMismatch Class = "AUDIENCE_MISMATCH"

	// ClassLedgerUnavailable: the ledger could not be reached. IP §6.4:
	// identity-issuing and signing operations fail closed, because I3 admits
	// no action without a record.
	ClassLedgerUnavailable Class = "LEDGER_UNAVAILABLE"

	// ClassSigningUnavailable: Fulcio could not be reached. IP §6.3: "Fulcio
	// down → SIGNING_UNAVAILABLE, retryable. The commit is not created."
	ClassSigningUnavailable Class = "SIGNING_UNAVAILABLE"

	// ClassTransparencyUnavailable: Rekor could not be reached. IP §6.3: "A
	// signature without a transparency entry is not non-repudiable and must
	// not exist."
	ClassTransparencyUnavailable Class = "TRANSPARENCY_UNAVAILABLE"

	// ClassRunNotFound: no such run. After a successful retirement that is the
	// expected state.
	ClassRunNotFound Class = "RUN_NOT_FOUND"

	// ClassRunAlreadyRetired: the run is retired. IP §6.2: retirement is
	// effective immediately, with no cached-credential grace path.
	ClassRunAlreadyRetired Class = "RUN_ALREADY_RETIRED"

	// ClassDuplicateRequest: an idempotency key was reused for a request that
	// is not the request it originally keyed (ADR-0004). A replay of the same
	// request is not this class — IP §6.6 requires it to return the original
	// result.
	ClassDuplicateRequest Class = "DUPLICATE_REQUEST"

	// ClassInvariantViolation: alert-level. Either this code has a defect or
	// something is using a credential it should not have (IP §6.2, §6.10).
	ClassInvariantViolation Class = "INVARIANT_VIOLATION"
)

// classOrder is the vocabulary in IP §4 order.
var classOrder = []Class{
	ClassAttestationFailed,
	ClassIdentityUnavailable,
	ClassCredentialExpired,
	ClassAudienceMismatch,
	ClassLedgerUnavailable,
	ClassSigningUnavailable,
	ClassTransparencyUnavailable,
	ClassRunNotFound,
	ClassRunAlreadyRetired,
	ClassDuplicateRequest,
	ClassInvariantViolation,
}

// classRetryable is IP §4's `retryable` flag, per class.
//
// IP states three of these verbatim — ATTESTATION_FAILED "not retryable" and
// IDENTITY_UNAVAILABLE "retryable" in §6.1, SIGNING_UNAVAILABLE "retryable" in
// §6.3 — and leaves the other eight to be derived. ADR-0016 records the rule
// that derives them and the reading it rejects: a class is retryable exactly
// when it names a dependency outage, a condition outside the request that may
// clear on its own. Every other class describes the request itself or durable
// state, and repeating the request cannot change either.
//
// Retryability is therefore a property of the class, never a per-call hint. A
// classifier closer to the failure may narrow it (see Classify); nothing may
// widen it, or a caller is told to retry a refusal.
var classRetryable = map[Class]bool{
	ClassAttestationFailed:       false,
	ClassIdentityUnavailable:     true,
	ClassCredentialExpired:       false,
	ClassAudienceMismatch:        false,
	ClassLedgerUnavailable:       true,
	ClassSigningUnavailable:      true,
	ClassTransparencyUnavailable: true,
	ClassRunNotFound:             false,
	ClassRunAlreadyRetired:       false,
	ClassDuplicateRequest:        false,
	ClassInvariantViolation:      false,
}

// Classes returns the eleven classes of IP §4, in the order IP §4 lists them.
func Classes() []Class { return slices.Clone(classOrder) }

// Valid reports whether c is one of the eleven. The vocabulary is closed: a
// value outside it never reaches the wire (see Error.MarshalJSON).
func (c Class) Valid() bool {
	_, ok := classRetryable[c]
	return ok
}

// Retryable reports whether a caller may usefully repeat a request that failed
// with this class. An unknown class is not retryable: fail closed.
func (c Class) Retryable() bool { return classRetryable[c] }

// Error is the Go carrier of the structured error IP §4 requires of every
// tool: `{error_class, message, retryable, run_id?}`. It marshals to exactly
// that object and nothing else.
type Error struct {
	// Class is the IP §4 error class.
	Class Class
	// Message is the human-readable detail. It is the only free-text field on
	// the wire; it must never carry a credential, a token or a key.
	Message string
	// Retryable is IP §4's `retryable`. Constructors take it from the class.
	Retryable bool
	// RunID is IP §4's optional `run_id`. Empty means the failure is not
	// scoped to one run, and the field is then absent from the wire rather
	// than present and empty (doc 02 §1).
	RunID string
	// Err is the underlying cause, kept for errors.Is/As. Callers must not
	// pattern-match on its text.
	Err error
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(string(e.Class))
	if e.RunID != "" {
		b.WriteString(" [run ")
		b.WriteString(e.RunID)
		b.WriteString("]")
	}
	if e.Retryable {
		b.WriteString(" (retryable)")
	} else {
		b.WriteString(" (not retryable)")
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// wireError is the IP §4 wire shape. The field order here is the order the
// fields appear on the wire, and `run_id` is omitted rather than emitted empty
// — doc 02 §1's absent-versus-empty rule applies to the wire too.
type wireError struct {
	Class     Class  `json:"error_class"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RunID     string `json:"run_id,omitempty"`
}

// MarshalJSON renders the IP §4 structured error.
//
// A class outside the closed vocabulary is reported as INVARIANT_VIOLATION
// with the rejected value named in the message: an invented class must never
// reach a caller, because a caller switching on `error_class` would have no
// case for it and the operator would have no way to know a defect fired.
func (e *Error) MarshalJSON() ([]byte, error) {
	w := wireError{
		Class:     e.Class,
		Message:   e.Message,
		Retryable: e.Retryable,
		RunID:     e.RunID,
	}
	if !e.Class.Valid() {
		w.Class = ClassInvariantViolation
		w.Retryable = false
		w.Message = fmt.Sprintf("%q is not an IP §4 error class; reported as %s: %s",
			string(e.Class), ClassInvariantViolation, e.Message)
	}
	if w.Message == "" {
		w.Message = string(w.Class)
	}
	return json.Marshal(w)
}

// Errorf builds a classified error. The retryable flag comes from the class,
// never from the call site: a tool chooses what went wrong, and IP §4 decides
// whether a retry can help.
//
// A single %w verb in format is honoured, so errors.Is and errors.As reach the
// underlying cause.
func Errorf(class Class, runID, format string, args ...any) *Error {
	wrapped := fmt.Errorf(format, args...)
	return &Error{
		Class:     class,
		Message:   wrapped.Error(),
		Retryable: class.Retryable(),
		RunID:     runID,
		Err:       errors.Unwrap(wrapped),
	}
}

// Classified is an error that already knows its own IP §4 class.
//
// It is the extension point for every failure carrier that is not this
// package's own *Error: the idempotency store (RM-021), the five tools
// (RM-022..025, RM-033) and anything after them report through the one
// taxonomy by implementing this method rather than by growing a case in
// Classify or, worse, by rendering IP §4's object themselves. There is one
// vocabulary and one place that writes it to the wire.
//
// internal/spire predates this interface and is carried across explicitly.
type Classified interface {
	error
	// ErrorClass reports the IP §4 class, the run the failure is scoped to
	// (empty for none), and whether the layer that raised it measured the
	// failure as retryable.
	//
	// The retryable flag may only NARROW the class default — see Classify. A
	// layer that would widen it is telling a caller to retry a refusal, and is
	// ignored.
	ErrorClass() (class Class, runID string, retryable bool)
}

// Classify renders any error as an IP §4 structured error.
//
// An error this package cannot name is INVARIANT_VIOLATION, not a made-up
// "internal error" class: IP §4's vocabulary is closed, and an unclassified
// failure inside the MCP is a defect, which is alert-level and never
// retryable.
func Classify(err error) *Error {
	if err == nil {
		return nil
	}
	var classified *Error
	if errors.As(err, &classified) {
		return classified
	}
	// internal/spire keeps retryability as a field rather than deriving it
	// from the class, because IP §6.1 makes IDENTITY_UNAVAILABLE retryable
	// when SPIRE is unreachable and not retryable when SPIRE answered
	// something the client cannot act on.
	var fromSPIRE *spire.Error
	if errors.As(err, &fromSPIRE) {
		return classifyAs(Class(fromSPIRE.Class), fromSPIRE.RunID, fromSPIRE.Message,
			fromSPIRE.Retryable, "internal/spire", fromSPIRE)
	}
	var self Classified
	if errors.As(err, &self) {
		class, runID, retryable := self.ErrorClass()
		return classifyAs(class, runID, err.Error(), retryable, "a Classified error", err)
	}
	return &Error{
		Class:     ClassInvariantViolation,
		Message:   err.Error(),
		Retryable: false,
		Err:       err,
	}
}

// classifyAs carries a lower layer's classification into this package.
//
// Two rules are enforced here so that no caller has to remember them. A class
// outside IP §4's closed vocabulary is not passed through under an invented
// name — it is INVARIANT_VIOLATION, with the rejected value named. And the
// retryable flag is ANDed with the class default: a layer closer to the
// failure may narrow it, never widen it, because the class default is what
// IP §4 promises a caller.
func classifyAs(class Class, runID, message string, retryable bool, source string, cause error) *Error {
	if !class.Valid() {
		return &Error{
			Class:     ClassInvariantViolation,
			Message:   fmt.Sprintf("%s reported the unknown class %q: %s", source, string(class), message),
			Retryable: false,
			RunID:     runID,
			Err:       cause,
		}
	}
	return &Error{
		Class:     class,
		Message:   message,
		Retryable: class.Retryable() && retryable,
		RunID:     runID,
		Err:       cause,
	}
}

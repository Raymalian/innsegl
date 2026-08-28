// SPDX-License-Identifier: Apache-2.0

// Package spire is the SPIRE side of Innsegl: the admin client the MCP uses to
// create and delete one registration entry per agent run, and the workload-side
// credential fetch a run uses to obtain its own SVID.
//
// IP §1 states the whole of the lifecycle this package implements:
//
//	One SPIRE registration entry per run, short TTL, created at registration,
//	deleted at retirement. Identity ≡ single run ≡ single purpose.
//
// It holds no ledger, no idempotency store and no MCP tool surface. Pairing an
// entry with its `run_registered` event atomically (IP §6.5) is the MCP's, and
// so is deciding what a caller is told; this package's job is to talk to SPIRE
// and to classify what SPIRE says into the error vocabulary of IP §4.
package spire

import "errors"

// Class is one member of the error-class vocabulary in IP §4. The string values
// are a PROTECTED SURFACE (VERSIONING.md): they appear in MCP responses and in
// scripts/protected-surfaces.sh, and they change only in a major release.
type Class string

// The classes this package can return. IP §4 lists eleven; the seven that
// belong to identity issuance and credential fetch are the ones a SPIRE client
// can produce. The rest (LEDGER_UNAVAILABLE, SIGNING_UNAVAILABLE,
// TRANSPARENCY_UNAVAILABLE, CREDENTIAL_EXPIRED, AUDIENCE_MISMATCH) belong to
// components that are not SPIRE.
const (
	// ClassAttestationFailed: SPIRE refused to issue an identity to the calling
	// workload. IP §6.1: "Attestation selector mismatch → ATTESTATION_FAILED,
	// not retryable." Retrying cannot make a workload be something else.
	ClassAttestationFailed Class = "ATTESTATION_FAILED"

	// ClassIdentityUnavailable: SPIRE could not be reached or could not answer.
	// IP §6.1: "spire-server down at register_agent → IDENTITY_UNAVAILABLE,
	// retryable." The run has no identity and does no attributed work; it does
	// not get a provisional one.
	ClassIdentityUnavailable Class = "IDENTITY_UNAVAILABLE"

	// ClassInvariantViolation: SPIRE refused something this client should never
	// have asked for, or answered with an identity that is not the one asked
	// for. Both are alert-level. An out-of-subtree entry creation refused by
	// SPIRE authorization (SPI-005, AB-10) lands here: either this code has a
	// defect or the admin credential is being used by something that is not us.
	ClassInvariantViolation Class = "INVARIANT_VIOLATION"

	// ClassRunNotFound: SPIRE holds no registration entry for the run. After a
	// successful retirement that is the expected state, and it is what makes
	// refusal immediate rather than waiting for a cache to converge — see
	// Client.RequireActiveRun.
	ClassRunNotFound Class = "RUN_NOT_FOUND"

	// ClassDuplicateRequest: an entry for this run's SPIFFE ID already exists.
	// One entry per run (IP §1) makes a second creation a duplicate, not a
	// second identity. The MCP resolves it against its idempotency store
	// (ADR-0004); this package only reports what SPIRE said.
	ClassDuplicateRequest Class = "DUPLICATE_REQUEST"
)

// Error is a classified failure. It is the shape IP §4 requires of every tool
// response — `{error_class, message, retryable, run_id?}` — carried as a Go
// error so the MCP can render it without re-deriving the class.
type Error struct {
	// Class is the IP §4 error class.
	Class Class
	// Op names the operation that failed, for the message only.
	Op string
	// Message is the human-readable detail.
	Message string
	// Retryable is IP §4's `retryable`. It is a property of the class and the
	// underlying failure, never a hint: a caller that retries a
	// non-retryable failure gets the same answer.
	Retryable bool
	// RunID is IP §4's optional `run_id`, empty when the failure is not
	// scoped to one run.
	RunID string
	// Err is the underlying cause, kept for errors.Is/As. Callers must not
	// pattern-match on its text.
	Err error
}

func (e *Error) Error() string {
	var b []byte
	b = append(b, e.Op...)
	b = append(b, ": "...)
	b = append(b, e.Class...)
	if e.RunID != "" {
		b = append(b, " [run "...)
		b = append(b, e.RunID...)
		b = append(b, ']')
	}
	if !e.Retryable {
		b = append(b, " (not retryable)"...)
	}
	if e.Message != "" {
		b = append(b, ": "...)
		b = append(b, e.Message...)
	}
	return string(b)
}

func (e *Error) Unwrap() error { return e.Err }

// newError builds a classified error. retryable is not derived from the class
// because two classes are ambiguous on their own: IDENTITY_UNAVAILABLE is
// retryable when SPIRE is unreachable and not retryable when SPIRE answered
// something this client cannot act on.
func newError(class Class, op, runID, message string, retryable bool, cause error) *Error {
	return &Error{
		Class:     class,
		Op:        op,
		Message:   message,
		Retryable: retryable,
		RunID:     runID,
		Err:       cause,
	}
}

// ClassOf returns the error class of err, if it carries one.
func ClassOf(err error) (Class, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Class, true
	}
	return "", false
}

// IsRetryable reports whether err is a classified error marked retryable. An
// unclassified error is not retryable: fail closed rather than spin.
func IsRetryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Retryable
	}
	return false
}

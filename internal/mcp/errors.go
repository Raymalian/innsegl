// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/ledger"
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
// internal/spire and internal/ledger both predate this interface, and neither
// can implement it: ErrorClass's signature names this package's own Class
// type, and internal/mcp already imports both of them, so either importing
// mcp back would be a cycle. Both are carried across explicitly in Classify
// instead — the same move, made twice, because Go's import graph forbids the
// interface where it would otherwise apply.
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
	// internal/ledger measured whether the database was gone or the schema was
	// wrong (RM-067, #87) and keeps that verdict as a field rather than
	// deriving it a second time here — *ledger.StoreError carries no run_id of
	// its own, so a caller that has one (register_agent.go, runs.go) attaches
	// it before this is ever reached; this case is the fallback for a ledger
	// failure that reaches Classify unwrapped.
	var fromLedger *ledger.StoreError
	if errors.As(err, &fromLedger) {
		return classifyAs(Class(fromLedger.Class), "", fromLedger.Error(),
			fromLedger.Retryable, "internal/ledger", fromLedger)
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

// classifyStorage maps a database failure the MCP idempotency store (RM-021)
// observed directly — over its own pool, never through internal/ledger — onto
// IP §4's vocabulary.
//
// # RM-067 (#87): the rule this now shares with internal/ledger.classify
//
// Before this fix, every SQLSTATE that was not a constraint violation fell
// through to LEDGER_UNAVAILABLE with retryable FALSE, on the reasoning "the
// database answered, but not usefully". That reasoning does not hold for
// SQLSTATE class 08 (connection exception), 53 (insufficient resources), 57
// (operator intervention) or 58 (system error): those codes are not the
// database refusing a statement, they ARE the outage — 57P01, "terminating
// connection due to unexpected postmaster exit", is what a stale pooled
// connection receives on the first call after Postgres is genuinely killed.
// internal/ledger.classify already recognised this shape and reported it
// retryable; this function did not, so the same real outage produced opposite
// advice depending on which layer's pool happened to answer first — measured
// against a real killed Postgres, not a stub (test/contract's settleOutage,
// and this package's TestMCP021...).
//
// ADR-0016 §2 permits a layer closer to the failure to NARROW retryable, never
// to widen it, but narrowing has to be earned by evidence that a retry cannot
// help — a specific SQLSTATE class saying so. Treating "the database sent a
// structured answer" itself as that evidence was an over-application: nearly
// every failure on an established connection arrives as a *pgconn.PgError,
// so the blanket rule silently discarded LEDGER_UNAVAILABLE's class default
// (retryable, ADR-0016 §1) for almost every real Postgres failure, dependency
// outages included. isConnectionLifecycleSQLState below is the narrower,
// evidence-based rule instead: only the SQLSTATE classes that name a server
// leaving or gone are treated as retryable, exactly as internal/ledger.classify
// already treats them, so the two layers agree by construction rather than by
// coincidence.
//
// A missing table, a bad privilege grant or a syntax error (SQLSTATE 42, 22)
// stays retryable=false: nothing about those improves on a retry, and this
// function's default case is unchanged from before this fix.
func classifyStorage(op string, err error) *Error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		// No answer from the database at all: an unreachable or closed pool.
		return classifyAs(ClassLedgerUnavailable, "",
			fmt.Sprintf("idempotency store %s: %v", op, err), true, storeSource, err)
	}
	if pgErr.Code == IdempotencyStateSQLState || strings.HasPrefix(pgErr.Code, "23") {
		// The database refused to break the store's own rules. Never a
		// transport problem, and never worth retrying.
		return classifyAs(ClassInvariantViolation, "",
			fmt.Sprintf("idempotency store %s refused by the schema (SQLSTATE %s): %s",
				op, pgErr.Code, pgErr.Message), false, storeSource, err)
	}
	if isConnectionLifecycleSQLState(pgErr.Code) {
		// The server answered, and the answer IS that it is going away or
		// already gone — not a refusal of this statement. Retrying is exactly
		// what a caller should do (RM-067, #87).
		return classifyAs(ClassLedgerUnavailable, "",
			fmt.Sprintf("idempotency store %s: SQLSTATE %s: %s", op, pgErr.Code, pgErr.Message),
			true, storeSource, err)
	}
	// The database answered, but not usefully — a missing table, a syntax
	// error, a privilege refusal. Retrying cannot change any of those.
	return classifyAs(ClassLedgerUnavailable, "",
		fmt.Sprintf("idempotency store %s: SQLSTATE %s: %s", op, pgErr.Code, pgErr.Message),
		false, storeSource, err)
}

// isConnectionLifecycleSQLState reports whether code names the SERVER itself
// arriving or leaving, rather than the server refusing the statement it was
// sent. This is exactly the set internal/ledger.classify (postgres.go) treats
// as retryable LEDGER_UNAVAILABLE, named here by the same prefixes so a future
// change to one has to change the other to stay in sync (RM-067, #87):
//
//   - 08 connection exception (08006 connection failure, 08003 connection
//     does not exist)
//   - 53 insufficient resources
//   - 57 operator intervention (57P01 admin shutdown / unexpected postmaster
//     exit, 57P02 crash shutdown, 57P03 cannot connect now)
//   - 58 system error
//   - 40 transaction rollback / serialization failure
func isConnectionLifecycleSQLState(code string) bool {
	for _, prefix := range []string{"08", "53", "57", "58", "40"} {
		if strings.HasPrefix(code, prefix) {
			return true
		}
	}
	return false
}

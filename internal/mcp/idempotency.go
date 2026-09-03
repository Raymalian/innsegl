// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
)

// IdempotencyStore makes an MCP tool call happen at most once and answer the
// same way every time it is replayed (RM-021, IP §6.6, ADR-0017).
//
// # What it is for, and what it is not
//
// IP §6.6: "Every tool call is idempotent via required idempotency_key;
// replaying any request after a crash returns the original result, never a
// second identity, second event, or second commit."
//
// The ledger already dedupes EVENTS: internal/ledger's UNIQUE
// idempotency_key means one key appends at most one row, and a replayed
// Append returns the original event (LED-008). That is the permanent
// guarantee and this store neither replaces nor repeats it.
//
// A tool CALL is a larger thing than an append. It can have an effect before
// any event exists — an identity minted in SPIRE, a commit signed into Rekor —
// and its reply can carry values no event holds, such as an expiry. So the
// ledger cannot answer "what did that call return?", and after a crash between
// the effect and the reply, nothing can, unless the reply itself was recorded.
// Recording it is this store's whole job.
//
// The two layers agree because one key names one action at both: the same
// string is this table's primary key and the ledger's UNIQUE column.
//
// # Why Postgres and not a map
//
// Doc 05 §2: "MCP replicas are stateless (idempotency store lives in
// Postgres) — MCP-011's crash/replay property is what makes horizontal
// scaling safe." Process-local state passes every single-process test and
// then fails, silently and in the direction that mints a second identity, the
// first time there are two replicas or one restart.
//
// # Claims, leases and the second execution
//
// A call claims its key, runs, and records its reply. Concurrent callers of
// the same key do not run the tool: they wait and are given the recorded
// reply. That is the ordinary path, and the tool runs exactly once.
//
// A claim carries a lease, because a replica that is SIGKILLed mid-call leaves
// its claim behind and IP §6.6 requires the replay to RETURN something. When
// the lease has run out the next caller takes the claim over and runs the tool
// a second time. That second execution is deliberate and is where the layering
// pays: the inner effect is itself idempotent — the ledger's UNIQUE key for an
// event, the run's own SPIRE entry for an identity — so the second execution
// produces no second record. What must never happen, and does not, is two
// ANSWERS: whichever call completes first is the one every caller is given,
// including the overtaken one.
//
// The store holds no state between calls. Everything above is decided by
// single SQL statements against the row, so two replicas reach the same
// conclusions with nothing shared but the database.
type IdempotencyStore struct {
	pool  *pgxpool.Pool
	lease time.Duration
	// onEnteringWait, when set, is called each time this caller has found the
	// key held by a call that is still running, immediately before it waits for
	// it. Nil on every shipped path — only this package's own tests can set it,
	// and nothing here consults it for a decision — so no real caller's
	// behaviour turns on it.
	//
	// It exists because "this caller is now waiting" is otherwise observable
	// from nowhere. A waiter takes no lock, bumps no claim_count and writes no
	// row: the claim it just made was declined, so the database has nothing new
	// to be asked about. Without this the only way to exercise the give-up path
	// below was to hand a caller a deadline and hope it expired inside the 25ms
	// wait rather than inside one of the sub-millisecond claim statements on
	// either side of it — and both landings produce the same in-flight error,
	// so the case could not tell them apart while the branch coverage gate
	// could. That is #128, and two tunings of that deadline did not fix it.
	onEnteringWait func()
}

const (
	// DefaultIdempotencyLease is how long one claim on a key is honoured
	// before another caller may take it over.
	//
	// It is the window in which a crashed replica's call is presumed still
	// running. Too short and a slow tool is executed twice for nothing; too
	// long and a replay after a crash blocks for the difference. A minute is
	// longer than any tool IP §4 describes and short enough that an agent
	// retrying after a crash is not left waiting on a process that is gone.
	DefaultIdempotencyLease = 60 * time.Second

	// MaxIdempotencyResponseBytes caps a recorded reply. It is the same number
	// as the column's CHECK; TestTheResponseLimitIsSpelledTheSameInGoAndInSQL
	// holds the two together.
	MaxIdempotencyResponseBytes = 64 << 10

	// IdempotencyStateSQLState is raised by the schema's own guard when a
	// statement would rewrite a recorded reply, repoint a claim at another
	// call, or discard a claim that is still in flight. A user-defined class:
	// Postgres reserves classes beginning 0-4 and A-H, and IN001/IN002 are the
	// ledger's.
	IdempotencyStateSQLState = "IN003"

	// replayPollInterval is how often a waiting caller re-reads the claim it
	// is waiting on. Fixed rather than backed off: the wait is bounded by the
	// caller's own context and by the lease, both of which are visible to an
	// operator, and a backoff schedule would be a third bound that is not.
	replayPollInterval = 25 * time.Millisecond

	statusInProgress = "in_progress"
	statusCompleted  = "completed"

	// storeSource names this layer in a classified error.
	storeSource = "the MCP idempotency store"
)

// Sentinel causes, for errors.Is. The error a caller receives is always an
// *Error carrying an IP §4 error_class; these say which situation produced it.
var (
	// ErrInvalidCall reports a call that cannot be recorded under the key it
	// supplied — no tool, no key, or a key the ledger would later refuse.
	ErrInvalidCall = errors.New("the call cannot be recorded under this idempotency_key")

	// ErrKeyNamesADifferentRequest reports a key already used for another
	// call. RM-009 refuses the same reuse one layer down for the same reason:
	// doc 02 §2 gives the key one job, dedupe, and returning the earlier reply
	// would answer a question the caller did not ask.
	ErrKeyNamesADifferentRequest = errors.New("idempotency_key already names a different request")

	// ErrCallInFlight reports that the original call was still running when
	// this caller stopped waiting. Its reply is not lost: a later replay of
	// the same request returns it.
	ErrCallInFlight = errors.New("a call with this idempotency_key is still running")
)

// Call is one MCP tool call, named by the key that makes it repeatable.
//
// ADR-0004 fixes which tools carry a key: it is required if and only if the
// originating tool accepts one (IP §4), and forbidden elsewhere. A tool that
// takes no key does not reach this store — its idempotency is intrinsic to
// its own arguments, and inventing a key for it would either collide or be
// decorative.
type Call struct {
	// Tool is the MCP tool name. It is part of the request fingerprint, so one
	// key can never name two different tools.
	Tool string
	// Key is the caller's idempotency_key: doc 02 §2's "string ≤128", counted
	// in bytes (ADR-0004).
	Key string
	// Params are the tool's arguments. They are fingerprinted, not stored: the
	// store never becomes a second copy of a request that may carry a payload.
	Params map[string]any
}

// Outcome is what a tool hands back to its caller.
type Outcome struct {
	// Response is the recorded reply, byte for byte as the first completed
	// call produced it. On a replay these are the STORED bytes, never a second
	// computation.
	Response []byte
	// Replayed is true when Response was read rather than produced. A tool may
	// log it; it is not part of the reply.
	Replayed bool
}

// Record is one row of the store, for operators and for the crash/replay
// harness. Reading a record is not how a call is replayed — Do is — but it is
// how an operator sees what is stuck and why.
type Record struct {
	Key            string
	Tool           string
	RequestDigest  string
	Status         string
	Response       []byte
	Claims         int32
	ClaimedAt      time.Time
	LeaseExpiresAt time.Time
	// CompletedAt is the zero time while the call is in flight.
	CompletedAt time.Time
}

// IdempotencyOption configures an IdempotencyStore.
type IdempotencyOption func(*IdempotencyStore)

// WithIdempotencyLease sets how long a claim is honoured before another caller
// may take it over. Zero means a claim is takeable immediately, which is the
// state a SIGKILLed replica leaves behind.
func WithIdempotencyLease(d time.Duration) IdempotencyOption {
	return func(s *IdempotencyStore) { s.lease = d }
}

// withWaitObserver installs f, called each time a caller of this store finds
// the key held by a call that is still running and is about to wait for it.
//
// Unexported on purpose: it is a test seam and not a feature. It lets a case
// DRIVE the moment a waiting caller gives up — cancel its context, or take its
// database away — instead of racing a clock into a window that moves with load
// (#128). It observes; it decides nothing, and a store built without it runs
// exactly as it did before this existed.
func withWaitObserver(f func()) IdempotencyOption {
	return func(s *IdempotencyStore) { s.onEnteringWait = f }
}

// NewIdempotencyStore returns a store over a pool the caller owns.
//
// The pool is not opened or closed here. An MCP replica has one pool for one
// database — the ledger's, since the chain and this store share a database by
// ADR-0005 — and a component that closed a pool it did not create would take
// the ledger down with it. Migrations are the ledger's runner too: this table
// ships as migration 0002 in the same embedded set, so a deployment cannot
// have one schema without the other.
func NewIdempotencyStore(pool *pgxpool.Pool, opts ...IdempotencyOption) *IdempotencyStore {
	s := &IdempotencyStore{pool: pool, lease: DefaultIdempotencyLease}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Do performs call at most once and returns what it returned.
//
// The first caller of a key runs fn and its reply is recorded. Every later
// caller of the same key and the same request is given that recorded reply and
// fn is not run. A caller presenting the key with a DIFFERENT request is
// refused as DUPLICATE_REQUEST rather than given an answer to a question it
// did not ask.
//
// A caller that arrives while the original is still running waits for it,
// bounded by two things and no third: its own context, and the claim's lease.
// When the lease runs out — which is what a crashed replica leaves behind —
// the waiting caller takes the claim over and runs fn itself.
//
// fn's result is canonicalized (RFC 8785) and stored. Callers read
// Outcome.Response the same way on the first call and on every replay, so
// there is one serialization of a reply and not two.
func (s *IdempotencyStore) Do(ctx context.Context, call Call, fn func(context.Context) (any, error)) (Outcome, error) {
	digest, err := call.fingerprint()
	if err != nil {
		return Outcome{}, err
	}

	// waiting records that this caller has already seen the key held by
	// someone else. Once that is true, any failure to reach an answer is
	// reported as the wait ending rather than as a bare store failure: the
	// caller's next question is whether the original call's reply is still
	// coming, and it is.
	waiting := false
	for {
		claim, cerr := s.claim(ctx, call, digest)
		if cerr != nil {
			if waiting {
				return Outcome{}, inFlightError(call.Key, cerr)
			}
			return Outcome{}, cerr
		}
		if claim.mine {
			return s.run(ctx, call.Key, fn)
		}
		if claim.digest != digest {
			return Outcome{}, classifyAs(ClassDuplicateRequest, "",
				fmt.Sprintf("idempotency_key %q already names the %q call with request digest %s, not this one (%s)",
					call.Key, claim.tool, claim.digest, digest),
				false, storeSource, ErrKeyNamesADifferentRequest)
		}
		if claim.status == statusCompleted {
			return Outcome{Response: claim.response, Replayed: true}, nil
		}
		// In flight elsewhere. Wait, and come back: either it completes and
		// the next pass returns its reply, or its lease runs out and the next
		// pass takes the claim over.
		waiting = true
		if s.onEnteringWait != nil {
			s.onEnteringWait()
		}
		if werr := waitBeforeRetry(ctx, replayPollInterval); werr != nil {
			return Outcome{}, inFlightError(call.Key, werr)
		}
	}
}

// inFlightError reports that this caller stopped waiting for a call that was
// still running, and why.
//
// The class is a considered compromise and is flagged in ADR-0017. IP §4's
// vocabulary is closed and has no class for "the original has not finished
// yet". DUPLICATE_REQUEST is what ADR-0016 fixes as not retryable and what
// errors.go defines as a key reused for a DIFFERENT request, which this is
// not; INVARIANT_VIOLATION is alert-level and would page an operator over a
// slow tool. LEDGER_UNAVAILABLE is the only class that gives the caller the
// instruction the situation actually warrants — try again, the reply is
// coming — and internal/ledger already reports a context failure during a
// ledger operation the same way. The message names the true situation.
func inFlightError(key string, cause error) *Error {
	return classifyAs(ClassLedgerUnavailable, "",
		fmt.Sprintf("stopped waiting for the call already running under idempotency_key %q; "+
			"its reply is recorded when it finishes, and a replay of the same request returns it: %v",
			key, cause),
		true, storeSource, errors.Join(ErrCallInFlight, cause))
}

// Lookup returns the record a key holds, if any.
func (s *IdempotencyStore) Lookup(ctx context.Context, key string) (Record, bool, error) {
	var (
		rec         Record
		completedAt *time.Time
	)
	err := s.pool.QueryRow(ctx, lookupSQL, key).Scan(
		&rec.Key, &rec.Tool, &rec.RequestDigest, &rec.Status, &rec.Response,
		&rec.Claims, &rec.ClaimedAt, &rec.LeaseExpiresAt, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, classifyStorage("lookup", err)
	}
	if completedAt != nil {
		rec.CompletedAt = *completedAt
	}
	return rec, true, nil
}

// run executes the tool under a claim this caller holds, and records the
// reply.
func (s *IdempotencyStore) run(ctx context.Context, key string, fn func(context.Context) (any, error)) (Outcome, error) {
	result, err := fn(ctx)
	if err != nil {
		// The tool reported failure, so nothing was recorded and the key is
		// freed for an immediate retry rather than held for a whole lease. If
		// the failure came after a partial effect, the retry meets the inner
		// idempotency — the ledger's UNIQUE key, the run's own SPIRE entry —
		// which is the layer that exists for exactly this.
		return Outcome{}, errors.Join(err, s.release(ctx, key))
	}

	response, cerr := event.Canonicalize(result)
	if cerr != nil {
		// The effect has already happened and cannot be described. The claim
		// is deliberately NOT released: an immediate retry would repeat an
		// effect that succeeded, so the lease paces it instead.
		return Outcome{}, classifyAs(ClassInvariantViolation, "",
			fmt.Sprintf("the tool's reply under idempotency_key %q cannot be canonicalized, "+
				"so the call had its effect and cannot be replayed: %v", key, cerr),
			false, storeSource, cerr)
	}

	stored, mine, serr := s.complete(ctx, key, response)
	if serr != nil {
		return Outcome{}, serr
	}
	// mine is false when another caller took the claim over and completed
	// first. Its reply is the one that was recorded, so it is the one every
	// caller gets — including this one, which computed a different answer to
	// the same question and must not return it.
	return Outcome{Response: stored, Replayed: !mine}, nil
}

// claimState is what one claim attempt learned about the key.
type claimState struct {
	mine     bool
	tool     string
	digest   string
	status   string
	response []byte
}

// claimSQL claims the key, or reports what already holds it, in one statement.
//
// The INSERT takes an unheld key. ON CONFLICT DO UPDATE takes over a claim
// whose lease has run out AND whose request is this one — a takeover never
// repurposes a key for a different call. When neither applies, the data
// modifying CTE returns no row and the second arm reports the row as it stands
// (the plain SELECT reads the statement's snapshot, so it sees the existing
// row rather than a row this statement just wrote).
//
// One statement, one round trip, and no window between deciding and acting: an
// INSERT and a later UPDATE would leave one, and two replicas would both walk
// through it.
const claimSQL = `
WITH claimed AS (
    INSERT INTO innsegl.idempotency
           (idempotency_key, tool, request_digest, status, claimed_at, lease_expires_at)
    VALUES ($1, $2, $3, 'in_progress', clock_timestamp(),
            clock_timestamp() + ($4::bigint * interval '1 millisecond'))
    ON CONFLICT (idempotency_key) DO UPDATE
       SET claimed_at       = clock_timestamp(),
           lease_expires_at = clock_timestamp() + ($4::bigint * interval '1 millisecond'),
           claim_count      = innsegl.idempotency.claim_count + 1
     WHERE innsegl.idempotency.status = 'in_progress'
       AND innsegl.idempotency.lease_expires_at <= clock_timestamp()
       AND innsegl.idempotency.request_digest = $3
    RETURNING true AS mine, tool, request_digest, status, response
)
SELECT mine, tool, request_digest, status, response FROM claimed
UNION ALL
SELECT false, tool, request_digest, status, response
  FROM innsegl.idempotency
 WHERE idempotency_key = $1 AND NOT EXISTS (SELECT 1 FROM claimed)`

func (s *IdempotencyStore) claim(ctx context.Context, call Call, digest string) (claimState, error) {
	var st claimState
	err := s.pool.QueryRow(ctx, claimSQL, call.Key, call.Tool, digest, s.lease.Milliseconds()).
		Scan(&st.mine, &st.tool, &st.digest, &st.status, &st.response)
	if errors.Is(err, pgx.ErrNoRows) {
		// Neither arm produced a row, which happens for one reason and is not
		// a failure: another caller's claim committed WHILE this statement was
		// running. The INSERT blocks on the uncommitted conflicting row, so it
		// sees the winner and declines; the SELECT arm reads this statement's
		// snapshot, taken before that commit, so it does not see it at all.
		//
		// What was learned is therefore "someone else holds this key, and this
		// statement cannot say what with". That is exactly the in-flight state,
		// so it is reported as one: the caller waits and comes back, and the
		// next statement takes a fresh snapshot and sees the row. A different
		// request under the key costs one extra poll before it is refused —
		// never a wrong answer.
		return claimState{tool: call.Tool, digest: digest, status: statusInProgress}, nil
	}
	if err != nil {
		return claimState{}, classifyStorage("claim", err)
	}
	return st, nil
}

// completeSQL records the reply, or reports the reply that was recorded first.
//
// The UPDATE matches only a claim that is still in flight, so the first caller
// to complete wins and a caller that was overtaken reads the winner's reply
// out of the second arm rather than overwriting it.
//
// FOR UPDATE on that second arm is load-bearing and is why this is not the
// obvious statement (RM-066, ADR-0023). A plain SELECT beside the UPDATE reads
// the statement's snapshot, and the losing completer's snapshot is by
// definition older than the winner's commit: its UPDATE blocked on the
// winner's row lock, re-evaluated against the post-commit row, and declined,
// while its SELECT still saw status='in_progress', response IS NULL — an empty
// reply handed to a caller the store promised the winner's bytes. A locking
// read is the one construct that sees past the snapshot: READ COMMITTED walks
// the update chain to the row's current version and re-checks the WHERE
// against it, so the loser reads what actually committed.
//
// `recorded` is read BEFORE the UPDATE rather than beside it, and the UPDATE
// depends on it, so the order is fixed by the data and not by the planner: the
// row is locked and re-read first, and the UPDATE fires only when that current
// version is still in flight. First-completion-wins is therefore decided
// against the committed row twice — once by the EXISTS and once by the
// UPDATE's own `status = 'in_progress'`, which EvalPlanQual re-checks — and a
// completed row is never touched, so the schema's IN003 guard is never
// provoked into refusing a legitimate call.
const completeSQL = `
WITH recorded AS (
    SELECT status, response
      FROM innsegl.idempotency
     WHERE idempotency_key = $1
       FOR UPDATE
), done AS (
    UPDATE innsegl.idempotency
       SET status = 'completed', response = $2, completed_at = clock_timestamp()
     WHERE idempotency_key = $1
       AND status = 'in_progress'
       AND EXISTS (SELECT 1 FROM recorded WHERE recorded.status = 'in_progress')
    RETURNING true AS mine, response
)
SELECT mine, response FROM done
UNION ALL
SELECT false, response FROM recorded WHERE NOT EXISTS (SELECT 1 FROM done)`

func (s *IdempotencyStore) complete(ctx context.Context, key string, response []byte) ([]byte, bool, error) {
	var (
		stored []byte
		mine   bool
	)
	if err := s.pool.QueryRow(ctx, completeSQL, key, response).Scan(&mine, &stored); err != nil {
		return nil, false, classifyStorage("complete", err)
	}
	return stored, mine, nil
}

// releaseSQL expires a claim without deleting it.
//
// Expiring rather than deleting keeps the key bound to the call it named, so a
// retry of the same request proceeds while a different request under that key
// is still refused. Deleting would free the key for anything at all.
const releaseSQL = `
UPDATE innsegl.idempotency
   SET lease_expires_at = clock_timestamp()
 WHERE idempotency_key = $1 AND status = 'in_progress'`

func (s *IdempotencyStore) release(ctx context.Context, key string) error {
	if _, err := s.pool.Exec(ctx, releaseSQL, key); err != nil {
		return classifyStorage("release", err)
	}
	return nil
}

const lookupSQL = `
SELECT idempotency_key, tool, request_digest, status, response,
       claim_count, claimed_at, lease_expires_at, completed_at
  FROM innsegl.idempotency
 WHERE idempotency_key = $1`

// fingerprint is the digest a replay must match: the tool and its arguments,
// in the project's one canonical form (RFC 8785, doc 02 §4.2), so that a
// caller passing an integer and a caller passing the same integer differently
// spelled are the same request.
//
// The key itself is not in the digest — it is what the digest is looked up by.
func (c *Call) fingerprint() (string, error) {
	reject := func(format string, args ...any) (string, error) {
		return "", classifyAs(ClassInvariantViolation, "",
			fmt.Sprintf(format, args...), false, storeSource, ErrInvalidCall)
	}
	if c.Tool == "" {
		return reject("a call with no tool name cannot be recorded (IP §4)")
	}
	if c.Key == "" {
		return reject("%s: idempotency_key is required on every tool call that takes one (IP §6.6, ADR-0004)",
			ErrInvalidCall)
	}
	// The same limit the ledger enforces, in the same unit. A key this store
	// accepted and the ledger later refused would be a recorded reply for an
	// action with no record (I3).
	if len(c.Key) > event.MaxIdempotencyKeyBytes {
		return reject("idempotency_key is %d bytes, limit %d (doc 02 §2 counted in bytes, ADR-0004)",
			len(c.Key), event.MaxIdempotencyKeyBytes)
	}
	if !utf8.ValidString(c.Key) {
		return reject("idempotency_key is not valid UTF-8 (doc 02 §1)")
	}

	canonical, err := event.Canonicalize(map[string]any{"tool": c.Tool, "params": c.Params})
	if err != nil {
		return reject("the call's parameters cannot be canonicalized, so a replay could never be matched to it: %v", err)
	}
	return event.Digest(canonical), nil
}

// waitBeforeRetry sleeps, or reports that the caller's context ended first.
func waitBeforeRetry(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// classifyStorage maps a database failure onto IP §4's vocabulary.
//
// The policy is internal/ledger's, because it is the same database and a
// caller must not have to know which layer answered: a refusal the schema
// raised is an invariant violation and never retryable; anything else is
// LEDGER_UNAVAILABLE, retryable only when the ledger might answer next time.
// Callers check err != nil first — this is never handed a nil.
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
	// The database answered, but not usefully — a missing table, a syntax
	// error, a privilege refusal. Retrying cannot change any of those.
	return classifyAs(ClassLedgerUnavailable, "",
		fmt.Sprintf("idempotency store %s: SQLSTATE %s: %s", op, pgErr.Code, pgErr.Message),
		false, storeSource, err)
}

// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"time"
)

// A run's state is decided by its newest recorded fact, and this is the only
// place that decides it (RM-155, #258).
//
// # Why one place, and what it cost to have three
//
// Three components used to answer "is this run closed?" on their own terms and
// they did not agree. The reconciler read a run as closed from its first
// `run_expired` for ever, regardless of anything the run did afterwards — so
// every run the restore path legitimately brought back (internal/mcp's
// get_credential re-creates the SPIRE entry when a quiet run speaks again) was
// reported as `spire_entry_not_deleted`: an integrity alert, permanent under
// I4, against a system that was working exactly as designed. Meanwhile the
// read API had already been taught the right rule and said the same run was
// active. An operator shown both learns to believe neither.
//
// So the rule is written once, here, in two renderings that are held to each
// other by test: RunStateOf for a caller that has the facts in memory, and
// RunStateSQL for a caller that must filter and count a table it will not ship
// to a client (FD §7). Both are the same four clauses in the same order.
//
// # The rule
//
// A run's state is whichever of its recorded facts is newest, read in this
// order and no other:
//
//  1. RETIRED WINS UNCONDITIONALLY. Someone SAID stop — a harness that owned
//     the process, or a human — and a straggling call arriving afterwards must
//     not resurrect the run. Retirement is the one fact in this system that is
//     terminal, and I4 makes it permanent.
//  2. A WITHDRAWAL STANDS ONLY WHILE NOTHING NEWER CONTRADICTS IT. The reaper
//     withdraws a credential from a run that went quiet; a run that speaks
//     again has answered the only question the reaper was asking. "Speaks" is
//     an event the reaper did not write — see RunFacts.LastActivityAt — so the
//     reaper cannot read its own record as evidence about the run it withdrew
//     from.
//  3. A WITHDRAWAL THAT STANDS IS LAPSED, OR ABANDONED PAST THE HORIZON. The
//     horizon is how long a withdrawn run may still be restored; past it, this
//     system will no longer mint for the run. That says nothing whatever about
//     the agent, and E7 forbids pretending otherwise: it says what this
//     deployment will no longer do.
//  4. OTHERWISE ACTIVE.
//
// # Nothing here is stored, and nothing here may become stored
//
// There is no state column and no state table (IP §6.1, doc 08). Every answer
// is a function of recorded facts and their order, computed at read time. A
// stored state would be a fact nobody appended, and keeping it correct would
// mean updating rows in an append-only ledger (I4).
//
// # No event type, member or enum value changes for any of this
//
// `run_expired` remains the event and remains protected (doc 02 §3). What
// changed is only which of a run's facts names its state — the newest, rather
// than the first closing one.

// The four states, in lifecycle order.
//
// `expired` is deliberately not among them and stays gone: it survives as the
// name of the `run_expired` EVENT, which is a protected string. Three words
// ("active / retired / expired") could not tell a run that is QUIET from a run
// that is OVER, and the word the two collapsed into read as death.
const (
	// RunActive: not ended, and either never withdrawn or heard from since the
	// newest withdrawal.
	RunActive = "active"
	// RunLapsed: the newest fact is a withdrawal, inside the restore horizon.
	// Resuming the run restores its identity.
	RunLapsed = "lapsed"
	// RunAbandoned: the newest fact is a withdrawal, and the horizon has
	// passed, so the identity will not be restored again.
	RunAbandoned = "abandoned"
	// RunRetired: the run was ended by its harness or by a human. Terminal in
	// a way silence never is.
	RunRetired = "retired"
)

// RunStates is the closed set, in lifecycle order. A state reaches SQL as a
// string, so a caller checks a request against this rather than trusting it.
var RunStates = []string{RunActive, RunLapsed, RunAbandoned, RunRetired}

// RunFacts is everything the rule reads: four recorded facts about one run,
// and the instant it was registered.
//
// Every member is something a component read off the chain. Nothing here is an
// inference about an agent, and nothing here may become one.
type RunFacts struct {
	// Retired reports whether any `run_retired` is on the chain for this run.
	//
	// Separate from RetiredAt because it is what DECIDES, and it must be
	// decidable without a readable instant: the SQL rendering derives it as
	// bool_or(event_type = 'run_retired') and never needs a timestamp at all.
	// A caller that could only date the retirement approximately still knows
	// perfectly well that the run was retired.
	Retired bool
	// RetiredAt is the EARLIEST `run_retired`, zero when the run was never
	// retired or the instant could not be read.
	//
	// Earliest, where WithdrawnAt is newest, and the difference is the
	// difference between the facts (ADR-0020 §5). Two concurrent retirements
	// of one run are two reports of ONE ending, so every caller is told the
	// original instant for ever.
	RetiredAt time.Time
	// WithdrawnAt is the NEWEST `run_expired`, zero when the reaper never took
	// this run's authorisation.
	//
	// Newest, because a run has one withdrawal per quiet spell and they are
	// not reports of one fact. Read as the earliest, a run that lapsed on its
	// first day, resumed, and worked for longer than the horizon would be
	// abandoned by arithmetic rather than by silence (MCP-078).
	WithdrawnAt time.Time
	// LastActivityAt is the newest event on this run that the REAPER DID NOT
	// WRITE, zero when the run's entire record is the reaper's.
	//
	// `source` is the discriminator (doc 02 §2 makes it "who appended it"), and
	// it is the discriminator for a reason that is not tidiness: counting the
	// reaper's own `run_expired` would let the reaper read its own record as
	// evidence that the run it just withdrew from is working, and no withdrawal
	// would ever stand.
	//
	// # ONLY the reaper is excluded, and that has a consequence worth stating
	//
	// The discriminator is the read API's own — `source IS DISTINCT FROM
	// 'reaper'` (#256) — extracted here verbatim rather than narrowed, because
	// a rule two components read differently is the defect #258 closes and
	// changing it is a decision for a human rather than a side effect of
	// moving it.
	//
	// So an event the RECONCILER writes counts as activity. One does exist:
	// `ledger_drift_detected` carries the run's `run_id` and `spiffe_id` when
	// the finding is attributable, and `source` `reconciler`. A withdrawn run
	// whose surviving entry is reported therefore reads active from the moment
	// the alert lands — the standing finding stops being reported on the next
	// cycle, and the dashboard calls the run active. The alert itself is
	// permanent and was raised, so nothing is lost silently; what is lost is
	// the repetition and the label.
	//
	// That is not this file's to fix: narrowing the discriminator to "only the
	// run's own tooling" changes what every component answers, and it wants an
	// issue, not a quiet edit. It is written down here so the next reader finds
	// it stated rather than measured.
	LastActivityAt time.Time
	// RegisteredAt is the `run_registered` instant, zero when it could not be
	// read. It decides nothing; it dates an active run for DecidedAt.
	RegisteredAt time.Time
}

// WithdrawalStands reports whether the newest withdrawal is still this run's
// newest fact — nothing the reaper did not write has happened since.
//
// A zero LastActivityAt is older than any withdrawal, which is the right
// reading: a run whose whole record is the reaper's has said nothing.
func (f RunFacts) WithdrawalStands() bool {
	return !f.WithdrawnAt.IsZero() && !f.LastActivityAt.After(f.WithdrawnAt)
}

// DecidedAt is the instant of the fact the state rests on: the retirement, the
// standing withdrawal, or — for an active run — the newest of its registration
// and its activity.
//
// It exists so that a control which must not accuse a system still mid-call
// can age the run against the fact that made it what it is, rather than
// against whichever event happens to be oldest. internal/spire's reconciler is
// the caller; see its MinAge.
func (f RunFacts) DecidedAt() time.Time {
	switch {
	case f.Retired:
		return f.RetiredAt
	case f.WithdrawalStands():
		return f.WithdrawnAt
	case f.LastActivityAt.After(f.RegisteredAt):
		return f.LastActivityAt
	default:
		return f.RegisteredAt
	}
}

// RunStateOf returns one of the four states, by the rule at the top of this
// file.
//
// now and horizon decide only between RunLapsed and RunAbandoned, and a
// horizon of zero or less means the deployment set none — a withdrawn run then
// stays restorable until something ends it, which is a real setting and not an
// oversight.
func RunStateOf(facts RunFacts, now time.Time, horizon time.Duration) string {
	switch {
	case facts.Retired:
		return RunRetired
	case facts.WithdrawalStands():
		if before := AbandonedBefore(horizon, now); before != nil && !facts.WithdrawnAt.After(*before) {
			return RunAbandoned
		}
		return RunLapsed
	default:
		return RunActive
	}
}

// RunStateSQL is the same rule as RunStateOf, as a SQL expression.
//
// # Why a second rendering exists at all
//
// FD §7 requires the runs table to be filtered, counted and paged BY THE
// SERVER — "never ship-the-table-to-the-client" — and FD §3.2 wants that at
// millions of rows. A status computed in Go after the rows arrive cannot be a
// WHERE clause or a count(*) FILTER, so the read API needs the rule as an
// expression. Two renderings of one rule is the cost; the mitigation is that
// they are written side by side here and asserted to agree over every
// combination of the facts (REC-018).
//
// # What a caller must put in scope
//
// The expression names four columns and nothing else. A caller supplies them
// under exactly these names, with exactly these types:
//
//	retired           boolean      bool_or(event_type = 'run_retired')
//	withdrawn_at      timestamptz  max(ts) FILTER (WHERE event_type = 'run_expired')
//	last_activity_at  timestamptz  max(ts) FILTER (WHERE source IS DISTINCT FROM 'reaper')
//	abandoned_before  timestamptz  AbandonedBefore's instant, or NULL
//
// They are unqualified so that this stays one constant rather than a builder
// pasting table aliases into SQL. A caller whose query has a name collision
// aliases its own columns, and `abandoned_before` is conventionally a one-row
// CTE cross-joined in — see internal/api, which computes the cutoff ONCE per
// request so that every row of one answer is judged against one instant.
//
// `SQL NULL` stands for "no such fact", which is why the clause order below
// reads slightly differently from the Go: `last_activity_at IS NULL OR
// last_activity_at <= withdrawn_at` is RunFacts.WithdrawalStands, and
// `abandoned_before IS NOT NULL AND withdrawn_at <= abandoned_before` is
// AbandonedBefore's nil check followed by the same comparison.
const RunStateSQL = `CASE
     WHEN retired THEN '` + RunRetired + `'
     WHEN withdrawn_at IS NOT NULL
          AND (last_activity_at IS NULL OR last_activity_at <= withdrawn_at)
          THEN CASE WHEN abandoned_before IS NOT NULL
                         AND withdrawn_at <= abandoned_before
                    THEN '` + RunAbandoned + `' ELSE '` + RunLapsed + `' END
     ELSE '` + RunActive + `' END`

// DefaultRestoreHorizon is how long after a withdrawal a run may still be
// restored when the deployment names no other bound.
//
// It is `innsegl serve`'s own `--abandon-after` default, and it has to be the
// same number: the horizon that divides Lapsed from Abandoned on a dashboard
// is the horizon get_credential actually refuses a restore at, and two numbers
// that were meant to be one is a page saying "restorable" about a run the MCP
// will turn away.
//
// Deliberately DAYS. A short horizon is the defect this epic replaced — it
// killed working agents — and tuning the window only chooses which error to
// make.
const DefaultRestoreHorizon = 30 * 24 * time.Hour

// EnvRestoreHorizon is the environment variable the horizon is read from.
//
// One variable, read by every component that has an opinion about abandonment,
// is what keeps the horizon one number rather than several. A deployment that
// sets it gets the same answer from the query API, the reconciler and the MCP;
// a deployment that sets nothing gets DefaultRestoreHorizon in all of them.
const EnvRestoreHorizon = "INNSEGL_ABANDON_AFTER"

// RestoreHorizonFromEnv reads EnvRestoreHorizon, falling back to the default.
//
// Unset, unparsable and negative all land on the default rather than on zero:
// zero means "no horizon, a withdrawn run stays restorable until something
// ends it", which is a real setting a deployment can choose and not something
// a typo should select by accident. It is chosen by writing `0`, which parses.
func RestoreHorizonFromEnv() time.Duration {
	d, err := time.ParseDuration(os.Getenv(EnvRestoreHorizon))
	if err != nil || d < 0 {
		return DefaultRestoreHorizon
	}
	return d
}

// AbandonedBefore is the instant a withdrawal has to predate for its run to be
// past the horizon, or nil when the deployment set no horizon.
//
// Returned as an instant rather than applied as `now() - interval` so that a
// caller can compute it ONCE and judge every row of one answer against one
// instant. A page whose first row was measured against a different "now" than
// its last is a page that can show the same run twice in two states.
func AbandonedBefore(horizon time.Duration, now time.Time) *time.Time {
	if horizon <= 0 {
		return nil
	}
	at := now.Add(-horizon)
	return &at
}

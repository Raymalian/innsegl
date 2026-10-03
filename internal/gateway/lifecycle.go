// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// lifecycle.go is #379 (RM-234): the LifecyclePolicy the contract
// (lifecycle_contract.go) declares, and the two retirement paths ADR-0058
// decision 7 gives besides hand-back -- the session-end signal (7a, this
// file's SessionEnder) and the silence backstop (7c, this file's Backstop).
// Hand-back (7b) belongs to #377's tree linking, not here. Registration and
// restoration themselves -- what actually calls Registrar.Register or
// .Restore off a Decision -- are #380's identity Guard; this file decides
// and retires, and performs neither register nor restore.
//
// # Continue/Restore versus Fork/Adopt, told apart with no extra field
//
// LifecycleInput carries exactly one prior mapping row (Prior) and one flag
// (Found) -- there is no separate "matched by fingerprint" bit. The
// contract's own MappingStore says why none is needed: BySessionAgent is
// keyed on (sessionID, agentID), so whenever a caller fills Prior from that
// lookup, Prior.SessionID and Prior.AgentID are, by construction, the
// request's own. A caller that instead falls back to ByFingerprint (because
// BySessionAgent found nothing) can only be filling Prior from a DIFFERENT
// (sessionID, agentID) -- if it were the same one, BySessionAgent would
// already have found it. So this file tells the two apart the only way the
// input allows: by comparing Prior's own (SessionID, AgentID) to
// LifecycleInput.ID's. Equal means the request is its own prior mapping's
// continuation (Continue, Restore, or -- if that same run is now retired --
// Adopt); unequal means Prior is another session's run that this
// conversation's fingerprint happens to match (Fork, or Adopt if that other
// run is retired).
//
// # Abandoned decides the same way retired does, and that is a choice made
// HERE, not a seventh row the decision table names
//
// ADR-0058's decision table (issue #379's own text) names six outcomes;
// ADR-0052's four ledger states include a fourth, "abandoned", that none of
// the six mentions by name. Abandoned is not death and it is not
// retirement -- no `run_retired` is on the chain -- but ADR-0052 is exact
// about what it DOES mean: "this deployment will no longer mint for the
// run." A run this deployment will not mint for cannot be Continued
// (nothing to continue: get_credential would refuse) and cannot be Restored
// (the one thing "abandoned" says is that restoration has stopped). The
// only two outcomes left in the table that do not require minting for the
// old run are Adopt and Refuse, and Refuse is for input this policy cannot
// read at all, not for a state it read cleanly and has an answer for. So
// PriorState == ledger.RunAbandoned decides Adopt, exactly as
// ledger.RunRetired does, and ADR-0058 decision 7's own closing lines
// license exactly this: the backstop and ADR-0052's abandon horizon are
// "independent settings; neither ADR supersedes the other," and under the
// stated defaults the backstop (seven days) fires before abandonment
// (thirty) would ever be reached -- so a deployment that raised the
// backstop's horizon past the abandon horizon is the only one that ever
// asks this policy about an abandoned prior, and this is the answer it
// gets.
//
// # Unset refuses
//
// DecisionRefuse is the contract's own zero value, and this policy earns
// that rather than relying on it by accident: a LifecycleInput this policy
// was never actually handed for a real request has a zero Identification,
// and harness.go's own contract for Identification is that AgentID is
// "never empty for a recognised request" (mainAgentID, "main", stands in
// for the root). A recognised request's SessionID is likewise never empty
// -- HarnessGuard refuses before either could be. So an empty SessionID or
// AgentID is not a shape a live request can carry; it can only be a
// LifecycleInput nobody filled in, and that refuses before this policy asks
// anything else of it.
//
// # What this file does not own
//
// Registrar's own implementation (register_agent / retire_agent wiring),
// MappingStore's own implementation, and TreeLinker's own implementation
// belong to #376, #378 and #377 respectively -- this file consumes those
// three interfaces and defines none of them. guard.go, proxy.go and cmd/ are
// #380's to wire a Decision into an actual Guard; nothing here reaches an
// HTTP request or a command-line flag.

// ---------------------------------------------------------------------------
// The decision table (GID-010).
// ---------------------------------------------------------------------------

// Policy is the LifecyclePolicy this issue ships. It holds no state of its
// own: every Decide call reads only the LifecycleInput it is given, exactly
// as the contract requires ("LifecyclePolicy decides; it performs
// nothing").
type Policy struct{}

// NewPolicy returns the shipped LifecyclePolicy.
func NewPolicy() Policy { return Policy{} }

// Policy satisfies the contract; a drift in either fails to compile here,
// the same guarantee lifecycle_fakes_test.go already gives its own fakes.
var _ LifecyclePolicy = Policy{}

// Decide implements LifecyclePolicy. See this file's own doc comment for
// how Continue/Restore are told apart from Fork/Adopt, why an abandoned
// prior decides Adopt, and why an unset input refuses.
func (Policy) Decide(_ context.Context, in LifecycleInput) (Decision, error) {
	// Unset, or a request no harness-shape guard ever recognised: refuse
	// before reading anything else this input claims.
	if in.ID.SessionID == "" || in.ID.AgentID == "" {
		return DecisionRefuse, nil
	}

	// No mapping row at all: a genuinely new run, whether this is the root
	// of a session (ParentRunID empty) or a child the TreeLinker already
	// resolved a parent for (ParentRunID set) -- the decision is New either
	// way; ParentRunID only shapes what #380 registers with, not which
	// Decision this call answers.
	if !in.Found {
		return DecisionNew, nil
	}

	// Found, but with no run id to act on, is not a shape a real mapping
	// row takes (RunMapping.RunID is set on every Insert this package's own
	// contract describes) -- refuse rather than guess which run "found"
	// meant.
	if in.Prior.RunID == "" {
		return DecisionRefuse, nil
	}

	// See this file's doc comment: Prior's own (SessionID, AgentID) equal to
	// the request's own is what BySessionAgent guarantees and ByFingerprint
	// cannot, so this is the one comparison that tells a continuing prior
	// from a fingerprint match on another session's run.
	sameRun := in.Prior.SessionID == in.ID.SessionID && in.Prior.AgentID == in.ID.AgentID

	switch in.PriorState {
	case ledger.RunActive:
		if sameRun {
			return DecisionContinue, nil
		}
		return DecisionFork, nil
	case ledger.RunLapsed:
		if sameRun {
			return DecisionRestore, nil
		}
		return DecisionFork, nil
	case ledger.RunRetired, ledger.RunAbandoned:
		// Same run or fingerprint-matched, retired or abandoned: ADR-0058
		// decision 8, "resumption after retirement is adoption, never
		// revival" -- extended to abandoned by this file's own doc comment.
		return DecisionAdopt, nil
	default:
		// PriorState is empty or not one of ledger.RunStates: unreadable,
		// and this policy does not guess at a chain state it was not
		// handed correctly.
		return DecisionRefuse, nil
	}
}

// ---------------------------------------------------------------------------
// The silence backstop (GID-011, ADR-0058 decision 7c).
// ---------------------------------------------------------------------------

// DefaultBackstopHorizon is how long a run may stand silent -- measured from
// the newest fact ledger.RunFacts.DecidedAt would credit it with -- before
// Backstop.Sweep retires it through the Registrar. ADR-0058 decision 7c's
// own default: seven days.
//
// This is deliberately a SEPARATE number from ledger.DefaultRestoreHorizon
// (thirty days), not a second name for it: ADR-0058 decision 7's own closing
// lines call them "independent settings; neither ADR supersedes the other."
// Under both defaults the backstop fires first, so the common case never
// reaches ledger.RunAbandoned before this backstop retires the run; a
// deployment that raises this past the restore horizon is the one that
// changes that, on purpose.
const DefaultBackstopHorizon = 7 * 24 * time.Hour

// EnvBackstopHorizon is the environment variable a deployment sets to
// override DefaultBackstopHorizon, named to sit beside
// ledger.EnvRestoreHorizon in an operator's own configuration -- the same
// kind of knob, a different clock. Reading it into a running sweep is
// wiring this file deliberately leaves to whatever schedules Backstop.Sweep
// (#380 or later, not cmd/ here): this file only names the variable and
// validates whatever duration NewBackstop is handed.
const EnvBackstopHorizon = "INNSEGL_GATEWAY_SILENCE_AFTER"

// SilentRun is one run a Backstop sweep is asked to judge: its id, and the
// RunFacts internal/ledger/runstate.go already defines for it.
//
// Facts is read fresh off the chain by Sweep's caller, for every sweep --
// "the chain's own run state, never a stored status" (#379's own scope) is
// enforced by this type carrying nothing but what one read of the chain
// already produced, and by Backstop itself (below) holding no candidate
// list between calls.
type SilentRun struct {
	RunID string
	Facts ledger.RunFacts
}

// BackstopConfig configures a Backstop.
type BackstopConfig struct {
	// Registrar retires a run past the horizon. Required.
	Registrar Registrar
	// Horizon is how long a run may stand silent before Sweep retires it.
	// Zero means DefaultBackstopHorizon. A negative horizon is refused by
	// NewBackstop: unlike ledger's own restore horizon, where zero or less
	// is itself the deliberate "never restore-expire" setting (see
	// AbandonedBefore), there is no reading of a negative silence horizon
	// that means anything a deployment would choose on purpose.
	Horizon time.Duration
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// Backstop is ADR-0058 decision 7c's silence backstop: the one retirement
// source that ADR admits is an inference from silence rather than an
// observed signal, firing only when neither the session-end signal
// (SessionEnder, below) nor a subagent's hand-back (#377) arrived first.
type Backstop struct {
	registrar Registrar
	horizon   time.Duration
	now       func() time.Time
}

// NewBackstop builds a Backstop, or refuses -- the same "refuse rather than
// silently adjust" posture NewSessionRateLimiter (limit.go) already takes
// with this package's other configurable defaults.
func NewBackstop(cfg BackstopConfig) (*Backstop, error) {
	if cfg.Registrar == nil {
		return nil, errors.New(
			"innsegl gateway: backstop configuration: no Registrar; nothing could retire a silent run")
	}

	horizon := cfg.Horizon
	switch {
	case horizon == 0:
		horizon = DefaultBackstopHorizon
	case horizon < 0:
		return nil, fmt.Errorf(
			"innsegl gateway: backstop configuration: a silence horizon of %s admits nothing; "+
				"use a positive duration, or zero for the default (%s)", cfg.Horizon, DefaultBackstopHorizon)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	return &Backstop{registrar: cfg.Registrar, horizon: horizon, now: now}, nil
}

// Sweep retires, through the Registrar, every candidate whose newest fact
// (RunFacts.DecidedAt) is older than the configured horizon and that is not
// already retired. An already-retired candidate is skipped rather than
// retired again: Registrar.Retire is itself idempotent (the contract's own
// doc comment), but a sweep that only ever asks about runs it has reason to
// think are still open is a sweep whose cost tracks open runs, not every
// run this deployment has ever seen -- the same reasoning silence.go's own
// reaper gives for asking the ledger only about entries already past their
// deadline.
//
// Sweep continues past a Retire failure rather than stopping the whole
// sweep over one run: every error encountered is joined into the single
// error returned, and every run this call did successfully retire is named
// in retired regardless of whether a later candidate in the same sweep
// failed.
func (b *Backstop) Sweep(ctx context.Context, candidates []SilentRun) (retired []string, err error) {
	now := b.now()
	var errs []error
	for _, c := range candidates {
		if c.Facts.Retired {
			continue
		}
		if now.Sub(c.Facts.DecidedAt()) < b.horizon {
			continue
		}
		if _, retireErr := b.registrar.Retire(ctx, c.RunID); retireErr != nil {
			errs = append(errs, fmt.Errorf("retire silent run %q: %w", c.RunID, retireErr))
			continue
		}
		retired = append(retired, c.RunID)
	}
	return retired, errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// The session-end signal (GID-011, ADR-0058 decision 7a) -- MARK, then
// SWEEP, never an immediate retirement (#380 code review, 2026-09-28).
//
// # The threat this redesign answers
//
// The signal arrives over a loopback-only HTTP endpoint (cmd/innsegl's
// sessionEndHandler) that ADR-0060 decision 2 protects by network
// segmentation alone -- the same guarantee the whole gateway rests on. But
// ADR-0060 decision 7 is explicit that the host carries the harness's own
// hooks as ordinary processes under the OPERATOR'S OWN USER, and nothing
// stops an AGENT process -- which runs as that same user -- from reaching
// the identical loopback port with the identical, non-existent credential a
// genuine hook would have. There is no way for this gateway to tell "the
// session-end hook" apart from "an agent that read or guessed a session
// id"; the two are indistinguishable callers of one unauthenticated local
// socket. So the signal itself has to be SAFE TO FORGE, because it cannot be
// verified.
//
// Retiring on receipt would fail that: an agent could end ANOTHER session's
// run merely by naming its session id, and retirement is permanent (ADR-0058
// decision 8, I4) -- a forged signal would be a false, PERMANENT record with
// no way back, exactly the failure this project exists to make impossible
// rather than merely unlikely.
//
// # Why mark-then-sweep makes forging harmless
//
// A signal only records that a session's main agent SAID it was ending; it
// does nothing else. SessionEnder.Sweep, called periodically, retires
// through the Registrar only the sessions whose signal has stood
// UNCANCELLED for a grace period (DefaultSessionEndGrace) -- and any request
// from that session's main agent in the meantime cancels it
// (SessionEndSignals.Cancel, called by the identity guard, identity.go). So:
//
//   - Forging a signal against a session that is genuinely still talking
//     costs nothing. The next real request -- and under ordinary traffic
//     there is one well inside a few minutes -- cancels the mark before the
//     grace period ever elapses. No retirement happens; nothing is recorded
//     that did not already have to be true.
//   - Forging a signal against a session that has genuinely gone quiet only
//     ACCELERATES, by the grace period, a retirement the ordinary silence
//     backstop (Backstop.Sweep, above) would have made in any case, for the
//     identical reason: silence. It never fabricates a retirement of a
//     session that is still active, which is the only kind of forgery that
//     would create a false record.
//
// Both cases are recorded by the caller as an operational log line
// (cmd/innsegl's sessionEndHandler, not this package: "nothing here logs"
// stays true of this file), so a flood of forged signals -- which retires
// nothing on its own -- is still visible to an operator, even though it is
// harmless.
// ---------------------------------------------------------------------------

// DefaultSessionEndGrace is how long a session-end signal stands before
// SessionEnder.Sweep retires the run it named, if nothing cancelled it
// first. Minutes, not days: this is not the silence backstop's own horizon
// (DefaultBackstopHorizon, seven days) and does not replace it -- a session
// that never signals at all is still caught by Backstop.Sweep on its own
// schedule. This grace period exists only to give a genuine signal's own
// retirement a moment to be pre-empted by traffic that arrives a beat
// later, which is precisely what makes a forged signal against a live
// session harmless (see this section's own doc comment above).
const DefaultSessionEndGrace = 3 * time.Minute

// EnvSessionEndGrace is the environment variable a deployment sets to
// override DefaultSessionEndGrace, named to sit beside EnvBackstopHorizon:
// the same kind of knob, a different clock.
const EnvSessionEndGrace = "INNSEGL_GATEWAY_SESSION_END_GRACE"

// DefaultMaxSessionEndSignals bounds SessionEndSignals' own table, the same
// reasoning DefaultMaxPendingSpawns gives tree.go's own bounded table: a
// session id here is harness-asserted and never authenticated (see this
// section's own doc comment), so an unbounded table is a memory-exhaustion
// vector open to exactly the same forging this redesign otherwise makes
// harmless.
const DefaultMaxSessionEndSignals = 4096

// sessionEndMark is one signal not yet acted on: when it arrived.
type sessionEndMark struct {
	signaledAt time.Time
}

// SessionEndSignals is the bounded, in-memory record of session-end signals
// that have not yet been swept -- session id to when its signal arrived.
// Safe for concurrent use. Shared between a SessionEnder (Mark, via
// SessionEnded, and Sweep) and the identity guard (Cancel, on every further
// request from a signalled session's main agent) -- that sharing is the
// whole of what makes a forged signal harmless, so the two are always
// wired onto the same instance in production (cmd/innsegl's
// openIdentityStack).
type SessionEndSignals struct {
	mu    sync.Mutex
	max   int
	order []string // session ids, oldest signal first
	marks map[string]sessionEndMark
	// store, when set (Persist), keeps marks across a restart.
	store SessionEndStore
	logf  func(format string, args ...any)
	queue chan SessionEndEvent
}

// NewSessionEndSignals builds an empty table. maxSignals bounds it; zero or
// less means DefaultMaxSessionEndSignals.
func NewSessionEndSignals(maxSignals int) *SessionEndSignals {
	if maxSignals <= 0 {
		maxSignals = DefaultMaxSessionEndSignals
	}
	return &SessionEndSignals{max: maxSignals, marks: make(map[string]sessionEndMark)}
}

// Mark records sessionID's signal as having arrived at now, restarting its
// grace period if one was already recorded -- a second signal for a session
// already marked is not a second, distinct entry. At capacity, the oldest
// DISTINCT session's mark is evicted to make room, the same "furthest from
// ever being useful" reasoning tree.go's own evictOldest already gives,
// applied to signal age instead of spawn age.
func (s *SessionEndSignals) Mark(sessionID string, now time.Time) {
	if sessionID == "" {
		return
	}
	s.mark(sessionID, now)
	s.record(SessionEndEvent{SessionID: sessionID, Kind: SessionEndSignalled, At: now})
}

// mark is Mark without the write, for Load.
func (s *SessionEndSignals) mark(sessionID string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.marks[sessionID]; !exists {
		if len(s.order) >= s.max && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.marks, oldest)
		}
		s.order = append(s.order, sessionID)
	}
	s.marks[sessionID] = sessionEndMark{signaledAt: now}
}

// Cancel removes sessionID's mark, if any -- what a request from that
// session's main agent does (identity.go's IdentityGuard.Check), and what
// Sweep itself does once a marked session's run has actually been acted on
// (retired, or found to have no run at all).
// CancelAgent removes a subagent's mark: what a request from that subagent
// does.
func (s *SessionEndSignals) CancelAgent(sessionID, agentID string) {
	s.Cancel(agentMarkKey(sessionID, agentID))
}

func (s *SessionEndSignals) Cancel(sessionID string) {
	s.mu.Lock()
	_, marked := s.marks[sessionID]
	s.remove(sessionID)
	s.mu.Unlock()
	if marked {
		s.record(SessionEndEvent{SessionID: sessionID, Kind: SessionEndCancelled, At: time.Now().UTC()})
	}
}

// remove deletes sessionID from both the map and the order slice. Called
// under s.mu.
func (s *SessionEndSignals) remove(sessionID string) {
	if _, ok := s.marks[sessionID]; !ok {
		return
	}
	delete(s.marks, sessionID)
	for i, id := range s.order {
		if id == sessionID {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// Due answers every session marked at least grace ago, as of now -- read,
// not consumed: Sweep removes each one it actually acts on, explicitly,
// rather than this call clearing them as a side effect a caller might not
// expect.
func (s *SessionEndSignals) Due(grace time.Duration, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var due []string
	for _, id := range s.order {
		if now.Sub(s.marks[id].signaledAt) >= grace {
			due = append(due, id)
		}
	}
	return due
}

// Len reports how many distinct sessions are currently marked -- the
// bounded table's own live size, for a test (or an operator metric) to read
// directly rather than infer.
func (s *SessionEndSignals) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.order)
}

// SessionEnder is ADR-0058 decision 7a's session-end signal, redesigned so
// that receiving one -- over a socket this gateway cannot authenticate --
// never itself retires anything. See this section's own doc comment for the
// threat this answers and why the design makes forging harmless.
type SessionEnder struct {
	signals   *SessionEndSignals
	mappings  MappingStore
	registrar Registrar
	grace     time.Duration
	now       func() time.Time
}

// NewSessionEnder builds a SessionEnder over signals, shared with whatever
// else needs to Cancel a mark (in production, the identity guard). grace is
// DefaultSessionEndGrace's own meaning; zero or less means the default. now
// is nil for time.Now.
func NewSessionEnder(signals *SessionEndSignals, mappings MappingStore, registrar Registrar, grace time.Duration, now func() time.Time) *SessionEnder {
	if grace <= 0 {
		grace = DefaultSessionEndGrace
	}
	if now == nil {
		now = time.Now
	}
	return &SessionEnder{signals: signals, mappings: mappings, registrar: registrar, grace: grace, now: now}
}

// SessionEnded records sessionID's own signal. It does not look anything up
// and it does not retire anything -- see this section's own doc comment for
// why a signal over an unauthenticated loopback socket must not act by
// itself. An empty session id is refused rather than marked: it could never
// name a real run either way, and marking it would only grow the table for
// nothing.
func (e *SessionEnder) SessionEnded(_ context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("innsegl gateway: session end: no session id")
	}
	e.signals.Mark(sessionID, e.now())
	return nil
}

// SubagentEnded marks one subagent of sessionID as finished (the harness's
// SubagentStop). Its run is retired after the same grace period, unless the
// subagent speaks again first (CancelAgent).
func (e *SessionEnder) SubagentEnded(_ context.Context, sessionID, agentID string) error {
	if sessionID == "" || agentID == "" || agentID == mainAgentID {
		return errors.New("innsegl gateway: subagent end: a session id and a subagent id are both needed")
	}
	e.signals.Mark(agentMarkKey(sessionID, agentID), e.now())
	return nil
}

// agentMarkKey is a subagent's mark in the same table as the sessions'. A
// session id never holds the separator (IsSessionID), so the two kinds of
// key cannot collide.
func agentMarkKey(sessionID, agentID string) string { return sessionID + agentMarkSep + agentID }

const agentMarkSep = "/"

// splitMarkKey answers a mark's session and, for a subagent's, its agent.
func splitMarkKey(key string) (sessionID, agentID string) {
	if i := strings.Index(key, agentMarkSep); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// SessionRuns is the optional MappingStore query that lets a session's end
// retire every agent of the session, not only its main agent.
type SessionRuns interface {
	// AgentsOfSession answers each agent's newest mapping in sessionID.
	AgentsOfSession(ctx context.Context, sessionID string) ([]RunMapping, error)
}

// Sweep retires, through the Registrar, the main-agent run of every session
// whose signal has stood uncancelled for at least the grace period --
// called periodically (cmd/innsegl's own ticker), the same shape
// Backstop.Sweep already takes for the silence horizon. A session the
// mapping store has never heard of, or one whose signal outlived its own
// usefulness for any other reason, has its mark cleared without an error:
// there is nothing left to retire, and clearing it stops Sweep asking about
// it again on the next tick.
//
// Sweep continues past one session's failure rather than stopping the whole
// sweep: every error is joined into the one returned, and every run this
// call did retire is named in retired regardless of a later failure in the
// same sweep -- the identical contract Backstop.Sweep already gives.
func (e *SessionEnder) Sweep(ctx context.Context) (retired []string, err error) {
	due := e.signals.Due(e.grace, e.now())
	var errs []error
	for _, key := range due {
		sessionID, agentID := splitMarkKey(key)
		runs, lookupErr := e.runsFor(ctx, sessionID, agentID)
		if lookupErr != nil {
			errs = append(errs, lookupErr)
			continue
		}
		failed := false
		for _, m := range runs {
			if _, retireErr := e.registrar.Retire(ctx, m.RunID); retireErr != nil {
				if m.AgentID == mainAgentID || agentID != "" {
					failed = true
				}
				errs = append(errs, fmt.Errorf("innsegl gateway: session end: retire run %q for "+
					"session %q: %w", m.RunID, sessionID, retireErr))
				continue
			}
			retired = append(retired, m.RunID)
		}
		// A subagent of an ended session that could not be retired (it may
		// already be) does not hold the session's mark: the main agent's run
		// decides, and the backstop is still there for the rest.
		if !failed {
			e.signals.Cancel(key)
		}
	}
	return retired, errors.Join(errs...)
}

// runsFor answers the runs a due mark retires: one subagent's, or for a
// session every agent's when the store can list them, else the main
// agent's alone.
func (e *SessionEnder) runsFor(ctx context.Context, sessionID, agentID string) ([]RunMapping, error) {
	if agentID == "" {
		if lister, ok := e.mappings.(SessionRuns); ok {
			all, err := lister.AgentsOfSession(ctx, sessionID)
			if err != nil {
				return nil, fmt.Errorf("innsegl gateway: session end: list the agents of session %q: %w", sessionID, err)
			}
			return all, nil
		}
		agentID = mainAgentID
	}
	m, found, err := e.mappings.BySessionAgent(ctx, sessionID, agentID)
	if err != nil {
		return nil, fmt.Errorf("innsegl gateway: session end: look up the run of agent %q in session %q: %w",
			agentID, sessionID, err)
	}
	if !found {
		return nil, nil
	}
	return []RunMapping{m}, nil
}

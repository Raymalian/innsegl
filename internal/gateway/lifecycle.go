// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
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
// The session-end signal (GID-011, ADR-0058 decision 7a).
// ---------------------------------------------------------------------------

// SessionEnder retires a session's main-agent run the moment the harness
// says the session ended -- ADR-0058 decision 7a, the first retirement
// source in the order that decision states, ahead of hand-back (7b, #377)
// and this file's own Backstop (7c). The host-side hook that calls
// SessionEnded is wired in E18 (#389); this type is only the method it
// calls, with no HTTP endpoint and no cmd/ wiring of its own.
type SessionEnder struct {
	mappings  MappingStore
	registrar Registrar
}

// NewSessionEnder builds a SessionEnder.
func NewSessionEnder(mappings MappingStore, registrar Registrar) *SessionEnder {
	return &SessionEnder{mappings: mappings, registrar: registrar}
}

// SessionEnded retires sessionID's main-agent run (harness.go's
// mainAgentID, "main" -- never a subagent's own id: a subagent has no
// session of its own to end, and ends by hand-back instead, decision 7b).
//
// A session the mapping store has never heard of -- one that ended before
// any request reached this gateway, or one whose main agent never spoke --
// retires nothing and answers nil: there is no run to retire, and looking
// one up is what answers that question, rather than assuming one exists
// ahead of asking.
func (e *SessionEnder) SessionEnded(ctx context.Context, sessionID string) error {
	m, found, err := e.mappings.BySessionAgent(ctx, sessionID, mainAgentID)
	if err != nil {
		return fmt.Errorf("innsegl gateway: session end: look up the main-agent run for session %q: %w",
			sessionID, err)
	}
	if !found {
		return nil
	}
	if _, err := e.registrar.Retire(ctx, m.RunID); err != nil {
		return fmt.Errorf("innsegl gateway: session end: retire run %q for session %q: %w",
			m.RunID, sessionID, err)
	}
	return nil
}

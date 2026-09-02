// SPDX-License-Identifier: Apache-2.0

// Package identity decides what an agent run's SPIFFE ID SAYS about the run.
//
// # The leak this package closes (RM-079, #116)
//
// doc 02 §5's SPIFFE ID grammar is
// spiffe://{trust_domain}/agent/{agent_type}/{task_id}/{run_id}, and the
// project's own example is
//
//	spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42
//
// That string is the URI SAN of the Fulcio certificate every commit is signed
// under. Under public Sigstore it is a PERMANENT PUBLIC RECORD, so `jira-118`
// — a ticket number — and `fix-ci` — the kind of work — leave the organisation
// forever. The same string is the `Agent-Identity` trailer, which is public in
// any public repository whatever the trust root is.
//
// `run_id` is already opaque: register_agent derives it as 128 bits of a
// digest. `agent_type` and `task_ref` are the two that carry meaning.
//
// # What changes, and what emphatically does not
//
// The grammar holds each segment to `[a-z0-9][a-z0-9-]{0,62}`. Eight hex
// digits satisfy that regex exactly as well as a ticket number does. So this
// package changes WHAT GOES INTO the two fields and never their shape:
//
//	before:  spiffe://innsegl.dev/agent/fix-ci/jira-118/run-850d52ce…
//	after:   spiffe://innsegl.dev/agent/a7f3c91b/e2d5f004/run-850d52ce…
//
// No PROTECTED SURFACE moves (doc 08 "Protected surfaces"): not the grammar,
// not the trailer keys, not the event schema's field names or enum values, not
// the canonical serialization, not a tool name or an error class. There is no
// new schema_version and no migration attestation, because nothing that is
// pinned changed.
//
// # The key generates; the ledger resolves
//
// This is the property worth stating on its own, because it would be easy to
// build the worse thing by accident.
//
// The deployment secret is needed to GENERATE a pseudonym. It is needed to
// RESOLVE one NEVER. Resolution — public pseudonym back to the real ticket —
// goes through the `run_registered` event, which carries the pseudonymous
// `spiffe_id` ALONGSIDE the real `agent_type` and the real `task_ref`. That one
// row IS the mapping; there is no second table.
//
// Two consequences follow, and both are the reason to build it this way:
//
//   - Losing or rotating the secret does not orphan history. Every past run is
//     still resolvable by anyone with read access to the ledger. A design that
//     needed the key to read the past would turn key loss into permanent data
//     loss.
//   - Nothing on a read path holds the secret. `get_credential`, `record_event`
//     and `retire_agent` work from the `spiffe_id` the ledger already recorded,
//     so a rotation cannot strand a live run either.
//
// Only `register_agent` (which mints the identity) and `sign_commit` (which
// must render the same task segment into the `Agent-Task` trailer) hold a
// Pseudonymiser.
//
// # What a collision means
//
// Eight hex digits are 32 bits, so two different task references can share a
// pseudonym at a birthday bound around 2^16 distinct references. Nothing breaks
// when they do: the run id still separates the SPIFFE IDs, the SPIRE entries
// and the ledger rows, and the real values are in the event. Ambiguity in the
// public record is this package's PURPOSE, not its failure mode.
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// Mode is how a deployment fills the SPIFFE ID's {agent_type} and {task_id}.
type Mode string

const (
	// ModePseudonymous puts a keyed pseudonym in each. It is the DEFAULT:
	// nothing is released, so there is no history to migrate, and the safe
	// default for a privacy control is the one that protects.
	ModePseudonymous Mode = "pseudonymous"

	// ModeLiteral puts the caller's own values in, which is what the system
	// did before RM-079. A deployment chooses it deliberately — for a private
	// repository where the commit was never public, and where the operator
	// judges the human legibility of `Agent-Task: JIRA-118` in `git log` worth
	// the Rekor entry — and it is never reached by omission.
	ModeLiteral Mode = "literal"
)

// The two fields this package pseudonymises. The strings are the event schema's
// own member names (doc 02 §3) — used here as HMAC DOMAIN SEPARATORS, not
// written anywhere — so an agent type and a task reference that read the same
// cannot pseudonymise to the same eight characters.
//
// Neither name contains a colon, and the separator is a colon, so no pair of
// (field, value) can spell another pair's preimage.
const (
	domainAgentType = "agent_type"
	domainTaskRef   = "task_ref"
)

// PseudonymLen is how many hex characters of the HMAC a pseudonym carries.
//
// Eight is 32 bits: enough that a pseudonym is not enumerable from the outside
// against any realistic ticket-reference space, short enough to stay legible in
// a SPIFFE ID an operator has to read in a log line, and far inside doc 02 §5's
// 63-character bound.
const PseudonymLen = 8

// MinSecretBytes is the shortest deployment secret this package will key an
// HMAC with.
//
// The pseudonym publishes 32 bits of HMAC output. An adversary who holds one
// (value, pseudonym) pair — and a task reference is often guessable — can test
// candidate keys offline against it. That makes the key's own entropy the
// thing protecting every other pseudonym, so a short one is refused rather
// than accepted with a warning nobody reads. 16 bytes is 128 bits if the
// operator generated it rather than typed it, which is what the deployment
// documentation tells them to do.
const MinSecretBytes = 16

// Pseudonymiser maps a caller's agent type and task reference onto the values
// that go into the SPIFFE ID. Its zero value is not usable; build one with New.
type Pseudonymiser struct {
	mode   Mode
	secret []byte
}

// New builds a Pseudonymiser for a deployment, or refuses.
//
// Every refusal here is a start-up refusal, on the same principle
// ConfigureRegisterAgent applies: an operator finds out when the process
// starts, not when an agent registers.
//
// The one that matters is an EMPTY SECRET IN PSEUDONYMOUS MODE. Three things
// could have been done with it and two of them are traps:
//
//   - Fall back to literal values. The configuration would say the deployment
//     is pseudonymous while every ticket number went into Rekor. This project
//     has shipped a default meaning "no protection" that looked like a
//     considered choice twice; this is not the third.
//   - Generate a random secret per process. The pseudonym would then change on
//     every restart and differ between replicas, so one run's replayed
//     register_agent would derive a SECOND SPIFFE ID for the run id it already
//     minted — SPIRE would hold two entries for one run, which is IP §1's
//     invariant broken by a privacy feature.
//   - Refuse. The deployment does not start, the operator sets a secret or
//     writes `literal` on purpose, and neither failure above can happen.
//
// It refuses.
func New(mode Mode, secret string) (*Pseudonymiser, error) {
	switch mode {
	case ModeLiteral:
		if secret != "" {
			return nil, fmt.Errorf(
				"identity mode %q was given a %d-byte secret: an operator who set a secret "+
					"asked for pseudonyms, and ignoring it would put every ticket reference "+
					"in the certificate while the configuration said otherwise. Set mode %q, "+
					"or unset the secret",
				mode, len(secret), ModePseudonymous)
		}
		return &Pseudonymiser{mode: mode}, nil

	case ModePseudonymous:
		if len(secret) < MinSecretBytes {
			return nil, fmt.Errorf(
				"identity mode %q needs a deployment secret of at least %d bytes and was "+
					"given %d: without one the SPIFFE ID and the Agent-Identity trailer carry "+
					"the ticket reference into a permanent public record. Set the secret, or "+
					"choose mode %q deliberately to keep the literal values",
				mode, MinSecretBytes, len(secret), ModeLiteral)
		}
		return &Pseudonymiser{mode: mode, secret: []byte(secret)}, nil

	default:
		return nil, fmt.Errorf(
			"identity mode %q is neither %q nor %q; a mode this package does not implement "+
				"is a configuration typo, and guessing which was meant is how a deployment "+
				"ends up literal by accident",
			mode, ModePseudonymous, ModeLiteral)
	}
}

// Mode reports which mode the deployment is in. It is here so that a wiring
// site can log the choice at start-up: a privacy control nobody can see the
// state of is one nobody can audit.
func (p *Pseudonymiser) Mode() Mode { return p.mode }

// AgentType returns the {agent_type} segment for a caller's agent type.
//
// The caller's value is checked against doc 02 §5's grammar FIRST, in both
// modes. Pseudonymisation maps anything at all onto eight hex digits and would
// happily carry a 4 KB agent type or one with a slash in it; admitting those
// would make `pseudonymous` a wider tool contract than `literal`, and MCP-001
// pins one contract.
func (p *Pseudonymiser) AgentType(agentType string) (string, error) {
	if err := event.ValidateIdentifier(agentType); err != nil {
		return "", fmt.Errorf("agent_type: %w", err)
	}
	return p.render(domainAgentType, agentType), nil
}

// TaskID returns the {task_id} segment for a caller's task reference.
//
// The reference is LOWERCASED before it is checked and before it is
// pseudonymised, which is what register_agent did to it before RM-079 and is
// kept for two reasons: doc 02 §5's grammar has no upper case, and one ticket
// written two ways must be one identity rather than two.
//
// The caller's own casing survives untouched in the event's `task_ref`; that
// split is golden fixture 01's, and it is not this package's to change.
func (p *Pseudonymiser) TaskID(taskRef string) (string, error) {
	lowered := strings.ToLower(taskRef)
	if err := event.ValidateIdentifier(lowered); err != nil {
		return "", fmt.Errorf("task_id %q once lowercased: %w", taskRef, err)
	}
	return p.render(domainTaskRef, lowered), nil
}

// ClaimedTask returns what the `Agent-Task` commit trailer carries for a
// caller's task reference.
//
// It is NOT always TaskID, and the difference is the point of having two:
//
//   - `pseudonymous`: the pseudonym, identical to TaskID. The ticket number
//     leaves `git log` as well as the certificate. That is the cost RM-079
//     accepts — the attested link from a commit to a tracker is gone, and
//     resolving it needs the ledger or the dashboard.
//   - `literal`: the caller's reference with the caller's OWN CASING —
//     `JIRA-118`, not `jira-118`. That is what the trailer said before RM-079,
//     and reproducing it exactly is what makes `literal` an escape hatch
//     rather than a third behaviour.
//
// Both satisfy ADR-0018 §6: the trailer must LOWERCASE to the identity's
// {task_id} segment. That is the invariant check 3 relies on — a stranger
// compares Agent-Identity against the certificate, and the other two trailers
// are redundant with it by construction, so all three are settled at once.
func (p *Pseudonymiser) ClaimedTask(taskRef string) (string, error) {
	segment, err := p.TaskID(taskRef)
	if err != nil {
		return "", err
	}
	if p.mode == ModeLiteral {
		// The caller's own bytes, checked by TaskID above and returned
		// unchanged; strings.ToLower of them is `segment`.
		return taskRef, nil
	}
	return segment, nil
}

// render is the one place a segment is produced, in either mode.
//
// HMAC-SHA256 rather than a bare hash: the value is low-entropy and often
// guessable, so an unkeyed digest of `jira-118` would be reversible by anyone
// with a ticket-number generator, and a pseudonym anyone can reverse is not one.
func (p *Pseudonymiser) render(domain, value string) string {
	if p.mode == ModeLiteral {
		return value
	}
	mac := hmac.New(sha256.New, p.secret)
	// Neither domain contains a colon, so (domain, value) has exactly one
	// preimage and no pair of fields can be made to collide by choosing a
	// value that spells the other field's separator.
	mac.Write([]byte(domain + ":" + value))
	return hex.EncodeToString(mac.Sum(nil))[:PseudonymLen]
}

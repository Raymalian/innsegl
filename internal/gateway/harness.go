// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
)

// harness.go recognises ADR-0058's harness-asserted session and agent
// identification on an incoming request. Decision 2 of that ADR calls the
// header this file reads "harness-asserted, not attested by SPIRE" -- the
// same caveat ADR-0025 already states for register_agent's own arguments --
// so recognition here is deliberately narrow: a request either matches a
// harness version's recorded shape exactly, or it is refused (guard.go)
// rather than parsed loosely and guessed at. Recognised shapes are pinned
// as fixtures under testdata/harness/<harness>-<version>/ (GW-012); adding
// a harness version is adding a recogniser function below and a fixture
// directory, never loosening an existing recogniser.
//
// What is recognised today is Claude Code 2.1's model traffic, as measured
// in docs/decisions/model-gateway-spike.md on 2026-09-28: requests to the
// Anthropic Messages API, carrying Claude Code's own session header on
// every request and its own agent header only on a subagent's.

const (
	// headerClaudeCodeSessionID names the session every Claude Code 2.1
	// model request carries, main agent and subagent alike.
	headerClaudeCodeSessionID = "X-Claude-Code-Session-Id"
	// headerClaudeCodeAgentID names the header present only on a
	// subagent's request -- ADR-0058 decision 2: no header names the root
	// agent.
	headerClaudeCodeAgentID = "X-Claude-Code-Agent-Id"
)

// mainAgentID is Identification.AgentID for the root agent. Claude Code
// sends no header for it, and this package never leaves AgentID empty for a
// recognised request, so a later consumer keys or logs by it without a
// special case for the root.
const mainAgentID = "main"

// claudeCode21ModelPaths are the Anthropic Messages API paths Claude Code
// 2.1 sends model traffic to, matching the recorded fixtures under
// testdata/harness/claude-code-2.1/.
var claudeCode21ModelPaths = map[string]bool{
	"/v1/messages":              true,
	"/v1/messages/count_tokens": true,
}

// Identification is what a harness-shape guard extracts from a recognised
// request: which harness and version matched, and the (session, agent)
// pair ADR-0058 decision 2 says the traffic itself names. It is
// harness-asserted, not attested -- see this file's own doc comment -- and
// a later consumer that needs more than that caveat allows (identity,
// #375's rate limiting, E15's identity work) cross-checks it against an
// independent witness per ADR-0057, rather than trusting it alone.
type Identification struct {
	// Harness and Version name which recogniser matched, e.g.
	// "claude-code" and "2.1" -- see testdata/harness/claude-code-2.1/.
	Harness, Version string
	// SessionID is the session id every recognised request carries.
	SessionID string
	// AgentID is the subagent's own id, or mainAgentID ("main") for the
	// root agent. Never empty for a recognised request.
	AgentID string
}

// harnessRecogniser reports whether r matches one harness version's
// recorded request shape. ok is false if it does not; reason then names
// which part of the shape did not match, for the guard's refusal message
// (GW-011). A recogniser never guesses: on a false, it returns a zero
// Identification rather than a partly filled-in one.
type harnessRecogniser func(r *http.Request) (id Identification, ok bool, reason string)

// registeredRecognisers is every recogniser this build supports, tried in
// order by HarnessGuard (guard.go) until one matches. Adding a harness
// version is appending its recogniser here.
var registeredRecognisers = []harnessRecogniser{recogniseClaudeCode21}

const (
	reasonUnknownPath        = "the request path does not match a recognised model-traffic path"
	reasonMissingSessionID   = "the request carries no " + headerClaudeCodeSessionID + " header"
	reasonMalformedSessionID = "the " + headerClaudeCodeSessionID + " header is not a UUID"
	reasonMalformedAgentID   = "the " + headerClaudeCodeAgentID + " header is not an agent id"
)

// recogniseClaudeCode21 is testdata/harness/claude-code-2.1/'s recogniser:
// the Anthropic Messages API paths Claude Code 2.1 sends model traffic to,
// carrying its own session header on every request and its own agent
// header on a subagent's.
func recogniseClaudeCode21(r *http.Request) (Identification, bool, string) {
	if !claudeCode21ModelPaths[r.URL.Path] {
		return Identification{}, false, reasonUnknownPath
	}

	sessionID := r.Header.Get(headerClaudeCodeSessionID)
	if sessionID == "" {
		return Identification{}, false, reasonMissingSessionID
	}
	if !isUUID(sessionID) {
		return Identification{}, false, reasonMalformedSessionID
	}

	agentID := mainAgentID
	if raw := r.Header.Get(headerClaudeCodeAgentID); raw != "" {
		if !isAgentID(raw) {
			return Identification{}, false, reasonMalformedAgentID
		}
		agentID = raw
	}

	return Identification{
		Harness:   "claude-code",
		Version:   "2.1",
		SessionID: sessionID,
		AgentID:   agentID,
	}, true, ""
}

// IsSessionID reports whether s has the shape a recognised request's own
// session id must (isUUID, below) -- exported so a caller outside this
// package can refuse a malformed session id the same way a request's own
// session header already is, rather than duplicating the grammar.
// cmd/innsegl's session-end endpoint (#380) is the first such caller: a
// signal naming something that could never be a real session id is refused
// before it is ever marked.
func IsSessionID(s string) bool { return isUUID(s) }

// IsAgentID reports whether s has the shape of a subagent's own id (see
// isAgentID). The session-workspace endpoint checks a hook's agent_id with
// it, the same check the agent-id header gets.
func IsAgentID(s string) bool { return isAgentID(s) }

// isAgentID reports whether s has the shape of a subagent's own id: one to
// 64 lowercase letters, digits and hyphens, starting with a letter or digit.
// Claude Code 2.1.283 sends "a" plus 16 hex digits (measured 2026-09-29), and
// the bound is loose on purpose, like isUUID's: the header is a claim. One
// claim is refused outright: mainAgentID, the root agent's own mapping key,
// which no header may name.
func isAgentID(s string) bool {
	if s == "" || len(s) > 64 || s == mainAgentID || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// isUUID reports whether s is a UUID in its standard 8-4-4-4-12 hyphenated
// hex form (RFC 4122 §3). Neither version nor variant is checked: this
// gateway is verifying shape, not minting or validating identity --
// ADR-0058 decision 2 makes clear the header is a claim, not an attested
// value, and this package's job is to refuse an obviously wrong one, not to
// police the provider's UUID generator.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexDigit(s[i]) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// identificationContextKey is an unexported type so a value stored under it
// can never collide with a context key another package defines.
type identificationContextKey struct{}

// WithIdentification returns a copy of ctx carrying id, retrievable with
// IdentificationFromContext. HarnessGuard (guard.go) calls this for every
// request it recognises, so the request forwarded onward -- and any Guard
// or observer that runs after it in Proxy.Guards -- can read the
// (session, agent) pair without re-parsing headers of its own.
func WithIdentification(ctx context.Context, id Identification) context.Context {
	return context.WithValue(ctx, identificationContextKey{}, id)
}

// IdentificationFromContext returns the Identification a harness-shape
// guard attached to ctx, and whether one was found. A request that never
// passed a harness-shape guard -- or was refused by one -- carries none.
func IdentificationFromContext(ctx context.Context) (Identification, bool) {
	id, ok := ctx.Value(identificationContextKey{}).(Identification)
	return id, ok
}

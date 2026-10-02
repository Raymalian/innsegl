// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"unicode/utf8"

	"innsegl.dev/innsegl/internal/event"
)

// RM-314: a harness's agent-type names never refuse a subagent.
//
// Claude Code names subagent types as it likes: "Plan", "Explore",
// "flutter-all:flutter-architect". doc 02 §5's identifier grammar is
// protected, so the gateway folds the name (event.FoldIdentifier) before
// register_agent and keeps the harness's own string in the mapping row,
// outside the chain.
//
// Two sources name the type. The SubagentStart hook's agent_type is the
// harness's own statement about the agent it started; the spawning tool
// call's subagent_type is what the model asked for. The hook's wins. The
// model's is a witness: when the two fold to different types, that is a
// finding, never a refusal.

// AgentTypeFinding is a subagent whose hook-stated type and model-asked type
// disagree after folding.
type AgentTypeFinding struct {
	SessionID, AgentID string
	// Hook is the SubagentStart hook's agent_type, verbatim: the type
	// recorded. Model is the spawning tool call's subagent_type, verbatim.
	Hook, Model string
}

// maxAgentTypeVerbatimBytes bounds the harness string kept in the mapping
// row (migrations/0011's CHECK). It is unauthenticated input.
const maxAgentTypeVerbatimBytes = 256

// verbatimAgentType makes a harness string storable as text: valid UTF-8, no
// NUL (Postgres text refuses one), at most maxAgentTypeVerbatimBytes, cut on
// a character boundary. Anything else is kept as sent.
func verbatimAgentType(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\x00", "�")
	if len(s) <= maxAgentTypeVerbatimBytes {
		return s
	}
	cut := maxAgentTypeVerbatimBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// agentTypeFor is what this build records as RegisterInput.AgentType for a
// run the gateway registers from traffic alone (RM-263, #416; RM-314), and
// the harness string it came from (empty when none did).
//
// The root agent's type is the harness shape itself: Identification.AgentID
// is mainAgentID only for the root (harness.go's own recogniser never sets it
// to anything else), so that fixed value is recorded. A subagent's type is the
// hook's agent_type when it stated one, else spawnAgentType -- read from the
// spawning Agent/Task tool call's own subagent_type (identity.go's
// SpawnRecorder, resolved by the TreeLinker) -- folded into the identifier
// grammar. A subagent with neither falls back to defaultSubagentType, a
// stated placeholder, never id.AgentID: that is an opaque per-run id, not a
// type.
func (g *IdentityGuard) agentTypeFor(id Identification, hookAgentType, spawnAgentType string) (folded, verbatim string) {
	if id.AgentID == mainAgentID {
		return mainAgentID, ""
	}
	switch {
	case hookAgentType != "":
		if spawnAgentType != "" &&
			event.FoldIdentifier(spawnAgentType) != event.FoldIdentifier(hookAgentType) && g.onWitness != nil {
			g.onWitness(AgentTypeFinding{
				SessionID: id.SessionID, AgentID: id.AgentID,
				Hook: verbatimAgentType(hookAgentType), Model: verbatimAgentType(spawnAgentType),
			})
		}
		verbatim = hookAgentType
	case spawnAgentType != "":
		verbatim = spawnAgentType
	default:
		return defaultSubagentType, ""
	}
	return event.FoldIdentifier(verbatim), verbatimAgentType(verbatim)
}

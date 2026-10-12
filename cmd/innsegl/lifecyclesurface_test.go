// SPDX-License-Identifier: Apache-2.0

package main

import (
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/mcp"
)

// OPS-214 (#604, ADR-0083) — with no admin listener, the identity lifecycle is
// served nowhere.
//
// Before ADR-0083 an empty -admin-listen put register_agent, retire_agent and
// the other admin tools back on the agent listener, with no credential in
// front of them: anything that reached it could mint a run (doc 04 AB-13,
// AB-15). The split now always holds. The agent listener serves the agent
// tools only; the admin tools are served on -admin-listen when one is set, and
// otherwise not at all. The old behaviour survives only behind
// -lifecycle-on-agent-listener, which is named for what it does and refused
// beside an admin listener.
func TestOPS214NoAdminListenerServesNoLifecycleTool(t *testing.T) {
	t.Run("the default serves the agent tools only", func(t *testing.T) {
		got := agentListenerTools(serveOptions{})
		if !slices.Equal(got, mcp.AgentTools()) {
			t.Fatalf("with no admin listener the agent listener serves %v, want %v", got, mcp.AgentTools())
		}
		for _, admin := range mcp.AdminTools() {
			if slices.Contains(got, admin) {
				t.Errorf("%s is served on the agent listener with no admin listener", admin)
			}
		}
	})

	t.Run("an admin listener keeps the same agent surface", func(t *testing.T) {
		got := agentListenerTools(serveOptions{adminListen: "127.0.0.1:0"})
		if !slices.Equal(got, mcp.AgentTools()) {
			t.Fatalf("with an admin listener the agent listener serves %v, want %v", got, mcp.AgentTools())
		}
	})

	t.Run("the old behaviour needs its own flag", func(t *testing.T) {
		got := agentListenerTools(serveOptions{lifecycleOnAgentListener: true})
		if got != nil {
			t.Fatalf("-lifecycle-on-agent-listener serves %v on the agent listener, want every tool (nil)", got)
		}
	})

	t.Run("the flag beside an admin listener is refused", func(t *testing.T) {
		o := validServeOptions()
		o.adminListen, o.adminJWKS = "127.0.0.1:0", "jwks.json"
		o.lifecycleOnAgentListener = true
		problem := o.validate()
		if !strings.Contains(problem, "-lifecycle-on-agent-listener") {
			t.Fatalf("validate() = %q, want a refusal naming -lifecycle-on-agent-listener", problem)
		}
	})
}

// validServeOptions is the complete configuration
// TestValidateRefusesEveryUnusableCombination starts from.
func validServeOptions() serveOptions {
	return serveOptions{
		dsn: "postgres://x", spireAddress: "h:1", trustDomain: "innsegl.dev",
		parentID: "spiffe://innsegl.dev/spire/agent/x", fulcioURL: "http://f", rekorURL: "http://r",
		listen: "127.0.0.1:0", healthListen: "127.0.0.1:0",
		rateCalls: 1, rateWindow: 60_000_000_000,
		identityMode: "pseudonymous", identitySecret: testIdentitySecret,
	}
}

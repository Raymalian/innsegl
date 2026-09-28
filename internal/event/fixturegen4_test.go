// SPDX-License-Identifier: Apache-2.0

package event

import (
	"os"
	"path/filepath"
	"testing"
)

// The v4 golden fixture generator (ADR-0061, #407).
//
// Schema 4 changes nothing an existing event carries: run_registered's
// forked_from_run_id and tool_call's workspace_tree_hash are both optional, and
// the one new type, agent_message, has no v3 counterpart to derive from. So the
// v4 set is the v3 set -- minus v3's OWN 2 -> 3 migration attestation, for the
// same reason v3 excluded v2's -- re-versioned and re-chained, member for
// member, plus five vectors chained on the end: a run_registered demonstrating
// the fork member, a tool_call demonstrating the workspace-tree member, an
// agent_message for each role, and the attestation of the 3 -> 4 cutover.

const (
	v4ForkFixture              = "19-run_registered_fork"
	v4WorkspaceTreeFixture     = "20-tool_call_workspace_tree_hash"
	v4AgentMessageBriefFixture = "21-agent_message_brief"
	v4AgentMessageAssistant    = "22-agent_message_assistant"
	v4MigrationFixture         = "23-schema_migrated"

	// v4KeyID is the <key-id> component of the keyed grammar in the committed
	// vectors below. It names no real secret: this package never computes or
	// holds the HMAC key (E16, ADR-0061 decision 2).
	v4KeyID = "core-2026-09"

	v4BriefDigestInVector = "hmac-sha256:" + v4KeyID +
		":62e8aa0715ae5aa61bc2595c6afa0d6664ef799d9b3f50a8e2cb87b8e5639a67"
	v4AssistantDigestInVector = "hmac-sha256:" + v4KeyID +
		":da8e2466f8089a6d4e5346dfdfb1084225123c7dfd9749d55c9c603b03097fed"
	v4WorkspaceTreeHashInVector = "4e7bdba4a624a59b0b481e723b32f1998115a7c8"
)

func TestGenerateV4Fixtures(t *testing.T) {
	if os.Getenv("INNSEGL_WRITE_V4_FIXTURES") == "" {
		t.Skip("a generator, not a gate: set INNSEGL_WRITE_V4_FIXTURES=1 to rewrite " +
			"testdata/fixtures/v4, and read the README there before you do")
	}
	src := filepath.Join("testdata", "fixtures", "v3")
	dst := filepath.Join("testdata", "fixtures", "v4")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}

	prev := GenesisPrevEventHash()
	var position int64
	for _, name := range fixtureNamesIn(t, src) {
		// The probe is rewritten below under this version; the v3 attestation
		// records the 2 -> 3 cutover, which is not this set's.
		if name == "format-probe" || name == v3MigrationFixture {
			continue
		}
		f := loadFixtureFrom(t, src, name).input.Clone()
		f[FieldSchemaVersion] = SchemaVersion
		f[FieldPrevEventHash] = prev
		prev = writeV2Fixture(t, dst, name, f)
		if p := fixtureInt(t, f, FieldChainPosition); p > position {
			position = p
		}
	}

	// The fork: run-44's traffic-observed conversation fingerprint continues
	// run-40's, with no spawning tool call anywhere -- forked_from_run_id and
	// not parent_run_id (ADR-0058 decision 5, ADR-0061 decision 1).
	fork := loadFixtureFrom(t, src, "01-run_registered").input.Clone()
	fork[FieldSchemaVersion] = SchemaVersion
	fork[FieldEventID] = "01a047b2-1e4f-7b32-8d5a-6c9f3e8a7b21"
	fork[FieldIdempotencyKey] = "reg-8f21c-fork"
	fork[FieldChainPosition] = position + 1
	fork[FieldPrevEventHash] = prev
	fork[FieldRunID] = "run-44"
	fork[FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-44"
	fork[FieldForkedFromRunID] = "run-40"
	prev = writeV2Fixture(t, dst, v4ForkFixture, fork)

	// The workspace snapshot: the tree's state after the tool ran, evidence of
	// tree state rather than a claim of authorship (ADR-0061 decision 3,
	// Consequences).
	tc := loadFixtureFrom(t, src, "03-tool_call").input.Clone()
	tc[FieldSchemaVersion] = SchemaVersion
	tc[FieldEventID] = "01a047b2-1e4f-7b32-8d5a-6c9f3e8a7b22"
	tc[FieldIdempotencyKey] = "call-9c3f2-tree"
	tc[FieldChainPosition] = position + 2
	tc[FieldPrevEventHash] = prev
	tc[FieldWorkspaceTreeHash] = v4WorkspaceTreeHashInVector
	prev = writeV2Fixture(t, dst, v4WorkspaceTreeFixture, tc)

	// The brief: captured once at the gateway, keyed so that a party with
	// ledger or read-only-API access alone -- holding neither the body nor the
	// per-deployment secret -- cannot confirm a guess by hashing it
	// (ADR-0061 decision 2).
	brief := Fields{
		FieldSchemaVersion: SchemaVersion,
		FieldEventID:       "01a047b2-1e4f-7b32-8d5a-6c9f3e8a7b23",
		FieldChainPosition: position + 3,
		FieldEventType:     EventTypeAgentMessage,
		FieldTS:            "2026-09-28T12:00:00.000Z",
		FieldRunID:         "run-42",
		FieldSpiffeID:      "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
		FieldSource:        SourceMCP,
		FieldPrevEventHash: prev,
		FieldRole:          "brief",
		FieldPayloadDigest: v4BriefDigestInVector,
	}
	prev = writeV2Fixture(t, dst, v4AgentMessageBriefFixture, brief)

	// The agent's own message: same shape, the other role.
	assistant := brief.Clone()
	assistant[FieldEventID] = "01a047b2-1e4f-7b32-8d5a-6c9f3e8a7b24"
	assistant[FieldChainPosition] = position + 4
	assistant[FieldPrevEventHash] = prev
	assistant[FieldRole] = "assistant"
	assistant[FieldPayloadDigest] = v4AssistantDigestInVector
	prev = writeV2Fixture(t, dst, v4AgentMessageAssistant, assistant)

	// The migration attestation, last in the chain and last for a reason: it
	// records the position where events began carrying this version.
	att := loadFixtureFrom(t, src, v3MigrationFixture).input.Clone()
	att[FieldSchemaVersion] = SchemaVersion
	att[FieldEventID] = "01a047b2-1e4f-7b32-8d5a-6c9f3e8a7b25"
	att[FieldChainPosition] = position + 5
	att[FieldPrevEventHash] = prev
	att[FieldFromSchemaVersion] = "3"
	att[FieldToSchemaVersion] = SchemaVersion
	writeV2Fixture(t, dst, v4MigrationFixture, att)

	// The serializer's own probe, under this version's tags.
	writeProbeFixture(t, dst)
}

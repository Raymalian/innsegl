// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RPG-004: commit <-> step (hasPrefixSHA) and spawn <-> child linking
// (resolveSpawns), including a child's own commits.

func TestRPG004HasPrefixSHA(t *testing.T) {
	full := "c906a8c4b1f2e3d4a5b6c7d8e9f0a1b2c3d4e5f6"
	if !hasPrefixSHA(full, "c906a8c") {
		t.Error("a genuine prefix should match")
	}
	if hasPrefixSHA(full, "d906a8c") {
		t.Error("a non-prefix must not match")
	}
	if hasPrefixSHA(full, full+"more") {
		t.Error("a short longer than the full sha must not match")
	}
}

// writeBriefBody writes an agent_message-shaped body (plain text, content
// addressed by its own sha256, matching internal/mcp/agentmessage.go's own
// layout) under dir/runID.
func writeBriefBody(t *testing.T, dir, runID, text string) {
	t.Helper()
	runDir := filepath.Join(dir, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(text))
	name := hex.EncodeToString(sum[:]) + ".json"
	if err := os.WriteFile(filepath.Join(runDir, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// jsonString quotes s as a JSON string literal, for building inline JSON
// test fixtures. json.Marshal cannot fail on a plain Go string; the error
// is handled rather than discarded only to satisfy this codebase's own
// check-blank discipline.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func digestOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestRPG004ResolveSpawnsMatchesByExactBriefText(t *testing.T) {
	dir := t.TempDir()
	prompt := "do the one true thing"

	stepBodyBytes := marshalBody(t, gatewayBody{
		Tool: "Agent", Input: json.RawMessage(`{"subagent_type":"x","prompt":` + jsonString(prompt) + `}`),
	})
	digest := digestOf(stepBodyBytes)
	writeAgentStepBodyRaw(t, dir, "run-parent", digest, stepBodyBytes)
	writeBriefBody(t, dir, "run-child", prompt)

	rs := &recordServer{}
	steps := []toolCallStepRef{{N: 3, EventID: "evt-3", Tool: "Agent", Digest: digest}}
	children := []familyNode{{RunID: "run-child", RegisteredAt: time.Now()}}

	matches := rs.resolveSpawns(dir, "run-parent", steps, children)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
	}
	if matches[0].ChildRunID != "run-child" || matches[0].StepN != 3 {
		t.Errorf("match = %+v, want ChildRunID=run-child StepN=3", matches[0])
	}
}

func TestRPG004ResolveSpawnsNeverGuessesWithoutAMatch(t *testing.T) {
	dir := t.TempDir()
	prompt := "do the one true thing"
	stepBodyBytes := marshalBody(t, gatewayBody{
		Tool: "Agent", Input: json.RawMessage(`{"subagent_type":"x","prompt":` + jsonString(prompt) + `}`),
	})
	digest := digestOf(stepBodyBytes)
	writeAgentStepBodyRaw(t, dir, "run-parent", digest, stepBodyBytes)
	// The child's own directory holds nothing matching this exact prompt.
	writeBriefBody(t, dir, "run-child", "a completely different brief")

	rs := &recordServer{}
	steps := []toolCallStepRef{{N: 1, EventID: "evt-1", Tool: "Agent", Digest: digest}}
	children := []familyNode{{RunID: "run-child", RegisteredAt: time.Now()}}

	matches := rs.resolveSpawns(dir, "run-parent", steps, children)
	if len(matches) != 0 {
		t.Fatalf("got %d matches, want 0 — a single parent and a single child is not evidence of a link: %+v",
			len(matches), matches)
	}
}

func TestRPG004ResolveSpawnsFIFOAmongIdenticalPrompts(t *testing.T) {
	dir := t.TempDir()
	prompt := "identical brief"
	bodyA := marshalBody(t, gatewayBody{Tool: "Agent", Input: json.RawMessage(`{"prompt":` + jsonString(prompt) + `}`)})
	digestA := digestOf(bodyA)
	writeAgentStepBodyRaw(t, dir, "run-parent", digestA, bodyA)

	writeBriefBody(t, dir, "run-child-1", prompt)
	writeBriefBody(t, dir, "run-child-2", prompt)

	rs := &recordServer{}
	steps := []toolCallStepRef{{N: 1, EventID: "evt-1", Tool: "Agent", Digest: digestA}}
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	children := []familyNode{
		{RunID: "run-child-2", RegisteredAt: newer},
		{RunID: "run-child-1", RegisteredAt: older},
	}
	// resolveSpawns matches in the ORDER children is given; callers sort by
	// RegisteredAt first (buildRunRecord does). Sorted oldest-first here:
	sorted := []familyNode{children[1], children[0]}
	matches := rs.resolveSpawns(dir, "run-parent", steps, sorted)
	if len(matches) != 1 || matches[0].ChildRunID != "run-child-1" {
		t.Fatalf("matches = %+v, want the OLDEST child (run-child-1) matched first", matches)
	}
}

// ---------------------------------------------------------------------------
// #443 (RM-278) rule 2b: hook spawn linking by agent id.
// ---------------------------------------------------------------------------

// writeHookAgentStepBody writes a hook-shaped Agent-tool step body (the
// parent's own), with a description/prompt/model input and a
// tool_response.agentId.
func writeHookAgentStepBody(t *testing.T, dir, runID, toolUseID, description, prompt, model, spawnedAgentID string) string {
	t.Helper()
	input := fmt.Sprintf(`{"description":%s,"prompt":%s,"model":%s}`, jsonString(description), jsonString(prompt), jsonString(model))
	response := fmt.Sprintf(`{"agentId":%s,"content":"spawned"}`, jsonString(spawnedAgentID))
	raw := []byte(fmtHookBody(t, toolUseID, "Agent", input, response))
	digest := digestOf(raw)
	writeAgentStepBodyRaw(t, dir, runID, digest, raw)
	return digest
}

// writeHookChildBody writes one hook-shaped body for a child run, carrying
// the envelope's own top-level agent_id — childAgentID's own evidence.
func writeHookChildBody(t *testing.T, dir, runID, toolUseID, agentID string) {
	t.Helper()
	raw := []byte(fmtHookBody(t, toolUseID, "Bash", `{"command":"true"}`, `{"stdout":"","stderr":"","interrupted":false}`))
	// fmtHookBody's own envelope hardcodes agent_id "agent-1"; a scenario
	// that needs a DIFFERENT agent id builds its own envelope instead of
	// reusing that helper.
	if agentID != "agent-1" {
		raw = []byte(fmt.Sprintf(`{"hook_event_name":"PostToolUse","tool_use_id":%s,"tool_name":"Bash",`+
			`"tool_input":{"command":"true"},"tool_response":{"stdout":"","stderr":"","interrupted":false},"agent_id":%s}`,
			jsonString(toolUseID), jsonString(agentID)))
	}
	digest := digestOf(raw)
	writeAgentStepBodyRaw(t, dir, runID, digest, raw)
}

func TestRM278ResolveHookSpawnsMatchesByAgentID(t *testing.T) {
	dir := t.TempDir()
	digest := writeHookAgentStepBody(t, dir, "run-parent", "toolu_agent1",
		"do the subtask", "the spawn prompt", "sonnet", "agent-child-1")
	writeHookChildBody(t, dir, "run-child", "toolu_child1", "agent-child-1")

	rs := &recordServer{}
	steps := []toolCallStepRef{{N: 2, EventID: "evt-2", Tool: "Agent", Digest: digest}}
	children := []familyNode{{RunID: "run-child", RegisteredAt: time.Now()}}

	matches := rs.resolveHookSpawns(dir, "run-parent", steps, children)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.ChildRunID != "run-child" || m.StepN != 2 || m.LinkedBy != "agent_id" {
		t.Errorf("match = %+v, want ChildRunID=run-child StepN=2 LinkedBy=agent_id", m)
	}
	if m.Title != "do the subtask" || m.Prompt != "the spawn prompt" || m.Model != "sonnet" {
		t.Errorf("match = %+v, want the Agent step's own description/prompt/model", m)
	}
}

func TestRM278ResolveHookSpawnsNoMatchWithoutAnAgentIDAgreement(t *testing.T) {
	dir := t.TempDir()
	digest := writeHookAgentStepBody(t, dir, "run-parent", "toolu_agent1",
		"do the subtask", "the spawn prompt", "sonnet", "agent-child-1")
	writeHookChildBody(t, dir, "run-child", "toolu_child1", "agent-SOMETHING-ELSE")

	rs := &recordServer{}
	steps := []toolCallStepRef{{N: 1, EventID: "evt-1", Tool: "Agent", Digest: digest}}
	children := []familyNode{{RunID: "run-child", RegisteredAt: time.Now()}}

	matches := rs.resolveHookSpawns(dir, "run-parent", steps, children)
	if len(matches) != 0 {
		t.Fatalf("got %d matches, want 0 — the agent ids disagree: %+v", len(matches), matches)
	}
}

func TestChildAgentIDReadsOnlyOneBody(t *testing.T) {
	dir := t.TempDir()
	writeHookChildBody(t, dir, "run-child", "toolu_1", "agent-42")

	id, ok := childAgentID(dir, "run-child")
	if !ok || id != "agent-42" {
		t.Errorf("childAgentID = %q, %v; want agent-42, true", id, ok)
	}

	if _, ok := childAgentID(dir, "run-does-not-exist"); ok {
		t.Error("childAgentID should answer false for a run with no retained bodies")
	}
}

func TestResolveChildLinksCombinesBriefAndAgentID(t *testing.T) {
	dir := t.TempDir()

	// One child linked by the exact brief match (rule 2a).
	briefDigest := digestOf(marshalBody(t, gatewayBody{
		Tool: "Agent", Input: json.RawMessage(`{"description":"brief child","prompt":"the brief prompt","model":"opus"}`),
	}))
	writeAgentStepBodyRaw(t, dir, "run-parent", briefDigest,
		marshalBody(t, gatewayBody{Tool: "Agent", Input: json.RawMessage(`{"description":"brief child","prompt":"the brief prompt","model":"opus"}`)}))
	writeBriefBody(t, dir, "run-child-brief", "the brief prompt")

	// One child linked by agent id (rule 2b).
	hookDigest := writeHookAgentStepBody(t, dir, "run-parent", "toolu_agent2",
		"hook child", "the hook prompt", "sonnet", "agent-hook-1")
	writeHookChildBody(t, dir, "run-child-hook", "toolu_hc1", "agent-hook-1")

	rs := &recordServer{}
	steps := []toolCallStepRef{
		{N: 1, EventID: "evt-1", Tool: "Agent", Digest: briefDigest},
		{N: 2, EventID: "evt-2", Tool: "Agent", Digest: hookDigest},
	}
	children := []familyNode{
		{RunID: "run-child-brief", RegisteredAt: time.Now()},
		{RunID: "run-child-hook", RegisteredAt: time.Now()},
		{RunID: "run-child-unmatched", RegisteredAt: time.Now()},
	}

	links := rs.resolveChildLinks(dir, "run-parent", steps, children)
	if len(links) != 2 {
		t.Fatalf("got %d links, want 2: %+v", len(links), links)
	}
	if m := links["run-child-brief"]; m.LinkedBy != "brief" || m.StepN != 1 || m.Title != "brief child" {
		t.Errorf("run-child-brief link = %+v", m)
	}
	if m := links["run-child-hook"]; m.LinkedBy != "agent_id" || m.StepN != 2 || m.Title != "hook child" {
		t.Errorf("run-child-hook link = %+v", m)
	}
	if _, ok := links["run-child-unmatched"]; ok {
		t.Error("run-child-unmatched should not be linked by either rule")
	}
}

// writeAgentStepBodyRaw writes a pre-marshaled body under its own digest —
// used where a test needs the EXACT bytes it already hashed, rather than
// writeAgentStepBody's own convenience shape.
func writeAgentStepBodyRaw(t *testing.T, dir, runID, digest string, body []byte) {
	t.Helper()
	runDir := filepath.Join(dir, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hexPart, _ := splitDigestHex(digest)
	if err := os.WriteFile(filepath.Join(runDir, hexPart+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

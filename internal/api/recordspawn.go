// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
)

// recordspawn.go links a parent run's own Agent-tool steps to the children
// they spawned — record.go's RecordStep.SpawnedRunID/SpawnedCommits and
// RecordTreeNode.SpawnedBy — by the one rule ADR-0058 decision 3 itself
// uses: EXACT EQUALITY between the spawn's own prompt and the child's
// brief, re-derived from the retained bodies on disk rather than read off
// the gateway's own (long gone, in-memory) linker. See recordbody.go's
// spawnBodyMatches for why this needs no secret.
//
// Matching is greedy and FIFO on both sides — candidate Agent steps in
// chain order, candidate children in registration order — the same tie
// break internal/gateway/tree.go gives two parents spawning an identical
// prompt: "the oldest spawn is matched first". A step or a child matched
// once is never matched again.

// toolCallStepRef is one tool_call of a run, numbered 1..N in chain order —
// enough to resolve RecordTreeNode.SpawnedBy for ANY family member without
// reading its whole record.
type toolCallStepRef struct {
	N       int
	EventID string
	Tool    string
	Digest  string
}

// toolCallStepsFromRows derives toolCallStepRef for the PRIMARY run from its
// own already-read timeline — never a second query for the one run this
// handler reads in full.
func toolCallStepsFromRows(rows []recordEventRow) []toolCallStepRef {
	var out []toolCallStepRef
	n := 0
	for _, r := range rows {
		if r.EventType != "tool_call" {
			continue
		}
		n++
		out = append(out, toolCallStepRef{
			N: n, EventID: r.EventID,
			Tool:   stringOf(r.Body[toolCallToolNameField]),
			Digest: stringOf(r.Body[toolCallDigestField]),
		})
	}
	return out
}

// toolCallToolNameField and toolCallDigestField spell the two canonical
// field names this file reads out of a decoded event body — the same
// strings event.FieldToolName and event.FieldPayloadDigest name, restated
// as constants here so this file has no import cycle concern and reads
// identically whether the body came from a fresh query or from rows this
// handler already holds.
const (
	toolCallToolNameField = "tool_name"
	toolCallDigestField   = "payload_digest"
)

// spawnMatch is one resolved (parent step) -> (child run) link. Title,
// Prompt and Model (#443, RM-278) are the matched step's own input,
// read once at match time rather than re-read by every caller that wants
// them (record.go's RecordAgent/RecordAncestor/RecordChild all do).
type spawnMatch struct {
	StepN       int
	StepEventID string
	ChildRunID  string
	// LinkedBy is "brief" (resolveSpawns) or "agent_id" (resolveHookSpawns)
	// — record.go's RecordAgent.LinkedBy.
	LinkedBy string
	Title    string
	Prompt   string
	Model    string
}

// resolveSpawns matches parentSteps (this parent's own tool_call steps, in
// chain order) against children (this parent's own children, in
// registration order), reading each Agent-tool step's own prompt from its
// retained body and checking it against each unmatched child's own retained
// bodies. logDir == "" (no body store configured) answers no matches at
// all — never a guess from mere counts or ordering alone, however tempting
// a 1:1 case would be to assume.
func (rs *recordServer) resolveSpawns(
	logDir, parentRunID string, parentSteps []toolCallStepRef, children []familyNode,
) []spawnMatch {
	if logDir == "" || len(children) == 0 {
		return nil
	}
	remaining := make([]familyNode, len(children))
	copy(remaining, children)

	// Each child's stored body names, listed once (#440). Checking a prompt
	// by opening its file under every child cost one filesystem lookup per
	// spawn per child: measured, ~1.7 s for a 132-child family on a bind
	// mount. A name only narrows the candidates; the bytes are still compared.
	names := make(map[string]map[string]bool, len(children))
	for _, child := range children {
		set := map[string]bool{}
		if entries, err := os.ReadDir(filepath.Join(logDir, filepath.Base(child.RunID))); err == nil {
			for _, e := range entries {
				set[e.Name()] = true
			}
		}
		names[child.RunID] = set
	}

	var matches []spawnMatch
	for _, step := range parentSteps {
		if step.Tool != "Agent" || step.Digest == "" {
			continue
		}
		body, ok := stepBody(logDir, parentRunID, step.Digest)
		if !ok {
			continue
		}
		prompt, ok := agentPromptOf(body.Input)
		if !ok {
			continue
		}
		sum := sha256.Sum256([]byte(prompt))
		name := hex.EncodeToString(sum[:]) + ".json"
		for i, child := range remaining {
			if child.RunID == "" || !names[child.RunID][name] {
				continue
			}
			if spawnBodyMatches(logDir, child.RunID, prompt) {
				in, _ := agentSpawnInputOf(body.Input)
				matches = append(matches, spawnMatch{
					StepN: step.N, StepEventID: step.EventID, ChildRunID: child.RunID,
					LinkedBy: "brief", Title: in.Description, Prompt: in.Prompt, Model: in.Model,
				})
				remaining = append(remaining[:i], remaining[i+1:]...)
				break
			}
		}
		if len(remaining) == 0 {
			break
		}
	}
	return matches
}

// ---------------------------------------------------------------------------
// #443 (RM-278) rule 2b: a hook-recorded child is linked to its spawning
// Agent step by the harness's own agent id, not by the brief/prompt text
// resolveSpawns matches on — a hook body never carries the content-
// addressed brief ADR-0058 decision 3 needs.
// ---------------------------------------------------------------------------

// childAgentID reads the agent id ONE of runID's own retained bodies
// carries (record.go: "Read only ONE body per child for its agent_id") —
// every body a given run's own steps produced shares the SAME hookAgentID
// (the harness assigns one id per subagent, not per call), so the first
// body found settles it. ok is false when the run has no retained body at
// all, or its one body read is not hook-shaped (a gateway-recorded run
// carries no agent id of this kind at all).
func childAgentID(dir, runID string) (string, bool) {
	if dir == "" || runID == "" {
		return "", false
	}
	entries, err := os.ReadDir(filepath.Join(dir, filepath.Base(runID)))
	if err != nil {
		return "", false
	}
	for _, e := range entries {
		hexPart, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		body, ok := stepBody(dir, runID, "sha256:"+hexPart)
		if !ok || !body.hookShape || body.hookAgentID == "" {
			continue
		}
		return body.hookAgentID, true
	}
	return "", false
}

// resolveHookSpawns matches parentSteps's own Agent-tool steps against
// children by agent id (rule 2b): a step's own tool_response.agentId
// (hookSpawnedAgentID, parsed at body-read time by hookBodyAsGateway)
// against each child's own childAgentID. Unlike resolveSpawns this needs no
// FIFO tie-break — the harness assigns a fresh agent id per subagent, so an
// exact match is never ambiguous — but ties the same rule anyway: a step or
// a child matched once is never matched again.
func (rs *recordServer) resolveHookSpawns(
	logDir, parentRunID string, parentSteps []toolCallStepRef, children []familyNode,
) []spawnMatch {
	if logDir == "" || len(children) == 0 {
		return nil
	}

	type agentStep struct {
		step toolCallStepRef
		body gatewayBody
	}
	var steps []agentStep
	for _, step := range parentSteps {
		if step.Tool != "Agent" || step.Digest == "" {
			continue
		}
		body, ok := stepBody(logDir, parentRunID, step.Digest)
		if !ok || !body.hookShape || body.hookSpawnedAgentID == "" {
			continue
		}
		steps = append(steps, agentStep{step: step, body: body})
	}
	if len(steps) == 0 {
		return nil
	}

	usedSteps := map[int]bool{}
	var matches []spawnMatch
	for _, child := range children {
		agentID, ok := childAgentID(logDir, child.RunID)
		if !ok {
			continue
		}
		for i, as := range steps {
			if usedSteps[i] || as.body.hookSpawnedAgentID != agentID {
				continue
			}
			in, _ := agentSpawnInputOf(as.body.Input)
			matches = append(matches, spawnMatch{
				StepN: as.step.N, StepEventID: as.step.EventID, ChildRunID: child.RunID,
				LinkedBy: "agent_id", Title: in.Description, Prompt: in.Prompt, Model: in.Model,
			})
			usedSteps[i] = true
			break
		}
	}
	return matches
}

// resolveChildLinks is record.go's one entry point for rule 2 as a whole:
// EVERY direct child of parentRunID, linked to the step that spawned it —
// gateway/brief first (resolveSpawns), then agent id (resolveHookSpawns)
// for whichever children that left unmatched. A child matched by neither is
// simply absent from the result; callers hold "unmatched" (title/model "",
// spawned_at_step 0, linked_by "") as their own zero value.
func (rs *recordServer) resolveChildLinks(
	logDir, parentRunID string, parentSteps []toolCallStepRef, children []familyNode,
) map[string]spawnMatch {
	out := map[string]spawnMatch{}
	for _, m := range rs.resolveSpawns(logDir, parentRunID, parentSteps, children) {
		out[m.ChildRunID] = m
	}
	if len(out) == len(children) {
		return out
	}
	var remaining []familyNode
	for _, c := range children {
		if _, ok := out[c.RunID]; !ok {
			remaining = append(remaining, c)
		}
	}
	for _, m := range rs.resolveHookSpawns(logDir, parentRunID, parentSteps, remaining) {
		out[m.ChildRunID] = m
	}
	return out
}

// agentStepRefsFor reads parentID's own Agent-tool tool_call steps, numbered
// within parentID's own full step list (the SAME numbering buildSteps gives
// the primary run) — resolveChildLinks's own input for a parent that is NOT
// the run whose record is being built (#443: every ancestor in
// RecordAgent.Lineage), one query pair per such parent, the same cost
// spawnedByForFamily already pays per parent in a family.
func (rs *recordServer) agentStepRefsFor(ctx context.Context, parentID string) ([]toolCallStepRef, error) {
	steps, err := rs.store.agentSteps(ctx, []string{parentID})
	if err != nil {
		return nil, err
	}
	numbering, err := rs.store.stepNumbering(ctx, parentID)
	if err != nil {
		return nil, err
	}
	refs := make([]toolCallStepRef, 0, len(steps))
	for _, s := range steps {
		if n, ok := numbering[s.EventID]; ok {
			refs = append(refs, toolCallStepRef{N: n, EventID: s.EventID, Tool: "Agent", Digest: s.PayloadDigest})
		}
	}
	return refs, nil
}

// spawnedByForFamily resolves RecordTreeNode.SpawnedBy for every non-root
// member of family: for each member that is itself a parent within the
// family, its own tool_call steps are read (one query per such parent —
// bounded by the family's own size, which doc 05 §4 keeps small) and
// matched against its direct children exactly as resolveSpawns does for the
// primary run. The root always answers 0 (record.go's own rule).
func (rs *recordServer) spawnedByForFamily(ctx context.Context, logDir string, family []familyNode) (map[string]int, error) {
	spawnedBy := map[string]int{}
	if logDir == "" {
		return spawnedBy, nil
	}

	childrenOf := map[string][]familyNode{}
	for _, n := range family {
		if n.ParentRunID == "" {
			continue
		}
		childrenOf[n.ParentRunID] = append(childrenOf[n.ParentRunID], n)
	}
	for parentID, children := range childrenOf {
		steps, err := rs.store.agentSteps(ctx, []string{parentID})
		if err != nil {
			return nil, err
		}
		refs := make([]toolCallStepRef, 0, len(steps))
		// agentSteps already filters to tool_name = 'Agent'; N here numbers
		// only among those, which is wrong for a step index into the
		// parent's OWN full step list. See stepNumbering below.
		numbering, err := rs.store.stepNumbering(ctx, parentID)
		if err != nil {
			return nil, err
		}
		for _, s := range steps {
			if n, ok := numbering[s.EventID]; ok {
				refs = append(refs, toolCallStepRef{N: n, EventID: s.EventID, Tool: "Agent", Digest: s.PayloadDigest})
			}
		}
		for _, m := range rs.resolveSpawns(logDir, parentID, refs, children) {
			spawnedBy[m.ChildRunID] = m.StepN
		}
	}
	return spawnedBy, nil
}

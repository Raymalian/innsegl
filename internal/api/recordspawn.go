// SPDX-License-Identifier: Apache-2.0

package api

import "context"

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

// spawnMatch is one resolved (parent step) -> (child run) link.
type spawnMatch struct {
	StepN       int
	StepEventID string
	ChildRunID  string
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
		for i, child := range remaining {
			if child.RunID == "" {
				continue
			}
			if spawnBodyMatches(logDir, child.RunID, prompt) {
				matches = append(matches, spawnMatch{StepN: step.N, StepEventID: step.EventID, ChildRunID: child.RunID})
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

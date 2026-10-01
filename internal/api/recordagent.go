// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// recordagent.go builds RunRecord.Agent, .Children and .Written (record.go,
// #443/RM-278): a run seen as one agent, the agents it started, and the
// files its own steps wrote. recordbuild.go's buildRunRecord is the one
// caller; see its own doc comment for how the pieces here fit into the
// whole record.
//
// # The signing-identity rule (rule 1)
//
// A child with zero tool_call events and at least one commit_recorded
// never ran a tool at all — it exists only to hold a second identity's
// signature on a commit the ACTUAL agent (this run, or a real subagent)
// made. It is not an agent by any definition record.go's own Agent/Child
// types give one, so it is excluded from both, and from every ancestor's
// own Agents count (RecordAncestor.Agents). Its own commit is folded into
// the run that caused it into this run's own Commits instead, SignedBy set
// to the signing identity's own run id.
//
// # Lineage and Children share one set of grouped queries
//
// RecordAgent.Lineage needs each ancestor's own Agents count (its direct
// children, signing identities excluded) and, for every ancestor but the
// root, which of ITS OWN parent's steps spawned it. RecordChildren needs
// the exact same two things for runID's own direct children. Both are
// computed ONCE, for the union of "this run's own children" and "every
// ancestor's own children" — buildRunRecord's own childCounts call and its
// own per-parent resolveChildLinks loop — never a query per child (#443
// rule 8).

// maxLineageDepth bounds RecordAgent.Lineage (#443 rule 3): defensive, like
// recordquery.go's own maxFamilyDepth, against a chain this deployment never
// expects to see.
const maxLineageDepth = 16

// childrenOfInFamily is family's own direct children of parentID — no
// query: family (recordquery.go) already holds the whole tree.
func childrenOfInFamily(family []familyNode, parentID string) []familyNode {
	var out []familyNode
	for _, n := range family {
		if n.ParentRunID == parentID {
			out = append(out, n)
		}
	}
	return out
}

// ancestorChainOf walks family from immediateParentID up to the root,
// capped at maxLineageDepth, and returns it root-first — record.go's own
// "every ancestor, the session first and the parent last". immediateParentID
// == "" (runID is itself the root) answers no ancestors at all.
func ancestorChainOf(family []familyNode, immediateParentID string) []familyNode {
	if immediateParentID == "" {
		return nil
	}
	byID := make(map[string]familyNode, len(family))
	for _, n := range family {
		byID[n.RunID] = n
	}

	var chain []familyNode
	seen := map[string]bool{}
	cur := immediateParentID
	for cur != "" && len(chain) < maxLineageDepth {
		n, ok := byID[cur]
		if !ok || seen[cur] {
			break
		}
		seen[cur] = true
		chain = append(chain, n)
		cur = n.ParentRunID
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// idsOf is the RunID of every node in nodes.
func idsOf(nodes []familyNode) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.RunID
	}
	return out
}

// isSigningIdentity is #443 rule 1's own test: zero tool_call events, at
// least one commit_recorded. A run absent from counts entirely (no
// tool_call and no commit_recorded) answers false — it simply has not done
// anything yet, which is not the same as having signed something.
func isSigningIdentity(counts childCounts) bool {
	return counts.Steps == 0 && counts.Commits >= 1
}

// nonSigningChildrenOf filters children to those counts does not mark a
// signing identity.
func nonSigningChildrenOf(children []familyNode, counts map[string]childCounts) []familyNode {
	out := make([]familyNode, 0, len(children))
	for _, c := range children {
		if !isSigningIdentity(counts[c.RunID]) {
			out = append(out, c)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// RecordAgent.
// ---------------------------------------------------------------------------

// buildAgentRecord assembles RecordAgent for runID. ancestors is
// ancestorChainOf's own root-first chain; links[P] is resolveChildLinks's
// own result for parent P (every P in ancestors, plus runID itself,
// already resolved by buildRunRecord); childrenOfParent[P] is P's own
// direct children (childrenOfInFamily); counts is the one childCounts read
// covering every child these need.
func buildAgentRecord(
	reg registeredFields, runID string,
	ancestors []familyNode, links map[string]map[string]spawnMatch, childrenOfParent map[string][]familyNode,
	counts map[string]childCounts, brief RecordMessage, replies []RecordMessage, steps []RecordStep,
) RecordAgent {
	agent := RecordAgent{Lineage: []RecordAncestor{}}

	if reg.ParentRunID == "" {
		agent.Role = "session"
		agent.Asked = RecordText{Text: brief.Text, Available: brief.Available, Step: 0}
	} else {
		agent.Role = "subagent"
		if m, ok := links[reg.ParentRunID][runID]; ok {
			agent.Title, agent.Model, agent.SpawnedAtStep, agent.LinkedBy = m.Title, m.Model, m.StepN, m.LinkedBy
			agent.Asked = RecordText{Text: m.Prompt, Available: true, Step: 0}
		}
	}

	for _, anc := range ancestors {
		role := "session"
		var title string
		var spawnedAtStep int
		if anc.ParentRunID != "" {
			role = "subagent"
			if m, ok := links[anc.ParentRunID][anc.RunID]; ok {
				title, spawnedAtStep = m.Title, m.StepN
			}
		}
		agentsCount := 0
		for _, c := range childrenOfParent[anc.RunID] {
			if !isSigningIdentity(counts[c.RunID]) {
				agentsCount++
			}
		}
		agent.Lineage = append(agent.Lineage, RecordAncestor{
			RunID: anc.RunID, Title: title, AgentType: anc.AgentType, Role: role,
			SpawnedAtStep: spawnedAtStep, Agents: agentsCount,
		})
	}

	agent.Reported = reportedOf(steps, replies)
	return agent
}

// subagentHandbackInput is the one member a SubagentHandback step's own
// input carries that record.go's Reported rule reads.
type subagentHandbackInput struct {
	Message string `json:"message"`
}

// reportedOf is record.go rule 3's own Reported rule: the LAST step whose
// tool is SubagentHandback (its own tool_input.message); else the last
// AVAILABLE reply; else unavailable.
func reportedOf(steps []RecordStep, replies []RecordMessage) RecordText {
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Tool != "SubagentHandback" {
			continue
		}
		var in subagentHandbackInput
		if json.Unmarshal([]byte(steps[i].Input), &in) == nil && in.Message != "" {
			return RecordText{Text: in.Message, Available: true, Step: steps[i].N}
		}
		return RecordText{}
	}
	for i := len(replies) - 1; i >= 0; i-- {
		if replies[i].Available {
			return RecordText{Text: replies[i].Text, Available: true, Step: 0}
		}
	}
	return RecordText{}
}

// ---------------------------------------------------------------------------
// RecordChild (#443 rule 4).
// ---------------------------------------------------------------------------

// buildChildren assembles RunRecord.Children: direct, non-signing children,
// newest first by registration. links is resolveChildLinks's own result for
// runID (keyed by child run id); counts is the shared childCounts read.
func (rs *recordServer) buildChildren(
	ctx context.Context, children []familyNode, links map[string]spawnMatch, counts map[string]childCounts,
	now time.Time, horizon time.Duration,
) ([]RecordChild, error) {
	if len(children) == 0 {
		return []RecordChild{}, nil
	}
	facts, err := rs.store.familyFacts(ctx, idsOf(children))
	if err != nil {
		return nil, err
	}

	sorted := append([]familyNode{}, children...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].RegisteredAt.After(sorted[j].RegisteredAt) })

	out := make([]RecordChild, 0, len(sorted))
	for _, c := range sorted {
		m := links[c.RunID]
		cnt := counts[c.RunID]
		f := facts[c.RunID]
		status, _ := statusAndAt(f, f.RetiredAt, f.Retired, now, horizon)
		out = append(out, RecordChild{
			RunID: c.RunID, Title: m.Title, AgentType: c.AgentType, Model: m.Model,
			SpawnedAtStep: m.StepN, Steps: cnt.Steps, Commits: cnt.Commits,
			Status: status, EndedAt: childEndedAt(f, status, f.RetiredAt, f.Retired),
		})
	}
	return out, nil
}

// childEndedAt is record.go rule 4's own EndedAt: retirement, else the
// child's own last activity when it is lapsed or abandoned (statusAndAt's
// own StatusAt reads WithdrawnAt instead, which a lapsed run with no
// run_expired event yet leaves zero — EndedAt reads LastActivityAt so a
// freshly-lapsed child still shows something rather than null), else null.
func childEndedAt(f ledger.RunFacts, status string, retiredAt time.Time, retired bool) *time.Time {
	if retired {
		t := retiredAt.UTC()
		return &t
	}
	if (status == ledger.RunLapsed || status == ledger.RunAbandoned) && !f.LastActivityAt.IsZero() {
		t := f.LastActivityAt.UTC()
		return &t
	}
	return nil
}

// ---------------------------------------------------------------------------
// #443 rule 1: a signing identity's own commit, folded into the run that
// caused it — Step resolved by scripts/innsegl-commit.sh's own printed
// line, never by a step's own CommitSHA (that field names a commit THIS
// run's own Bash made, which a signing identity's commit never is).
// ---------------------------------------------------------------------------

// signedStepFor is record.go rule 1's own Step rule: the FIRST step (lowest
// N) of this run whose own Output contains "signed <the commit's own
// 7-character short sha>" — scripts/innsegl-commit.sh's own
// "innsegl-commit: signed <sha7>  rekor index N" line. 0 when sha is too
// short to abbreviate, or no step's Output names it.
func signedStepFor(steps []RecordStep, sha string) int {
	if len(sha) < 7 {
		return 0
	}
	marker := "signed " + sha[:7]
	for _, st := range steps {
		if strings.Contains(st.Output, marker) {
			return st.N
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// RecordWrite (#443 rules 6-7).
// ---------------------------------------------------------------------------

// isWriteTool reports whether toolName is one of the four tools record.go
// rule 6 lists as writing a file.
func isWriteTool(toolName string) bool {
	switch toolName {
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return true
	}
	return false
}

// writeStatusOf is record.go rule 6's own Status rule: a hook Write reads
// its own structured tool_response.type (hookWriteType, parsed once at
// body-read time — recordbody.go's hookBodyAsGateway); a gateway Write
// reads the SAME rendered result text record.go's RecordStep.Output already
// carries; Edit/MultiEdit/NotebookEdit are always M; anything else this
// cannot place is "W", never a guess.
func writeStatusOf(toolName string, body gatewayBody, output string) string {
	switch toolName {
	case "Edit", "MultiEdit", "NotebookEdit":
		return "M"
	case "Write":
		if body.hookShape {
			switch body.hookWriteType {
			case "create":
				return "A"
			case "update":
				return "M"
			}
			return "W"
		}
		switch {
		case strings.HasPrefix(output, "File created successfully"):
			return "A"
		case strings.Contains(output, "has been updated"):
			return "M"
		}
		return "W"
	}
	return "W"
}

func nonNilWritten(w []RecordWrite) []RecordWrite {
	if w == nil {
		return []RecordWrite{}
	}
	return w
}

// ---------------------------------------------------------------------------
// RunRecord.Children (filtered for the signing-identity rule).
// ---------------------------------------------------------------------------

func nonNilChildren(c []RecordChild) []RecordChild {
	if c == nil {
		return []RecordChild{}
	}
	return c
}

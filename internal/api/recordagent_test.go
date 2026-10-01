// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"
)

// #443 (RM-278): RunRecord.Agent, .Children, .Written, and the
// signing-identity rule folded into .Commits — against the real Postgres
// fixture (recordintegration_test.go's own newRecordFixture), both the
// EXISTING gateway-recorded family (run-e19-parent/run-e19-child) and the
// NEW hook-recorded family (seedHookFamily) it now also seeds.

// TestRM278GatewaySessionAgentAndChildren covers rule 2a (brief linking)
// and rule 4 (Children) against the ALREADY-EXISTING gateway fixture: a
// session (run-e19-parent) with one real, non-signing child
// (run-e19-child, one tool_call and one commit_recorded) linked by its
// exact brief text.
func TestRM278GatewaySessionAgentAndChildren(t *testing.T) {
	f := newRecordFixture(t)
	rec, err := f.rs.buildRunRecord(context.Background(), f.parentID)
	if err != nil {
		t.Fatalf("buildRunRecord: %v", err)
	}

	if rec.Agent.Role != "session" {
		t.Errorf("Agent.Role = %q, want session (no parent_run_id)", rec.Agent.Role)
	}
	if len(rec.Agent.Lineage) != 0 {
		t.Errorf("Agent.Lineage = %+v, want empty for a session", rec.Agent.Lineage)
	}
	if !rec.Agent.Asked.Available || rec.Agent.Asked.Text != recordFixtureBriefText || rec.Agent.Asked.Step != 0 {
		t.Errorf("Agent.Asked = %+v, want the session's own brief, step 0", rec.Agent.Asked)
	}
	if rec.Agent.Reported.Available {
		t.Errorf("Agent.Reported = %+v, want unavailable — no SubagentHandback step and no assistant reply", rec.Agent.Reported)
	}

	if len(rec.Children) != 1 {
		t.Fatalf("got %d children, want 1: %+v", len(rec.Children), rec.Children)
	}
	c := rec.Children[0]
	if c.RunID != f.childID {
		t.Errorf("Children[0].RunID = %q, want %q", c.RunID, f.childID)
	}
	if c.SpawnedAtStep != 4 {
		t.Errorf("Children[0].SpawnedAtStep = %d, want 4 (the Agent step)", c.SpawnedAtStep)
	}
	if c.Steps != 1 {
		t.Errorf("Children[0].Steps = %d, want 1 (the child's own Write)", c.Steps)
	}
	if c.Commits != 1 {
		t.Errorf("Children[0].Commits = %d, want 1", c.Commits)
	}
	if c.Status != "active" {
		t.Errorf("Children[0].Status = %q, want active", c.Status)
	}
	if c.EndedAt != nil {
		t.Errorf("Children[0].EndedAt = %v, want nil for an active child", c.EndedAt)
	}

	// Rule 5: the Agent step is Kind "spawn", with SpawnedRunID resolved
	// (already true before #443; this just must still hold).
	if len(rec.Steps) != 4 {
		t.Fatalf("got %d steps, want 4", len(rec.Steps))
	}
	spawnStep := rec.Steps[3]
	if spawnStep.Kind != "spawn" {
		t.Errorf("Steps[3].Kind = %q, want spawn", spawnStep.Kind)
	}
	if spawnStep.SpawnedRunID != f.childID {
		t.Errorf("Steps[3].SpawnedRunID = %q, want %q", spawnStep.SpawnedRunID, f.childID)
	}

	// Rule 6: the parent's own step 1 (Write a.txt) is listed in Written.
	if len(rec.Written) != 1 {
		t.Fatalf("got %d written entries, want 1: %+v", len(rec.Written), rec.Written)
	}
	w := rec.Written[0]
	if w.Path != "a.txt" || w.Status != "A" || w.Step != 1 {
		t.Errorf("Written[0] = %+v, want {a.txt A 1}", w)
	}

	// Rule 1: this run's own commit carries SignedBy = this run's own id.
	if len(rec.Commits) != 1 {
		t.Fatalf("got %d commits, want 1", len(rec.Commits))
	}
	if rec.Commits[0].SignedBy != f.parentID {
		t.Errorf("Commits[0].SignedBy = %q, want %q (this run's own commit)", rec.Commits[0].SignedBy, f.parentID)
	}
}

// TestRM278HookSubagentLinkedByAgentID covers rule 2b (agent id linking),
// rule 3 (Agent: lineage, asked, reported), and rule 5 (SubagentHandback ->
// "report") for the hook-recorded subagent.
func TestRM278HookSubagentLinkedByAgentID(t *testing.T) {
	f := newRecordFixture(t)
	rec, err := f.rs.buildRunRecord(context.Background(), f.hookSubagentID)
	if err != nil {
		t.Fatalf("buildRunRecord: %v", err)
	}

	if rec.Agent.Role != "subagent" {
		t.Errorf("Agent.Role = %q, want subagent", rec.Agent.Role)
	}
	if rec.Agent.LinkedBy != "agent_id" {
		t.Errorf("Agent.LinkedBy = %q, want agent_id", rec.Agent.LinkedBy)
	}
	if rec.Agent.Title != hookFamilyTitle {
		t.Errorf("Agent.Title = %q, want %q", rec.Agent.Title, hookFamilyTitle)
	}
	if rec.Agent.Model != hookFamilyModel {
		t.Errorf("Agent.Model = %q, want %q", rec.Agent.Model, hookFamilyModel)
	}
	if rec.Agent.SpawnedAtStep != 2 {
		t.Errorf("Agent.SpawnedAtStep = %d, want 2 (the session's own Agent step)", rec.Agent.SpawnedAtStep)
	}
	if !rec.Agent.Asked.Available || rec.Agent.Asked.Text != hookFamilyPrompt || rec.Agent.Asked.Step != 0 {
		t.Errorf("Agent.Asked = %+v, want {%q true 0}", rec.Agent.Asked, hookFamilyPrompt)
	}

	// Lineage: the session only, one level up, with its own agents count —
	// ONE non-signing child (the hook subagent itself; the signing identity
	// is excluded).
	if len(rec.Agent.Lineage) != 1 {
		t.Fatalf("got %d lineage entries, want 1: %+v", len(rec.Agent.Lineage), rec.Agent.Lineage)
	}
	anc := rec.Agent.Lineage[0]
	if anc.RunID != f.hookSessionID {
		t.Errorf("Lineage[0].RunID = %q, want %q", anc.RunID, f.hookSessionID)
	}
	if anc.Role != "session" || anc.AgentType != "session" {
		t.Errorf("Lineage[0] = %+v, want Role=session AgentType=session", anc)
	}
	if anc.SpawnedAtStep != 0 {
		t.Errorf("Lineage[0].SpawnedAtStep = %d, want 0 (the session has no parent of its own)", anc.SpawnedAtStep)
	}
	if anc.Agents != 1 {
		t.Errorf("Lineage[0].Agents = %d, want 1 (the signing identity does not count)", anc.Agents)
	}

	// Reported: the LAST SubagentHandback step (step 3 of the subagent's
	// own steps).
	if !rec.Agent.Reported.Available || rec.Agent.Reported.Text != hookFamilyReport || rec.Agent.Reported.Step != 3 {
		t.Errorf("Agent.Reported = %+v, want {%q true 3}", rec.Agent.Reported, hookFamilyReport)
	}

	if len(rec.Steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(rec.Steps))
	}
	if rec.Steps[2].Kind != "report" {
		t.Errorf("Steps[2].Kind = %q, want report (SubagentHandback)", rec.Steps[2].Kind)
	}
	if rec.Steps[2].Tool != "SubagentHandback" {
		t.Fatalf("Steps[2].Tool = %q, want SubagentHandback", rec.Steps[2].Tool)
	}

	// Rules 6-7: the hook Write step (step 2) is listed in Written, and its
	// own rendered Output reads the gateway's own sentence.
	if len(rec.Written) != 1 {
		t.Fatalf("got %d written entries, want 1: %+v", len(rec.Written), rec.Written)
	}
	w := rec.Written[0]
	if w.Path != "output.txt" || w.Status != "A" || w.Step != 2 {
		t.Errorf("Written[0] = %+v, want {output.txt A 2}", w)
	}
	if rec.Steps[1].Output != "File created successfully at: output.txt" {
		t.Errorf("Steps[1].Output = %q, want the rendered create sentence", rec.Steps[1].Output)
	}

	if len(rec.Children) != 0 {
		t.Errorf("Children = %+v, want none — this run started nothing", rec.Children)
	}
}

// TestRM278HookSessionChildrenExcludeTheSigningIdentity covers rule 1: the
// signing identity (zero tool_call events, one commit_recorded) is absent
// from Children, absent from the session's own Agents count (already
// covered above via Lineage[0].Agents), and its commit is folded into the
// session's own Commits with SignedBy set to the signing identity's own run
// id and Step resolved by the "signed <sha7>" text search.
func TestRM278HookSessionChildrenExcludeTheSigningIdentity(t *testing.T) {
	f := newRecordFixture(t)
	rec, err := f.rs.buildRunRecord(context.Background(), f.hookSessionID)
	if err != nil {
		t.Fatalf("buildRunRecord: %v", err)
	}

	if len(rec.Children) != 1 {
		t.Fatalf("got %d children, want 1 (the hook subagent only, not the signing identity): %+v", len(rec.Children), rec.Children)
	}
	if rec.Children[0].RunID != f.hookSubagentID {
		t.Errorf("Children[0].RunID = %q, want %q", rec.Children[0].RunID, f.hookSubagentID)
	}
	if rec.Children[0].SpawnedAtStep != 2 {
		t.Errorf("Children[0].SpawnedAtStep = %d, want 2", rec.Children[0].SpawnedAtStep)
	}
	if rec.Children[0].Title != hookFamilyTitle {
		t.Errorf("Children[0].Title = %q, want %q", rec.Children[0].Title, hookFamilyTitle)
	}

	if len(rec.Commits) != 1 {
		t.Fatalf("got %d commits, want 1 (the signing identity's own, folded in): %+v", len(rec.Commits), rec.Commits)
	}
	rc := rec.Commits[0]
	if rc.SHA != f.signingCommitSHA {
		t.Errorf("Commits[0].SHA = %q, want %q", rc.SHA, f.signingCommitSHA)
	}
	if rc.SignedBy != f.signingID {
		t.Errorf("Commits[0].SignedBy = %q, want %q", rc.SignedBy, f.signingID)
	}
	if rc.Step != 1 {
		t.Errorf("Commits[0].Step = %d, want 1 (the Bash step whose output names \"signed %s\")", rc.Step, f.signingCommitSHA[:7])
	}

	if rec.Steps[1].Kind != "spawn" {
		t.Errorf("Steps[1].Kind = %q, want spawn (the Agent step)", rec.Steps[1].Kind)
	}
	if rec.Steps[1].SpawnedRunID != f.hookSubagentID {
		t.Errorf("Steps[1].SpawnedRunID = %q, want %q", rec.Steps[1].SpawnedRunID, f.hookSubagentID)
	}
	if rec.Steps[1].Summary != hookFamilyTitle {
		t.Errorf("Steps[1].Summary = %q, want the spawn's own description %q", rec.Steps[1].Summary, hookFamilyTitle)
	}
}

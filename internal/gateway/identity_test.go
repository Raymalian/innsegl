// SPDX-License-Identifier: Apache-2.0

package gateway

// identity_test.go — RM-235 (#380): the identity Guard, composing #376-379's
// own declared interfaces through their shared fakes (lifecycle_fakes_test.go)
// plus a fake RunStateReader (this file's own, since RunStateReader is
// declared here, not in the frozen contract). The real LifecyclePolicy
// (lifecycle.go's Policy) is used throughout rather than fakePolicy: what
// this file proves is the Guard's OWN composition -- reading the right
// things, acting on the decision it gets back, inserting the right mapping
// row -- and a real, pure Decide gives that composition genuine coverage
// rather than asserting against a canned decision.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
)

// ---------------------------------------------------------------------------
// fakeRunStates: RunStateReader.
// ---------------------------------------------------------------------------

type fakeRunStates struct {
	mu            sync.Mutex
	states        map[string]string
	registrations map[string]RunRegistration
	err           error
}

func newFakeRunStates() *fakeRunStates {
	return &fakeRunStates{states: map[string]string{}, registrations: map[string]RunRegistration{}}
}

func (f *fakeRunStates) register(runID string, reg RunRegistration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.registrations[runID] = reg
}

func (f *fakeRunStates) RunRegistration(_ context.Context, runID string) (RunRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return RunRegistration{}, f.err
	}
	reg, ok := f.registrations[runID]
	if !ok {
		return RunRegistration{}, errors.New("no registration for " + runID)
	}
	return reg, nil
}

func (f *fakeRunStates) set(runID, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[runID] = state
}

func (f *fakeRunStates) RunState(_ context.Context, runID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	return f.states[runID], nil
}

var _ RunStateReader = (*fakeRunStates)(nil)

// countingMappingStore wraps fakeMappingStore and counts BySessionAgent
// calls, so a test can prove the identity guard's own cache is actually
// saving a lookup within one process's lifetime.
type countingMappingStore struct {
	*fakeMappingStore
	bySessionAgentCalls int
}

func newCountingMappingStore() *countingMappingStore {
	return &countingMappingStore{fakeMappingStore: &fakeMappingStore{}}
}

func (c *countingMappingStore) BySessionAgent(ctx context.Context, sessionID, agentID string) (RunMapping, bool, error) {
	c.bySessionAgentCalls++
	return c.fakeMappingStore.BySessionAgent(ctx, sessionID, agentID)
}

// ---------------------------------------------------------------------------
// The fixture.
// ---------------------------------------------------------------------------

type identityFixture struct {
	mappings          *countingMappingStore
	tree              *fakeTreeLinker
	registrar         *fakeRegistrar
	workspaces        *fakeWorkspaceResolver
	runStates         *fakeRunStates
	sessionEndSignals *SessionEndSignals
	sessionWorkspaces *SessionWorkspaces
	witnessed         []AgentTypeFinding
	guard             *IdentityGuard
}

// fixtureDirectory is what the session hook stated for session "s1" in
// every fixture: the directory a new run is registered from.
const fixtureDirectory = "/workspace/id-test"

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	f := &identityFixture{
		mappings:          newCountingMappingStore(),
		tree:              &fakeTreeLinker{},
		registrar:         &fakeRegistrar{},
		workspaces:        &fakeWorkspaceResolver{ws: Workspace{Repo: "acme/id-test", Branch: "main", Task: "task-1"}},
		runStates:         newFakeRunStates(),
		sessionEndSignals: NewSessionEndSignals(0),
		sessionWorkspaces: NewSessionWorkspaces(0),
	}
	f.sessionWorkspaces.Record("s1", "", fixtureDirectory)
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings:           f.mappings,
		Tree:               f.tree,
		Policy:             NewPolicy(),
		Registrar:          f.registrar,
		Workspaces:         f.workspaces,
		RunStates:          f.runStates,
		SessionEndSignals:  f.sessionEndSignals,
		SessionWorkspaces:  f.sessionWorkspaces,
		Now:                func() time.Time { return time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC) },
		OnAgentTypeWitness: func(af AgentTypeFinding) { f.witnessed = append(f.witnessed, af) },
	})
	if err != nil {
		t.Fatalf("NewIdentityGuard: %v", err)
	}
	f.guard = g
	return f
}

// identityTestMessage mirrors one Anthropic Messages API message.
type identityTestMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// messagesBody builds a minimal Anthropic Messages request body: brief is
// the first user message's text; when assistantText is non-empty a second,
// assistant message is added, which is what makes ComputeFingerprint
// non-empty (facts.go: "empty until the conversation has a first assistant
// turn").
func messagesBody(t *testing.T, brief, assistantText string) string {
	t.Helper()
	messages := []identityTestMessage{{Role: "user", Content: brief}}
	if assistantText != "" {
		messages = append(messages, identityTestMessage{Role: "assistant", Content: assistantText})
	}
	b, err := json.Marshal(struct {
		Messages []identityTestMessage `json:"messages"`
	}{Messages: messages})
	if err != nil {
		t.Fatalf("marshal messages body: %v", err)
	}
	return string(b)
}

func identityRequest(t *testing.T, id Identification, brief, assistantText string) *http.Request {
	t.Helper()
	body := messagesBody(t, brief, assistantText)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader(body))
	req = req.WithContext(WithIdentification(context.Background(), id))
	return req
}

// testFingerprint computes the SAME Fingerprint ExtractRequestFacts and
// ComputeFingerprint would derive from a request built by messagesBody, so
// a seeded RunMapping row's Fingerprint actually matches what a later
// request's own fp will be -- a fake fingerprint string would never be
// found by ByFingerprint, which is keyed on the real thing.
func testFingerprint(t *testing.T, brief, assistantText string) Fingerprint {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/messages", strings.NewReader(messagesBody(t, brief, assistantText)))
	return ComputeFingerprint(ExtractRequestFacts(req))
}

func mustRunID(t *testing.T, r *http.Request) string {
	t.Helper()
	runID, ok := RunIDFromContext(r.Context())
	if !ok {
		t.Fatalf("no run id attached to the permitted request's context")
	}
	return runID
}

// ---------------------------------------------------------------------------
// Continue.
// ---------------------------------------------------------------------------

func TestIdentityGuardContinuesAnActiveRun(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-continue", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-continue", ledger.RunActive)

	r2, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if got := mustRunID(t, r2); got != "run-continue" {
		t.Errorf("run id = %q, want run-continue", got)
	}
	if len(f.registrar.calls) != 0 {
		t.Errorf("registrar calls = %v, want none for Continue", f.registrar.calls)
	}
}

// TestIdentityGuardCancelsASessionEndSignalOnTheNextMainAgentRequest is
// review case (a) through the actual Guard (lifecycle_test.go's own
// TestGID011ARequestWithinGraceCancelsTheSignalAndSweepRetiresNothing
// proves the same contract directly against SessionEnder; this proves the
// Guard is the one that actually calls Cancel, on every permitted request,
// before it does anything else -- see identity.go's Check, immediately
// after Identification is resolved).
func TestIdentityGuardCancelsASessionEndSignalOnTheNextMainAgentRequest(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-continue", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-continue", ledger.RunActive)
	f.sessionEndSignals.Mark(id.SessionID, time.Now())
	if got := f.sessionEndSignals.Len(); got != 1 {
		t.Fatalf("Len() before the request = %d, want 1", got)
	}

	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}

	if got := f.sessionEndSignals.Len(); got != 0 {
		t.Errorf("Len() after a main-agent request = %d, want 0: the request must cancel the signal", got)
	}
}

// A subagent's own request must NOT cancel its session's main-agent
// signal: SessionEnder only ever concerns the main agent's run (decision
// 7a), and a subagent continuing says nothing about whether the main
// session itself is still driving anything.
func TestIdentityGuardDoesNotCancelASessionEndSignalOnASubagentRequest(t *testing.T) {
	f := newIdentityFixture(t)
	sub := Identification{SessionID: "s1", AgentID: "sub-agent-id"}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-sub", SessionID: sub.SessionID, AgentID: sub.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-sub", ledger.RunActive)
	f.sessionEndSignals.Mark(sub.SessionID, time.Now())

	if _, refusal := f.guard.Check(identityRequest(t, sub, "hello", "hi")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}

	if got := f.sessionEndSignals.Len(); got != 1 {
		t.Errorf("Len() after a subagent request = %d, want 1: only a main-agent request cancels it", got)
	}
}

// ---------------------------------------------------------------------------
// Restore.
// ---------------------------------------------------------------------------

func TestIdentityGuardRestoresALapsedRun(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-restore", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-restore", ledger.RunLapsed)
	f.runStates.register("run-restore", RunRegistration{AgentType: mainAgentID, TaskID: "task-1", Repo: "acme/id-test"})

	r2, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if got := mustRunID(t, r2); got != "run-restore" {
		t.Errorf("run id = %q, want run-restore", got)
	}
	if len(f.registrar.calls) != 1 || f.registrar.calls[0] != "restore" {
		t.Errorf("registrar calls = %v, want exactly [restore]", f.registrar.calls)
	}
}

// ---------------------------------------------------------------------------
// New, with the tree-resolved parent link.
// ---------------------------------------------------------------------------

func TestIdentityGuardRegistersANewRootRun(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	r2, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	runID := mustRunID(t, r2)
	if runID == "" {
		t.Fatal("no run id attached")
	}
	if len(f.registrar.calls) != 1 || f.registrar.calls[0] != "register" {
		t.Fatalf("registrar calls = %v, want exactly [register]", f.registrar.calls)
	}
	if f.registrar.lastSeen.ParentRunID != "" {
		t.Errorf("ParentRunID = %q, want empty for a root run", f.registrar.lastSeen.ParentRunID)
	}
	// RM-263 (#416): the root registers with the harness's own fixed root
	// type, not merely a value that happens to equal id.AgentID.
	if f.registrar.lastSeen.AgentType != mainAgentID {
		t.Errorf("AgentType = %q, want %q (the root's fixed type)", f.registrar.lastSeen.AgentType, mainAgentID)
	}
	m, found, err := f.mappings.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent after registration: found=%v err=%v", found, err)
	}
	if m.RunID != runID {
		t.Errorf("recorded mapping's run id = %q, want %q", m.RunID, runID)
	}
}

func TestIdentityGuardRegistersANewChildWithTheResolvedParent(t *testing.T) {
	f := newIdentityFixture(t)
	if err := f.tree.RecordSpawn(t.Context(), PendingSpawn{
		ParentRunID: "run-parent", SessionID: "s1", Prompt: "do the subtask", AgentType: "code-reviewer",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	child := Identification{SessionID: "s1", AgentID: "child-agent-id"}

	r2, refusal := f.guard.Check(identityRequest(t, child, "do the subtask", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	_ = mustRunID(t, r2)
	if f.registrar.lastSeen.ParentRunID != "run-parent" {
		t.Errorf("ParentRunID = %q, want run-parent", f.registrar.lastSeen.ParentRunID)
	}
	// RM-263 (#416): the child registers with the spawn's own real type,
	// never the harness-asserted agent id (an opaque per-run id, never a
	// type).
	if f.registrar.lastSeen.AgentType != "code-reviewer" {
		t.Errorf("AgentType = %q, want %q (the spawn's own type, not the agent id %q)",
			f.registrar.lastSeen.AgentType, "code-reviewer", child.AgentID)
	}
}

// TestIdentityGuardChildWithNoSpawnAgentTypeFallsBackToTheDefaultNeverTheAgentID
// (RM-263, #416): the spawn matched -- there is a real parent link -- but
// its own tool_use carried no subagent type at all. The child must still
// register with a stated default, never with id.AgentID standing in for a
// type it never claimed to be.
func TestIdentityGuardChildWithNoSpawnAgentTypeFallsBackToTheDefaultNeverTheAgentID(t *testing.T) {
	f := newIdentityFixture(t)
	if err := f.tree.RecordSpawn(t.Context(), PendingSpawn{
		ParentRunID: "run-parent", SessionID: "s1", Prompt: "do the subtask",
	}); err != nil {
		t.Fatalf("RecordSpawn: %v", err)
	}
	child := Identification{SessionID: "s1", AgentID: "child-agent-id"}

	r2, refusal := f.guard.Check(identityRequest(t, child, "do the subtask", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	_ = mustRunID(t, r2)
	if f.registrar.lastSeen.AgentType != defaultSubagentType {
		t.Errorf("AgentType = %q, want the stated default %q", f.registrar.lastSeen.AgentType, defaultSubagentType)
	}
	if f.registrar.lastSeen.AgentType == child.AgentID {
		t.Error("AgentType fell back to the agent id; it must never stand in for a type")
	}
}

// TestIdentityGuardChildWithNoResolvedParentFallsBackToTheDefaultNeverTheAgentID
// (RM-263, #416): no spawn matched at all -- this "child" is unlinked --
// which must fall back the same way a matched-but-typeless spawn does,
// never to id.AgentID.
func TestIdentityGuardChildWithNoResolvedParentFallsBackToTheDefaultNeverTheAgentID(t *testing.T) {
	f := newIdentityFixture(t)
	child := Identification{SessionID: "s1", AgentID: "child-agent-id"}

	r2, refusal := f.guard.Check(identityRequest(t, child, "an unlinked child's own brief", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	_ = mustRunID(t, r2)
	if f.registrar.lastSeen.ParentRunID != "" {
		t.Errorf("ParentRunID = %q, want empty: nothing was ever recorded to link to", f.registrar.lastSeen.ParentRunID)
	}
	if f.registrar.lastSeen.AgentType != defaultSubagentType {
		t.Errorf("AgentType = %q, want the stated default %q", f.registrar.lastSeen.AgentType, defaultSubagentType)
	}
	if f.registrar.lastSeen.AgentType == child.AgentID {
		t.Error("AgentType fell back to the agent id; it must never stand in for a type")
	}
}

// ---------------------------------------------------------------------------
// Fork: a known fingerprint under a new session.
// ---------------------------------------------------------------------------

func TestIdentityGuardRegistersAForkWithForkedFromRunID(t *testing.T) {
	f := newIdentityFixture(t)
	origin := Identification{SessionID: "s-origin", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-origin", SessionID: origin.SessionID, AgentID: origin.AgentID,
		Fingerprint: testFingerprint(t, "hello", "hi"),
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-origin", ledger.RunActive)

	forked := Identification{SessionID: "s-forked", AgentID: mainAgentID}
	// A forked session's own SessionStart (source "fork") states its directory.
	f.sessionWorkspaces.Record(forked.SessionID, "", fixtureDirectory)
	r2, refusal := f.guard.Check(identityRequest(t, forked, "hello", "hi"))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	runID := mustRunID(t, r2)
	if runID == "run-origin" {
		t.Fatal("the fork registered as the same run as its origin")
	}
	if f.registrar.lastSeen.ForkedFromRunID != "run-origin" {
		t.Errorf("ForkedFromRunID = %q, want run-origin", f.registrar.lastSeen.ForkedFromRunID)
	}
	m, found, err := f.mappings.BySessionAgent(t.Context(), forked.SessionID, forked.AgentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent after the fork: found=%v err=%v", found, err)
	}
	if m.ForkedFromRunID != "run-origin" {
		t.Errorf("recorded mapping's ForkedFromRunID = %q, want run-origin", m.ForkedFromRunID)
	}
}

// ---------------------------------------------------------------------------
// Adopt: resumption after retirement, never revival.
// ---------------------------------------------------------------------------

func TestIdentityGuardAdoptsARetiredRun(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-retired", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-retired", ledger.RunRetired)

	r2, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	runID := mustRunID(t, r2)
	if runID == "run-retired" {
		t.Fatal("adoption returned the retired run's own id; a retired run must never be revived")
	}
	if len(f.registrar.calls) != 1 || f.registrar.calls[0] != "register" {
		t.Fatalf("registrar calls = %v, want exactly [register] (adoption registers a new run)", f.registrar.calls)
	}
	m, found, err := f.mappings.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent after adoption: found=%v err=%v", found, err)
	}
	if m.AdoptedFromRunID != "run-retired" {
		t.Errorf("recorded mapping's AdoptedFromRunID = %q, want run-retired", m.AdoptedFromRunID)
	}
}

// ---------------------------------------------------------------------------
// GID-012: no identity, no request.
// ---------------------------------------------------------------------------

func TestIdentityGuardGID012RefusesWithNoIdentification(t *testing.T) {
	f := newIdentityFixture(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/v1/messages", strings.NewReader(messagesBody(t, "hi", "")))

	r2, refusal := f.guard.Check(req)
	if refusal == nil {
		t.Fatal("want a refusal")
	}
	if refusal.Status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", refusal.Status, http.StatusForbidden)
	}
	if !strings.Contains(refusal.Reason, "innsegl") {
		t.Errorf("reason %q does not name innsegl", refusal.Reason)
	}
	if r2 != nil {
		t.Error("a refused Check must not return a request to forward")
	}
}

func TestIdentityGuardGID012RefusesWhenThePolicyCannotReadThePriorState(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-unreadable", SessionID: id.SessionID, AgentID: id.AgentID,
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	// No state set for run-unreadable: fakeRunStates answers "", which is
	// not one of ledger.RunStates -- the policy refuses rather than guess.

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal == nil {
		t.Fatal("want a refusal")
	}
	if refusal.Status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", refusal.Status, http.StatusForbidden)
	}
	if len(f.registrar.calls) != 0 {
		t.Errorf("registrar calls = %v, want none: nothing should be forwarded (GID-012)", f.registrar.calls)
	}
}

func TestIdentityGuardGID012RefusesWhenRunStatesErrors(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-x", SessionID: id.SessionID, AgentID: id.AgentID,
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.err = errors.New("the chain is unreachable")

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(refusal.Reason, "reading run state") {
		t.Errorf("reason %q does not name the failing step", refusal.Reason)
	}
}

func TestIdentityGuardGID012RefusesWhenTheWorkspaceCannotBeResolved(t *testing.T) {
	f := newIdentityFixture(t)
	f.workspaces.err = errors.New("the working directory is outside the projects mount")
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal == nil {
		t.Fatal("want a refusal")
	}
	if refusal.Status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", refusal.Status, http.StatusForbidden)
	}
	if len(f.registrar.calls) != 0 {
		t.Errorf("registrar calls = %v, want none: an unresolved workspace must never reach Register", f.registrar.calls)
	}
}

func TestIdentityGuardGID012RefusesWhenRegistrationFails(t *testing.T) {
	f := newIdentityFixture(t)
	f.registrar.err = errors.New("the ledger is unreachable")
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal == nil {
		t.Fatal("want a refusal")
	}
	if refusal.Status != http.StatusForbidden {
		t.Errorf("status = %d, want %d", refusal.Status, http.StatusForbidden)
	}
}

// ---------------------------------------------------------------------------
// A later row when a fingerprint first becomes known (Continue).
// ---------------------------------------------------------------------------

func TestIdentityGuardRecordsALaterRowWhenAFingerprintFirstBecomesKnown(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-fp", SessionID: id.SessionID, AgentID: id.AgentID, // no fingerprint yet
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-fp", ledger.RunActive)

	before := len(f.mappings.rows)
	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	afterFirst := len(f.mappings.rows)
	if afterFirst != before+1 {
		t.Fatalf("rows after the fingerprint first became known = %d, want %d", afterFirst, before+1)
	}
	m, found, err := f.mappings.BySessionAgent(t.Context(), id.SessionID, id.AgentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent: found=%v err=%v", found, err)
	}
	if m.Fingerprint == "" {
		t.Error("the later row does not carry the fingerprint")
	}
	if m.RunID != "run-fp" {
		t.Errorf("the later row's run id = %q, want run-fp (unchanged)", m.RunID)
	}

	// A second request of the SAME conversation must not insert yet another
	// row: the fingerprint is already known.
	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi")); refusal != nil {
		t.Fatalf("refused (second request): %+v", refusal)
	}
	if got := len(f.mappings.rows); got != afterFirst {
		t.Errorf("rows after a second request of the same conversation = %d, want %d (no duplicate row)",
			got, afterFirst)
	}
}

// ---------------------------------------------------------------------------
// NewIdentityGuard: refuse rather than run half-wired.
// ---------------------------------------------------------------------------

func TestNewIdentityGuardRefusesAnIncompleteConfiguration(t *testing.T) {
	complete := func() IdentityGuardConfig {
		return IdentityGuardConfig{
			Mappings: &fakeMappingStore{}, Tree: &fakeTreeLinker{}, Policy: NewPolicy(),
			Registrar: &fakeRegistrar{}, Workspaces: &fakeWorkspaceResolver{}, RunStates: newFakeRunStates(),
			SessionWorkspaces: NewSessionWorkspaces(0),
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*IdentityGuardConfig)
	}{
		{"no MappingStore", func(c *IdentityGuardConfig) { c.Mappings = nil }},
		{"no TreeLinker", func(c *IdentityGuardConfig) { c.Tree = nil }},
		{"no LifecyclePolicy", func(c *IdentityGuardConfig) { c.Policy = nil }},
		{"no Registrar", func(c *IdentityGuardConfig) { c.Registrar = nil }},
		{"no WorkspaceResolver", func(c *IdentityGuardConfig) { c.Workspaces = nil }},
		{"no RunStateReader", func(c *IdentityGuardConfig) { c.RunStates = nil }},
		{"no SessionWorkspaces", func(c *IdentityGuardConfig) { c.SessionWorkspaces = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := complete()
			tc.mutate(&cfg)
			if _, err := NewIdentityGuard(cfg); err == nil {
				t.Fatalf("%s: NewIdentityGuard accepted an incomplete configuration", tc.name)
			}
		})
	}
}

func TestNewIdentityGuardAcceptsAMinimalConfiguration(t *testing.T) {
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: &fakeMappingStore{}, Tree: &fakeTreeLinker{}, Policy: NewPolicy(),
		Registrar: &fakeRegistrar{}, Workspaces: &fakeWorkspaceResolver{}, RunStates: newFakeRunStates(),
		SessionWorkspaces: NewSessionWorkspaces(0),
	})
	if err != nil {
		t.Fatalf("NewIdentityGuard: %v", err)
	}
	if g == nil {
		t.Fatal("NewIdentityGuard returned a nil guard with no error")
	}
}

// ---------------------------------------------------------------------------
// insertAndCache: a store failure is not cached, so the next request tries
// again rather than trusting a row the store never actually has.
// ---------------------------------------------------------------------------

// failingInsertMappingStore wraps fakeMappingStore and fails every Insert.
type failingInsertMappingStore struct{ *fakeMappingStore }

func (f failingInsertMappingStore) Insert(context.Context, RunMapping) error {
	return errors.New("the store is down")
}

func TestIdentityGuardDoesNotCacheARowTheStoreFailedToInsert(t *testing.T) {
	f := newIdentityFixture(t)
	failing := failingInsertMappingStore{fakeMappingStore: f.mappings.fakeMappingStore}
	g, err := NewIdentityGuard(IdentityGuardConfig{
		Mappings: failing, Tree: f.tree, Policy: NewPolicy(), Registrar: f.registrar,
		Workspaces: f.workspaces, RunStates: f.runStates, SessionWorkspaces: f.sessionWorkspaces,
	})
	if err != nil {
		t.Fatalf("NewIdentityGuard: %v", err)
	}
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	// A registration still succeeds -- Insert's own failure does not refuse
	// the request, since the run itself is real and already registered.
	if _, refusal := g.Check(identityRequest(t, id, "hello", "")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}

	// But nothing was cached: a second request looks the run up again
	// (fakeMappingStore never learned of it either, since Insert always
	// failed), so it registers a SECOND time rather than continuing the
	// first -- which is the honest consequence of a mapping store that
	// cannot record what happened, not a defect in the cache.
	if _, refusal := g.Check(identityRequest(t, id, "hello", "")); refusal != nil {
		t.Fatalf("refused (second request): %+v", refusal)
	}
	if len(f.registrar.calls) != 2 {
		t.Errorf("registrar calls = %v, want 2 (both requests registered, since neither was ever recorded)",
			f.registrar.calls)
	}
}

// ---------------------------------------------------------------------------
// The in-memory cache: a second request of the same (session, agent) does
// not repeat the store lookup.
// ---------------------------------------------------------------------------

func TestIdentityGuardCachesThePriorMappingAcrossRequests(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-cached", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-cached", ledger.RunActive)

	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	firstCalls := f.mappings.bySessionAgentCalls
	if firstCalls == 0 {
		t.Fatal("the first request never consulted the store at all")
	}

	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi")); refusal != nil {
		t.Fatalf("refused (second request): %+v", refusal)
	}
	if got := f.mappings.bySessionAgentCalls; got != firstCalls {
		t.Errorf("BySessionAgent was called %d times after a second request, want %d "+
			"(the cache should have answered it)", got, firstCalls)
	}
}

// ---------------------------------------------------------------------------
// The working directory comes from the session hook (SessionWorkspaces),
// never from the conversation's prose.
// ---------------------------------------------------------------------------

func TestIdentityGuardRegistersFromTheDirectoryTheHookStated(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	r2, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if f.workspaces.dir != fixtureDirectory {
		t.Errorf("resolved directory = %q, want the hook's %q", f.workspaces.dir, fixtureDirectory)
	}
	facts, _ := RequestFactsFromContext(r2.Context())
	if facts.WorkingDirectory != fixtureDirectory {
		t.Errorf("RequestFacts.WorkingDirectory = %q, want the hook's %q: the recorder snapshots it",
			facts.WorkingDirectory, fixtureDirectory)
	}
}

// The prose of the conversation never names the workspace, even when it
// states a directory the hook did not.
func TestIdentityGuardIgnoresADirectoryStatedInTheConversation(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	if _, refusal := f.guard.Check(identityRequest(t, id, " - Primary working directory: /workspace/prose", "")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if f.workspaces.dir != fixtureDirectory {
		t.Errorf("resolved directory = %q, want the hook's %q", f.workspaces.dir, fixtureDirectory)
	}
}

// A session the hook has not stated is forwarded unrecorded (RM-313): a 503
// with Retry-After was a loop the harness retried into ten times and then
// failed. Nothing is resolved or registered.
func TestIdentityGuardForwardsUnrecordedWhenNoDirectoryIsKnown(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s-unstated", AgentID: mainAgentID}

	out, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal != nil || out == nil {
		t.Fatalf("refused %+v, want it forwarded", refusal)
	}
	if _, ok := RunIDFromContext(out.Context()); ok {
		t.Error("an unstated session carries a run")
	}
	if f.workspaces.calls != 0 || len(f.registrar.calls) != 0 {
		t.Errorf("resolver calls = %d, registrar calls = %v; want none", f.workspaces.calls, f.registrar.calls)
	}
}

// Restoring a lapsed run replays its registration from what the chain
// recorded. It needs no directory, so a gateway restart that emptied the
// registry cannot strand a run that already exists.
func TestIdentityGuardRestoresFromTheChainWithoutADirectory(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s-unstated", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-restore", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-restore", ledger.RunLapsed)
	f.runStates.register("run-restore", RunRegistration{AgentType: "reviewer", TaskID: "task-9", Repo: "acme/chain"})

	if _, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi")); refusal != nil {
		t.Fatalf("refused: %+v", refusal)
	}
	if f.workspaces.calls != 0 {
		t.Errorf("resolver calls = %d, want none: a restore reads the chain", f.workspaces.calls)
	}
	got := f.registrar.lastSeen
	if got.AgentType != "reviewer" || got.Workspace.Task != "task-9" || got.Workspace.Repo != "acme/chain" {
		t.Errorf("restore input = %+v, want the chain's agent type, task and repo", got)
	}
}

func TestIdentityGuardRefusesARestoreWhoseRegistrationCannotBeRead(t *testing.T) {
	f := newIdentityFixture(t)
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{
		RunID: "run-unread", SessionID: id.SessionID, AgentID: id.AgentID, Fingerprint: "fp-1",
	}); err != nil {
		t.Fatalf("seed Insert: %v", err)
	}
	f.runStates.set("run-unread", ledger.RunLapsed)

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal == nil || refusal.Status != http.StatusForbidden {
		t.Fatalf("refusal = %+v, want 403", refusal)
	}
	if len(f.registrar.calls) != 0 {
		t.Errorf("registrar calls = %v, want none", f.registrar.calls)
	}
}

// A dependency outage (a retryable class: IDENTITY_UNAVAILABLE,
// LEDGER_UNAVAILABLE, ...) is answered 503 with Retry-After and a reason
// naming what is down, so the harness retries and a person reading the error
// knows what to start. A refusal of the request itself stays 403.
func TestIdentityGuardAnswersADependencyOutageWithARetry(t *testing.T) {
	f := newIdentityFixture(t)
	f.registrar.err = mcp.Errorf(mcp.ClassIdentityUnavailable, "", "spire-server is unreachable")
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal == nil || refusal.Status != http.StatusServiceUnavailable || refusal.RetryAfter <= 0 {
		t.Fatalf("refusal = %+v, want 503 with Retry-After", refusal)
	}
	if !strings.Contains(refusal.Reason, "IDENTITY_UNAVAILABLE") || !strings.Contains(refusal.Reason, "spire-server is unreachable") {
		t.Errorf("reason %q does not name the outage", refusal.Reason)
	}
}

func TestIdentityGuardKeeps403ForARefusalOfTheRequestItself(t *testing.T) {
	f := newIdentityFixture(t)
	f.registrar.err = mcp.Errorf(mcp.ClassInvariantViolation, "", "the repository is outside the admin scope")
	id := Identification{SessionID: "s1", AgentID: mainAgentID}

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", ""))
	if refusal == nil || refusal.Status != http.StatusForbidden || refusal.RetryAfter != 0 {
		t.Fatalf("refusal = %+v, want 403 with no Retry-After", refusal)
	}
}

// The mapping store unreachable (Postgres down) is an outage too.
func TestIdentityGuardAnswersAnUnreachableStoreWithARetry(t *testing.T) {
	f := newIdentityFixture(t)
	f.runStates.err = &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	id := Identification{SessionID: "s1", AgentID: mainAgentID}
	if err := f.mappings.Insert(t.Context(), RunMapping{RunID: "run-x", SessionID: "s1", AgentID: mainAgentID}); err != nil {
		t.Fatal(err)
	}

	_, refusal := f.guard.Check(identityRequest(t, id, "hello", "hi"))
	if refusal == nil || refusal.Status != http.StatusServiceUnavailable {
		t.Fatalf("refusal = %+v, want 503", refusal)
	}
}

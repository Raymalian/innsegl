// SPDX-License-Identifier: Apache-2.0

package gateway

// In-memory fakes of the E15 contract (lifecycle_contract.go), shared by every
// issue's tests so none depends on another's implementation. Behaviour here is
// the contract's, deliberately simple; the real implementations prove
// themselves against the same expectations.

import (
	"context"
	"sync"
	"time"
)

type fakeMappingStore struct {
	mu   sync.Mutex
	rows []RunMapping
}

func (f *fakeMappingStore) Insert(_ context.Context, m RunMapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m.RecordedAt.IsZero() {
		m.RecordedAt = time.Now()
	}
	f.rows = append(f.rows, m)
	return nil
}

func (f *fakeMappingStore) BySessionAgent(_ context.Context, sessionID, agentID string) (RunMapping, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.rows) - 1; i >= 0; i-- {
		if f.rows[i].SessionID == sessionID && f.rows[i].AgentID == agentID {
			return f.rows[i], true, nil
		}
	}
	return RunMapping{}, false, nil
}

func (f *fakeMappingStore) ByFingerprint(_ context.Context, fp Fingerprint) ([]RunMapping, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []RunMapping
	for _, r := range f.rows {
		if fp != "" && r.Fingerprint == fp {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeRegistrar struct {
	mu       sync.Mutex
	next     int
	err      error
	calls    []string // "register", "restore", "retire" in call order
	retired  map[string]string
	lastSeen RegisterInput
}

func (f *fakeRegistrar) Register(_ context.Context, in RegisterInput) (RegisteredRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "register")
	f.lastSeen = in
	if f.err != nil {
		return RegisteredRun{}, f.err
	}
	f.next++
	id := "run-fake" + string(rune('a'+f.next-1))
	return RegisteredRun{RunID: id, SPIFFEID: "spiffe://innsegl.dev/agent/x/y/" + id, RunToken: "token-" + id}, nil
}

func (f *fakeRegistrar) Restore(_ context.Context, prior RunMapping, in RegisterInput) (RegisteredRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "restore")
	f.lastSeen = in
	if f.err != nil {
		return RegisteredRun{}, f.err
	}
	return RegisteredRun{RunID: prior.RunID, RunToken: "token-" + prior.RunID}, nil
}

func (f *fakeRegistrar) Retire(_ context.Context, runID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "retire")
	if f.err != nil {
		return "", f.err
	}
	if f.retired == nil {
		f.retired = map[string]string{}
	}
	f.retired[runID] = "2026-09-28T00:00:00Z"
	return f.retired[runID], nil
}

type fakeTreeLinker struct {
	mu     sync.Mutex
	spawns []PendingSpawn
}

func (f *fakeTreeLinker) RecordSpawn(_ context.Context, s PendingSpawn) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spawns = append(f.spawns, s)
	return nil
}

func (f *fakeTreeLinker) ResolveParent(_ context.Context, sessionID, childBrief string) (string, string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.spawns {
		if s.SessionID == sessionID && s.Prompt == childBrief {
			f.spawns = append(f.spawns[:i], f.spawns[i+1:]...)
			return s.ParentRunID, s.AgentType, true, nil
		}
	}
	return "", "", false, nil
}

type fakePolicy struct {
	decision Decision
	err      error
	seen     []LifecycleInput
}

func (f *fakePolicy) Decide(_ context.Context, in LifecycleInput) (Decision, error) {
	f.seen = append(f.seen, in)
	return f.decision, f.err
}

type fakeWorkspaceResolver struct {
	ws  Workspace
	err error
}

func (f fakeWorkspaceResolver) Resolve(context.Context, string) (Workspace, error) {
	return f.ws, f.err
}

// The fakes satisfy the contract; a drift in either fails to compile here.
var (
	_ MappingStore      = (*fakeMappingStore)(nil)
	_ Registrar         = (*fakeRegistrar)(nil)
	_ TreeLinker        = (*fakeTreeLinker)(nil)
	_ LifecyclePolicy   = (*fakePolicy)(nil)
	_ WorkspaceResolver = fakeWorkspaceResolver{}
)

// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// codexSpawns holds exact canonical task-name associations witnessed in the
// parent's relayed spawn_agent call. It does not infer a brief from a name or
// parse encrypted child messages. Entries, including consumed claims and
// ambiguous names, share the existing pending-spawn lifetime and cache bound.
type codexSpawns struct {
	mu      sync.Mutex
	max     int
	order   []identityCacheKey
	entries map[identityCacheKey]codexSpawn
}

type codexSpawn struct {
	parentRun, parentThread, callID, childThread string
	created                                      time.Time
	ambiguous                                    bool
}

func newCodexSpawns(limit int) *codexSpawns {
	return &codexSpawns{max: limit, entries: make(map[identityCacheKey]codexSpawn)}
}

func (s *codexSpawns) expire(now time.Time) {
	for len(s.order) > 0 {
		k := s.order[0]
		if now.Sub(s.entries[k].created) < DefaultPendingSpawnWindow {
			break
		}
		delete(s.entries, k)
		s.order = s.order[1:]
	}
}

func (s *codexSpawns) record(session, name string, spawn codexSpawn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(spawn.created)
	k := identityCacheKey{session, name}
	if old, ok := s.entries[k]; ok {
		// Replayed stream events are one observation. Two distinct calls using
		// the same canonical name are ambiguous, even if their prompts agree.
		if old.callID != spawn.callID || old.parentThread != spawn.parentThread || old.parentRun != spawn.parentRun {
			old.ambiguous = true
			s.entries[k] = old
		}
		return
	}
	if len(s.order) >= s.max {
		delete(s.entries, s.order[0])
		s.order = s.order[1:]
	}
	s.order = append(s.order, k)
	s.entries[k] = spawn
}

func (s *codexSpawns) claim(t CodexThreadIdentity, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(now)
	k := identityCacheKey{t.SessionID, t.AgentName}
	spawn, ok := s.entries[k]
	if !ok || spawn.ambiguous || spawn.parentThread != t.ParentThreadID || spawn.childThread != "" && spawn.childThread != t.ThreadID {
		return "", false
	}
	spawn.childThread = t.ThreadID
	s.entries[k] = spawn
	return spawn.parentRun, true
}

var (
	_ ToolUseObserver        = (*IdentityGuard)(nil)
	_ ContextToolUseObserver = (*IdentityGuard)(nil)
)

// OnToolUse has no request context and therefore cannot establish a parent.
func (g *IdentityGuard) OnToolUse(ToolUse) {}

// OnToolUseContext observes the measured Codex collaboration.spawn_agent
// function in its parent's request context. Claude spawning remains owned
// by SpawnRecorder and its exact brief matching rule.
func (g *IdentityGuard) OnToolUseContext(ctx context.Context, call ToolUse) {
	if call.Truncated || call.WireType != "function_call" || call.Namespace != "collaboration" || call.Name != "collaboration.spawn_agent" || call.ID == "" {
		return
	}
	id, ok := IdentificationFromContext(ctx)
	if !ok || id.Harness != "codex" {
		return
	}
	thread, ok := CodexThreadFromContext(ctx)
	if !ok {
		return
	}
	run, ok := RunIDFromContext(ctx)
	if !ok || run == "" {
		return
	}
	var in struct {
		TaskName string `json:"task_name"`
		Message  string `json:"message"`
	}
	if json.Unmarshal(call.Input, &in) != nil || in.TaskName == "" || strings.Contains(in.TaskName, "/") || in.Message == "" {
		return
	}
	name := thread.AgentName + "/" + in.TaskName
	if !validCodexAgentName(name) {
		return
	}
	g.codexSpawns.record(id.SessionID, name, codexSpawn{parentRun: run, parentThread: thread.ThreadID, callID: call.ID, created: g.now()})
}

// codexParent either consumes an observed association, or recovers the
// registration already bound to this child's idempotency key on the chain.
// Recovery reuses a known association; it never creates one from a header.
func (g *IdentityGuard) codexParent(ctx context.Context, id Identification, thread CodexThreadIdentity) (string, error) {
	if parent, ok := g.codexSpawns.claim(thread, g.now()); ok {
		return parent, nil
	}
	reg, found, err := g.runStates.RegistrationByKey(ctx, idempotencyKeyFor(id))
	if err != nil {
		return "", err
	}
	if !found || reg.RunID == "" || reg.ParentRunID == "" {
		return "", errors.New("no unambiguous independently observed Codex spawn matches this child")
	}
	agent := thread.ParentThreadID
	if agent == id.SessionID {
		agent = mainAgentID
	}
	parent, found, err := g.mappings.BySessionAgent(ctx, id.SessionID, agent)
	if err != nil {
		return "", err
	}
	caller, _ := InstallationFromContext(ctx)
	if !found || parent.RunID != reg.ParentRunID || parent.ClientID != caller {
		return "", errors.New("the recorded Codex child registration does not agree with its scoped parent mapping")
	}
	return reg.ParentRunID, nil
}

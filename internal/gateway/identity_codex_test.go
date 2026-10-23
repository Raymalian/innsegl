// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// OAI-006: a header naming a parent cannot create a child identity without
// an independently observed spawning call.
func TestOAI006CodexChildWithoutSpawnRefused(t *testing.T) {
	f := newIdentityFixture(t)
	f.sessionWorkspaces.Record("11111111-1111-4111-8111-111111111111", "", fixtureDirectory)
	r := codexChildRequest(t, "22222222-2222-4222-8222-222222222222", "/root/worker", "11111111-1111-4111-8111-111111111111")
	r, refusal := NewHarnessGuard().Check(r)
	if refusal != nil {
		t.Fatal(refusal)
	}
	if _, refusal = f.guard.Check(r); refusal == nil {
		t.Fatal("unproven child was allowed to acquire an identity")
	}
	if len(f.registrar.calls) != 0 {
		t.Fatal("unproven child registered")
	}
}

// OAI-006: independent observed spawns produce separate runs, including a
// grandchild, even when sibling prompts are identical.
func TestOAI006CodexObservedSpawnLinksIndependentChildren(t *testing.T) {
	f := newIdentityFixture(t)
	f.sessionWorkspaces.Record("11111111-1111-4111-8111-111111111111", "", fixtureDirectory)
	observer, ok := any(f.guard).(ContextToolUseObserver)
	if !ok {
		t.Fatal("identity guard does not observe Codex spawning calls")
	}
	root := codexChildRequest(t, "11111111-1111-4111-8111-111111111111", "/root", "")
	root.Header.Del("X-OpenAI-Subagent")
	root.Header.Del("X-Codex-Parent-Thread-Id")
	root.Header.Set("X-Codex-Turn-Metadata", `{"session_id":"11111111-1111-4111-8111-111111111111","thread_id":"11111111-1111-4111-8111-111111111111","agent_name":"/root"}`)
	parent, refusal := NewHarnessGuard().Check(root)
	if refusal != nil {
		t.Fatal(refusal)
	}
	parent, refusal = f.guard.Check(parent)
	if refusal != nil {
		t.Fatal(refusal)
	}
	parentRun := mustRunID(t, parent)
	observe := func(ctx context.Context, name, call string) {
		observer.OnToolUseContext(ctx, ToolUse{WireType: "function_call", Namespace: "collaboration", Name: "collaboration.spawn_agent", ID: call, Input: json.RawMessage(`{"task_name":"` + name + `","message":"identical prompt","fork_turns":"none"}`)})
	}
	child := func(thread, name, parentThread string) *http.Request {
		r, refusal := NewHarnessGuard().Check(codexChildRequest(t, thread, name, parentThread))
		if refusal != nil {
			t.Fatal(refusal)
		}
		r, refusal = f.guard.Check(r)
		if refusal != nil {
			t.Fatal(refusal)
		}
		return r
	}
	observe(parent.Context(), "worker", "spawn-1")
	first := child("22222222-2222-4222-8222-222222222222", "/root/worker", "11111111-1111-4111-8111-111111111111")
	if f.registrar.lastSeen.ParentRunID != parentRun {
		t.Fatalf("parent=%q want %q", f.registrar.lastSeen.ParentRunID, parentRun)
	}
	observe(parent.Context(), "sibling", "spawn-2")
	second := child("33333333-3333-4333-8333-333333333333", "/root/sibling", "11111111-1111-4111-8111-111111111111")
	if mustRunID(t, first) == mustRunID(t, second) || mustRunID(t, first) == parentRun {
		t.Fatal("child identities were shared")
	}
	observe(first.Context(), "nested", "spawn-3")
	_ = child("44444444-4444-4444-8444-444444444444", "/root/worker/nested", "22222222-2222-4222-8222-222222222222")
	if f.registrar.lastSeen.ParentRunID != mustRunID(t, first) {
		t.Fatalf("nested parent=%q", f.registrar.lastSeen.ParentRunID)
	}
	// Same thread after a gateway restart relies on its durable run mapping.
	f.runStates.set(mustRunID(t, first), ledger.RunActive)
	f.guard.cache = newIdentityCache[RunMapping](1)
	f.guard.codexSpawns = newCodexSpawns(1)
	before := len(f.registrar.calls)
	if got := mustRunID(t, child("22222222-2222-4222-8222-222222222222", "/root/worker", "11111111-1111-4111-8111-111111111111")); got != mustRunID(t, first) {
		t.Fatal("resume changed run")
	}
	if len(f.registrar.calls) != before {
		t.Fatal("resume registered another run")
	}
}

// OAI-019: a child's inherited transcript cannot substitute another agent's
// run for the independently observed spawn association.
func TestOAI019CodexChildDoesNotInheritFingerprintIdentity(t *testing.T) {
	f := newIdentityFixture(t)
	if err := f.mappings.Insert(t.Context(), RunMapping{SessionID: "11111111-1111-4111-8111-111111111111", AgentID: "main", RunID: "root-run", Fingerprint: "same-transcript"}); err != nil {
		t.Fatal(err)
	}
	id := Identification{Harness: "codex", SessionID: "11111111-1111-4111-8111-111111111111", AgentID: "22222222-2222-4222-8222-222222222222"}
	if prior, found, err := f.guard.priorMapping(t.Context(), id, "same-transcript"); err != nil || found {
		t.Fatalf("child inherited fingerprint mapping: %+v found=%v err=%v", prior, found, err)
	}
}

// OAI-006/OAI-019: replay never supplies a second child, repeated canonical
// names are ambiguous, and pending/consumed associations stay bounded.
func TestOAI006CodexSpawnClaimsReplayAmbiguityAndBounds(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	thread := CodexThreadIdentity{SessionID: "s", ThreadID: "child", AgentName: "/root/worker", ParentThreadID: "parent"}
	spawn := codexSpawn{parentRun: "parent-run", parentThread: "parent", callID: "call-1", created: now}
	t.Run("replay and one child", func(t *testing.T) {
		s := newCodexSpawns(2)
		s.record("s", "/root/worker", spawn)
		s.record("s", "/root/worker", spawn)
		if run, ok := s.claim(thread, now); !ok || run != "parent-run" {
			t.Fatalf("claim=%q,%v", run, ok)
		}
		if _, ok := s.claim(thread, now); !ok {
			t.Fatal("same child retry lost its parent")
		}
		other := thread
		other.ThreadID = "other-child"
		if _, ok := s.claim(other, now); ok {
			t.Fatal("spawn was reused by another thread")
		}
		other = thread
		other.ParentThreadID = "wrong-parent"
		if _, ok := s.claim(other, now); ok {
			t.Fatal("header-selected parent replaced observed parent")
		}
	})
	t.Run("ambiguous names", func(t *testing.T) {
		s := newCodexSpawns(2)
		s.record("s", "/root/worker", spawn)
		other := spawn
		other.callID = "call-2"
		s.record("s", "/root/worker", other)
		if _, ok := s.claim(thread, now); ok {
			t.Fatal("ambiguous canonical name linked")
		}
	})
	t.Run("capacity", func(t *testing.T) {
		s := newCodexSpawns(1)
		s.record("s", "/root/worker", spawn)
		s.record("s", "/root/sibling", spawn)
		if _, ok := s.claim(thread, now); ok {
			t.Fatal("oldest association survived capacity eviction")
		}
		if len(s.entries) != 1 {
			t.Fatal("unbounded associations")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		s := newCodexSpawns(2)
		s.record("s", "/root/worker", spawn)
		if _, ok := s.claim(thread, now.Add(DefaultPendingSpawnWindow)); ok {
			t.Fatal("expired association linked")
		}
	})
}

func TestOAI006CodexSpawnObserverRejectsUnprovenCalls(t *testing.T) {
	f := newIdentityFixture(t)
	thread := CodexThreadIdentity{SessionID: "s", ThreadID: "parent", AgentName: "/root"}
	ctx := context.WithValue(WithRunID(WithIdentification(t.Context(), Identification{Harness: "codex", SessionID: "s", AgentID: "main"}), "parent-run"), codexThreadContextKey{}, thread)
	valid := ToolUse{WireType: "function_call", Namespace: "collaboration", Name: "collaboration.spawn_agent", ID: "call", Input: json.RawMessage(`{"task_name":"worker","message":"opaque"}`)}
	for _, variant := range []string{"truncated", "namespace", "kind", "missing call", "missing message", "bad name", "no parent context", "no run", "other harness"} {
		t.Run(variant, func(t *testing.T) {
			call := valid
			c := ctx
			switch variant {
			case "truncated":
				call.Truncated = true
			case "namespace":
				call.Namespace = ""
			case "kind":
				call.WireType = "custom_tool_call"
			case "missing call":
				call.ID = ""
			case "missing message":
				call.Input = json.RawMessage(`{"task_name":"worker"}`)
			case "bad name":
				call.Input = json.RawMessage(`{"task_name":"../worker","message":"opaque"}`)
			case "no parent context":
				c = t.Context()
			case "no run":
				c = WithRunID(ctx, "")
			case "other harness":
				c = WithIdentification(ctx, Identification{Harness: "claude-code"})
			}
			f.guard.OnToolUseContext(c, call)
			if _, ok := f.guard.codexSpawns.claim(CodexThreadIdentity{SessionID: "s", ThreadID: "child", AgentName: "/root/worker", ParentThreadID: "parent"}, f.guard.now()); ok {
				t.Fatal("unproven spawning call linked")
			}
		})
	}
}

// OAI-019: recover a chain-known child after registration succeeded but its
// mapping insert was lost. The original parent must match the scoped mapping.
func TestOAI019CodexChildRecoversRecordedRegistration(t *testing.T) {
	for _, variant := range []string{"recover", "wrong parent", "foreign installation"} {
		t.Run(variant, func(t *testing.T) {
			f := newIdentityFixture(t)
			const session = "11111111-1111-4111-8111-111111111111"
			const child = "22222222-2222-4222-8222-222222222222"
			f.sessionWorkspaces.Record(session, "", fixtureDirectory)
			parent := RunMapping{SessionID: session, AgentID: "main", RunID: "parent-run"}
			if variant == "wrong parent" {
				parent.RunID = "another-run"
			}
			if variant == "foreign installation" {
				parent.ClientID = "foreign-installation"
			}
			if err := f.mappings.Insert(t.Context(), parent); err != nil {
				t.Fatal(err)
			}
			id := Identification{Harness: "codex", Version: "0.163.0", SessionID: session, AgentID: child}
			f.runStates.register("known-child", RunRegistration{RunID: "known-child", IdempotencyKey: idempotencyKeyFor(id), AgentType: "subagent", TaskID: "original-task", Repo: "acme/id-test", Branch: "original-branch", ParentRunID: "parent-run"})
			f.runStates.set("known-child", ledger.RunActive)
			r, refusal := NewHarnessGuard().Check(codexChildRequest(t, child, "/root/worker", session))
			if refusal != nil {
				t.Fatal(refusal)
			}
			next, refusal := f.guard.Check(r)
			if variant != "recover" {
				if refusal == nil {
					t.Fatal("unproven parent mapping recovered a child")
				}
				return
			}
			if refusal != nil {
				t.Fatalf("known child registration not recovered: %+v", refusal)
			}
			if mustRunID(t, next) != "known-child" {
				t.Fatal("recovery created another run")
			}
			if len(f.registrar.calls) != 1 || f.registrar.calls[0] != "restore" {
				t.Fatalf("calls=%v", f.registrar.calls)
			}
			if f.registrar.lastSeen.ParentRunID != "parent-run" || f.registrar.lastSeen.Workspace.Branch != "original-branch" {
				t.Fatalf("registration was recomputed: %+v", f.registrar.lastSeen)
			}
		})
	}
}

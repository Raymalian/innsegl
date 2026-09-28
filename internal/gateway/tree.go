// SPDX-License-Identifier: Apache-2.0

package gateway

// tree.go is #377 (RM-232): TreeLinker's (lifecycle_contract.go) in-memory
// implementation. A child is linked to the parent whose spawning tool call
// carried exactly the child's brief (ADR-0058 decision 3), never by
// containment. Containment mislinked twice in the spike behind that
// decision: once as a parsing-order bug (a spawn parsed only at the end of
// a stream), and once for a reason no timing fix removes -- a parent's own
// brief can legitimately quote a child's job text as a substring, and the
// first run of that spike's three-level tree "linked main to itself" for
// exactly that reason (docs/decisions/model-gateway-spike.md, spike 5).
// Exact equality does not have either failure mode: a parent's own brief is
// a different, larger text that CONTAINS a child's prompt, never one that
// EQUALS it, so a parent is never mistaken for its own child.
//
// # Bounded, the same shape as limit.go's session table
//
// A PendingSpawn is recorded from a parent's own tool call (sse.go's
// ToolUseObserver, upstream of this file) as soon as it is seen, which can
// be before its child's first request has even reached the gateway. A spawn
// that never resolves -- a denied tool call, a crash, a hand-back with no
// follow-up -- must not grow this table forever, the same reasoning
// SessionRateLimiter (limit.go) already applies to its own harness-asserted
// keys (ADR-0025's framing). Two bounds:
//
//   - DefaultPendingSpawnWindow: a spawn older than this, by this linker's
//     own clock rather than the caller-supplied PendingSpawn.ObservedAt
//     (harness-adjacent input, trusted for its content, never for its
//     timing), is evicted on the next RecordSpawn or ResolveParent call.
//   - DefaultMaxPendingSpawns: the table's hard cap. At capacity, the
//     OLDEST spawn is evicted to make room -- the one furthest from ever
//     being matched now that a fresher one has arrived, the same "furthest
//     from being useful" reasoning limit.go's evictFullest uses, applied to
//     age instead of refill time.
//
// One spawn links exactly one child: ResolveParent removes a spawn the
// moment it matches, so a second child (or the same child asking twice)
// cannot consume it again. Two DIFFERENT parents spawning children with the
// identical prompt in the same session each get their own match, oldest
// spawn first (FIFO) -- see
// TestTreeLinkerParallelIdenticalPromptsLinkOnePerChild.

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultPendingSpawnWindow bounds how long a recorded spawn survives
	// waiting for its child before it is evicted, whether or not it is ever
	// matched. A child's first request ordinarily reaches the gateway
	// within the same round trip that closed the spawning tool_use block --
	// seconds, the same model-latency order limit.go's own reasoning
	// already uses for its sustained-rate default -- so a window in the
	// tens of minutes is generous for a live spawn while still bounding
	// memory for one that never resolves.
	DefaultPendingSpawnWindow = 30 * time.Minute

	// DefaultMaxPendingSpawns bounds the table's size, the same reasoning
	// SessionRateLimiter's DefaultSessionRateLimitMaxSessions already gives:
	// a spawn's key (session id, brief) is harness-asserted, not
	// authenticated, so an unbounded table is a memory-exhaustion vector of
	// its own, independent of the window above.
	DefaultMaxPendingSpawns = 4096

	treeLinkerSource = "the gateway's agent tree linker"
)

// spawnKey is what a PendingSpawn is matched by: ADR-0058 decision 3's exact
// equality, never containment.
type spawnKey struct {
	sessionID string
	prompt    string
}

// spawnEntry is one live PendingSpawn, plus the linker's own record of when
// it arrived -- used for window eviction instead of the caller-supplied
// PendingSpawn.ObservedAt (see this file's own doc comment).
type spawnEntry struct {
	key        spawnKey
	spawn      PendingSpawn
	recordedAt time.Time
}

// TreeLinkerStats is the monitored surface, the same shape
// SessionRateLimitStats (limit.go) gives its own bounded table.
type TreeLinkerStats struct {
	// Pending is the table's current size.
	Pending int
	// Recorded and Resolved count RecordSpawn and ResolveParent successes,
	// cumulative.
	Recorded, Resolved int64
	// EvictedWindow counts spawns dropped for being older than the
	// configured window; EvictedCap counts spawns dropped to stay inside
	// MaxPendingSpawns. Kept separate because they mean different things to
	// an operator, the same distinction limit.go's own Evicted/EvictedIdle
	// draws: EvictedCap means the table is under pressure, EvictedWindow
	// means nothing more than housekeeping.
	EvictedWindow, EvictedCap int64
}

// TreeLinkerConfig configures an InMemoryTreeLinker. Every field is
// optional.
type TreeLinkerConfig struct {
	// Window bounds a spawn's lifetime. Zero or less means
	// DefaultPendingSpawnWindow.
	Window time.Duration
	// MaxPendingSpawns bounds the table's size. Zero or less means
	// DefaultMaxPendingSpawns.
	MaxPendingSpawns int
	// Now reads the clock. Nil means time.Now.
	Now func() time.Time
}

// InMemoryTreeLinker is TreeLinker's (lifecycle_contract.go) in-memory
// implementation. Safe for concurrent use.
type InMemoryTreeLinker struct {
	window    time.Duration
	maxSpawns int
	now       func() time.Time

	mu    sync.Mutex
	order *list.List // every live *spawnEntry, oldest first
	byKey map[spawnKey][]*list.Element
	stats TreeLinkerStats
}

// NewInMemoryTreeLinker builds a linker from cfg.
func NewInMemoryTreeLinker(cfg TreeLinkerConfig) *InMemoryTreeLinker {
	window := cfg.Window
	if window <= 0 {
		window = DefaultPendingSpawnWindow
	}
	maxSpawns := cfg.MaxPendingSpawns
	if maxSpawns <= 0 {
		maxSpawns = DefaultMaxPendingSpawns
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &InMemoryTreeLinker{
		window:    window,
		maxSpawns: maxSpawns,
		now:       now,
		order:     list.New(),
		byKey:     make(map[spawnKey][]*list.Element),
	}
}

// Compile-time gate: a drift from the frozen contract fails to compile here,
// exactly as lifecycle_fakes_test.go already gates its own fakes.
var _ TreeLinker = (*InMemoryTreeLinker)(nil)

// RecordSpawn implements TreeLinker. It refuses a spawn missing any of the
// three things a later ResolveParent needs to ever find or trust it: a
// session to match within, a prompt to match against, and a parent to
// report back. Recording one anyway would let ResolveParent hand out an
// empty or unowned parent, which is worse than refusing outright.
func (l *InMemoryTreeLinker) RecordSpawn(_ context.Context, s PendingSpawn) error {
	switch {
	case s.SessionID == "":
		return fmt.Errorf("%s: a pending spawn with no session id can never be matched", treeLinkerSource)
	case s.Prompt == "":
		return fmt.Errorf("%s: a pending spawn with no prompt can never be matched", treeLinkerSource)
	case s.ParentRunID == "":
		return fmt.Errorf("%s: a pending spawn with no parent run id would link a child to no one; "+
			"refusing rather than recording a spawn nothing can own", treeLinkerSource)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.evictWindow(now)
	if l.order.Len() >= l.maxSpawns {
		l.evictOldest()
	}

	entry := &spawnEntry{
		key:        spawnKey{sessionID: s.SessionID, prompt: s.Prompt},
		spawn:      s,
		recordedAt: now,
	}
	elem := l.order.PushBack(entry)
	l.byKey[entry.key] = append(l.byKey[entry.key], elem)
	l.stats.Recorded++
	return nil
}

// ResolveParent implements TreeLinker: exact equality of childBrief against
// a pending spawn's prompt, within the same session, never containment
// (ADR-0058 decision 3). A match is consumed -- removed from the table --
// so one spawn links exactly one child; among several spawns recorded for
// the same (sessionID, prompt) pair, the oldest is matched first (FIFO), so
// parallel children with an identical brief each link to their own spawn in
// the order those spawns were recorded.
func (l *InMemoryTreeLinker) ResolveParent(_ context.Context, sessionID, childBrief string) (string, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictWindow(l.now())

	key := spawnKey{sessionID: sessionID, prompt: childBrief}
	queue := l.byKey[key]
	if len(queue) == 0 {
		return "", false, nil
	}

	elem := queue[0]
	if len(queue) == 1 {
		delete(l.byKey, key)
	} else {
		l.byKey[key] = queue[1:]
	}
	l.order.Remove(elem)

	entry := mustSpawnEntry(elem.Value)
	l.stats.Resolved++
	return entry.spawn.ParentRunID, true, nil
}

// mustSpawnEntry asserts that v -- always an *list.Element's own Value in
// this file -- is a *spawnEntry, the only type this linker ever pushes onto
// l.order. A failure here can only mean an internal bug in this file, never
// caller input, so it panics rather than returning a third, silently-wrong
// value up through callers that have no way to report it.
func mustSpawnEntry(v any) *spawnEntry {
	entry, ok := v.(*spawnEntry)
	if !ok {
		panic(fmt.Sprintf("%s: internal error: list element held %T, not *spawnEntry", treeLinkerSource, v))
	}
	return entry
}

// Stats reports the counters.
func (l *InMemoryTreeLinker) Stats() TreeLinkerStats {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.stats
	s.Pending = l.order.Len()
	return s
}

// evictWindow drops every spawn at the front of l.order (oldest first)
// whose age has passed l.window. Called under l.mu.
func (l *InMemoryTreeLinker) evictWindow(now time.Time) {
	for {
		front := l.order.Front()
		if front == nil {
			return
		}
		entry := mustSpawnEntry(front.Value)
		if now.Sub(entry.recordedAt) < l.window {
			return
		}
		l.removeElement(front)
		l.stats.EvictedWindow++
	}
}

// evictOldest drops the single oldest spawn to make room for one more.
// Called under l.mu, only when the table is already at MaxPendingSpawns.
func (l *InMemoryTreeLinker) evictOldest() {
	front := l.order.Front()
	if front == nil {
		return
	}
	l.removeElement(front)
	l.stats.EvictedCap++
}

// removeElement removes elem from both l.order and its key's queue in
// l.byKey. Called under l.mu.
func (l *InMemoryTreeLinker) removeElement(elem *list.Element) {
	entry := mustSpawnEntry(elem.Value)
	l.order.Remove(elem)

	queue := l.byKey[entry.key]
	for i, e := range queue {
		if e == elem {
			queue = append(queue[:i], queue[i+1:]...)
			break
		}
	}
	if len(queue) == 0 {
		delete(l.byKey, entry.key)
	} else {
		l.byKey[entry.key] = queue
	}
}

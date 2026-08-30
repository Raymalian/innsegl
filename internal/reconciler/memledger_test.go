// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/reconciler"
)

// memLedger is a chain in memory, and it is a REAL chain: every append runs
// through ledger.Append (the same hash-chain function Postgres uses) and
// event.ValidateEvent (doc 02's closed schema), and the idempotency_key is
// UNIQUE across it the way LED-008 requires.
//
// It exists so the decision logic can be exercised without Postgres. It is not
// a substitute for the real store — REC-002's proof runs against a real
// Postgres, a real Rekor and a real signed commit, because IP §2 says a mock
// proves nothing about I5.
type memLedger struct {
	mu      sync.Mutex
	head    ledger.Head
	records []event.Fields
	byKey   map[string]event.Fields
	clock   func() time.Time
	// failOn, when set, makes an append of that event type fail. It is how the
	// error-return paths of this component are reached.
	failOn string
}

func newMemLedger(clock func() time.Time) *memLedger {
	return &memLedger{byKey: map[string]event.Fields{}, clock: clock}
}

func (m *memLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if et := str(body, event.FieldEventType); et == m.failOn && et != "" {
		return nil, fmt.Errorf("memLedger: refusing to append %s", et)
	}
	if key, ok := body[event.FieldIdempotencyKey].(string); ok && key != "" {
		if existing, found := m.byKey[key]; found {
			return existing, nil
		}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	stamped := body.Clone()
	stamped[event.FieldEventID] = id.String()
	stamped[event.FieldTS] = event.NewTimestamp(m.clock()).String()

	record, head, err := ledger.Append(m.head, stamped)
	if err != nil {
		return nil, err
	}
	if err := event.ValidateEvent(record); err != nil {
		return nil, err
	}
	m.head = head
	m.records = append(m.records, record)
	if key, ok := record[event.FieldIdempotencyKey].(string); ok && key != "" {
		m.byKey[key] = record
	}
	return record, nil
}

func (m *memLedger) Count(context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.records)), nil
}

func (m *memLedger) Events(_ context.Context, from, to int64) ([]event.Fields, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if from < 1 || to > int64(len(m.records)) || from > to {
		return nil, fmt.Errorf("memLedger: positions %d..%d out of range 1..%d",
			from, to, len(m.records))
	}
	return m.records[from-1 : to], nil
}

// types is the chain as a list of (event_type, source) pairs.
func (m *memLedger) types() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, str(r, event.FieldEventType)+"/"+str(r, event.FieldSource))
	}
	return out
}

func (m *memLedger) last() event.Fields {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.records) == 0 {
		return nil
	}
	return m.records[len(m.records)-1]
}

// ---------------------------------------------------------------------------
// The git and Rekor halves, as fakes. Both are replaced by the real thing in
// the integration case.
// ---------------------------------------------------------------------------

type fakeRepos struct {
	// commits maps repo -> tree hash -> the signed commits holding that tree.
	commits map[string]map[string][]string
	err     error
	calls   int
}

func (f *fakeRepos) SignedCommitsWithTree(_ context.Context, repo, tree string) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.commits[repo][tree], nil
}

type fakeLog struct {
	entries map[string]reconciler.LogEntry
	err     error
	calls   int
}

func (f *fakeLog) EntryForCommit(_ context.Context, commitSHA string) (reconciler.LogEntry, error) {
	f.calls++
	if f.err != nil {
		return reconciler.LogEntry{}, f.err
	}
	entry, found := f.entries[commitSHA]
	if !found {
		return reconciler.LogEntry{}, reconciler.ErrNoEntry
	}
	return entry, nil
}

// ---------------------------------------------------------------------------
// Seeding.
// ---------------------------------------------------------------------------

const (
	testTrustDomain = "innsegl.dev"
	testRepo        = "github.com/innsegl/demo"
	testTree        = "5dda8fd290f4d08d527bbe82c310a27fc0cddadb"
	testCommit      = "709483c5a911bd74809f728c23d67da0bebbf72a"
)

func spiffeIDFor(runID string) string {
	return fmt.Sprintf("spiffe://%s/agent/demo/rm-035/%s", testTrustDomain, runID)
}

// seedRun appends the run_registered every run starts with.
func seedRun(t *testing.T, m *memLedger, runID string) {
	t.Helper()
	if _, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "reg-" + runID,
		event.FieldAgentType:      "demo",
		event.FieldTaskRef:        "RM-035",
	}); err != nil {
		t.Fatalf("seed run_registered: %v", err)
	}
}

// seedIntent appends Phase A exactly as sign_commit appends it, derived key and
// all — the intent this component's whole job is to resolve.
func seedIntent(t *testing.T, m *memLedger, runID, tree string) event.Fields {
	t.Helper()
	record, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/intent/" + runID,
		event.FieldRepo:           testRepo,
		event.FieldTreeHash:       tree,
	})
	if err != nil {
		t.Fatalf("seed commit_intent: %v", err)
	}
	return record
}

// str reads a string member, or "" when it is absent or of another type. doc 02
// §1 does not admit an empty string as a value, so "" is unambiguously absent.
func str(record event.Fields, name string) string {
	value, ok := record[name].(string)
	if !ok {
		return ""
	}
	return value
}

func member[T any](t *testing.T, record event.Fields, name string) T {
	t.Helper()
	value, ok := record[name].(T)
	if !ok {
		t.Fatalf("event has no %s of the expected type: %#v", name, record[name])
	}
	return value
}

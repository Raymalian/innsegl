// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"time"
)

// SessionEndKind is what one session-end event says.
type SessionEndKind string

const (
	// SessionEndSignalled is a session-end signal received (Mark).
	SessionEndSignalled SessionEndKind = "signalled"
	// SessionEndCancelled is a mark taken back: the session spoke again, or
	// its run was acted on (Cancel).
	SessionEndCancelled SessionEndKind = "cancelled"
)

// SessionEndEvent is one row of the session-end store.
type SessionEndEvent struct {
	SessionID string
	Kind      SessionEndKind
	At        time.Time
}

// SessionEndStore keeps session-end marks across a restart of the core. It
// is append-only, like every table the gateway writes: a cancellation is a
// later row, never a deletion. A session's latest event decides.
type SessionEndStore interface {
	Record(ctx context.Context, e SessionEndEvent) error
	// Open answers, per session, the latest event when it is a signal no
	// older than since.
	Open(ctx context.Context, since time.Time) ([]SessionEndEvent, error)
}

// sessionEndWriteTimeout bounds one write. A write runs off the request
// path, so a slow database never delays a model request; a lost write costs
// what the in-memory table always cost, a retirement by the backstop.
const sessionEndWriteTimeout = 5 * time.Second

// SessionEndReload bounds how far back Load reads: a mark older than this
// has long since been swept, or its run retired by other means.
const SessionEndReload = 24 * time.Hour

// sessionEndQueue bounds the events waiting for the writer. A full queue
// drops the event and says so: the cost is what the in-memory table always
// cost, a retirement by the backstop.
const sessionEndQueue = 1024

// Persist makes s write each mark and each cancellation of a mark to store,
// in order, from one writer that runs until base ends. Writes are detached
// from the request that caused them, so a slow database never delays one.
// logf, when set, reports a failed or dropped write. Call it once, before
// the table is shared.
func (s *SessionEndSignals) Persist(base context.Context, store SessionEndStore, logf func(format string, args ...any)) {
	s.store = store
	s.logf = logf
	s.queue = make(chan SessionEndEvent, sessionEndQueue)
	go func() {
		for {
			select {
			case <-base.Done():
				return
			case e := <-s.queue:
				ctx, cancel := context.WithTimeout(base, sessionEndWriteTimeout)
				if err := store.Record(ctx, e); err != nil && logf != nil {
					logf("could not keep the session-end %s for session %s: %v", e.Kind, e.SessionID, err)
				}
				cancel()
			}
		}
	}()
}

// Load restores the open marks from the store, at the time each was
// signalled, so a restart resumes their grace periods instead of losing them.
func (s *SessionEndSignals) Load(ctx context.Context, since time.Time) error {
	if s.store == nil {
		return nil
	}
	open, err := s.store.Open(ctx, since)
	if err != nil {
		return err
	}
	for _, e := range open {
		s.mark(e.SessionID, e.At)
	}
	return nil
}

// record queues e for the writer when a store is set.
func (s *SessionEndSignals) record(e SessionEndEvent) {
	if s.queue == nil {
		return
	}
	select {
	case s.queue <- e:
	default:
		if s.logf != nil {
			s.logf("the session-end writer is behind; the %s for session %s is not kept", e.Kind, e.SessionID)
		}
	}
}

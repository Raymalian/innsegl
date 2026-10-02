// SPDX-License-Identifier: Apache-2.0

package gateway

// journal.go is the gateway's half of ADR-0068: the client journals what
// the core cannot record, and the core imports it.
//
// Two things live here. The core says, on every reply it relays, whether it
// recorded the exchange (clientjournal.RecordedHeader): "false" exactly
// where an UnrecordedFinding names a repository, so the client journals it.
// And a journaled exchange is replayed through the same guards and the same
// reply observers a live one passes (Proxy.Replay), so an imported exchange
// is registered and recorded by the code that records a live one, never by
// a second copy of it.

import (
	"context"
	"io"
	"net/http"
	"sync"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// unrecordedMark is a request's note, set by the identity guard, that the
// core forwards it without recording it although it states a repository.
type unrecordedMark struct {
	mu   sync.Mutex
	repo string
}

type unrecordedMarkKey struct{}

// withUnrecordedMark gives ctx an empty mark, so a guard deeper in the chain
// can set it without returning a new request.
func withUnrecordedMark(ctx context.Context) context.Context {
	if _, ok := ctx.Value(unrecordedMarkKey{}).(*unrecordedMark); ok {
		return ctx
	}
	return context.WithValue(ctx, unrecordedMarkKey{}, &unrecordedMark{})
}

// markUnrecordedRepo notes that the request is forwarded unrecorded inside
// repo. An empty repo marks nothing: outside a repository there is nothing
// to journal.
func markUnrecordedRepo(ctx context.Context, repo string) {
	m, ok := ctx.Value(unrecordedMarkKey{}).(*unrecordedMark)
	if !ok || repo == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repo = repo
}

// unrecordedRepo answers the repository a request was forwarded unrecorded
// in, or "".
func unrecordedRepo(ctx context.Context) string {
	m, ok := ctx.Value(unrecordedMarkKey{}).(*unrecordedMark)
	if !ok {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.repo
}

// recordedValue is clientjournal.RecordedHeader's value for a request the
// guards permitted.
func recordedValue(ctx context.Context) string {
	if runID, ok := RunIDFromContext(ctx); ok && runID != "" {
		return clientjournal.RecordedTrue
	}
	if unrecordedRepo(ctx) != "" {
		return clientjournal.RecordedFalse
	}
	return clientjournal.RecordedNone
}

type replayKey struct{}

// WithReplay marks ctx as a journal import's replay of an exchange that
// already happened.
func WithReplay(ctx context.Context) context.Context {
	return context.WithValue(ctx, replayKey{}, true)
}

// IsReplay reports whether ctx is a replay. The per-session rate limit lets
// a replay through (a backlog is not a runaway loop), and the identity guard
// takes the replayed entry's own statement over the registry's newest.
func IsReplay(ctx context.Context) bool {
	v, ok := ctx.Value(replayKey{}).(bool)
	return ok && v
}

type journalEntryKey struct{}

// WithJournalEntry attaches the hash of the signed entry a replay comes
// from.
func WithJournalEntry(ctx context.Context, hash string) context.Context {
	return context.WithValue(ctx, journalEntryKey{}, hash)
}

// JournalEntryFromContext answers the entry a replay comes from.
func JournalEntryFromContext(ctx context.Context) (string, bool) {
	h, ok := ctx.Value(journalEntryKey{}).(string)
	return h, ok && h != ""
}

// ReplayOutcome is what a replay decided.
type ReplayOutcome struct {
	// RunID is the run the exchange was recorded under; empty when it was
	// not recorded.
	RunID string
	// Refusal is the guard chain's refusal, nil when it permitted.
	Refusal *Refusal
	// UnrecordedRepo names the repository the exchange was not recorded in
	// (an installation that may not record it).
	UnrecordedRepo string
}

// Replayer replays one journaled exchange. *Proxy is one.
type Replayer interface {
	Replay(r *http.Request, contentType string, reply []byte) ReplayOutcome
}

var _ Replayer = (*Proxy)(nil)

// Replay runs r through p's guards exactly as ServeHTTP does, then hands
// reply -- the journaled reply, as it was streamed -- to p's reply
// observers. Nothing is sent upstream: the exchange already happened.
func (p *Proxy) Replay(r *http.Request, contentType string, reply []byte) ReplayOutcome {
	return p.replay(r.WithContext(WithReplay(r.Context())), contentType, reply)
}

func (p *Proxy) replay(r *http.Request, contentType string, reply []byte) ReplayOutcome {
	guards := p.Guards
	if guards == nil {
		guards = defaultGuards
	}
	for _, g := range guards {
		next, refusal := g.Check(r)
		if refusal != nil {
			return ReplayOutcome{Refusal: refusal}
		}
		if next != nil {
			r = next
		}
	}
	out := ReplayOutcome{UnrecordedRepo: unrecordedRepo(r.Context())}
	out.RunID, _ = RunIDFromContext(r.Context())
	if obs := p.replyObserver(r, contentType); obs != nil {
		discardWriteError(obs.Write(reply))
	}
	return out
}

// replyObserver is the writer a reply of contentType is copied into besides
// the caller, or nil when nobody watches it (proxy.go's stream).
func (p *Proxy) replyObserver(r *http.Request, contentType string) io.Writer {
	if (p.ToolUse == nil && p.ReplyText == nil) || !isEventStream(contentType) {
		return nil
	}
	var observer ToolUseObserver
	if p.ToolUse != nil {
		observer = boundToolUseObserver(r.Context(), p.ToolUse)
	}
	interp := newMessagesInterpreter(observer)
	if p.ReplyText != nil {
		ctx := r.Context()
		interp.onText = func(text string) { p.ReplyText.OnReplyText(ctx, text) }
	}
	return interp
}

// SPDX-License-Identifier: Apache-2.0

package client

// Delivering the outbox (outbox.go): one loop, oldest first. Delivery stops
// per kind: a kind stops at its own first item the core does not take now,
// and the other kinds go on. A core that does not answer at all stops every
// kind for that pass.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// DefaultUploadInterval is how often the delivery loop looks for items when
// nothing woke it sooner.
const DefaultUploadInterval = 30 * time.Second

// maxUploadBackoff bounds the wait after failed deliveries.
const maxUploadBackoff = 10 * time.Minute

// uploadBatchBytes and uploadBatchEntries bound one journal import request;
// a single larger entry still goes alone.
const (
	uploadBatchBytes   = 8 << 20
	uploadBatchEntries = 64
)

// liveFlushTimeout bounds the delivery run before a live model request.
const liveFlushTimeout = 5 * time.Second

// itemTimeout bounds one telemetry export or end sent to the core.
const itemTimeout = 10 * time.Second

// DrainResult is what one Drain did.
type DrainResult struct {
	// Delivered items were taken by the core and deleted.
	Delivered int
	// Rejected is the core's rejection of a journal entry; the entry is kept
	// for inspection, and nothing after it is sent until it is resolved.
	Rejected *clientjournal.ImportResult
	// Retry is the core's request to send a journal entry again later.
	Retry *clientjournal.ImportResult
}

// kindRoute is where each kind other than an exchange goes.
var kindRoute = map[string]string{KindTelemetry: TelemetryLogsPath, KindEnd: SessionEndPath}

// refusedForGood reports whether the core's answer says it will never take
// this item: the item itself is malformed or unwanted. Anything else -- no
// answer, a 5xx, a rate limit, an authentication refusal -- is "not now",
// and the item waits.
func refusedForGood(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// errNoAnswer is a core that did not answer at all.
type errNoAnswer struct{ err error }

func (e errNoAnswer) Error() string { return "the core did not answer: " + e.err.Error() }
func (e errNoAnswer) Unwrap() error { return e.err }

// Drain sends every held item to the core, oldest first, and deletes those
// the core took. Each kind stops at its own first item the core does not
// take now; a core that does not answer stops every kind. The error is the
// first item not taken, if any.
func (s *Server) Drain(ctx context.Context) (DrainResult, error) {
	s.deliverMu.Lock()
	defer s.deliverMu.Unlock()
	return s.drainLocked(ctx, false)
}

// drainLocked is Drain; skipExchanges leaves the journal entries for the
// next full pass.
func (s *Server) drainLocked(ctx context.Context, skipExchanges bool) (DrainResult, error) {
	var res DrainResult
	stopped := map[string]bool{KindExchange: skipExchanges}
	var first error
	notNow := func(kind string, err error) {
		stopped[kind] = true
		if first == nil {
			first = err
		}
	}
	items := s.outbox.pending()
	for len(items) > 0 {
		it := items[0]
		if stopped[it.kind] {
			items = items[1:]
			continue
		}
		if it.kind == KindExchange {
			n, stop, err := s.deliverExchanges(ctx, items, &res)
			var silent errNoAnswer
			switch {
			case errors.As(err, &silent):
				return res, err
			case err != nil:
				notNow(KindExchange, err)
			case stop:
				stopped[KindExchange] = true
			}
			items = items[max(n, 1):]
			continue
		}
		items = items[1:]
		body, err := s.outbox.read(it)
		if err != nil {
			err = fmt.Errorf("reading %s: %w", itemName(it.order, it.kind), err)
			s.setDelivery("failed: " + err.Error())
			notNow(it.kind, err)
			continue
		}
		status, err := s.sendToCore(ctx, kindRoute[it.kind], body, "application/json")
		switch {
		case err != nil:
			err = errNoAnswer{err}
			s.setDelivery(fmt.Sprintf("failed: %s: %v", itemName(it.order, it.kind), err))
			return res, err
		case status/100 == 2:
			if err := s.outbox.remove(it); err != nil {
				s.setDelivery("failed: removing a delivered item: " + err.Error())
				notNow(it.kind, err)
				continue
			}
			res.Delivered++
		case refusedForGood(status):
			s.log.Printf("the core refused the held %s %s for good (%d); it is dropped",
				it.kind, itemName(it.order, it.kind), status)
			if err := s.outbox.drop(it); err != nil {
				s.setDelivery("failed: removing a refused item: " + err.Error())
				notNow(it.kind, err)
			}
		default:
			err := fmt.Errorf("the core answered %s with %d", itemName(it.order, it.kind), status)
			s.setDelivery("failed: " + err.Error())
			notNow(it.kind, err)
		}
	}
	if first == nil && res.Rejected == nil && res.Retry == nil {
		s.setDelivery("ok")
	}
	return res, first
}

// deliverExchanges sends the run of exchanges at the front of items to the
// journal import, in batches. It answers how many items it consumed and
// whether the journal must stop: an entry rejected or to be retried stops
// it, as does any error. A core that does not answer is errNoAnswer.
func (s *Server) deliverExchanges(ctx context.Context, items []outboxItem, res *DrainResult) (int, bool, error) {
	var batch []clientjournal.Sealed
	var held []outboxItem
	var size int
	for _, it := range items {
		if it.kind != KindExchange {
			break
		}
		sealed, err := s.outbox.readSealed(it.order)
		if err != nil {
			s.setDelivery("failed: reading " + itemName(it.order, it.kind) + ": " + err.Error())
			return 0, true, err
		}
		if len(batch) > 0 && (size+len(sealed.Entry) > uploadBatchBytes || len(batch) >= uploadBatchEntries) {
			break
		}
		batch, held = append(batch, sealed), append(held, it)
		size += len(sealed.Entry)
	}
	results, err := s.postImport(ctx, batch)
	if err != nil {
		s.setDelivery("failed: " + err.Error())
		return 0, true, err
	}
	for i, r := range results {
		if i >= len(batch) || r.Hash != batch[i].Hash() {
			err := fmt.Errorf("the core answered for an entry it was not sent (%q)", r.Hash)
			s.setDelivery("failed: " + err.Error())
			return i, true, err
		}
		if !clientjournal.Acknowledged(r.Status) {
			r := r
			name := itemName(held[i].order, KindExchange)
			if r.Status == clientjournal.ImportRejected {
				res.Rejected = &r
				s.setDelivery(fmt.Sprintf("rejected: entry %d (%s): %s", r.Seq, name, r.Reason))
				s.log.Printf("the core rejected client journal entry %d (%s); it is kept at %s for inspection, "+
					"and no journal entry after it is delivered until it is resolved", r.Seq, r.Reason, s.outbox.dir)
			} else {
				res.Retry = &r
				s.setDelivery(fmt.Sprintf("retry: entry %d (%s): %s", r.Seq, name, r.Reason))
			}
			return i, true, nil
		}
		if err := s.outbox.remove(held[i]); err != nil {
			s.setDelivery("failed: removing an acknowledged entry: " + err.Error())
			return i, true, err
		}
		res.Delivered++
	}
	if len(results) < len(batch) {
		s.setDelivery("retry: the core answered for fewer entries than it was sent")
		return len(results), true, nil
	}
	return len(batch), false, nil
}

func (s *Server) postImport(ctx context.Context, batch []clientjournal.Sealed) ([]clientjournal.ImportResult, error) {
	body, err := json.Marshal(clientjournal.ImportRequest{Entries: batch})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	url := strings.TrimSuffix(s.core.CoreURL, "/") + clientjournal.ImportPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Transport: s.transport}).Do(req)
	if err != nil {
		return nil, errNoAnswer{err}
	}
	defer func() { _ = resp.Body.Close() }()
	// The core answered: model requests try it again.
	s.downUntil.Store(0)
	if resp.StatusCode != http.StatusOK {
		head, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRefusalLogBytes))
		if rerr != nil {
			head = []byte("(unreadable: " + rerr.Error() + ")")
		}
		return nil, fmt.Errorf("the core answered the import with %d: %s", resp.StatusCode, strings.TrimSpace(string(head)))
	}
	var out clientjournal.ImportResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("the core's import answer: %w", err)
	}
	return out.Results, nil
}

// sendToCore posts body to the core's path over the client certificate and
// answers the core's status; an error is a core that did not answer.
func (s *Server) sendToCore(ctx context.Context, path string, body []byte, contentType string) (int, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), itemTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.core.CoreURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		return 0, err
	}
	s.downUntil.Store(0)
	return resp.StatusCode, nil
}

func (s *Server) setDelivery(result string) { s.outbox.setDelivery(s.Now(), result) }

// kickOutbox wakes the delivery loop.
func (s *Server) kickOutbox() {
	select {
	case s.outboxKick <- struct{}{}:
	default:
	}
}

// RunOutbox delivers the outbox until ctx ends: when it is kicked (an item
// was written, or the core answered a live request), every interval while
// items are held, and with doubling backoff after a failure. A journal entry
// the core rejected or asked to retry waits out its backoff: a kick then
// delivers the other kinds and does not send it again. It resumes after a
// restart from what is on disk.
func (s *Server) RunOutbox(ctx context.Context) {
	interval := s.uploadInterval
	backoff := interval
	timer := time.NewTimer(0)
	defer timer.Stop()
	journalHeld := false
	for {
		kicked := false
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-s.outboxKick:
			kicked = true
		}
		if s.outbox.count("") == 0 {
			if !kicked || !journalHeld {
				timer.Reset(interval)
			}
			continue
		}
		if kicked && journalHeld {
			// The timer keeps running for the journal's backoff.
			s.deliverMu.Lock()
			_, err := s.drainLocked(ctx, true)
			s.deliverMu.Unlock()
			if err != nil {
				s.log.Printf("delivering the client outbox: %v", err)
			}
			continue
		}
		res, err := s.Drain(ctx)
		journalHeld = res.Rejected != nil || res.Retry != nil
		if err != nil || journalHeld {
			backoff = min(backoff*2, maxUploadBackoff)
			timer.Reset(backoff)
			continue
		}
		backoff = interval
		timer.Reset(interval)
	}
}

// flushOutboxBeforeLive delivers held items before a live model request
// goes to the core, so a tool call journaled during an outage is paired
// with the result the live request carries. Bounded, only when an exchange
// is held, and skipped while another delivery runs: a live request is never
// held up for long.
func (s *Server) flushOutboxBeforeLive(ctx context.Context) {
	if s.outbox.count(KindExchange) == 0 || !s.deliverMu.TryLock() {
		return
	}
	defer s.deliverMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), liveFlushTimeout)
	defer cancel()
	if _, err := s.drainLocked(ctx, false); err != nil {
		s.log.Printf("delivering the client outbox before a live request: %v", err)
	}
}

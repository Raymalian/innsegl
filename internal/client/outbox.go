// SPDX-License-Identifier: Apache-2.0

package client

// The outbox: what the core did not take, kept on disk and delivered in
// order once it answers. One folder, one bound, one delivery loop. Each item
// is one file named by its place in the order and its kind:
//
//   - exchange: a model exchange the core could not record (ADR-0068). It is
//     a journal entry: signed with the installation's key and hash-chained.
//     The chain runs over exchanges only, so the core's import sees the same
//     consecutive sequence it always has; head.json is its head.
//   - telemetry: an OTLP log export the core did not take.
//   - end: a session or subagent end the core did not take.
//
// Each kind goes to the core's own route for it, unchanged: exchanges to the
// journal import, telemetry to /v1/logs, ends to the session-end route.
// An item is deleted once the core takes it.
//
// The outbox is bounded. Telemetry never causes the one refusal: when an
// exchange or an end needs room, held telemetry is dropped first, oldest
// first, and counted. A model request that must be journaled when the
// outbox cannot hold it (full of what cannot be dropped, or unwritable) is
// the one request this service refuses.

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// The kinds of item the outbox holds.
const (
	KindExchange  = "exchange"
	KindTelemetry = "telemetry"
	KindEnd       = "end"
)

// DefaultOutboxMaxBytes bounds the outbox on disk.
const DefaultOutboxMaxBytes = 512 << 20

// ErrOutboxFull is an outbox at its bound with nothing left it may drop.
var ErrOutboxFull = errors.New("the client outbox is full")

const outboxHeadFile = "head.json"

// journalHead is the head of the exchange chain.
type journalHead struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// outboxItem is one held item.
type outboxItem struct {
	order uint64
	kind  string
	size  int64
	at    time.Time
}

func itemName(order uint64, kind string) string { return fmt.Sprintf("%020d.%s", order, kind) }

func parseItemName(name string) (uint64, string, bool) {
	num, kind, ok := strings.Cut(name, ".")
	if !ok || len(num) != 20 || (kind != KindExchange && kind != KindTelemetry && kind != KindEnd) {
		return 0, "", false
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return n, kind, err == nil && n > 0
}

// outbox is the on-disk outbox.
type outbox struct {
	dir          string
	maxBytes     int64
	key          *ecdsa.PrivateKey
	installation string
	logf         func(string, ...any)

	mu      sync.Mutex
	openErr error
	head    journalHead
	next    uint64
	items   map[uint64]outboxItem
	bytes   int64
	dropped map[string]int64
	last    *DeliveryStatus
}

// openOutbox opens the outbox at dir, creating it 0700. An outbox that
// cannot be opened is kept with its error: every request that would need
// it is then refused, and no other.
func openOutbox(dir, installation string, key *ecdsa.PrivateKey, maxBytes int64, logf func(string, ...any)) *outbox {
	if maxBytes <= 0 {
		maxBytes = DefaultOutboxMaxBytes
	}
	o := &outbox{
		dir: dir, maxBytes: maxBytes, key: key, installation: installation, logf: logf,
		next: 1, items: map[uint64]outboxItem{}, dropped: map[string]int64{},
	}
	o.openErr = o.load()
	return o
}

func (o *outbox) load() error {
	if err := os.MkdirAll(o.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(o.dir, 0o700); err != nil {
		return err
	}
	head, err := readHead(filepath.Join(o.dir, outboxHeadFile))
	if err != nil {
		return err
	}
	o.head = head
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return err
	}
	var newestExchange uint64
	for _, e := range entries {
		order, kind, ok := parseItemName(e.Name())
		if !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			return ierr
		}
		o.items[order] = outboxItem{order: order, kind: kind, size: info.Size(), at: info.ModTime()}
		o.bytes += info.Size()
		if order >= o.next {
			o.next = order + 1
		}
		if kind == KindExchange && order > newestExchange {
			newestExchange = order
		}
	}
	if newestExchange != 0 {
		return o.adoptHeadLocked(newestExchange)
	}
	return nil
}

func readHead(path string) (journalHead, error) {
	var h journalHead
	// #nosec G304 -- this service's own file.
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return h, nil
	case err != nil:
		return h, err
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return h, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

// adoptHeadLocked makes the exchange at order the chain's head when it is
// newer than the head on record: an entry written without its head (a crash
// between the two writes) is the chain's real head.
func (o *outbox) adoptHeadLocked(order uint64) error {
	s, err := o.readSealed(order)
	if err != nil {
		return err
	}
	// The sequence is read, not verified: the core verifies.
	var e struct {
		Seq uint64 `json:"seq"`
	}
	if err := json.Unmarshal(s.Entry, &e); err != nil {
		return fmt.Errorf("%s: %w", itemName(order, KindExchange), err)
	}
	if e.Seq > o.head.Seq {
		return o.setHeadLocked(journalHead{Seq: e.Seq, Hash: s.Hash()})
	}
	return nil
}

func (o *outbox) setHeadLocked(h journalHead) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(o.dir, outboxHeadFile), raw, 0o600); err != nil {
		return err
	}
	o.head = h
	return nil
}

func (o *outbox) read(it outboxItem) ([]byte, error) {
	// #nosec G304 -- an item this service wrote in its own folder.
	return os.ReadFile(filepath.Join(o.dir, itemName(it.order, it.kind)))
}

func (o *outbox) readSealed(order uint64) (clientjournal.Sealed, error) {
	var s clientjournal.Sealed
	raw, err := o.read(outboxItem{order: order, kind: KindExchange})
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("%s: %w", itemName(order, KindExchange), err)
	}
	return s, nil
}

// makeRoomLocked drops held telemetry, oldest first, until size more bytes
// fit. It answers whether they do.
func (o *outbox) makeRoomLocked(size int64) bool {
	if o.bytes+size <= o.maxBytes {
		return true
	}
	for _, it := range o.pendingLocked() {
		if it.kind != KindTelemetry {
			continue
		}
		if err := o.removeLocked(it); err != nil {
			o.logf("dropping held telemetry to make room: %v", err)
			return false
		}
		o.dropped[KindTelemetry]++
		o.logf("dropped a held telemetry export (%d bytes) to make room in the client outbox", it.size)
		if o.bytes+size <= o.maxBytes {
			return true
		}
	}
	return false
}

// reserve answers whether an exchange of about size bytes can be held now:
// the outbox opened, there is room once telemetry is dropped, and its
// folder takes a file.
func (o *outbox) reserve(size int64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.openErr != nil {
		return fmt.Errorf("the client outbox at %s cannot be opened: %w", o.dir, o.openErr)
	}
	if !o.makeRoomLocked(size) {
		return fmt.Errorf("%w: %d of %d bytes held at %s; the core takes and removes items when it answers",
			ErrOutboxFull, o.bytes, o.maxBytes, o.dir)
	}
	probe, err := os.CreateTemp(o.dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("the client outbox at %s cannot be written: %w", o.dir, err)
	}
	name := probe.Name()
	cerr := probe.Close()
	if rerr := os.Remove(name); rerr != nil && cerr == nil {
		cerr = rerr
	}
	if cerr != nil {
		return fmt.Errorf("the client outbox at %s cannot be written: %w", o.dir, cerr)
	}
	return nil
}

// appendExchange seals e as the next entry of the chain and holds it. The
// exchange already happened, so it is held even past the bound; telemetry
// is dropped to bring the outbox back under it.
func (o *outbox) appendExchange(e clientjournal.Entry) (clientjournal.Sealed, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.openErr != nil {
		return clientjournal.Sealed{}, o.openErr
	}
	e.Seq, e.Prev, e.InstallationID = o.head.Seq+1, o.head.Hash, o.installation
	sealed, err := clientjournal.Seal(e, o.key)
	if err != nil {
		return clientjournal.Sealed{}, err
	}
	body, err := json.Marshal(sealed)
	if err != nil {
		return clientjournal.Sealed{}, err
	}
	if err := o.writeLocked(KindExchange, body, time.Now()); err != nil {
		return clientjournal.Sealed{}, err
	}
	// The entry is written; a head that fails here is recovered from the
	// newest exchange on the next start (load).
	if err := o.setHeadLocked(journalHead{Seq: e.Seq, Hash: sealed.Hash()}); err != nil {
		return clientjournal.Sealed{}, err
	}
	o.makeRoomLocked(0)
	return sealed, nil
}

// hold keeps a telemetry export or an end. Past the bound, telemetry is not
// held; an end drops held telemetry to make room. What is not held is
// counted.
func (o *outbox) hold(kind string, body []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.openErr != nil {
		o.dropped[kind]++
		return fmt.Errorf("the client outbox at %s cannot be opened: %w", o.dir, o.openErr)
	}
	size := int64(len(body))
	fits := o.bytes+size <= o.maxBytes
	if !fits && kind != KindTelemetry {
		fits = o.makeRoomLocked(size)
	}
	if !fits {
		o.dropped[kind]++
		return fmt.Errorf("%w: %d of %d bytes held at %s", ErrOutboxFull, o.bytes, o.maxBytes, o.dir)
	}
	if err := o.writeLocked(kind, body, time.Now()); err != nil {
		o.dropped[kind]++
		return err
	}
	return nil
}

// writeLocked writes body as the next item.
func (o *outbox) writeLocked(kind string, body []byte, at time.Time) error {
	order := o.next
	if err := writeFileAtomic(filepath.Join(o.dir, itemName(order, kind)), body, 0o600); err != nil {
		return err
	}
	o.next++
	o.items[order] = outboxItem{order: order, kind: kind, size: int64(len(body)), at: at}
	o.bytes += int64(len(body))
	return nil
}

// pending answers the items held, oldest first.
func (o *outbox) pending() []outboxItem {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.pendingLocked()
}

func (o *outbox) pendingLocked() []outboxItem {
	out := make([]outboxItem, 0, len(o.items))
	for _, it := range o.items {
		out = append(out, it)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].order < out[b].order })
	return out
}

// remove deletes an item the core took.
func (o *outbox) remove(it outboxItem) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.removeLocked(it)
}

// drop deletes an item the core will never take, and counts it.
func (o *outbox) drop(it outboxItem) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.removeLocked(it); err != nil {
		return err
	}
	o.dropped[it.kind]++
	return nil
}

func (o *outbox) removeLocked(it outboxItem) error {
	if err := os.Remove(filepath.Join(o.dir, itemName(it.order, it.kind))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if known, ok := o.items[it.order]; ok {
		o.bytes -= known.size
		delete(o.items, it.order)
	}
	return nil
}

func (o *outbox) count(kind string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, it := range o.items {
		if kind == "" || it.kind == kind {
			n++
		}
	}
	return n
}

// OutboxStatus is the outbox's part of GET /_client/status.
type OutboxStatus struct {
	Dir   string `json:"dir"`
	Items int    `json:"items"`
	// Kinds counts the items held by kind.
	Kinds    map[string]int `json:"kinds"`
	Bytes    int64          `json:"bytes"`
	MaxBytes int64          `json:"max_bytes"`
	// OldestItemAt is when the oldest item still held was written.
	OldestItemAt *time.Time `json:"oldest_item_at,omitempty"`
	// Dropped counts, by kind, since the service started, what was not
	// held for want of room and what the core said it will never take.
	Dropped map[string]int64 `json:"dropped,omitempty"`
	// Error is why the outbox cannot be written, when it cannot.
	Error        string          `json:"error,omitempty"`
	LastDelivery *DeliveryStatus `json:"last_delivery,omitempty"`
}

// DeliveryStatus is the newest delivery's outcome.
type DeliveryStatus struct {
	At time.Time `json:"at"`
	// Result is "ok", "rejected: ...", "retry: ..." or "failed: ...".
	Result string `json:"result"`
}

func (o *outbox) status() OutboxStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	st := OutboxStatus{
		Dir: o.dir, Items: len(o.items), Bytes: o.bytes, MaxBytes: o.maxBytes,
		Kinds: map[string]int{KindExchange: 0, KindTelemetry: 0, KindEnd: 0},
	}
	if o.openErr != nil {
		st.Error = o.openErr.Error()
	}
	var oldest *outboxItem
	for _, it := range o.items {
		st.Kinds[it.kind]++
		if oldest == nil || it.order < oldest.order {
			it := it
			oldest = &it
		}
	}
	if oldest != nil {
		at := oldest.at.UTC()
		st.OldestItemAt = &at
	}
	if len(o.dropped) > 0 {
		st.Dropped = make(map[string]int64, len(o.dropped))
		for k, v := range o.dropped {
			st.Dropped[k] = v
		}
	}
	if o.last != nil {
		last := *o.last
		st.LastDelivery = &last
	}
	return st
}

func (o *outbox) setDelivery(at time.Time, result string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.last = &DeliveryStatus{At: at.UTC(), Result: result}
}

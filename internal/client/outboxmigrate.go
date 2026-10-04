// SPDX-License-Identifier: Apache-2.0

package client

// Moving the stores a client before the outbox kept into the outbox, once:
// the journal (journal/, one NNN.entry file per entry and head.json), the
// telemetry spool (telemetry-spool/, one file per export, named by its
// arrival in nanoseconds), and the ends kept in the watch table
// (session-processes.json, a key with a zero process). Each store's own
// order is kept; across stores, items are merged by the time each was
// written. Nothing is lost: a file is moved, never copied and deleted, and
// what cannot be moved stays where it was for the next start.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// oldJournalEntry matches a journal entry file of the old layout.
func oldJournalEntry(name string) (uint64, bool) {
	seq, ok := strings.CutSuffix(name, ".entry")
	if !ok || len(seq) != 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(seq, 10, 64)
	return n, err == nil && n > 0
}

// migrant is one item of the old layout.
type migrant struct {
	kind string
	at   time.Time
	// from is the file moved, for an exchange or an export; body is the
	// item written, for an end.
	from string
	body []byte
}

// migrateOldLayout moves the old stores under clientDir into the outbox.
func (s *Server) migrateOldLayout(clientDir string) {
	if s.outbox.openErr != nil {
		return
	}
	journalDir := filepath.Join(clientDir, "journal")
	spoolDir := filepath.Join(clientDir, "telemetry-spool")
	exchanges, err := oldExchanges(journalDir)
	if err != nil {
		s.log.Printf("reading the old client journal at %s: %v; it stays there", journalDir, err)
		exchanges = nil
	}
	exports, err := oldExports(spoolDir)
	if err != nil {
		s.log.Printf("reading the old telemetry spool at %s: %v; it stays there", spoolDir, err)
		exports = nil
	}
	ends, rest, tableErr := oldEnds(s.sessionWatchFile())
	if tableErr != nil {
		ends = nil
	}
	// The old journal's head moves even with no entry left: the chain
	// continues from it.
	if err := s.outbox.migrate(journalDir, mergeByTime(exchanges, exports, ends)); err != nil {
		s.log.Printf("moving the old client stores into the outbox: %v; what was not moved stays for the next start", err)
		return
	}
	if len(ends) > 0 {
		b, merr := json.Marshal(rest)
		if merr == nil {
			merr = writeFileAtomic(s.sessionWatchFile(), b, 0o600)
		}
		if merr != nil {
			// The ends are held twice until the table is written; a second
			// end of the same session is harmless to the core.
			s.log.Printf("rewriting the watched-session table without its kept ends: %v", merr)
		}
	}
	s.removeOldDirs(journalDir, spoolDir)
	if len(exchanges)+len(exports)+len(ends) == 0 {
		return
	}
	s.log.Printf("moved the old client stores into the outbox at %s: %d journal entries, %d telemetry exports, %d session ends",
		s.outbox.dir, len(exchanges), len(exports), len(ends))
}

func (s *Server) removeOldDirs(dirs ...string) {
	for _, d := range dirs {
		if err := os.Remove(d); err != nil && !errors.Is(err, fs.ErrNotExist) {
			s.log.Printf("the old store at %s is not empty and stays: %v", d, err)
		}
	}
}

// oldExchanges answers the old journal's entries in chain order.
func oldExchanges(dir string) ([]migrant, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	type seqd struct {
		seq uint64
		m   migrant
	}
	var found []seqd
	for _, e := range entries {
		seq, ok := oldJournalEntry(e.Name())
		if !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			return nil, ierr
		}
		found = append(found, seqd{seq, migrant{kind: KindExchange, at: info.ModTime(), from: filepath.Join(dir, e.Name())}})
	}
	sort.Slice(found, func(a, b int) bool { return found[a].seq < found[b].seq })
	out := make([]migrant, len(found))
	for i, f := range found {
		out[i] = f.m
	}
	return out, nil
}

// oldExports answers the old spool's exports in arrival order.
func oldExports(dir string) ([]migrant, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []migrant
	for _, e := range entries {
		stem, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			return nil, ierr
		}
		at := info.ModTime()
		if ns, perr := strconv.ParseInt(stem, 10, 64); perr == nil {
			at = time.Unix(0, ns)
		}
		out = append(out, migrant{kind: KindTelemetry, at: at, from: filepath.Join(dir, e.Name())})
	}
	// Arrival order is the name's order (ReadDir sorts by name).
	return out, nil
}

// oldEnds answers the ends kept in the watch table, and the table without
// them. A kept end is a key with a zero process: "session", or
// "session/agent" for a subagent.
func oldEnds(path string) ([]migrant, map[string]Process, error) {
	// #nosec G304 -- this service's own file.
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	var table map[string]Process
	if err := json.Unmarshal(raw, &table); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	var keys []string
	rest := map[string]Process{}
	for k, p := range table {
		if p == (Process{}) {
			keys = append(keys, k)
			continue
		}
		rest[k] = p
	}
	sort.Strings(keys)
	out := make([]migrant, 0, len(keys))
	for _, k := range keys {
		session, agent, _ := strings.Cut(k, "/")
		out = append(out, migrant{kind: KindEnd, at: info.ModTime(), body: endBody(session, agent)})
	}
	return out, rest, nil
}

// mergeByTime merges stores, each already in its own order, by time. A
// store's own order is never changed; on equal times the earlier store goes
// first.
func mergeByTime(stores ...[]migrant) []migrant {
	var out []migrant
	next := make([]int, len(stores))
	for {
		pick := -1
		var at time.Time
		for i, st := range stores {
			if next[i] >= len(st) {
				continue
			}
			if m := st[next[i]]; pick < 0 || m.at.Before(at) {
				pick, at = i, m.at
			}
		}
		if pick < 0 {
			return out
		}
		out = append(out, stores[pick][next[pick]])
		next[pick]++
	}
}

// migrate moves ms into the outbox in order, taking the old journal's head
// first so the chain continues even when every entry of it was delivered.
func (o *outbox) migrate(oldJournal string, ms []migrant) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	oldHeadPath := filepath.Join(oldJournal, outboxHeadFile)
	oldHead, err := readHead(oldHeadPath)
	if err != nil {
		return err
	}
	if oldHead.Seq > o.head.Seq {
		if err := o.setHeadLocked(oldHead); err != nil {
			return err
		}
	}
	var newestExchange uint64
	for _, m := range ms {
		order := o.next
		dst := filepath.Join(o.dir, itemName(order, m.kind))
		var size int64
		if m.from != "" {
			info, serr := os.Stat(m.from)
			if serr != nil {
				return serr
			}
			if rerr := os.Rename(m.from, dst); rerr != nil {
				return rerr
			}
			size = info.Size()
		} else {
			if werr := writeFileAtomic(dst, m.body, 0o600); werr != nil {
				return werr
			}
			// The item keeps the time it was first kept, across restarts.
			if terr := os.Chtimes(dst, m.at, m.at); terr != nil {
				return terr
			}
			size = int64(len(m.body))
		}
		o.next++
		o.items[order] = outboxItem{order: order, kind: m.kind, size: size, at: m.at}
		o.bytes += size
		if m.kind == KindExchange {
			newestExchange = order
		}
	}
	if newestExchange != 0 {
		if err := o.adoptHeadLocked(newestExchange); err != nil {
			return err
		}
	}
	if err := os.Remove(oldHeadPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

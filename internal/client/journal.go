// SPDX-License-Identifier: Apache-2.0

package client

// The client journal (ADR-0068). When the core cannot record an exchange in
// a repository -- it does not answer, or it relays the exchange and says it
// did not record it -- this service records it here: one file per exchange,
// signed with the installation's key, hash-chained, and uploaded to the core
// when it answers again. An entry is deleted only once the core has
// acknowledged it.
//
// The journal is bounded. A request that would have to be journaled when the
// journal cannot be written (full, or the directory unwritable) is the one
// request this service refuses: an unrecorded exchange in a repository is
// what the journal exists to prevent.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// DefaultJournalMaxBytes bounds the journal on disk.
const DefaultJournalMaxBytes = 512 << 20

// DefaultUploadInterval is how often the upload loop looks for entries when
// nothing woke it sooner.
const DefaultUploadInterval = 30 * time.Second

// maxUploadBackoff bounds the wait after failed uploads.
const maxUploadBackoff = 10 * time.Minute

// uploadBatchBytes and uploadBatchEntries bound one import request; a single
// larger entry still goes alone.
const (
	uploadBatchBytes   = 8 << 20
	uploadBatchEntries = 64
)

// ErrJournalFull is a journal at its bound.
var ErrJournalFull = errors.New("the client journal is full")

const journalHeadFile = "head.json"

type journalHead struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// journal is the on-disk journal.
type journal struct {
	dir          string
	maxBytes     int64
	key          *ecdsa.PrivateKey
	installation string

	mu       sync.Mutex
	openErr  error
	head     journalHead
	bytes    int64
	sizes    map[uint64]int64
	oldestAt map[uint64]time.Time
}

func entryName(seq uint64) string { return fmt.Sprintf("%020d.entry", seq) }

func entrySeq(name string) (uint64, bool) {
	if !strings.HasSuffix(name, ".entry") || len(name) != len("00000000000000000000.entry") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(name, ".entry"), 10, 64)
	return n, err == nil && n > 0
}

// openJournal opens the journal at dir, creating it 0700. A journal that
// cannot be opened is kept with its error: every request that would need
// it is then refused, and no other.
func openJournal(dir, installation string, key *ecdsa.PrivateKey, maxBytes int64) *journal {
	if maxBytes <= 0 {
		maxBytes = DefaultJournalMaxBytes
	}
	j := &journal{
		dir: dir, maxBytes: maxBytes, key: key, installation: installation,
		sizes: map[uint64]int64{}, oldestAt: map[uint64]time.Time{},
	}
	j.openErr = j.load()
	return j
}

func (j *journal) load() error {
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(j.dir, 0o700); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(j.dir, journalHeadFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		if uerr := json.Unmarshal(raw, &j.head); uerr != nil {
			return fmt.Errorf("%s: %w", filepath.Join(j.dir, journalHeadFile), uerr)
		}
	}
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return err
	}
	var newest uint64
	for _, e := range entries {
		seq, ok := entrySeq(e.Name())
		if !ok {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			return ierr
		}
		j.sizes[seq] = info.Size()
		j.oldestAt[seq] = info.ModTime()
		j.bytes += info.Size()
		if seq > newest {
			newest = seq
		}
	}
	// An entry written without its head (a crash between the two renames)
	// is the chain's real head.
	if newest > j.head.Seq {
		s, rerr := j.read(newest)
		if rerr != nil {
			return rerr
		}
		j.head = journalHead{Seq: newest, Hash: s.Hash()}
	}
	return nil
}

func (j *journal) read(seq uint64) (clientjournal.Sealed, error) {
	var s clientjournal.Sealed
	raw, err := os.ReadFile(filepath.Join(j.dir, entryName(seq)))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("%s: %w", entryName(seq), err)
	}
	return s, nil
}

// reserve answers whether an entry of about size bytes can be written now:
// the journal opened, it is under its bound, and its directory takes a file.
func (j *journal) reserve(size int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.openErr != nil {
		return fmt.Errorf("the client journal at %s cannot be opened: %w", j.dir, j.openErr)
	}
	if j.bytes+size > j.maxBytes {
		return fmt.Errorf("%w: %d of %d bytes held at %s; the core imports and removes entries when it answers",
			ErrJournalFull, j.bytes, j.maxBytes, j.dir)
	}
	probe, err := os.CreateTemp(j.dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("the client journal at %s cannot be written: %w", j.dir, err)
	}
	name := probe.Name()
	cerr := probe.Close()
	if rerr := os.Remove(name); rerr != nil && cerr == nil {
		cerr = rerr
	}
	if cerr != nil {
		return fmt.Errorf("the client journal at %s cannot be written: %w", j.dir, cerr)
	}
	return nil
}

// append seals e as the next entry of the chain and writes it.
func (j *journal) append(e clientjournal.Entry) (clientjournal.Sealed, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.openErr != nil {
		return clientjournal.Sealed{}, j.openErr
	}
	e.Seq, e.Prev, e.InstallationID = j.head.Seq+1, j.head.Hash, j.installation
	sealed, err := clientjournal.Seal(e, j.key)
	if err != nil {
		return clientjournal.Sealed{}, err
	}
	body, err := json.Marshal(sealed)
	if err != nil {
		return clientjournal.Sealed{}, err
	}
	if werr := writeFileAtomic(filepath.Join(j.dir, entryName(e.Seq)), body, 0o600); werr != nil {
		return clientjournal.Sealed{}, werr
	}
	next := journalHead{Seq: e.Seq, Hash: sealed.Hash()}
	headRaw, err := json.Marshal(next)
	if err != nil {
		return clientjournal.Sealed{}, err
	}
	// The entry is written; a head that fails here is recovered from the
	// newest entry on the next start (load).
	if err := writeFileAtomic(filepath.Join(j.dir, journalHeadFile), headRaw, 0o600); err != nil {
		return clientjournal.Sealed{}, err
	}
	j.head = next
	j.sizes[e.Seq] = int64(len(body))
	j.oldestAt[e.Seq] = time.Now()
	j.bytes += int64(len(body))
	return sealed, nil
}

// pending answers the sequence numbers held, oldest first.
func (j *journal) pending() []uint64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]uint64, 0, len(j.sizes))
	for seq := range j.sizes {
		out = append(out, seq)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// remove deletes an acknowledged entry.
func (j *journal) remove(seq uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.Remove(filepath.Join(j.dir, entryName(seq))); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	j.bytes -= j.sizes[seq]
	delete(j.sizes, seq)
	delete(j.oldestAt, seq)
	return nil
}

func (j *journal) depth() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.sizes)
}

// JournalStatus is the journal's part of GET /_client/status.
type JournalStatus struct {
	Dir      string `json:"dir"`
	Depth    int    `json:"depth"`
	Bytes    int64  `json:"bytes"`
	MaxBytes int64  `json:"max_bytes"`
	// OldestEntryAt is when the oldest entry still held was written.
	OldestEntryAt *time.Time `json:"oldest_entry_at,omitempty"`
	// Error is why the journal cannot be written, when it cannot.
	Error      string        `json:"error,omitempty"`
	LastUpload *UploadStatus `json:"last_upload,omitempty"`
}

// UploadStatus is the newest upload's outcome.
type UploadStatus struct {
	At time.Time `json:"at"`
	// Result is "ok", "rejected: ...", "retry: ..." or "failed: ...".
	Result string `json:"result"`
}

func (j *journal) status() JournalStatus {
	j.mu.Lock()
	defer j.mu.Unlock()
	st := JournalStatus{Dir: j.dir, Depth: len(j.sizes), Bytes: j.bytes, MaxBytes: j.maxBytes}
	if j.openErr != nil {
		st.Error = j.openErr.Error()
	}
	var oldestSeq uint64
	for seq := range j.oldestAt {
		if oldestSeq == 0 || seq < oldestSeq {
			oldestSeq = seq
		}
	}
	if oldestSeq != 0 {
		at := j.oldestAt[oldestSeq].UTC()
		st.OldestEntryAt = &at
	}
	return st
}

// UploadResult is what one UploadJournal did.
type UploadResult struct {
	// Acknowledged entries were deleted.
	Acknowledged int
	// Rejected is the core's rejection, when it rejected one; the entry is
	// kept for inspection, and nothing after it is sent until it is resolved.
	Rejected *clientjournal.ImportResult
	// Retry is the core's request to send again later.
	Retry *clientjournal.ImportResult
}

// UploadJournal sends every held entry to the core, oldest first, and
// deletes those the core acknowledged. It stops at the first entry the core
// rejects or asks to retry.
func (s *Server) UploadJournal(ctx context.Context) (UploadResult, error) {
	s.uploadMu.Lock()
	defer s.uploadMu.Unlock()
	return s.uploadLocked(ctx)
}

func (s *Server) uploadLocked(ctx context.Context) (UploadResult, error) {
	var res UploadResult
	seqs := s.journal.pending()
	for len(seqs) > 0 {
		var batch []clientjournal.Sealed
		var batchSeqs []uint64
		var size int
		for _, seq := range seqs {
			sealed, err := s.journal.read(seq)
			if err != nil {
				s.setUpload("failed: reading entry " + strconv.FormatUint(seq, 10) + ": " + err.Error())
				return res, err
			}
			if len(batch) > 0 && (size+len(sealed.Entry) > uploadBatchBytes || len(batch) >= uploadBatchEntries) {
				break
			}
			batch, batchSeqs = append(batch, sealed), append(batchSeqs, seq)
			size += len(sealed.Entry)
		}
		seqs = seqs[len(batch):]

		results, err := s.postImport(ctx, batch)
		if err != nil {
			s.setUpload("failed: " + err.Error())
			return res, err
		}
		for i, r := range results {
			if i >= len(batch) || r.Hash != batch[i].Hash() {
				err := fmt.Errorf("the core answered for an entry it was not sent (%q)", r.Hash)
				s.setUpload("failed: " + err.Error())
				return res, err
			}
			if !clientjournal.Acknowledged(r.Status) {
				r := r
				if r.Status == clientjournal.ImportRejected {
					res.Rejected = &r
					s.setUpload(fmt.Sprintf("rejected: entry %d: %s", batchSeqs[i], r.Reason))
					s.log.Printf("the core rejected client journal entry %d (%s); it is kept at %s for inspection, "+
						"and nothing after it is uploaded until it is resolved", batchSeqs[i], r.Reason, s.journal.dir)
				} else {
					res.Retry = &r
					s.setUpload(fmt.Sprintf("retry: entry %d: %s", batchSeqs[i], r.Reason))
				}
				return res, nil
			}
			if err := s.journal.remove(batchSeqs[i]); err != nil {
				s.setUpload("failed: removing an acknowledged entry: " + err.Error())
				return res, err
			}
			res.Acknowledged++
		}
		if len(results) < len(batch) {
			s.setUpload("retry: the core answered for fewer entries than it was sent")
			return res, nil
		}
	}
	s.setUpload("ok")
	return res, nil
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
		return nil, err
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

func (s *Server) setUpload(result string) {
	s.lastUploadMu.Lock()
	defer s.lastUploadMu.Unlock()
	s.lastUpload = &UploadStatus{At: s.Now().UTC(), Result: result}
}

func (s *Server) uploadStatus() *UploadStatus {
	s.lastUploadMu.Lock()
	defer s.lastUploadMu.Unlock()
	if s.lastUpload == nil {
		return nil
	}
	u := *s.lastUpload
	return &u
}

// kickUpload wakes the upload loop.
func (s *Server) kickUpload() {
	select {
	case s.uploadKick <- struct{}{}:
	default:
	}
}

// RunJournalUpload uploads the journal until ctx ends: when an entry is
// written, every interval while entries are held, and with doubling backoff
// after a failure. It resumes after a restart from what is on disk.
func (s *Server) RunJournalUpload(ctx context.Context) {
	interval := s.uploadInterval
	wait, backoff := time.Duration(0), interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		case <-s.uploadKick:
		}
		if s.journal.depth() == 0 {
			wait = interval
			continue
		}
		res, err := s.UploadJournal(ctx)
		if err != nil || res.Rejected != nil || res.Retry != nil {
			backoff *= 2
			if backoff > maxUploadBackoff {
				backoff = maxUploadBackoff
			}
			wait = backoff
			continue
		}
		wait, backoff = interval, interval
	}
}

// flushJournalBeforeLive uploads held entries before a live request goes to
// the core, so a tool call journaled during an outage is paired with the
// result the live request carries. Bounded, and skipped while another
// upload runs: a live request is never held up for long.
func (s *Server) flushJournalBeforeLive(ctx context.Context) {
	if s.journal.depth() == 0 || !s.uploadMu.TryLock() {
		return
	}
	defer s.uploadMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.uploadLocked(ctx); err != nil {
		s.log.Printf("uploading the client journal before a live request: %v", err)
	}
}

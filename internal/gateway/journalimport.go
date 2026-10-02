// SPDX-License-Identifier: Apache-2.0

package gateway

// journalimport.go is the core's import of a client journal (ADR-0068),
// behind the client-certificate guard.
//
// Each entry is verified before anything else is done with it: its
// signature under the key of the certificate the caller presented (the
// installation's own key), the installation it names (the caller's), and
// its place in that installation's chain (sequence and previous hash, kept
// per installation on the core). A failure is a rejection, and nothing after
// it is processed: a broken chain is evidence, and the client keeps the
// entry for inspection.
//
// A verified entry is replayed through the live pipeline (Replayer, which
// in production is the gateway's own Proxy), so the run is registered by
// the same identity lifecycle, scope and first-use claim a live request
// meets, and recorded by the same recorders. Then the signed entry is
// stored on the core as the recorded body, and the chain head advances.
// The events the replay records carry the core's own ts (doc 02 §2,
// LED-010); the client's times are in the stored entry, and a tool call
// recorded from it names the entry's hash in its body.
//
// Idempotency is by entry hash: an entry already stored is answered
// "duplicate" and replayed no second time.

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// MaxJournalImportBytes bounds one import request's body.
const MaxJournalImportBytes = 64 << 20

// JournalHead is the newest entry an installation's chain holds on the core.
type JournalHead struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// JournalStore keeps imported entries and each installation's chain head.
type JournalStore interface {
	Head(ctx context.Context, installation string) (JournalHead, error)
	Has(ctx context.Context, installation, hash string) (bool, error)
	// Put stores s and advances the installation's head to (seq, s.Hash()).
	Put(ctx context.Context, installation string, seq uint64, s clientjournal.Sealed) error
}

// installationIDShape is a client installation id: the only thing a
// directory name is ever built from here.
var installationIDShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// FileJournalStore keeps entries as files: <dir>/<installation>/<hex>.entry
// (the sealed entry, as the client sent it) and head.json beside them.
type FileJournalStore struct {
	dir string
}

// NewFileJournalStore stores under dir, created 0700 on first use.
func NewFileJournalStore(dir string) *FileJournalStore { return &FileJournalStore{dir: dir} }

func (s *FileJournalStore) installationDir(installation string) (string, error) {
	if !installationIDShape.MatchString(installation) {
		return "", fmt.Errorf("innsegl gateway: %q is not an installation id", installation)
	}
	return filepath.Join(s.dir, installation), nil
}

func entryFileName(hash string) (string, error) {
	hexPart := strings.TrimPrefix(hash, "sha256:")
	if len(hexPart) != 64 || strings.Trim(hexPart, "0123456789abcdef") != "" {
		return "", fmt.Errorf("innsegl gateway: %q is not an entry hash", hash)
	}
	return hexPart + ".entry", nil
}

// Head implements JournalStore. An installation with nothing stored has the
// zero head: the first entry is sequence 1 with no previous hash.
func (s *FileJournalStore) Head(_ context.Context, installation string) (JournalHead, error) {
	dir, err := s.installationDir(installation)
	if err != nil {
		return JournalHead{}, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "head.json")) //nolint:gosec // G304/G703: dir is built from an id checked against installationIDShape.
	if errors.Is(err, fs.ErrNotExist) {
		return JournalHead{}, nil
	}
	if err != nil {
		return JournalHead{}, err
	}
	var h JournalHead
	if err := json.Unmarshal(raw, &h); err != nil {
		return JournalHead{}, fmt.Errorf("innsegl gateway: the journal head of %s: %w", installation, err)
	}
	return h, nil
}

// Has implements JournalStore.
func (s *FileJournalStore) Has(_ context.Context, installation, hash string) (bool, error) {
	dir, err := s.installationDir(installation)
	if err != nil {
		return false, err
	}
	name, err := entryFileName(hash)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filepath.Join(dir, name)) //nolint:gosec // G703: dir and name are built from a checked id and hash.
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Put implements JournalStore: the entry first, then the head, each by an
// atomic rename. A crash between the two leaves an entry the head does not
// name; the same entry sent again is then a duplicate, never a gap.
func (s *FileJournalStore) Put(_ context.Context, installation string, seq uint64, sealed clientjournal.Sealed) error {
	dir, err := s.installationDir(installation)
	if err != nil {
		return err
	}
	hash := sealed.Hash()
	name, err := entryFileName(hash)
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(dir, 0o700); merr != nil { //nolint:gosec // G703: dir is built from a checked id.
		return merr
	}
	body, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	if werr := writeAtomic(filepath.Join(dir, name), body); werr != nil {
		return werr
	}
	head, err := json.Marshal(JournalHead{Seq: seq, Hash: hash})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "head.json"), head)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() //nolint:gosec // G703: name is a temporary file this function created.
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path) //nolint:gosec // G703: both paths are built from a checked id and hash.
}

// JournalImporterConfig is what a JournalImporter runs on.
type JournalImporterConfig struct {
	// Store keeps entries and chain heads. Required.
	Store JournalStore
	// Replayer replays a verified entry through the live pipeline.
	// Required.
	Replayer Replayer
	// OnResult, when set, is told every result, for the log.
	OnResult func(installation string, r clientjournal.ImportResult)
}

// JournalImporter imports client journals.
type JournalImporter struct {
	store    JournalStore
	replayer Replayer
	onResult func(string, clientjournal.ImportResult)
	// mu serialises imports: an installation's chain advances one entry at
	// a time, and imports are rare.
	mu sync.Mutex
}

// NewJournalImporter builds a JournalImporter, or refuses an incomplete
// configuration.
func NewJournalImporter(cfg JournalImporterConfig) (*JournalImporter, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("innsegl gateway: journal import configuration: no store")
	case cfg.Replayer == nil:
		return nil, errors.New("innsegl gateway: journal import configuration: no replayer")
	}
	onResult := cfg.OnResult
	if onResult == nil {
		onResult = func(string, clientjournal.ImportResult) {}
	}
	return &JournalImporter{store: cfg.Store, replayer: cfg.Replayer, onResult: onResult}, nil
}

// Import processes entries in order for installation, whose certificate
// key is pub, and answers one result per entry processed. It stops after
// the first rejection or retry.
func (im *JournalImporter) Import(ctx context.Context, installation string, pub crypto.PublicKey, entries []clientjournal.Sealed) []clientjournal.ImportResult {
	im.mu.Lock()
	defer im.mu.Unlock()
	var results []clientjournal.ImportResult
	report := func(r clientjournal.ImportResult) {
		results = append(results, r)
		im.onResult(installation, r)
	}
	head, err := im.store.Head(ctx, installation)
	if err != nil {
		if len(entries) > 0 {
			report(clientjournal.ImportResult{Hash: entries[0].Hash(), Status: clientjournal.ImportRetry,
				Reason: "the core could not read this installation's journal head: " + err.Error()})
		}
		return results
	}
	for _, sealed := range entries {
		r, next, stop := im.importOne(ctx, installation, pub, head, sealed)
		report(r)
		if stop {
			break
		}
		head = next
	}
	return results
}

// importOne decides one entry against head, and answers its result, the
// head after it, and whether the batch stops here.
func (im *JournalImporter) importOne(
	ctx context.Context, installation string, pub crypto.PublicKey, head JournalHead, sealed clientjournal.Sealed,
) (clientjournal.ImportResult, JournalHead, bool) {
	hash := sealed.Hash()
	res := clientjournal.ImportResult{Hash: hash}
	retry := func(reason string) (clientjournal.ImportResult, JournalHead, bool) {
		res.Status, res.Reason = clientjournal.ImportRetry, reason
		return res, head, true
	}
	reject := func(reason string) (clientjournal.ImportResult, JournalHead, bool) {
		res.Status, res.Reason = clientjournal.ImportRejected, reason
		return res, head, true
	}

	has, err := im.store.Has(ctx, installation, hash)
	if err != nil {
		return retry("the core could not read its journal store: " + err.Error())
	}
	if has {
		res.Status = clientjournal.ImportDuplicate
		return res, head, false
	}
	e, err := sealed.Open(pub)
	if err != nil {
		return reject(err.Error())
	}
	res.Seq = e.Seq
	if e.InstallationID != installation {
		return reject(fmt.Sprintf("the entry names installation %q, not the caller's", e.InstallationID))
	}
	if e.Seq != head.Seq+1 || e.Prev != head.Hash {
		return reject(fmt.Sprintf("the entry does not continue this installation's chain: it is sequence %d "+
			"after %q, and the core holds sequence %d with hash %q", e.Seq, e.Prev, head.Seq, head.Hash))
	}

	out, buildErr := im.replay(ctx, installation, hash, e)
	switch {
	case buildErr != nil:
		res.Status, res.Reason = clientjournal.ImportStored, "not recorded: "+buildErr.Error()
	case out.Refusal != nil && (out.Refusal.Status >= 500 || out.Refusal.Status == http.StatusTooManyRequests):
		return retry(fmt.Sprintf("the core could not record the entry now (%d): %s", out.Refusal.Status, out.Refusal.Reason))
	case out.Refusal != nil:
		res.Status = clientjournal.ImportStored
		res.Reason = fmt.Sprintf("not recorded: the replayed request was refused (%d): %s", out.Refusal.Status, out.Refusal.Reason)
	case out.RunID != "":
		res.Status = clientjournal.ImportRecorded
	case out.UnrecordedRepo != "":
		res.Status = clientjournal.ImportStored
		res.Reason = "not recorded: " + out.UnrecordedRepo + " is not a repository this installation may record"
	default:
		res.Status = clientjournal.ImportStored
		res.Reason = "not recorded: the entry states no repository the core could record it under"
	}
	if err := im.store.Put(ctx, installation, e.Seq, sealed); err != nil {
		return retry("the core could not store the entry: " + err.Error())
	}
	return res, JournalHead{Seq: e.Seq, Hash: hash}, false
}

// replay rebuilds the journaled request and hands it, with the journaled
// reply, to the Replayer.
func (im *JournalImporter) replay(ctx context.Context, installation, hash string, e clientjournal.Entry) (ReplayOutcome, error) {
	if !strings.HasPrefix(e.Path, "/") || strings.Contains(e.Path, "?") {
		return ReplayOutcome{}, fmt.Errorf("the entry's path %q is not a request path", e.Path)
	}
	target := e.Path
	if e.Query != "" {
		target += "?" + e.Query
	}
	ctx = WithJournalEntry(WithInstallation(ctx, installation), hash)
	r, err := http.NewRequestWithContext(ctx, e.Method, target, bytes.NewReader(e.RequestBody))
	if err != nil {
		return ReplayOutcome{}, fmt.Errorf("the entry's request cannot be rebuilt: %w", err)
	}
	r.ContentLength = int64(len(e.RequestBody))
	r.Header = clientjournal.KeptHeaders(e.RequestHeaders)
	if len(e.Statement) > 0 {
		var compact bytes.Buffer
		if err := json.Compact(&compact, e.Statement); err != nil {
			return ReplayOutcome{}, fmt.Errorf("the entry's statement is not JSON: %w", err)
		}
		r.Header.Set(StatementHeader, base64.RawURLEncoding.EncodeToString(compact.Bytes()))
	}
	return im.replayer.Replay(r, e.ResponseHeaders.Get("Content-Type"), e.ResponseBody), nil
}

// JournalImportHandler serves POST clientjournal.ImportPath behind the
// client-certificate guard: the installation is the guard's, the key the
// presented certificate's.
func JournalImportHandler(im *JournalImporter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeGatewayError(w, http.StatusMethodNotAllowed, "innsegl core: the journal import takes POST")
			return
		}
		installation, ok := InstallationFromContext(r.Context())
		if !ok || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			WriteClientRefusal(w)
			return
		}
		pub := r.TLS.PeerCertificates[0].PublicKey
		var req clientjournal.ImportRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxJournalImportBytes))
		if err := dec.Decode(&req); err != nil {
			writeGatewayError(w, http.StatusBadRequest, "innsegl core: the journal import body is not an import request: "+err.Error())
			return
		}
		results := im.Import(r.Context(), installation, pub, req.Entries)
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(clientjournal.ImportResponse{Results: results})
		if err != nil {
			writeGatewayError(w, http.StatusInternalServerError, "innsegl core: encoding the import results")
			return
		}
		discardWriteError(w.Write(body))
	})
}

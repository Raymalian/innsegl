// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"innsegl.dev/innsegl/internal/event"
)

// memStore is an in-memory Store with the write-once semantics the real object
// store provides through object-lock (IP §6.4, RM-011). Put refuses to change
// what is already there, so a test that wants to simulate tampering has to
// reach past it — which is what tamper() below does, deliberately and visibly.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int
	gets    int
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}} }

func (m *memStore) Get(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	b, ok := m.objects[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	return append([]byte(nil), b...), nil
}

func (m *memStore) Put(name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.puts++
	if existing, ok := m.objects[name]; ok && !bytes.Equal(existing, data) {
		return fmt.Errorf("object-lock: %s already holds different bytes", name)
	}
	m.objects[name] = append([]byte(nil), data...)
	return nil
}

// tamper edits a stored object in place, bypassing the write-once rule the way
// an operator with storage credentials and a misconfigured bucket would.
func (m *memStore) tamper(name string, edit func([]byte) []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	m.objects[name] = edit(append([]byte(nil), b...))
	return nil
}

func (m *memStore) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		out = append(out, k)
	}
	return out
}

// failingStore fails the first Put, then behaves. It is how the write step's
// error return is reached.
type failingStore struct {
	*memStore
	failPut int
	failGet int
	seenPut int
	seenGet int
}

var errStoreDown = errors.New("object store unavailable")

func (f *failingStore) Put(name string, data []byte) error {
	f.seenPut++
	if f.seenPut == f.failPut {
		return errStoreDown
	}
	return f.memStore.Put(name, data)
}

func (f *failingStore) Get(name string) ([]byte, error) {
	f.seenGet++
	if f.seenGet == f.failGet {
		return nil, errStoreDown
	}
	return f.memStore.Get(name)
}

// fileStore is a Store on disk, used by the SEG-002 crash matrix so that state
// survives a process that is killed outright.
//
// Put publishes atomically — write to a temporary file, then rename — because
// the Sealer's resume logic assumes an object is either wholly there or not
// there at all. A store that can publish half an object cannot be resumed
// against; it can only be re-sealed from scratch.
type fileStore struct{ dir string }

func (f fileStore) path(name string) string {
	return filepath.Join(f.dir, hex.EncodeToString([]byte(name))+".seg")
}

func (f fileStore) Get(name string) ([]byte, error) {
	b, err := os.ReadFile(f.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrObjectNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (f fileStore) Put(name string, data []byte) error {
	final := f.path(name)
	if existing, err := os.ReadFile(final); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("object-lock: %s already holds different bytes", name)
		}
		return nil
	}
	tmp, err := os.CreateTemp(f.dir, ".partial-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close(), os.Remove(tmp.Name()))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(err, os.Remove(tmp.Name()))
	}
	return os.Rename(tmp.Name(), final)
}

// seededRecords builds the ledger records a segment is sealed from: the two
// members the sealer reads, and nothing else.
func seededRecords(first int64, n int) []event.Fields {
	digests := seededDigests(n)
	out := make([]event.Fields, n)
	for i := range out {
		out[i] = event.Fields{
			event.FieldChainPosition: first + int64(i),
			event.EventHashField:     digests[i],
		}
	}
	return out
}

// digestOf is the content address of a byte string, computed the one way the
// system computes any digest (doc 02 §4.3).
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return event.HashPrefix + hex.EncodeToString(sum[:])
}

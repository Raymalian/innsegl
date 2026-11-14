// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// IncompleteCallStore keeps opaque, empty tombstones beside the body store.
// They can only deny a replay; they contain no commands, results or signing
// authority. No event schema or body-digest idempotency contract is changed.
type IncompleteCallStore struct {
	root string
}

func NewIncompleteCallStore(root string) (*IncompleteCallStore, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, fmt.Errorf("incomplete observations: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("incomplete observations: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("incomplete observations require a private directory")
	}
	return &IncompleteCallStore{root: root}, nil
}

func (s *IncompleteCallStore) path(runID, callID string) string {
	sum := sha256.Sum256([]byte(runID + "\x00" + callID))
	return filepath.Join(s.root, hex.EncodeToString(sum[:])+".closed")
}

func (s *IncompleteCallStore) Contains(runID, callID string) (bool, error) {
	info, err := os.Lstat(s.path(runID, callID)) // #nosec G703 -- basename is SHA-256 hex under the validated private directory.
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading incomplete observation: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0600 {
		return false, errors.New("invalid incomplete observation tombstone")
	}
	return true, nil
}

func (s *IncompleteCallStore) Remember(runID, callID string) error {
	f, err := os.OpenFile(s.path(runID, callID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G703 -- hashed basename; O_EXCL refuses an existing symlink.
	if errors.Is(err, fs.ErrExist) {
		_, checkErr := s.Contains(runID, callID)
		return checkErr
	}
	if err != nil {
		return fmt.Errorf("persisting incomplete observation: %w", err)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if persistErr := errors.Join(syncErr, closeErr); persistErr != nil {
		return fmt.Errorf("persisting incomplete observation: %w", persistErr)
	}
	dir, err := os.Open(s.root) // #nosec G703 -- constructor-validated private directory, opened only to sync metadata.
	if err != nil {
		return err
	}
	syncErr = dir.Sync()
	closeErr = dir.Close()
	return errors.Join(syncErr, closeErr)
}

// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
)

// CallStateStore retains observed associations and exact recording payloads
// within each run's body directory, so existing repository erasure removes
// these copies too. Restored observations never authorize signing.
type CallStateStore struct {
	root string
	mu   sync.Mutex
}

type storedCallState struct {
	RunID, CallID                                        string
	Call                                                 ToolUse
	Thread                                               CodexThreadIdentity
	ObservedAt                                           time.Time
	Directory, Repo, Installation, JournalEntry, Harness string
	Ambiguous                                            bool
	Record                                               *mcp.GatewayToolCallInput
	Recorded                                             bool
}

func NewCallStateStore(root string) (*CallStateStore, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("call observations require a body-store directory")
	}
	return &CallStateStore{root: root}, nil
}

func (s *CallStateStore) path(runID, callID string) string {
	sum := sha256.Sum256([]byte(callID))
	return filepath.Join(s.root, runID, ".gateway-call-"+hex.EncodeToString(sum[:])+".state")
}

func (s *CallStateStore) runDirectory(runID string) (string, error) {
	if err := event.ValidateIdentifier(runID); err != nil {
		return "", errors.New("invalid run identifier for persisted call observation")
	}
	dir := filepath.Join(s.root, runID)
	info, err := os.Lstat(dir) // #nosec G703 -- runID passed the protected identifier grammar; root is constructor-validated.
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err == nil && !info.IsDir() {
		return "", errors.New("persisted call run directory is not a directory")
	}
	return dir, nil
}

func (s *CallStateStore) load(runID, callID string) (*storedCallState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(runID, callID)
}

func (s *CallStateStore) loadLocked(runID, callID string) (*storedCallState, error) {
	if _, err := s.runDirectory(runID); err != nil {
		return nil, err
	}
	path := s.path(runID, callID)
	info, err := os.Lstat(path) // #nosec G703 -- hashed basename within the validated private directory.
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<20 {
		return nil, errors.New("invalid persisted call observation")
	}
	f, err := os.Open(path) // #nosec G703 -- checked private regular file, basename derived only from SHA-256.
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil {
		return nil, err
	}
	var state storedCallState
	if len(raw) > 64<<20 || json.Unmarshal(raw, &state) != nil || state.RunID != runID || state.CallID != callID {
		return nil, errors.New("invalid persisted call observation")
	}
	return &state, nil
}

func (s *CallStateStore) save(state storedCallState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, err := s.loadLocked(state.RunID, state.CallID)
	if err != nil {
		return err
	}
	if prior != nil && prior.Record != nil {
		// The first canonical payload is immutable; retry the same digest.
		recorded := state.Recorded
		state = *prior
		state.Recorded = state.Recorded || recorded
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(raw) > 64<<20 {
		return errors.New("persisted call observation exceeds limit")
	}
	runDir, err := s.runDirectory(state.RunID)
	if err != nil {
		return err
	}
	if mkdirErr := os.Mkdir(runDir, 0700); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) { // #nosec G703 -- validated run identifier within the configured body root.
		return mkdirErr
	}
	if _, checkErr := s.runDirectory(state.RunID); checkErr != nil {
		return checkErr
	}
	// Sync the parent before acknowledging any state in a newly created run
	// directory, including one concurrently created by the body writer.
	parent, err := os.Open(s.root) // #nosec G703 -- constructor-validated body-store root, opened only for metadata sync.
	if err != nil {
		return err
	}
	if syncErr := errors.Join(parent.Sync(), parent.Close()); syncErr != nil {
		return syncErr
	}
	if writeErr := writeAtomic(s.path(state.RunID, state.CallID), raw); writeErr != nil {
		return fmt.Errorf("persisting call observation: %w", writeErr)
	}
	return nil
}

func stateFromPending(runID, callID string, call pendingCall) storedCallState {
	return storedCallState{
		RunID: runID, CallID: callID,
		Call: ToolUse{ID: callID, Name: call.tool, Input: call.input, Namespace: call.namespace, WireType: call.wireType,
			Truncated: call.truncated, ObservationIncomplete: call.observationIncomplete, ContextIncomplete: call.contextIncomplete, ObservationGap: call.observationGap},
		Thread:     CodexThreadIdentity{SessionID: call.sessionID, ThreadID: call.threadID},
		ObservedAt: call.observedAt, Directory: call.workingDirectory, Repo: call.repo,
		Installation: call.installation, JournalEntry: call.journalEntry, Harness: call.harness, Ambiguous: call.ambiguous,
	}
}

func (s storedCallState) pending() pendingCall {
	input := s.Call.Input
	if s.Call.ObservationIncomplete {
		input = nil
	}
	return pendingCall{
		sessionID: s.Thread.SessionID, threadID: s.Thread.ThreadID, harness: s.Harness,
		tool: s.Call.Name, input: input, namespace: s.Call.Namespace, wireType: s.Call.WireType,
		truncated: s.Call.Truncated, observationIncomplete: s.Call.ObservationIncomplete,
		contextIncomplete: s.Call.ContextIncomplete, observationGap: s.Call.ObservationGap,
		observedAt: s.ObservedAt, workingDirectory: s.Directory, repo: s.Repo,
		installation: s.Installation, journalEntry: s.JournalEntry, ambiguous: s.Ambiguous,
		recorded: s.Recorded || s.Call.ObservationIncomplete, replayed: true,
	}
}

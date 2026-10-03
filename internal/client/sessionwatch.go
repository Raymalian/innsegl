// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A session closed without its SessionEnd hook -- a killed terminal, a
// crash, a machine that slept and was shut down -- sends no end, and its
// runs stayed active until the core's silence backstop retired them, days
// later. The session hook names the harness process that runs the session;
// this client watches it, and when it is gone sends the same end signal the
// hook would have. That is an observed end, not one inferred from silence.
// The core retires on it only after its grace period, and any request from
// the session meanwhile cancels it (internal/gateway/lifecycle.go), so a
// resumed session is never cut off.

// SessionEndPath is the core's session-end endpoint, as the hook uses it.
const SessionEndPath = "/_gateway/session-end"

// sessionWatchInterval is how often watched sessions are checked.
const sessionWatchInterval = 30 * time.Second

// maxWatchedSessions bounds the table; the oldest is not tracked past it.
const maxWatchedSessions = 4096

func (s *Server) sessionWatchFile() string {
	return filepath.Join(s.paths.Dir, "session-processes.json")
}

// loadWatchedSessions reads the table a previous run of this client left.
func (s *Server) loadWatchedSessions() {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	s.watched = map[string]Process{}
	// #nosec G304 -- this service's own file.
	b, err := os.ReadFile(s.sessionWatchFile())
	if err != nil {
		return
	}
	if err := json.Unmarshal(b, &s.watched); err != nil {
		s.log.Printf("the watched-session table is unreadable and starts empty: %v", err)
		s.watched = map[string]Process{}
	}
}

// saveWatchedLocked writes the table; the caller holds watchMu.
func (s *Server) saveWatchedLocked() {
	b, err := json.Marshal(s.watched)
	if err == nil {
		err = writeFileAtomic(s.sessionWatchFile(), b, 0o600)
	}
	if err != nil {
		s.log.Printf("saving the watched-session table: %v", err)
	}
}

// watchSession records the harness process a session runs in.
func (s *Server) watchSession(session string, p Process) {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watched[session] == p {
		return
	}
	if _, known := s.watched[session]; !known && len(s.watched) >= maxWatchedSessions {
		return
	}
	s.watched[session] = p
	s.saveWatchedLocked()
}

func (s *Server) watchedSessions() int {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	return len(s.watched)
}

// noteHarnessProcess takes the harness process off a session statement's URL,
// so it never reaches the core, and watches the session it names.
func (s *Server) noteHarnessProcess(r *http.Request, body []byte) {
	q := r.URL.Query()
	p, ok := harnessProcessFrom(q)
	q.Del("harness_pid")
	q.Del("harness_start")
	r.URL.RawQuery = q.Encode()
	if !ok {
		return
	}
	var st struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(body, &st) != nil || st.SessionID == "" {
		return
	}
	s.watchSession(st.SessionID, p)
}

// CheckSessions sends the end of every watched session whose harness
// process is gone. A session whose end the core did not take stays watched
// and is tried again.
func (s *Server) CheckSessions(ctx context.Context) {
	s.watchMu.Lock()
	var gone []string
	for session, p := range s.watched {
		if !p.Alive() {
			gone = append(gone, session)
		}
	}
	s.watchMu.Unlock()
	for _, session := range gone {
		if err := s.sendSessionEnd(ctx, session); err != nil {
			s.log.Printf("ending session %s, whose process is gone: %v", session, err)
			continue
		}
		s.watchMu.Lock()
		delete(s.watched, session)
		s.saveWatchedLocked()
		s.watchMu.Unlock()
	}
}

func (s *Server) sendSessionEnd(ctx context.Context, session string) error {
	body, err := json.Marshal(map[string]string{"session_id": session})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.core.CoreURL, "/")+SessionEndPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("the core answered %d", resp.StatusCode)
	}
	return nil
}

// RunSessionWatch checks watched sessions at once and then every
// sessionWatchInterval until ctx ends.
func (s *Server) RunSessionWatch(ctx context.Context) {
	for {
		s.CheckSessions(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(sessionWatchInterval):
		}
	}
}

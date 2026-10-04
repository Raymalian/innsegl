// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// A session closed without its SessionEnd hook -- a killed terminal, a
// crash, a machine that slept and was shut down -- sends no end, and its
// runs stayed active until the core's silence backstop retired them, days
// later. The session hook names the harness process that runs the session;
// this client watches it, and when it is gone sends the same end signal the
// hook would have, through the outbox (outbox.go). That is an observed end,
// not one inferred from silence. The core retires on it only after its
// grace period, and any request from the session meanwhile cancels it
// (internal/gateway/lifecycle.go), so a resumed session is never cut off.
//
// The watch table (session-processes.json) is state: which processes are
// alive. An end it decides on goes to the outbox, which delivers it.

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
	if known, ok := s.watched[session]; ok && known == p {
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

// CheckSessions holds the end of every watched session whose harness
// process is gone in the outbox, which delivers it, and stops watching it.
// A session whose end could not be held stays watched and is tried again.
func (s *Server) CheckSessions(context.Context) {
	s.watchMu.Lock()
	var gone []string
	for session, p := range s.watched {
		if !p.Alive() {
			gone = append(gone, session)
		}
	}
	sort.Strings(gone)
	s.watchMu.Unlock()
	held := false
	for _, session := range gone {
		if err := s.outbox.hold(KindEnd, endBody(session, "")); err != nil {
			s.log.Printf("holding the end of session %s, whose process is gone: %v", session, err)
			continue
		}
		held = true
		s.watchMu.Lock()
		delete(s.watched, session)
		s.saveWatchedLocked()
		s.watchMu.Unlock()
	}
	if held {
		s.kickOutbox()
	}
}

// endBody is the session-end route's body: the session, and the agent for
// a subagent's end.
func endBody(session, agent string) []byte {
	end := map[string]string{"session_id": session}
	if agent != "" {
		end["agent_id"] = agent
	}
	b, err := json.Marshal(end)
	if err != nil {
		// A map of strings always encodes.
		panic(err)
	}
	return b
}

// serveSessionEnd passes a session's end to the core and, when the core
// does not take it now, holds it in the outbox to send once the core
// answers. A lost end left the run active until the silence backstop, days
// later.
func (s *Server) serveSessionEnd(w http.ResponseWriter, r *http.Request) {
	var end struct {
		SessionID string `json:"session_id"`
		AgentID   string `json:"agent_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&end); err != nil || end.SessionID == "" {
		http.Error(w, "innsegl client: a session end needs a session_id", http.StatusBadRequest)
		return
	}
	body := endBody(end.SessionID, end.AgentID)
	status, err := s.liveToCore(r, SessionEndPath, body)
	switch {
	case err == nil && status/100 == 2:
		w.WriteHeader(http.StatusAccepted)
		return
	case err == nil && refusedForGood(status):
		s.log.Printf("the core refused the end of session %s (%d); it is not held", end.SessionID, status)
		http.Error(w, fmt.Sprintf("innsegl client: the core refused the session end (%d)", status), status)
		return
	}
	if herr := s.outbox.hold(KindEnd, body); herr != nil {
		s.log.Printf("LOST: the end of session %s was not taken by the core and could not be held: %v", end.SessionID, herr)
		http.Error(w, "innsegl client: the session end could not be delivered or held", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusAccepted)
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

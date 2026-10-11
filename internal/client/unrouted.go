// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/workspace"
)

// The unrouted-session detector (RM-319, #579). Detect, never prevent: the
// client does not lock the machine down, so a session can reach the
// provider without passing through it (its own base URL, a proxy setting
// left out). The harness keeps a transcript of every session; this client
// sees every session routed through it. A session that has model replies in
// its transcript since this service started, in a repository innsegl
// records, whose traffic never reached this service, bypassed innsegl. It is
// a finding: kept in unrouted-sessions.json, shown by GET /_client/status and
// `innsegl status`, and reported to the core for the dashboard. Nothing is
// refused.

// UnroutedPath is the core's route for a finding.
const UnroutedPath = "/_core/unrouted-session"

// unroutedInterval is how often the transcripts are looked at.
const unroutedInterval = time.Minute

// maxUnrouted bounds the findings kept; the oldest activity goes first.
const maxUnrouted = 256

// maxTranscriptLine bounds one transcript line read; a longer one is
// skipped, not read whole.
const maxTranscriptLine = 8 << 20

// UnroutedSession is one finding.
type UnroutedSession struct {
	SessionID    string    `json:"session_id"`
	Repo         string    `json:"repo"`
	FirstSeen    time.Time `json:"first_seen"`
	LastActivity time.Time `json:"last_activity"`
	// Reported is the last activity the core has taken; zero before the
	// first report.
	Reported time.Time `json:"reported_activity,omitempty"`
}

// UnroutedReport is what the core is told.
type UnroutedReport struct {
	SessionID      string    `json:"session_id"`
	LastActivityAt time.Time `json:"last_activity_at"`
}

// unroutedState is the detector's state.
type unroutedState struct {
	mu       sync.Mutex
	dirs     []string
	started  time.Time
	routed   map[string]bool
	findings map[string]UnroutedSession
	// seen is each transcript's size when it was last read, so an
	// unchanged one is not read again.
	seen map[string]int64
}

// defaultTranscriptDirs is where the harness keeps its transcripts:
// $CLAUDE_CONFIG_DIR/projects, else ~/.claude/projects.
func defaultTranscriptDirs(home string) []string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return []string{filepath.Join(dir, "projects")}
	}
	return []string{filepath.Join(home, ".claude", "projects")}
}

func (s *Server) unroutedFile() string {
	return filepath.Join(s.paths.Dir, "unrouted-sessions.json")
}

// initUnrouted sets the detector up and loads the findings a previous run
// of this service kept.
func (s *Server) initUnrouted(dirs []string) {
	if len(dirs) == 0 {
		if home, err := os.UserHomeDir(); err == nil {
			dirs = defaultTranscriptDirs(home)
		}
	}
	u := &unroutedState{dirs: dirs, started: s.Now(), routed: map[string]bool{},
		findings: map[string]UnroutedSession{}, seen: map[string]int64{}}
	// #nosec G304 -- this service's own file.
	if b, err := os.ReadFile(s.unroutedFile()); err == nil {
		var kept []UnroutedSession
		if json.Unmarshal(b, &kept) != nil {
			s.log.Printf("the unrouted-session findings are unreadable and start empty")
		}
		for _, f := range kept {
			u.findings[f.SessionID] = f
		}
	}
	s.unrouted = u
}

// noteRouted records that a session's model traffic reached this service.
func (s *Server) noteRouted(session string) {
	if session == "" || s.unrouted == nil {
		return
	}
	u := s.unrouted
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.routed) >= DefaultMaxStatements && !u.routed[session] {
		// Bounded: start again rather than grow. A session forgotten here
		// is routed, so its next request notes it again.
		u.routed = map[string]bool{}
	}
	u.routed[session] = true
}

// unroutedFindings answers the findings, newest activity first.
func (s *Server) unroutedFindings() []UnroutedSession {
	if s.unrouted == nil {
		return nil
	}
	u := s.unrouted
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]UnroutedSession, 0, len(u.findings))
	for _, f := range u.findings {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastActivity.After(out[j].LastActivity) })
	return out
}

// transcriptFacts is what one transcript says: its session, where it ran,
// and its newest model reply since the service started.
type transcriptFacts struct {
	session, cwd string
	lastReply    time.Time
}

// readTranscript reads one transcript for replies after since.
func readTranscript(path string, since time.Time) (transcriptFacts, error) {
	f, err := os.Open(path) // #nosec G304 -- a file in the harness's own transcript folder.
	if err != nil {
		return transcriptFacts{}, err
	}
	defer func() { _ = f.Close() }()
	var facts transcriptFacts
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), maxTranscriptLine)
	for sc.Scan() {
		var line struct {
			Type      string    `json:"type"`
			SessionID string    `json:"sessionId"`
			Cwd       string    `json:"cwd"`
			Timestamp time.Time `json:"timestamp"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.SessionID == "" || line.Cwd == "" {
			continue
		}
		facts.session, facts.cwd = line.SessionID, line.Cwd
		if line.Type == "assistant" && line.Timestamp.After(since) && line.Timestamp.After(facts.lastReply) {
			facts.lastReply = line.Timestamp
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return facts, err
	}
	return facts, nil
}

// CheckUnrouted looks at every transcript changed since this service
// started, keeps a finding for each unrouted session in a recorded
// repository, and reports to the core what it has not taken yet.
func (s *Server) CheckUnrouted(ctx context.Context) {
	u := s.unrouted
	if u == nil {
		return
	}
	u.mu.Lock()
	dirs, started := u.dirs, u.started
	u.mu.Unlock()

	changed := false
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*", "*.jsonl"))
		if err != nil {
			continue
		}
		for _, path := range matches {
			if s.checkTranscript(ctx, path, started) {
				changed = true
			}
		}
	}
	if changed {
		s.saveUnrouted()
	}
	s.reportUnrouted(ctx)
}

// checkTranscript reads one transcript when it changed, and answers whether
// a finding was added or moved on.
func (s *Server) checkTranscript(ctx context.Context, path string, started time.Time) bool {
	info, err := os.Stat(path)
	if err != nil || info.ModTime().Before(started) {
		return false
	}
	session := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	u := s.unrouted
	u.mu.Lock()
	routed := u.routed[session]
	unchanged := u.seen[path] == info.Size()
	u.mu.Unlock()
	if routed || unchanged {
		return false
	}
	facts, err := readTranscript(path, started)
	u.mu.Lock()
	u.seen[path] = info.Size()
	u.mu.Unlock()
	if err != nil || facts.lastReply.IsZero() || facts.session != session {
		return false
	}
	ws, err := workspace.Derive(ctx, facts.cwd)
	if err != nil {
		// Outside any repository innsegl records: nothing to attribute.
		return false
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.routed[session] {
		return false
	}
	f, known := u.findings[session]
	if known && !facts.lastReply.After(f.LastActivity) {
		return false
	}
	if !known {
		f = UnroutedSession{SessionID: session, Repo: ws.Repo, FirstSeen: s.Now().UTC()}
		s.log.Printf("finding: session %s in %s sent model traffic that did not pass through innsegl; "+
			"it is not recorded. Start it again after `innsegl connect` so its traffic is routed", session, ws.Repo)
	}
	f.LastActivity = facts.lastReply.UTC()
	u.findings[session] = f
	s.trimUnroutedLocked()
	return true
}

// trimUnroutedLocked drops the oldest findings past maxUnrouted.
func (s *Server) trimUnroutedLocked() {
	u := s.unrouted
	for len(u.findings) > maxUnrouted {
		oldest := ""
		for id, f := range u.findings {
			if oldest == "" || f.LastActivity.Before(u.findings[oldest].LastActivity) {
				oldest = id
			}
		}
		delete(u.findings, oldest)
	}
}

// saveUnrouted writes the findings.
func (s *Server) saveUnrouted() {
	b, err := json.Marshal(s.unroutedFindings())
	if err == nil {
		err = writeFileAtomic(s.unroutedFile(), b, 0o600)
	}
	if err != nil {
		s.log.Printf("saving the unrouted-session findings: %v", err)
	}
}

// reportUnrouted tells the core each finding whose newest activity it has
// not taken. A finding the core does not take is told again next time.
func (s *Server) reportUnrouted(ctx context.Context) {
	reported := false
	for _, f := range s.unroutedFindings() {
		if !f.LastActivity.After(f.Reported) {
			continue
		}
		body, err := json.Marshal(UnroutedReport{SessionID: f.SessionID, LastActivityAt: f.LastActivity})
		if err != nil {
			continue
		}
		status, err := s.sendToCore(ctx, UnroutedPath, body, "application/json")
		if err != nil || status/100 != 2 {
			s.log.Printf("the core did not take the finding for session %s (%d, %v); it is told again later",
				f.SessionID, status, err)
			continue
		}
		u := s.unrouted
		u.mu.Lock()
		if cur, ok := u.findings[f.SessionID]; ok {
			cur.Reported = f.LastActivity
			u.findings[f.SessionID] = cur
		}
		u.mu.Unlock()
		reported = true
	}
	if reported {
		s.saveUnrouted()
	}
}

// RunUnroutedWatch looks at the transcripts at once and then every
// unroutedInterval until ctx ends.
func (s *Server) RunUnroutedWatch(ctx context.Context) {
	for {
		s.CheckUnrouted(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(unroutedInterval):
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// HAR-022 — the unrouted-session detector (RM-319, #579). The harness keeps
// a transcript of every session; the client sees every session routed
// through it. A session with model replies in its transcript, in a
// repository innsegl records, whose traffic never reached the client,
// bypassed innsegl: it is a finding, shown in the status and reported to the
// core. Nothing is refused.

// transcriptLine is one line of the harness's transcript, in the shape
// measured from a real one (type, sessionId, cwd, timestamp).
func transcriptLine(t *testing.T, kind, session, cwd string, at time.Time) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type": kind, "sessionId": session, "cwd": cwd, "timestamp": at.UTC().Format(time.RFC3339Nano),
		"message": map[string]any{"role": kind, "content": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func appendTranscript(t *testing.T, dir, session string, lines ...string) {
	t.Helper()
	path := filepath.Join(dir, "-proj", session+".jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range lines {
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
}

// recordedRepo is a git repository whose origin names a repository innsegl
// records.
func recordedRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is not on PATH: %v", err)
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "https://github.com/acme/app.git"}} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

type unroutedReports struct {
	mu      sync.Mutex
	got     []UnroutedReport
	refuse  bool
	gotAuth bool
}

func (u *unroutedReports) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		defer u.mu.Unlock()
		if u.refuse {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		u.gotAuth = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		var rep UnroutedReport
		b, err := io.ReadAll(r.Body)
		if err != nil || json.Unmarshal(b, &rep) != nil {
			t.Errorf("an unreadable report: %q %v", b, err)
		}
		u.got = append(u.got, rep)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (u *unroutedReports) all() []UnroutedReport {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]UnroutedReport(nil), u.got...)
}

func TestHAR022AnUnroutedSessionInARecordedRepositoryIsAFinding(t *testing.T) {
	core, paths := enrolled(t)
	reports := &unroutedReports{}
	core.Mux.HandleFunc(UnroutedPath, reports.handler(t))
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message_stop\ndata: {}\n\n")
	})
	transcripts := t.TempDir()
	srv, front, logs := startJournalClient(t, paths, newProvider(t), ServerOptions{TranscriptDirs: []string{transcripts}})

	repo := recordedRepo(t)
	elsewhere := t.TempDir()
	after := time.Now().Add(time.Second)
	before := time.Now().Add(-time.Hour)

	appendTranscript(t, transcripts, "s-unrouted",
		transcriptLine(t, "user", "s-unrouted", repo, after), transcriptLine(t, "assistant", "s-unrouted", repo, after))
	appendTranscript(t, transcripts, "s-routed",
		transcriptLine(t, "user", "s-routed", repo, after), transcriptLine(t, "assistant", "s-routed", repo, after))
	appendTranscript(t, transcripts, "s-norepo", transcriptLine(t, "assistant", "s-norepo", elsewhere, after))
	appendTranscript(t, transcripts, "s-old", transcriptLine(t, "assistant", "s-old", repo, before))
	appendTranscript(t, transcripts, "s-useronly", transcriptLine(t, "user", "s-useronly", repo, after))

	// s-routed's model traffic passes through this client.
	if status, _, body := postJSON(t, front.URL+"/v1/messages", `{"messages":[]}`, modelHeaders("s-routed")); status != http.StatusOK {
		t.Fatalf("a routed request: %d %s", status, body)
	}

	srv.CheckUnrouted(context.Background())
	st := srv.Status(context.Background())
	if len(st.Unrouted) != 1 {
		t.Fatalf("findings %+v, want exactly s-unrouted\nlog:\n%s", st.Unrouted, logs.String())
	}
	f := st.Unrouted[0]
	if f.SessionID != "s-unrouted" || f.Repo != "github.com/acme/app" || f.LastActivity.IsZero() {
		t.Fatalf("finding %+v; want s-unrouted in github.com/acme/app with its last activity", f)
	}
	got := reports.all()
	if len(got) != 1 || got[0].SessionID != "s-unrouted" || !got[0].LastActivityAt.Equal(f.LastActivity) {
		t.Fatalf("the core was told %+v; want s-unrouted once, with its last activity", got)
	}
	if !reports.gotAuth {
		t.Error("the report did not reach the core over the client certificate")
	}

	t.Run("a second look with nothing new reports nothing again", func(t *testing.T) {
		srv.CheckUnrouted(context.Background())
		if n := len(reports.all()); n != 1 {
			t.Fatalf("%d reports after a second look, want still 1", n)
		}
	})

	t.Run("new activity is reported", func(t *testing.T) {
		later := after.Add(time.Minute)
		appendTranscript(t, transcripts, "s-unrouted", transcriptLine(t, "assistant", "s-unrouted", repo, later))
		srv.CheckUnrouted(context.Background())
		got := reports.all()
		if len(got) != 2 || !got[1].LastActivityAt.Equal(later.UTC().Truncate(time.Millisecond)) &&
			!got[1].LastActivityAt.Equal(later.UTC()) {
			t.Fatalf("reports %+v; want a second report at %s", got, later)
		}
	})

	t.Run("a core that does not take the report is told again later", func(t *testing.T) {
		reports.mu.Lock()
		reports.refuse = true
		reports.mu.Unlock()
		appendTranscript(t, transcripts, "s-second", transcriptLine(t, "assistant", "s-second", repo, after))
		srv.CheckUnrouted(context.Background())
		reports.mu.Lock()
		reports.refuse = false
		reports.mu.Unlock()
		srv.CheckUnrouted(context.Background())
		found := false
		for _, r := range reports.all() {
			found = found || r.SessionID == "s-second"
		}
		if !found {
			t.Fatal("s-second was never reported after the core came back")
		}
	})

	t.Run("the finding survives a restart of the client", func(t *testing.T) {
		again, err := NewServerWith(paths, io.Discard, ServerOptions{TranscriptDirs: []string{t.TempDir()}})
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, f := range again.Status(context.Background()).Unrouted {
			ids[f.SessionID] = true
		}
		if !ids["s-unrouted"] || !ids["s-second"] {
			t.Fatalf("after a restart the status shows %v; want both findings kept", ids)
		}
	})

	t.Run("the status endpoint carries the finding", func(t *testing.T) {
		resp, err := http.Get(front.URL + StatusPath) //nolint:noctx // a test against its own server
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		var body struct {
			Unrouted []UnroutedSession `json:"unrouted_sessions"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Unrouted) == 0 || body.Unrouted[0].Repo == "" {
			t.Fatalf("GET %s carries %+v", StatusPath, body.Unrouted)
		}
	})
}

func TestHAR022AnUnreadableTranscriptIsSkipped(t *testing.T) {
	_, paths := enrolled(t)
	transcripts := t.TempDir()
	srv, err := NewServerWith(paths, io.Discard, ServerOptions{TranscriptDirs: []string{transcripts, filepath.Join(transcripts, "missing")}})
	if err != nil {
		t.Fatal(err)
	}
	appendTranscript(t, transcripts, "s-garbage", "not json\n", `{"type":"assistant"}`+"\n")
	srv.CheckUnrouted(context.Background())
	if n := len(srv.Status(context.Background()).Unrouted); n != 0 {
		t.Fatalf("%d findings from an unreadable transcript", n)
	}
}

func TestHAR022TheDefaultTranscriptFolderIsTheHarnesss(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if got := defaultTranscriptDirs("/home/op"); len(got) != 1 || got[0] != filepath.Join("/home/op", ".claude", "projects") {
		t.Fatalf("defaultTranscriptDirs = %v", got)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "/etc/claude")
	if got := defaultTranscriptDirs("/home/op"); len(got) != 1 || got[0] != filepath.Join("/etc/claude", "projects") {
		t.Fatalf("defaultTranscriptDirs with CLAUDE_CONFIG_DIR = %v", got)
	}
}

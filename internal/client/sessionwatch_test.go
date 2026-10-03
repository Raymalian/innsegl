// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A session closed without its SessionEnd hook -- a killed terminal, a
// crash -- used to stay active until the silence backstop retired it, days
// later. The hook names the session's harness process; when that process is
// gone, the client sends the session's end itself.
func TestASessionWhoseProcessIsGoneIsEnded(t *testing.T) {
	core, paths := enrolled(t)
	ends := make(chan string, 4)
	queries := make(chan string, 4)
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, r *http.Request) {
		queries <- r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})
	core.Mux.HandleFunc(SessionEndPath, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the end signal: %v", err)
		}
		ends <- string(b)
		w.WriteHeader(http.StatusAccepted)
	})
	srv, front, _ := startClient(t, paths)

	harness := exec.CommandContext(t.Context(), "sleep", "60")
	if err := harness.Start(); err != nil {
		t.Fatalf("starting a stand-in harness: %v", err)
	}
	id, ok := ProcessOf(harness.Process.Pid)
	if !ok {
		t.Fatal("ProcessOf could not read a running process")
	}

	url := front.URL + SessionStatementPath + "?" + HarnessProcessQuery(id)
	body := `{"session_id":"s-1","agent_id":"","cwd":"/tmp"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stating the session: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if q := <-queries; q != "" {
		t.Errorf("the core received the harness process %q; it is the client's alone", q)
	}

	srv.CheckSessions(context.Background())
	select {
	case got := <-ends:
		t.Fatalf("a live session was ended: %s", got)
	default:
	}

	if err := harness.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := harness.Wait(); err == nil {
		t.Fatal("the stand-in harness exited cleanly after a kill")
	}
	srv.CheckSessions(context.Background())
	select {
	case got := <-ends:
		if got != `{"session_id":"s-1"}` {
			t.Errorf("end signal = %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session of a gone process was not ended")
	}
	if n := srv.watchedSessions(); n != 0 {
		t.Errorf("watched sessions after the end was delivered = %d, want 0", n)
	}
}

// The watched sessions survive a client restart: a session killed while the
// client was down is ended when it starts.
func TestWatchedSessionsSurviveARestart(t *testing.T) {
	_, paths := enrolled(t)
	srv, _, _ := startClient(t, paths)
	srv.watchSession("s-2", Process{PID: 1 << 22, Start: 1})
	again, _, _ := startClient(t, paths)
	if n := again.watchedSessions(); n != 1 {
		t.Fatalf("watched sessions after a restart = %d, want 1", n)
	}
}

func TestProcessOfReadsThisProcess(t *testing.T) {
	p, ok := ProcessOf(os.Getpid())
	if !ok || p.PID != os.Getpid() || p.Start == 0 {
		t.Fatalf("ProcessOf(self) = %+v, %v", p, ok)
	}
	if !p.Alive() {
		t.Fatal("this process reads as gone")
	}
	if (Process{PID: p.PID, Start: p.Start + 1}).Alive() {
		t.Fatal("a reused pid with another start time reads as the same process")
	}
	if _, err := strconv.Atoi(strings.TrimPrefix(HarnessProcessQuery(p), "harness_pid=")[:1]); err != nil {
		t.Fatalf("HarnessProcessQuery(%+v) = %q", p, HarnessProcessQuery(p))
	}
}

// A session's end sent while the core is down used to be lost: the client
// passed it on and the core never saw it, so the run stayed active until
// the silence backstop. The client now keeps it and sends it once the core
// answers -- a subagent's end too.
func TestASessionEndSentWhileTheCoreIsDownIsDeliveredAfter(t *testing.T) {
	core, paths := enrolled(t)
	ends := make(chan string, 4)
	core.Mux.HandleFunc(SessionEndPath, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the end signal: %v", err)
		}
		ends <- string(b)
		w.WriteHeader(http.StatusAccepted)
	})
	srv, front, _ := startClient(t, paths)
	core.Stop()

	for _, body := range []string{`{"session_id":"s-9"}`, `{"session_id":"s-9","agent_id":"a1b2c3"}`} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, front.URL+SessionEndPath, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("sending the end: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("end while the core is down answered %d, want 202 (kept)", resp.StatusCode)
		}
	}
	if n := srv.watchedSessions(); n != 2 {
		t.Fatalf("kept ends = %d, want 2", n)
	}

	core.Restart(t)
	srv.CheckSessions(context.Background())
	got := map[string]bool{}
	for range 2 {
		select {
		case b := <-ends:
			got[b] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("ends delivered = %v, want both", got)
		}
	}
	if !got[`{"session_id":"s-9"}`] || !got[`{"agent_id":"a1b2c3","session_id":"s-9"}`] {
		t.Errorf("ends delivered = %v", got)
	}
	if n := srv.watchedSessions(); n != 0 {
		t.Errorf("kept ends after delivery = %d, want 0", n)
	}
}

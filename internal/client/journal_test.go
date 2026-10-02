// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/clientjournal"
)

// ADR-0068: the client journals what the core cannot record, and the core
// imports it later. Claude Code is never blocked: the one refusal is a
// journal that cannot be written.

const (
	jrnRepoSession = "44444444-4444-4444-8444-444444444444"
	jrnHomeSession = "66666666-6666-4666-8666-666666666666"
	jrnSSE         = "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
)

// provider is a fake model provider: it streams jrnSSE in two flushes and
// remembers what it was sent.
type provider struct {
	srv  *httptest.Server
	hits atomic.Int32
	mu   sync.Mutex
	seen []http.Header
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	p := &provider{}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		p.mu.Lock()
		p.seen = append(p.seen, r.Header.Clone())
		p.mu.Unlock()
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		half := len(jrnSSE) / 2
		fmt.Fprint(w, jrnSSE[:half])
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		fmt.Fprint(w, jrnSSE[half:])
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func startJournalClient(t *testing.T, paths Paths, p *provider, opts ServerOptions) (*Server, *httptest.Server, *syncWriter) {
	t.Helper()
	logs := &syncWriter{}
	if p != nil {
		opts.ProviderURL, opts.ProviderClient = p.srv.URL, p.srv.Client()
	}
	srv, err := NewServerWith(paths, logs, opts)
	if err != nil {
		t.Fatalf("NewServerWith: %v", err)
	}
	front := httptest.NewServer(srv.Handler())
	t.Cleanup(front.Close)
	return srv, front, logs
}

func postJSON(t *testing.T, url, body string, header map[string]string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header, string(readAll(t, resp.Body))
}

func repoStatement(session string) string {
	return `{"session_id":"` + session + `","cwd":"/w/app","repo":"github.com/acme/app","branch":"main","task":"t1"}`
}

func modelHeaders(session string) map[string]string {
	return map[string]string{
		"X-Claude-Code-Session-Id": session, "Authorization": "Bearer provider-canary",
		"Anthropic-Version": "2023-06-01", "Content-Type": "application/json",
	}
}

func readJournal(t *testing.T, paths Paths, key *ecdsa.PublicKey) []clientjournal.Entry {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(paths.Journal, "*.entry"))
	if err != nil {
		t.Fatal(err)
	}
	var out []clientjournal.Entry
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var s clientjournal.Sealed
		if uerr := json.Unmarshal(raw, &s); uerr != nil {
			t.Fatal(uerr)
		}
		e, err := s.Open(key)
		if err != nil {
			t.Fatalf("%s does not open under the installation key: %v", f, err)
		}
		out = append(out, e)
	}
	return out
}

func installationKey(t *testing.T, paths Paths) *ecdsa.PrivateKey {
	t.Helper()
	k, err := loadKey(paths.Key)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// JRN-002: the core is down. A session in a repository is forwarded to the
// provider directly, streamed, and journaled: signed, the full reply, no
// credential. A session outside any repository is forwarded and journaled
// nowhere.
func TestJRN002CoreDownForwardsToTheProviderAndJournals(t *testing.T) {
	core, paths := enrolled(t)
	p := newProvider(t)
	srv, front, logs := startJournalClient(t, paths, p, ServerOptions{})
	if status, _, body := postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil); status != http.StatusNotFound {
		// The fake core has no statement route; a 404 proves it was reached.
		t.Fatalf("statement: %d %s", status, body)
	}
	core.Close()

	status, header, body := postJSON(t, front.URL+"/v1/messages?beta=true", `{"messages":[{"role":"user","content":"hi"}]}`,
		modelHeaders(jrnRepoSession))
	if status != http.StatusOK || body != jrnSSE || !strings.HasPrefix(header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("the harness got %d %q", status, body)
	}
	if p.hits.Load() != 1 {
		t.Fatalf("the provider saw %d requests, want 1", p.hits.Load())
	}
	seen := p.seen[0]
	if seen.Get("Authorization") != "Bearer provider-canary" || seen.Get(StatementHeader) != "" {
		t.Fatalf("the provider saw %v: the credential must pass, the statement must not", seen)
	}

	key := installationKey(t, paths)
	entries := readJournal(t, paths, &key.PublicKey)
	if len(entries) != 1 {
		t.Fatalf("%d journal entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Seq != 1 || e.Prev != "" || e.SessionID != jrnRepoSession || e.Reason != clientjournal.ReasonCoreUnreachable ||
		e.InstallationID != srv.core.InstallationID || e.Path != "/v1/messages" || e.Query != "beta=true" {
		t.Fatalf("entry = %+v", e)
	}
	if string(e.ResponseBody) != jrnSSE || !e.ResponseComplete || e.ResponseStatus != http.StatusOK {
		t.Fatalf("entry reply %d %q complete=%v, want the full stream", e.ResponseStatus, e.ResponseBody, e.ResponseComplete)
	}
	if !strings.Contains(string(e.Statement), `"repo":"github.com/acme/app"`) || string(e.RequestBody) != `{"messages":[{"role":"user","content":"hi"}]}` {
		t.Fatalf("entry statement %s, request %s", e.Statement, e.RequestBody)
	}
	if e.StartedAt.IsZero() || e.EndedAt.Before(e.StartedAt) {
		t.Fatalf("client times %v..%v", e.StartedAt, e.EndedAt)
	}
	raw, err := os.ReadFile(filepath.Join(paths.Journal, "00000000000000000001.entry"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("provider-canary")) {
		t.Fatal("the provider credential is in the journal")
	}
	for _, f := range []string{paths.Journal, filepath.Join(paths.Journal, "00000000000000000001.entry")} {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if st.IsDir() {
			want = 0o700
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", f, st.Mode().Perm(), want)
		}
	}

	// Outside any repository: forwarded, journaled nowhere, logged.
	if status, _, _ := postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnHomeSession)); status != http.StatusOK {
		t.Fatalf("a session outside any repository: %d", status)
	}
	if p.hits.Load() != 2 || len(readJournal(t, paths, &key.PublicKey)) != 1 {
		t.Fatalf("provider hits %d, entries %d; want 2 and still 1", p.hits.Load(), len(readJournal(t, paths, &key.PublicKey)))
	}
	if !strings.Contains(logs.String(), jrnHomeSession) {
		t.Errorf("the bypass is not in the log: %s", logs.String())
	}

	st := srv.Status(context.Background())
	if st.Journal.Depth != 1 || st.Journal.Bytes == 0 || st.Journal.OldestEntryAt == nil {
		t.Fatalf("status journal = %+v", st.Journal)
	}
}

// JRN-002: a journal that cannot be written is the one refusal: the request
// reaches nobody and the harness is told why.
func TestJRN002AnUnwritableJournalRefusesWithAClearMessage(t *testing.T) {
	core, paths := enrolled(t)
	p := newProvider(t)
	_, front, _ := startJournalClient(t, paths, p, ServerOptions{JournalMaxBytes: 1})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Close()

	status, _, body := postJSON(t, front.URL+"/v1/messages", `{"messages":[]}`, modelHeaders(jrnRepoSession))
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "journal") || !strings.Contains(body, "innsegl client") {
		t.Fatalf("full journal: %d %q, want a 503 naming the journal", status, body)
	}
	if p.hits.Load() != 0 {
		t.Fatal("a request that could not be journaled reached the provider")
	}

	if os.Geteuid() == 0 {
		t.Skip("root writes through a read-only directory")
	}
	core2, paths2 := enrolled(t)
	_, front2, _ := startJournalClient(t, paths2, p, ServerOptions{})
	postJSON(t, front2.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core2.Close()
	if err := os.Chmod(paths2.Journal, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(paths2.Journal, 0o700); err != nil {
			t.Error(err)
		}
	})
	status, _, body = postJSON(t, front2.URL+"/v1/messages", `{"messages":[]}`, modelHeaders(jrnRepoSession))
	if status != http.StatusServiceUnavailable || !strings.Contains(body, "journal") {
		t.Fatalf("unwritable journal: %d %q", status, body)
	}
	if p.hits.Load() != 0 {
		t.Fatal("a request that could not be journaled reached the provider")
	}
}

// JRN-008: the core relays the request but says it did not record it: the
// client journals the reply it relayed. "true" and "none" journal nothing;
// a provider's 5xx relayed by the core is passed on, never re-sent; the
// core's own 5xx is an outage.
func TestJRN008WhatTheCoreDidNotRecordIsJournaled(t *testing.T) {
	core, paths := enrolled(t)
	p := newProvider(t)
	var answer atomic.Value
	answer.Store(clientjournal.RecordedFalse)
	var status5xx atomic.Int32
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		if code := int(status5xx.Load()); code != 0 {
			if v, ok := answer.Load().(string); ok && v != "" {
				w.Header().Set(clientjournal.RecordedHeader, v)
			}
			w.WriteHeader(code)
			fmt.Fprint(w, `{"error":"x"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if v, ok := answer.Load().(string); ok && v != "" {
			w.Header().Set(clientjournal.RecordedHeader, v)
		}
		fmt.Fprint(w, jrnSSE)
	})
	_, front, _ := startJournalClient(t, paths, p, ServerOptions{})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	key := installationKey(t, paths)

	if status, _, body := postJSON(t, front.URL+"/v1/messages", `{"messages":[]}`, modelHeaders(jrnRepoSession)); status != http.StatusOK || body != jrnSSE {
		t.Fatalf("not recorded: %d %q", status, body)
	}
	entries := readJournal(t, paths, &key.PublicKey)
	if len(entries) != 1 || entries[0].Reason != clientjournal.ReasonCoreNotRecorded || string(entries[0].ResponseBody) != jrnSSE {
		t.Fatalf("entries %+v, want one core-not-recorded entry with the relayed reply", entries)
	}
	if p.hits.Load() != 0 {
		t.Fatal("a relayed request was sent to the provider again")
	}

	for _, v := range []string{clientjournal.RecordedTrue, clientjournal.RecordedNone} {
		answer.Store(v)
		postJSON(t, front.URL+"/v1/messages", `{"messages":[]}`, modelHeaders(jrnRepoSession))
	}
	if n := len(readJournal(t, paths, &key.PublicKey)); n != 1 {
		t.Fatalf("%d entries after recorded and repository-less replies, want still 1", n)
	}

	// A provider 5xx relayed by the core carries the header: passed on.
	answer.Store(clientjournal.RecordedTrue)
	status5xx.Store(http.StatusInternalServerError)
	if status, _, _ := postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession)); status != http.StatusInternalServerError {
		t.Fatalf("relayed provider 5xx: %d, want it passed on", status)
	}
	if p.hits.Load() != 0 {
		t.Fatal("a relayed provider error was re-sent to the provider")
	}

	// The core's own 503 carries none: an outage.
	answer.Store("")
	status5xx.Store(http.StatusServiceUnavailable)
	if status, _, body := postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession)); status != http.StatusOK || body != jrnSSE {
		t.Fatalf("core 503: %d %q, want the provider's reply", status, body)
	}
	entries = readJournal(t, paths, &key.PublicKey)
	if len(entries) != 2 || entries[1].Reason != clientjournal.ReasonCoreUnreachable || entries[1].Prev == "" {
		t.Fatalf("entries %+v, want a second, chained, core-unreachable entry", entries)
	}
}

// importer is a fake core import endpoint: it verifies each entry under the
// presented certificate's key and answers what the test says.
type importer struct {
	mu       sync.Mutex
	received []clientjournal.Sealed
	answer   func(i int, e clientjournal.Entry) string
}

func (im *importer) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req clientjournal.ImportRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var resp clientjournal.ImportResponse
		im.mu.Lock()
		defer im.mu.Unlock()
		for _, s := range req.Entries {
			e, err := s.Open(r.TLS.PeerCertificates[0].PublicKey)
			if err != nil {
				t.Errorf("an entry does not verify under the client certificate's key: %v", err)
				return
			}
			status := im.answer(len(im.received), e)
			im.received = append(im.received, s)
			resp.Results = append(resp.Results, clientjournal.ImportResult{Hash: s.Hash(), Seq: e.Seq, Status: status, Reason: "because"})
			if !clientjournal.Acknowledged(status) {
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Error(err)
		}
	}
}

// JRN-009: the upload sends entries in order over the client certificate;
// an acknowledged entry is deleted, a rejected one is kept and named in the
// status, and the chain continues across deletions and restarts.
func TestJRN009UploadDeletesOnlyAcknowledgedEntries(t *testing.T) {
	core, paths := enrolled(t)
	p := newProvider(t)
	// Until the test says so, the core asks for every entry again later:
	// the upload before each live request then leaves them all held.
	var accepting atomic.Bool
	im := &importer{answer: func(_ int, e clientjournal.Entry) string {
		switch {
		case !accepting.Load():
			return clientjournal.ImportRetry
		case e.Seq == 2:
			return clientjournal.ImportRejected
		}
		return clientjournal.ImportRecorded
	}}
	core.Mux.HandleFunc(clientjournal.ImportPath, im.serve(t))
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set(clientjournal.RecordedHeader, clientjournal.RecordedFalse)
		fmt.Fprint(w, jrnSSE)
	})
	srv, front, _ := startJournalClient(t, paths, p, ServerOptions{})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	for range 3 {
		postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	}
	key := installationKey(t, paths)
	if n := len(readJournal(t, paths, &key.PublicKey)); n != 3 {
		t.Fatalf("%d entries, want 3", n)
	}

	accepting.Store(true)
	res, err := srv.UploadJournal(context.Background())
	if err != nil {
		t.Fatalf("UploadJournal: %v", err)
	}
	if res.Acknowledged != 1 || res.Rejected == nil {
		t.Fatalf("upload result %+v, want one acknowledged and a rejection", res)
	}
	left := readJournal(t, paths, &key.PublicKey)
	if len(left) != 2 || left[0].Seq != 2 {
		t.Fatalf("left %d entries starting at %d, want 2 starting at 2", len(left), left[0].Seq)
	}
	st := srv.Status(context.Background())
	if st.Journal.Depth != 2 || st.Journal.LastUpload == nil || !strings.Contains(st.Journal.LastUpload.Result, "rejected") {
		t.Fatalf("status %+v", st.Journal)
	}

	// The core accepts everything now; a restarted service continues the
	// chain where it stopped.
	im.mu.Lock()
	im.answer = func(int, clientjournal.Entry) string { return clientjournal.ImportRecorded }
	im.mu.Unlock()
	srv2, front2, _ := startJournalClient(t, paths, p, ServerOptions{})
	postJSON(t, front2.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	postJSON(t, front2.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	if _, uerr := srv2.UploadJournal(context.Background()); uerr != nil {
		t.Fatal(uerr)
	}
	if n := len(readJournal(t, paths, &key.PublicKey)); n != 0 {
		t.Fatalf("%d entries left after a clean upload", n)
	}
	im.mu.Lock()
	defer im.mu.Unlock()
	last, err := im.received[len(im.received)-1].Open(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if last.Seq != 4 || last.Prev != im.received[len(im.received)-2].Hash() {
		t.Fatalf("the restarted service wrote seq %d after %q", last.Seq, last.Prev)
	}
	if st := srv2.Status(context.Background()); st.Journal.Depth != 0 || st.Journal.LastUpload == nil || st.Journal.LastUpload.Result != "ok" {
		t.Fatalf("status after a clean upload %+v", st.Journal)
	}
}

// JRN-009: the upload loop runs on its own and backs off; it stops with its
// context.
func TestJRN009TheUploadLoopDrainsTheJournal(t *testing.T) {
	core, paths := enrolled(t)
	im := &importer{answer: func(int, clientjournal.Entry) string { return clientjournal.ImportRecorded }}
	core.Mux.HandleFunc(clientjournal.ImportPath, im.serve(t))
	core.Mux.HandleFunc(SessionStatementPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set(clientjournal.RecordedHeader, clientjournal.RecordedFalse)
		fmt.Fprint(w, jrnSSE)
	})
	srv, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{UploadInterval: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.RunJournalUpload(ctx); close(done) }()
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	deadline := time.Now().Add(10 * time.Second)
	for srv.Status(context.Background()).Journal.Depth != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the upload loop never drained the journal")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the upload loop did not stop with its context")
	}
}

var _ = clienttest.Token

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/clientjournal"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/rundir"
)

// ADR-0068, end to end: the real client service against the real hosted
// core. The core goes away; a session in a repository keeps working
// straight to the provider and is journaled; the core comes back and
// imports the journal: the run is registered under the installation with
// the stated repository, the tool call is recorded naming the signed entry,
// and the entry is stored on the core. A replayed upload is idempotent, a
// tampered entry is rejected. A request the core relays but cannot record
// is journaled too; a session outside any repository is neither.

// switchable is a TCP forwarder in front of the core that can be turned
// off: off, it refuses new connections and cuts open ones.
type switchable struct {
	ln     net.Listener
	target string
	up     atomic.Bool
	mu     sync.Mutex
	conns  map[net.Conn]bool
}

func newSwitchable(t *testing.T, target string) *switchable {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &switchable{ln: ln, target: target, conns: map[net.Conn]bool{}}
	s.up.Store(true)
	t.Cleanup(func() { _ = ln.Close(); s.cut() })
	go s.serve()
	return s
}

func (s *switchable) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.up.Load() {
			_ = c.Close()
			continue
		}
		go s.pipe(c)
	}
}

func (s *switchable) pipe(c net.Conn) {
	b, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", s.target)
	if err != nil {
		_ = c.Close()
		return
	}
	s.mu.Lock()
	s.conns[c], s.conns[b] = true, true
	s.mu.Unlock()
	// A copy ends when either side closes; its error says nothing more.
	go func() {
		if _, err := io.Copy(b, c); err != nil {
			_ = b.Close()
			return
		}
		_ = b.Close()
	}()
	if _, err := io.Copy(c, b); err != nil {
		_ = c.Close()
		return
	}
	_ = c.Close()
}

func (s *switchable) cut() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = map[net.Conn]bool{}
}

func (s *switchable) set(up bool) {
	s.up.Store(up)
	if !up {
		s.cut()
	}
}

func (s *switchable) addr() string { return s.ln.Addr().String() }

func jrnToolUseSSE(id string) string {
	return "event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"` + id + `","name":"Bash","input":{}}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}` + "\n\n" +
		"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"
}

const jrnTextSSE = "event: content_block_start\n" +
	`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"done"}}` + "\n\n" +
	"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
	"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

// sseServer answers each request with the next reply, as a stream.
func sseServer(t *testing.T, replies ...string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(hits.Add(1)) - 1
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if i < len(replies) {
			fmt.Fprint(w, replies[i])
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func jrnConversation(t *testing.T, withResult bool) string {
	t.Helper()
	msgs := []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "text", "text": "list the files"}}}}
	if withResult {
		msgs = append(msgs,
			map[string]any{"role": "assistant", "content": []any{map[string]any{
				"type": "tool_use", "id": "toolu_jrn1", "name": "Bash", "input": map[string]any{"command": "ls"}}}},
			map[string]any{"role": "user", "content": []any{map[string]any{
				"type": "tool_result", "tool_use_id": "toolu_jrn1", "content": "a.go b.go"}}})
	}
	b, err := json.Marshal(map[string]any{"messages": msgs})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func configureJRNObserve(t *testing.T, dsn string) (*ledger.Store, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	dir, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		t.Fatal(err)
	}
	bodyDir := t.TempDir()
	restore, err := mcp.ConfigureObserveToolCall(mcp.ObserveToolCallConfig{
		Runs: dir, Ledger: store, Idempotency: mcp.NewIdempotencyStore(gwIdentityPool(t, dsn)), BodyDir: bodyDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	t.Setenv(envObserveBodyDir, bodyDir)
	return store, bodyDir
}

func TestJRN010TheJournalIsImportedThroughTheHostedCore(t *testing.T) {
	f := newEnFixture(t)
	store, bodyDir := configureJRNObserve(t, f.ownerDSN)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, jrnTextSSE)
	})
	g := startHostedGatewayWith(t, f, upstream)
	front := newSwitchable(t, g.addr)

	caPEM, err := os.ReadFile(filepath.Join(g.certDir, gateway.CACertFileName))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	enrolment, err := client.Enrol(ctx, client.EnrolOptions{
		CoreURL: "https://" + front.addr(), Token: f.token(t), Name: "journal machine", CA: ca,
	})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	paths := client.ClientPaths(t.TempDir())
	if werr := client.WriteEnrolment(paths, enrolment, "127.0.0.1:0"); werr != nil {
		t.Fatal(werr)
	}
	provider, providerHits := sseServer(t, jrnToolUseSSE("toolu_jrn1"), jrnTextSSE, jrnTextSSE)
	srv, err := client.NewServerWith(paths, io.Discard, client.ServerOptions{
		ProviderURL: provider.URL, ProviderClient: provider.Client(), CoreDownFor: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(srv.Handler())
	t.Cleanup(local.Close)
	post := func(path, body string, header map[string]string) (int, http.Header, string) {
		t.Helper()
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, local.URL+path, strings.NewReader(body))
		if rerr != nil {
			t.Fatal(rerr)
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatal(derr)
		}
		defer func() { _ = resp.Body.Close() }()
		b, berr := io.ReadAll(resp.Body)
		if berr != nil {
			t.Fatal(berr)
		}
		return resp.StatusCode, resp.Header, string(b)
	}

	const session = "88888888-8888-4888-8888-888888888888"
	if status, _, body := post(gatewaySessionWorkspacePath, statement(t, session, enRepo), nil); status != http.StatusNoContent {
		t.Fatalf("statement: %d %s", status, body)
	}

	// The core goes away.
	front.set(false)
	for i, body := range []string{jrnConversation(t, false), jrnConversation(t, true)} {
		status, _, reply := post("/v1/messages", body, messageHeaders(session))
		if status != http.StatusOK || !strings.Contains(reply, "message_stop") {
			t.Fatalf("request %d with the core down: %d %q", i, status, reply)
		}
	}
	if providerHits.Load() != 2 || g.upstream.Load() != 0 {
		t.Fatalf("provider saw %d, the core's upstream %d; want 2 and 0", providerHits.Load(), g.upstream.Load())
	}
	if d := srv.Status(ctx).Outbox.Kinds[client.KindExchange]; d != 2 {
		t.Fatalf("journal depth %d, want 2", d)
	}
	held := readSealed(t, paths.Outbox)

	// The core comes back: the journal is imported.
	front.set(true)
	res, err := srv.Drain(ctx)
	if err != nil || res.Delivered != 2 || res.Rejected != nil || res.Retry != nil {
		t.Fatalf("upload: %+v %v", res, err)
	}
	if d := srv.Status(ctx).Outbox.Items; d != 0 {
		t.Fatalf("outbox holds %d after the import, want 0", d)
	}
	var runID, clientID string
	if qerr := gwIdentityPool(t, f.ownerDSN).QueryRow(ctx,
		`SELECT run_id, client_id FROM innsegl.gateway_run_mapping WHERE session_id = $1 AND agent_id = 'main' LIMIT 1`,
		session).Scan(&runID, &clientID); qerr != nil {
		t.Fatalf("no run registered for the journaled session: %v", qerr)
	}
	if clientID != enrolment.InstallationID {
		t.Fatalf("the run is attributed to %q, want the installation %q", clientID, enrolment.InstallationID)
	}
	events := waitForJRNEvents(t, store, runID, event.EventTypeToolCall)
	var registeredRepo string
	for _, e := range events {
		if e[event.FieldEventType] == event.EventTypeRunRegistered {
			if repo, ok := e[event.FieldRepo].(string); ok {
				registeredRepo = repo
			}
		}
	}
	if registeredRepo != enRepo {
		t.Fatalf("run registered for %q, want %q", registeredRepo, enRepo)
	}
	var call event.Fields
	for _, e := range events {
		if e[event.FieldEventType] == event.EventTypeToolCall {
			call = e
		}
	}
	digest, ok := call[event.FieldPayloadDigest].(string)
	if !ok {
		t.Fatalf("the tool call carries no digest: %+v", call)
	}
	body, err := os.ReadFile(filepath.Join(bodyDir, runID, strings.TrimPrefix(digest, event.HashPrefix)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"journal_entry":"`+held[0].Hash()+`"`) {
		t.Fatalf("the tool call body does not name the entry its call came from: %s", body)
	}
	stored := filepath.Join(bodyDir, clientJournalSubdir, enrolment.InstallationID, strings.TrimPrefix(held[1].Hash(), "sha256:")+".entry")
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("the signed entry is not stored on the core: %v", err)
	}

	// A replayed upload is idempotent; a tampered entry is rejected.
	direct := enrolledHTTPClient(t, paths, ca)
	if got := importDirect(t, direct, front.addr(), held); len(got) != 2 ||
		got[0].Status != clientjournal.ImportDuplicate || got[1].Status != clientjournal.ImportDuplicate {
		t.Fatalf("replayed upload: %+v", got)
	}
	forged := clientjournal.Sealed{Entry: bytes.Replace(held[1].Entry, []byte(`"seq":2`), []byte(`"seq":3`), 1), Signature: held[1].Signature}
	if got := importDirect(t, direct, front.addr(), []clientjournal.Sealed{forged}); len(got) != 1 || got[0].Status != clientjournal.ImportRejected {
		t.Fatalf("tampered entry: %+v", got)
	}

	// (b) The core relays a request in a repository it may not record: the
	// client journals what it relayed; the import stores it, not recorded.
	const outSession = "99999999-9999-4999-8999-999999999999"
	post(gatewaySessionWorkspacePath, statement(t, outSession, enOtherRepo), nil)
	status, header, _ := post("/v1/messages", enMessage, messageHeaders(outSession))
	if status != http.StatusOK || header.Get(clientjournal.RecordedHeader) != clientjournal.RecordedFalse {
		t.Fatalf("out-of-scope request: %d, %s %q", status, clientjournal.RecordedHeader, header.Get(clientjournal.RecordedHeader))
	}
	if d := srv.Status(ctx).Outbox.Kinds[client.KindExchange]; d != 1 {
		t.Fatalf("journal depth %d after an unrecorded relay, want 1", d)
	}
	if res, err := srv.Drain(ctx); err != nil || res.Delivered != 1 {
		t.Fatalf("upload of the unrecorded relay: %+v %v", res, err)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1`, outSession); n != 0 {
		t.Fatalf("an out-of-scope session got %d mapping rows from its import", n)
	}

	// A session outside any repository: neither recorded nor journaled.
	const homeSession = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	post(gatewaySessionWorkspacePath, `{"session_id":"`+homeSession+`","cwd":"/client/notes"}`, nil)
	status, header, _ = post("/v1/messages", enMessage, messageHeaders(homeSession))
	if status != http.StatusOK || header.Get(clientjournal.RecordedHeader) != clientjournal.RecordedNone {
		t.Fatalf("repository-less request: %d %q", status, header.Get(clientjournal.RecordedHeader))
	}
	front.set(false)
	if status, _, _ := post("/v1/messages", enMessage, messageHeaders(homeSession)); status != http.StatusOK {
		t.Fatalf("repository-less request with the core down: %d", status)
	}
	if d := srv.Status(ctx).Outbox.Kinds[client.KindExchange]; d != 0 {
		t.Fatalf("a repository-less session was journaled (depth %d)", d)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl.gateway_run_mapping WHERE session_id = $1`, homeSession); n != 0 {
		t.Fatalf("a repository-less session has %d mapping rows", n)
	}
}

func readSealed(t *testing.T, dir string) []clientjournal.Sealed {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*."+client.KindExchange))
	if err != nil {
		t.Fatal(err)
	}
	var out []clientjournal.Sealed
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var s clientjournal.Sealed
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func enrolledHTTPClient(t *testing.T, paths client.Paths, ca *x509.Certificate) *http.Client {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(paths.Cert, paths.Key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	}}}
}

func importDirect(t *testing.T, c *http.Client, addr string, entries []clientjournal.Sealed) []clientjournal.ImportResult {
	t.Helper()
	body, err := json.Marshal(clientjournal.ImportRequest{Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+clientjournal.ImportPath, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out clientjournal.ImportResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("import answer (%d): %v", resp.StatusCode, err)
	}
	return out.Results
}

func waitForJRNEvents(t *testing.T, store *ledger.Store, runID, want string) []event.Fields {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		recs, err := store.EventsForRun(ctx, runID)
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r[event.FieldEventType] == want {
				return recs
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s event on run %s: %+v", want, runID, recs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

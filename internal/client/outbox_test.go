// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// The outbox: what the core did not take -- a model exchange it could not
// record, a telemetry export, a session end -- kept in one folder, under one
// bound, and delivered oldest first by one loop when the core answers.

// arrivals records, in order, what reached the fake core's three delivery
// routes.
type arrivals struct {
	mu  sync.Mutex
	got []string
}

func (a *arrivals) add(s string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, s)
}

func (a *arrivals) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.got...)
}

// deliveryRoutes mounts the core's three routes, each answering what
// answer says for its kind (0 is the route's own success).
func deliveryRoutes(t *testing.T, mux *http.ServeMux, a *arrivals, answer func(kind string) int) {
	t.Helper()
	im := &importer{answer: func(int, clientjournal.Entry) string { return clientjournal.ImportRecorded }}
	imp := im.serve(t)
	mux.HandleFunc(clientjournal.ImportPath, func(w http.ResponseWriter, r *http.Request) {
		if code := answer(KindExchange); code != 0 {
			w.WriteHeader(code)
			return
		}
		a.add(KindExchange)
		imp(w, r)
	})
	mux.HandleFunc(TelemetryLogsPath, func(w http.ResponseWriter, r *http.Request) {
		b := readAll(t, r.Body)
		if code := answer(KindTelemetry); code != 0 {
			w.WriteHeader(code)
			return
		}
		a.add(KindTelemetry + ":" + string(b))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(SessionEndPath, func(w http.ResponseWriter, r *http.Request) {
		b := readAll(t, r.Body)
		if code := answer(KindEnd); code != 0 {
			w.WriteHeader(code)
			return
		}
		a.add(KindEnd + ":" + string(b))
		w.WriteHeader(http.StatusNoContent)
	})
}

func telemetryBody(n int) string { return `{"resourceLogs":[],"n":` + strconv.Itoa(n) + `}` }

// Items of every kind held while the core is down reach it in the order
// they were held, once it answers.
func TestOutboxDeliversEveryKindOldestFirst(t *testing.T) {
	core, paths := enrolled(t)
	got := &arrivals{}
	deliveryRoutes(t, core.Mux, got, func(string) int { return 0 })
	srv, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Stop()

	if status, _, _ := postJSON(t, front.URL+TelemetryLogsPath, telemetryBody(1), nil); status != http.StatusOK {
		t.Fatalf("telemetry while the core is down: %d, want 200 (held)", status)
	}
	if status, _, _ := postJSON(t, front.URL+"/v1/messages", `{"messages":[]}`, modelHeaders(jrnRepoSession)); status != http.StatusOK {
		t.Fatalf("model request while the core is down: %d", status)
	}
	if status, _, _ := postJSON(t, front.URL+SessionEndPath, `{"session_id":"`+jrnRepoSession+`"}`, nil); status != http.StatusAccepted {
		t.Fatalf("session end while the core is down: %d, want 202 (held)", status)
	}
	if status, _, _ := postJSON(t, front.URL+TelemetryLogsPath, telemetryBody(2), nil); status != http.StatusOK {
		t.Fatalf("telemetry while the core is down: %d", status)
	}
	st := srv.outbox.status()
	if st.Items != 4 || st.Kinds[KindExchange] != 1 || st.Kinds[KindTelemetry] != 2 || st.Kinds[KindEnd] != 1 {
		t.Fatalf("outbox %+v, want one exchange, two telemetry, one end", st)
	}

	core.Restart(t)
	res, err := srv.Drain(context.Background())
	if err != nil || res.Delivered != 4 {
		t.Fatalf("Drain = %+v, %v; want 4 delivered", res, err)
	}
	want := []string{
		KindTelemetry + ":" + telemetryBody(1),
		KindExchange,
		KindEnd + `:{"session_id":"` + jrnRepoSession + `"}`,
		KindTelemetry + ":" + telemetryBody(2),
	}
	if g := got.list(); strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the core received\n%s\nwant\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
	}
	if st := srv.outbox.status(); st.Items != 0 || st.Bytes != 0 {
		t.Fatalf("outbox after delivery %+v, want empty", st)
	}
}

// Delivery stops per kind: a kind stops at its own first item the core does
// not take now, and nothing of that kind after it is sent; the other kinds
// go on. An item the core says it will never take (a 4xx about the item
// itself) is dropped, counted, and does not hold up the rest. A core that
// does not answer at all stops every kind.
func TestOutboxStopsAtTheFirstItemTheCoreDoesNotTake(t *testing.T) {
	core, paths := enrolled(t)
	got := &arrivals{}
	var telemetryAnswers []int // what the next telemetry posts are answered, then 0
	var telemetryTries atomic.Int32
	var mu sync.Mutex
	setAnswers := func(a ...int) { mu.Lock(); telemetryAnswers = a; mu.Unlock() }
	setAnswers(http.StatusServiceUnavailable)
	deliveryRoutes(t, core.Mux, got, func(kind string) int {
		if kind != KindTelemetry {
			return 0
		}
		telemetryTries.Add(1)
		mu.Lock()
		defer mu.Unlock()
		if len(telemetryAnswers) == 0 {
			return 0
		}
		code := telemetryAnswers[0]
		if code != http.StatusServiceUnavailable {
			telemetryAnswers = telemetryAnswers[1:]
		}
		return code
	})
	srv, front, logs := startClient(t, paths)
	core.Stop()
	postJSON(t, front.URL+TelemetryLogsPath, telemetryBody(1), nil)
	postJSON(t, front.URL+SessionEndPath, `{"session_id":"s-1"}`, nil)
	postJSON(t, front.URL+TelemetryLogsPath, telemetryBody(2), nil)
	postJSON(t, front.URL+SessionEndPath, `{"session_id":"s-2"}`, nil)
	if n := srv.outbox.status().Items; n != 4 {
		t.Fatalf("held %d, want 4", n)
	}

	// The core does not answer: every kind stops, nothing is lost.
	res, err := srv.Drain(context.Background())
	var silent errNoAnswer
	if !errors.As(err, &silent) || res.Delivered != 0 || srv.outbox.status().Items != 4 {
		t.Fatalf("Drain with the core down = %+v, %v; want the no-answer error and all 4 kept", res, err)
	}

	core.Restart(t)
	res, err = srv.Drain(context.Background())
	if err == nil || res.Delivered != 2 {
		t.Fatalf("Drain = %+v, %v; want both ends delivered and the 503 as the error", res, err)
	}
	if n := telemetryTries.Load(); n != 1 {
		t.Fatalf("telemetry was tried %d times, want once: it stops at its first 503", n)
	}
	want := []string{KindEnd + `:{"session_id":"s-1"}`, KindEnd + `:{"session_id":"s-2"}`}
	if g := got.list(); strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the core received %v, want %v", g, want)
	}
	st := srv.outbox.status()
	if st.Items != 2 || st.Kinds[KindTelemetry] != 2 || st.LastDelivery == nil || !strings.Contains(st.LastDelivery.Result, "503") {
		t.Fatalf("outbox %+v; want both exports kept and the 503 named", st)
	}

	setAnswers(http.StatusBadRequest)
	res, err = srv.Drain(context.Background())
	if err != nil || res.Delivered != 1 {
		t.Fatalf("Drain = %+v, %v; want the export after the refused one delivered", res, err)
	}
	if g := got.list(); len(g) != 3 || g[2] != KindTelemetry+":"+telemetryBody(2) {
		t.Fatalf("the core received %v", g)
	}
	st = srv.outbox.status()
	if st.Items != 0 || st.Dropped[KindTelemetry] != 1 {
		t.Fatalf("outbox %+v; want empty with one telemetry export counted as dropped", st)
	}
	if !strings.Contains(logs.String(), "400") {
		t.Errorf("the dropped export is not in the log: %s", logs.String())
	}
}

// One bound covers every kind. Telemetry never causes the one refusal: when
// a model request needs room, held telemetry is dropped first, oldest
// first, and counted. A model request is refused only when what is left
// cannot be dropped.
func TestOutboxBoundDropsTelemetryBeforeRefusingAModelRequest(t *testing.T) {
	core, paths := enrolled(t)
	p := newProvider(t)
	srv, front, _ := startJournalClient(t, paths, p, ServerOptions{OutboxMaxBytes: 8192})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Close()

	export := `{"pad":"` + strings.Repeat("x", 1000) + `"}`
	held := 0
	for range 20 {
		status, _, _ := postJSON(t, front.URL+TelemetryLogsPath, export, nil)
		if status != http.StatusOK {
			if status != http.StatusServiceUnavailable {
				t.Fatalf("telemetry past the bound: %d, want 503", status)
			}
			break
		}
		held++
	}
	if held < 4 || held == 20 {
		t.Fatalf("held %d exports of 1 KiB under an 8 KiB bound", held)
	}
	if d := srv.outbox.status().Dropped[KindTelemetry]; d != 1 {
		t.Fatalf("dropped telemetry %d, want the one export not held", d)
	}

	big := `{"messages":[{"role":"user","content":"` + strings.Repeat("y", 1500) + `"}]}`
	if status, _, body := postJSON(t, front.URL+"/v1/messages", big, modelHeaders(jrnRepoSession)); status != http.StatusOK {
		t.Fatalf("a model request with telemetry filling the outbox: %d %s; telemetry must make room", status, body)
	}
	st := srv.outbox.status()
	if st.Kinds[KindExchange] != 1 || st.Dropped[KindTelemetry] < 2 {
		t.Fatalf("outbox %+v; want the exchange held and telemetry dropped for it", st)
	}
	if st.Bytes > st.MaxBytes {
		t.Fatalf("outbox holds %d bytes over its bound %d", st.Bytes, st.MaxBytes)
	}

	// More model requests take the rest of the telemetry's room; once none
	// is left to drop, the next is the one refusal.
	for i := range 10 {
		hits := p.hits.Load()
		status, _, body := postJSON(t, front.URL+"/v1/messages", big, modelHeaders(jrnRepoSession))
		if status == http.StatusOK {
			continue
		}
		if status != http.StatusServiceUnavailable || !strings.Contains(body, "outbox") || !strings.Contains(body, "innsegl client") {
			t.Fatalf("request %d: %d %q, want the one refusal", i, status, body)
		}
		if p.hits.Load() != hits {
			t.Fatal("a request that could not be held reached the provider")
		}
		if st := srv.outbox.status(); st.Kinds[KindTelemetry] != 0 {
			t.Fatalf("refused a model request while %d telemetry exports were held", st.Kinds[KindTelemetry])
		}
		return
	}
	t.Fatal("the outbox never refused, though only exchanges were left in it")
}

// writeOldLayout leaves what a client before the outbox left on disk: a
// journal of two chained entries, a telemetry spool of two exports, and a
// watch table with one live process and two kept ends. Each store's items
// get times that interleave, so the merged order is checkable.
func writeOldLayout(t *testing.T, paths Paths) (sealed []clientjournal.Sealed, live Process) {
	t.Helper()
	key := installationKey(t, paths)
	cfg, err := ReadCoreConfig(paths)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	at := func(i int) time.Time { return base.Add(time.Duration(i) * time.Minute) }
	setTime := func(p string, ts time.Time) {
		if cerr := os.Chtimes(p, ts, ts); cerr != nil {
			t.Fatal(cerr)
		}
	}

	journalDir := filepath.Join(paths.Dir, "journal")
	if merr := os.MkdirAll(journalDir, 0o700); merr != nil {
		t.Fatal(merr)
	}
	prev := ""
	for i, minute := range []int{1, 4} {
		s, serr := clientjournal.Seal(clientjournal.Entry{
			Seq: uint64(i + 1), Prev: prev, InstallationID: cfg.InstallationID, SessionID: jrnRepoSession,
			Reason: clientjournal.ReasonCoreUnreachable, Method: http.MethodPost, Path: "/v1/messages",
			RequestBody: []byte(`{}`), ResponseStatus: http.StatusOK, StartedAt: at(minute), EndedAt: at(minute),
		}, key)
		if serr != nil {
			t.Fatal(serr)
		}
		raw, merr := json.Marshal(s)
		if merr != nil {
			t.Fatal(merr)
		}
		p := filepath.Join(journalDir, fmt.Sprintf("%020d.entry", i+1))
		if werr := os.WriteFile(p, raw, 0o600); werr != nil {
			t.Fatal(werr)
		}
		setTime(p, at(minute))
		sealed, prev = append(sealed, s), s.Hash()
	}
	head, err := json.Marshal(map[string]any{"seq": 2, "hash": prev})
	if err != nil {
		t.Fatal(err)
	}
	if werr := os.WriteFile(filepath.Join(journalDir, "head.json"), head, 0o600); werr != nil {
		t.Fatal(werr)
	}

	spool := filepath.Join(paths.Dir, "telemetry-spool")
	if merr := os.MkdirAll(spool, 0o700); merr != nil {
		t.Fatal(merr)
	}
	for i, minute := range []int{2, 5} {
		p := filepath.Join(spool, strconv.FormatInt(at(minute).UnixNano(), 10)+".json")
		if werr := os.WriteFile(p, []byte(telemetryBody(i+1)), 0o600); werr != nil {
			t.Fatal(werr)
		}
		setTime(p, at(minute))
	}

	live, ok := ProcessOf(os.Getpid())
	if !ok {
		t.Fatal("ProcessOf(self)")
	}
	table, err := json.Marshal(map[string]Process{"s-live": live, "s-kept": {}, "s-kept/a1b2c3": {}})
	if err != nil {
		t.Fatal(err)
	}
	tablePath := filepath.Join(paths.Dir, "session-processes.json")
	if err := os.WriteFile(tablePath, table, 0o600); err != nil {
		t.Fatal(err)
	}
	setTime(tablePath, at(3))
	return sealed, live
}

// A client that finds the old layout -- the journal, the telemetry spool,
// the kept ends in the watch table -- moves it into the outbox once, keeping
// each store's order, the journal's chain, and the live watches, and losing
// nothing.
func TestOutboxMigratesTheOldLayoutOnce(t *testing.T) {
	core, paths := enrolled(t)
	sealed, live := writeOldLayout(t, paths)

	srv, _, _ := startClient(t, paths)
	st := srv.outbox.status()
	if st.Items != 6 || st.Kinds[KindExchange] != 2 || st.Kinds[KindTelemetry] != 2 || st.Kinds[KindEnd] != 2 {
		t.Fatalf("outbox after migration %+v, want 2 exchanges, 2 exports, 2 ends", st)
	}
	for _, old := range []string{filepath.Join(paths.Dir, "journal"), filepath.Join(paths.Dir, "telemetry-spool")} {
		if _, err := os.Stat(old); !os.IsNotExist(err) {
			t.Errorf("%s is still there after migration (%v)", old, err)
		}
	}
	if n := srv.watchedSessions(); n != 1 {
		t.Fatalf("watched sessions %d, want the one live process", n)
	}
	srv.watchMu.Lock()
	kept := srv.watched["s-live"]
	srv.watchMu.Unlock()
	if kept != live {
		t.Fatalf("the live watch became %+v, want %+v", kept, live)
	}

	// A second start migrates nothing again.
	again, _, _ := startClient(t, paths)
	if n := again.outbox.status().Items; n != 6 {
		t.Fatalf("outbox after a second start holds %d, want still 6", n)
	}

	got := &arrivals{}
	deliveryRoutes(t, core.Mux, got, func(string) int { return 0 })
	res, err := again.Drain(context.Background())
	if err != nil || res.Delivered != 6 {
		t.Fatalf("Drain = %+v, %v; want 6", res, err)
	}
	want := []string{
		KindExchange,
		KindTelemetry + ":" + telemetryBody(1),
		KindEnd + `:{"session_id":"s-kept"}`,
		KindEnd + `:{"agent_id":"a1b2c3","session_id":"s-kept"}`,
		KindExchange,
		KindTelemetry + ":" + telemetryBody(2),
	}
	g := got.list()
	// The two kept ends carry one time (the table's); their order between
	// themselves is the table's key order.
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("delivered\n%s\nwant\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
	}

	// The chain continues from the migrated head, though every entry of it
	// was delivered and deleted.
	_, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Close()
	postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	key := installationKey(t, paths)
	entries := readJournal(t, paths, &key.PublicKey)
	if len(entries) != 1 || entries[0].Seq != 3 || entries[0].Prev != sealed[1].Hash() {
		t.Fatalf("the next entry is %+v, want seq 3 after the migrated head", entries)
	}
}

// GET /_client/status reports the outbox: items by kind, bytes, the bound,
// the oldest item's age, and the newest delivery.
func TestOutboxStatusReportsKindsBytesAndOldest(t *testing.T) {
	core, paths := enrolled(t)
	_, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{OutboxMaxBytes: 1 << 20})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Stop()
	postJSON(t, front.URL+TelemetryLogsPath, telemetryBody(1), nil)
	postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	postJSON(t, front.URL+SessionEndPath, `{"session_id":"s-1"}`, nil)

	resp, err := http.Get(front.URL + StatusPath) //nolint:noctx // a test against a local server
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Outbox struct {
			Dir          string           `json:"dir"`
			Items        int              `json:"items"`
			Kinds        map[string]int   `json:"kinds"`
			Bytes        int64            `json:"bytes"`
			MaxBytes     int64            `json:"max_bytes"`
			OldestItemAt *time.Time       `json:"oldest_item_at"`
			Dropped      map[string]int64 `json:"dropped"`
		} `json:"outbox"`
		Journal json.RawMessage `json:"journal"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	o := body.Outbox
	if o.Dir != paths.Outbox || o.Items != 3 || o.Kinds[KindExchange] != 1 || o.Kinds[KindTelemetry] != 1 ||
		o.Kinds[KindEnd] != 1 || o.Bytes == 0 || o.MaxBytes != 1<<20 || o.OldestItemAt == nil {
		t.Fatalf("status outbox = %s", raw)
	}
	if time.Since(*o.OldestItemAt) > time.Minute {
		t.Fatalf("oldest item at %v", o.OldestItemAt)
	}
	if body.Journal != nil {
		t.Fatalf("the status still carries a separate journal field: %s", body.Journal)
	}
}

// An old journal whose every entry was imported holds only its head. The
// head moves too: the next entry continues the installation's chain, which
// the core checks, instead of starting it again at 1.
func TestOutboxMigrationKeepsTheChainOfAnEmptyOldJournal(t *testing.T) {
	core, paths := enrolled(t)
	journalDir := filepath.Join(paths.Dir, "journal")
	if err := os.MkdirAll(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const prev = "sha256:0000000000000000000000000000000000000000000000000000000000000007"
	if err := os.WriteFile(filepath.Join(journalDir, "head.json"), []byte(`{"seq":7,"hash":"`+prev+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{})
	if _, err := os.Stat(journalDir); !os.IsNotExist(err) {
		t.Fatalf("the old journal is still there (%v)", err)
	}
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Close()
	postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	key := installationKey(t, paths)
	entries := readJournal(t, paths, &key.PublicKey)
	if len(entries) != 1 || entries[0].Seq != 8 || entries[0].Prev != prev {
		t.Fatalf("the next entry is %+v, want seq 8 after the old head", entries)
	}
}

// A journal entry the core rejected waits to be inspected. The core
// answering live traffic wakes the delivery loop, but must not make it send
// the rejected entry again with every request: only its backoff does.
func TestOutboxKicksDoNotResendARejectedEntry(t *testing.T) {
	core, paths := enrolled(t)
	var imports atomic.Int32
	im := &importer{answer: func(int, clientjournal.Entry) string {
		imports.Add(1)
		return clientjournal.ImportRejected
	}}
	core.Mux.HandleFunc(clientjournal.ImportPath, im.serve(t))
	srv, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{UploadInterval: time.Hour})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Stop()
	postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	core.Restart(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.RunOutbox(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for imports.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the delivery loop never sent the entry")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for range 20 {
		srv.kickOutbox()
		time.Sleep(5 * time.Millisecond)
	}
	if n := imports.Load(); n != 1 {
		t.Fatalf("the rejected entry was sent %d times, want once until its backoff passes", n)
	}
}

// Delivery stops per kind. A journal entry the core rejects stops the
// journal until it is inspected (ADR-0068), but a session end or a
// telemetry export behind it goes on: an end held back leaves a run active
// until the silence backstop.
func TestOutboxARejectedExchangeDoesNotHoldBackEndsOrTelemetry(t *testing.T) {
	core, paths := enrolled(t)
	got := &arrivals{}
	im := &importer{answer: func(int, clientjournal.Entry) string { return clientjournal.ImportRejected }}
	imp := im.serve(t)
	core.Mux.HandleFunc(clientjournal.ImportPath, func(w http.ResponseWriter, r *http.Request) {
		got.add(KindExchange)
		imp(w, r)
	})
	core.Mux.HandleFunc(TelemetryLogsPath, func(w http.ResponseWriter, r *http.Request) {
		got.add(KindTelemetry + ":" + string(readAll(t, r.Body)))
		w.WriteHeader(http.StatusOK)
	})
	core.Mux.HandleFunc(SessionEndPath, func(w http.ResponseWriter, r *http.Request) {
		got.add(KindEnd + ":" + string(readAll(t, r.Body)))
		w.WriteHeader(http.StatusNoContent)
	})
	srv, front, _ := startJournalClient(t, paths, newProvider(t), ServerOptions{})
	postJSON(t, front.URL+SessionStatementPath, repoStatement(jrnRepoSession), nil)
	core.Stop()
	postJSON(t, front.URL+"/v1/messages", `{}`, modelHeaders(jrnRepoSession))
	postJSON(t, front.URL+SessionEndPath, `{"session_id":"`+jrnRepoSession+`"}`, nil)
	postJSON(t, front.URL+TelemetryLogsPath, telemetryBody(1), nil)
	if st := srv.outbox.status(); st.Items != 3 {
		t.Fatalf("held %+v, want an exchange, an end and an export", st)
	}

	core.Restart(t)
	res, err := srv.Drain(context.Background())
	if err != nil || res.Rejected == nil || res.Delivered != 2 {
		t.Fatalf("Drain = %+v, %v; want the rejection and the end and export delivered", res, err)
	}
	want := []string{KindExchange, KindEnd + `:{"session_id":"` + jrnRepoSession + `"}`, KindTelemetry + ":" + telemetryBody(1)}
	if g := got.list(); strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the core received\n%s\nwant\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
	}
	if st := srv.outbox.status(); st.Items != 1 || st.Kinds[KindExchange] != 1 {
		t.Fatalf("outbox %+v, want only the rejected exchange kept", st)
	}
}

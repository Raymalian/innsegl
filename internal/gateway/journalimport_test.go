// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// ADR-0068: the core imports a client's journal behind the
// client-certificate guard. Each entry is verified (signature by the
// installation's own key, the chain, the installation it names), replayed
// through the live pipeline, stored as the recorded body, and acknowledged.

type fakeReplayer struct {
	mu      sync.Mutex
	seen    []*http.Request
	replies [][]byte
	outcome func(r *http.Request) ReplayOutcome
}

func (f *fakeReplayer) Replay(r *http.Request, _ string, reply []byte) ReplayOutcome {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r)
	f.replies = append(f.replies, reply)
	if f.outcome != nil {
		return f.outcome(r)
	}
	return ReplayOutcome{RunID: "run-1"}
}

type journalChain struct {
	key  *ecdsa.PrivateKey
	inst string
	seq  uint64
	prev string
}

func newJournalChain(t *testing.T, inst string) *journalChain {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &journalChain{key: k, inst: inst}
}

const jrnSession = "33333333-3333-4333-8333-333333333333"

func (c *journalChain) next(t *testing.T, edit func(*clientjournal.Entry)) clientjournal.Sealed {
	t.Helper()
	c.seq++
	e := clientjournal.Entry{
		Seq: c.seq, Prev: c.prev, InstallationID: c.inst, SessionID: jrnSession,
		Reason:    clientjournal.ReasonCoreUnreachable,
		Statement: json.RawMessage(`{"session_id":"` + jrnSession + `","cwd":"/w/app","repo":"github.com/acme/app","branch":"main","task":"t1"}`),
		Method:    http.MethodPost, Path: "/v1/messages", Query: "beta=true",
		RequestHeaders: http.Header{"X-Claude-Code-Session-Id": {jrnSession}, "Content-Type": {"application/json"}},
		RequestBody:    []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		ResponseStatus: http.StatusOK, ResponseHeaders: http.Header{"Content-Type": {"text/event-stream"}},
		ResponseBody: []byte(journalSSE), ResponseComplete: true,
		StartedAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), EndedAt: time.Date(2026, 10, 2, 9, 0, 1, 0, time.UTC),
	}
	if edit != nil {
		edit(&e)
	}
	s, err := clientjournal.Seal(e, c.key)
	if err != nil {
		t.Fatal(err)
	}
	c.prev = s.Hash()
	return s
}

func newImporter(t *testing.T, rp Replayer) (*JournalImporter, string) {
	t.Helper()
	dir := t.TempDir()
	im, err := NewJournalImporter(JournalImporterConfig{Store: NewFileJournalStore(dir), Replayer: rp})
	if err != nil {
		t.Fatal(err)
	}
	return im, dir
}

func statuses(results []clientjournal.ImportResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.Status)
	}
	return out
}

// JRN-005: a valid chain is replayed in order, with the statement, the
// installation and the entry on the request, stored, and acknowledged; the
// same upload again is idempotent.
func TestJRN005AValidChainIsImportedOnceAndStored(t *testing.T) {
	rp := &fakeReplayer{}
	im, dir := newImporter(t, rp)
	c := newJournalChain(t, cgInstA)
	batch := []clientjournal.Sealed{c.next(t, nil), c.next(t, nil)}

	got := im.Import(context.Background(), cgInstA, &c.key.PublicKey, batch)
	if s := statuses(got); len(s) != 2 || s[0] != clientjournal.ImportRecorded || s[1] != clientjournal.ImportRecorded {
		t.Fatalf("statuses %v, want two recorded: %+v", s, got)
	}
	if got[0].Hash != batch[0].Hash() || got[1].Seq != 2 {
		t.Fatalf("results do not name the entries: %+v", got)
	}
	if len(rp.seen) != 2 {
		t.Fatalf("%d replays, want 2", len(rp.seen))
	}
	r := rp.seen[0]
	if r.URL.Path != "/v1/messages" || r.URL.RawQuery != "beta=true" || r.Header.Get("X-Claude-Code-Session-Id") != jrnSession {
		t.Fatalf("replayed request %s %s %v", r.URL.Path, r.URL.RawQuery, r.Header)
	}
	if inst, _ := InstallationFromContext(r.Context()); inst != cgInstA {
		t.Fatalf("replay installation %q", inst)
	}
	if entry, _ := JournalEntryFromContext(r.Context()); entry != batch[0].Hash() {
		t.Fatalf("replay entry %q, want %q", entry, batch[0].Hash())
	}
	stmt, err := base64.RawURLEncoding.DecodeString(r.Header.Get(StatementHeader))
	if err != nil || !strings.Contains(string(stmt), `"repo":"github.com/acme/app"`) {
		t.Fatalf("replay statement %q (%v)", stmt, err)
	}
	if string(rp.replies[0]) != journalSSE {
		t.Fatal("the replayed reply is not the journaled one")
	}
	stored, err := os.ReadFile(filepath.Join(dir, cgInstA, strings.TrimPrefix(batch[1].Hash(), "sha256:")+".entry"))
	if err != nil {
		t.Fatalf("the signed entry is not stored on the core: %v", err)
	}
	var back clientjournal.Sealed
	if err := json.Unmarshal(stored, &back); err != nil || !bytes.Equal(back.Entry, batch[1].Entry) || !bytes.Equal(back.Signature, batch[1].Signature) {
		t.Fatalf("stored entry differs (%v)", err)
	}

	again := im.Import(context.Background(), cgInstA, &c.key.PublicKey, batch)
	if s := statuses(again); len(s) != 2 || s[0] != clientjournal.ImportDuplicate || s[1] != clientjournal.ImportDuplicate {
		t.Fatalf("replayed upload: %v, want two duplicates", s)
	}
	if len(rp.seen) != 2 {
		t.Fatalf("a duplicate was replayed again (%d replays)", len(rp.seen))
	}

	// The chain continues from where it stopped.
	third := c.next(t, nil)
	if s := statuses(im.Import(context.Background(), cgInstA, &c.key.PublicKey, []clientjournal.Sealed{third})); s[0] != clientjournal.ImportRecorded {
		t.Fatalf("the next entry: %v", s)
	}
}

// JRN-006: a tampered entry is rejected, and nothing after it is processed;
// an entry signed by another key, or naming another installation, or out of
// order, is rejected; nothing rejected is stored.
func TestJRN006TamperedForeignAndOutOfOrderEntriesAreRejected(t *testing.T) {
	for name, tc := range map[string]func(t *testing.T, c *journalChain) []clientjournal.Sealed{
		"tampered": func(t *testing.T, c *journalChain) []clientjournal.Sealed {
			first := c.next(t, nil)
			first.Entry = bytes.Replace(first.Entry, []byte(`"/v1/messages"`), []byte(`"/v1/messagez"`), 1)
			return []clientjournal.Sealed{first, c.next(t, nil)}
		},
		"another installation's key": func(t *testing.T, _ *journalChain) []clientjournal.Sealed {
			return []clientjournal.Sealed{newJournalChain(t, cgInstA).next(t, nil)}
		},
		"names another installation": func(t *testing.T, c *journalChain) []clientjournal.Sealed {
			return []clientjournal.Sealed{c.next(t, func(e *clientjournal.Entry) { e.InstallationID = cgInstB })}
		},
		"out of order": func(t *testing.T, c *journalChain) []clientjournal.Sealed {
			c.next(t, nil)
			return []clientjournal.Sealed{c.next(t, nil)}
		},
		"broken link": func(t *testing.T, c *journalChain) []clientjournal.Sealed {
			return []clientjournal.Sealed{c.next(t, func(e *clientjournal.Entry) { e.Prev = "sha256:" + strings.Repeat("0", 64) })}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rp := &fakeReplayer{}
			im, dir := newImporter(t, rp)
			c := newJournalChain(t, cgInstA)
			batch := tc(t, c)
			got := im.Import(context.Background(), cgInstA, &c.key.PublicKey, batch)
			if len(got) != 1 || got[0].Status != clientjournal.ImportRejected || got[0].Reason == "" {
				t.Fatalf("results %+v, want one rejection with a reason and nothing after it", got)
			}
			if len(rp.seen) != 0 {
				t.Fatal("a rejected entry was replayed")
			}
			entries, rerr := os.ReadDir(filepath.Join(dir, cgInstA))
			if rerr != nil && !os.IsNotExist(rerr) {
				t.Fatal(rerr)
			}
			if len(entries) != 0 {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				if strings.Contains(strings.Join(names, " "), ".entry") {
					t.Fatalf("a rejected entry was stored: %v", names)
				}
			}
		})
	}
}

// JRN-007: a dependency outage during the replay is "retry": nothing stored,
// the chain not advanced, so the same entry imports later. A refusal that is
// not an outage, or a repository the installation may not record, is
// "stored": the entry is kept on the core as evidence, with the reason.
func TestJRN007OutagesRetryAndRefusalsAreStoredWithTheirReason(t *testing.T) {
	outage := true
	rp := &fakeReplayer{outcome: func(*http.Request) ReplayOutcome {
		if outage {
			return ReplayOutcome{Refusal: &Refusal{Status: http.StatusServiceUnavailable, Reason: "ledger down"}}
		}
		return ReplayOutcome{UnrecordedRepo: "github.com/rival/held"}
	}}
	im, dir := newImporter(t, rp)
	c := newJournalChain(t, cgInstA)
	first, second := c.next(t, nil), c.next(t, nil)

	got := im.Import(context.Background(), cgInstA, &c.key.PublicKey, []clientjournal.Sealed{first, second})
	if len(got) != 1 || got[0].Status != clientjournal.ImportRetry {
		t.Fatalf("outage: %+v, want one retry and nothing after it", got)
	}
	if _, err := os.Stat(filepath.Join(dir, cgInstA, strings.TrimPrefix(first.Hash(), "sha256:")+".entry")); err == nil {
		t.Fatal("an entry was stored though its replay must be retried")
	}

	outage = false
	got = im.Import(context.Background(), cgInstA, &c.key.PublicKey, []clientjournal.Sealed{first})
	if len(got) != 1 || got[0].Status != clientjournal.ImportStored || !strings.Contains(got[0].Reason, "github.com/rival/held") {
		t.Fatalf("out of scope: %+v, want stored naming the repository", got)
	}

	rp.outcome = func(*http.Request) ReplayOutcome {
		return ReplayOutcome{Refusal: &Refusal{Status: http.StatusForbidden, Reason: "policy refused"}}
	}
	got = im.Import(context.Background(), cgInstA, &c.key.PublicKey, []clientjournal.Sealed{second})
	if len(got) != 1 || got[0].Status != clientjournal.ImportStored || !strings.Contains(got[0].Reason, "policy refused") {
		t.Fatalf("a refusal: %+v, want stored with the reason", got)
	}
}

func peerCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	// The guard has already verified the chain; the endpoint reads only the
	// leaf's key, so a self-signed leaf is enough here.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// JRN-005: the endpoint takes the installation from the guard and the key
// from the presented certificate; it refuses a request with neither.
func TestJRN005TheImportEndpoint(t *testing.T) {
	rp := &fakeReplayer{}
	im, _ := newImporter(t, rp)
	h := JournalImportHandler(im)
	c := newJournalChain(t, cgInstA)
	body, err := json.Marshal(clientjournal.ImportRequest{Entries: []clientjournal.Sealed{c.next(t, nil)}})
	if err != nil {
		t.Fatal(err)
	}

	post := func(ctx context.Context, withCert bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(ctx, http.MethodPost, clientjournal.ImportPath, bytes.NewReader(body))
		if withCert {
			r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert(t, c.key)}}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	if rec := post(context.Background(), true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no installation: %d", rec.Code)
	}
	if rec := post(WithInstallation(context.Background(), cgInstA), false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no certificate: %d", rec.Code)
	}
	rec := post(WithInstallation(context.Background(), cgInstA), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var resp clientjournal.ImportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Results) != 1 || resp.Results[0].Status != clientjournal.ImportRecorded {
		t.Fatalf("results %+v", resp.Results)
	}

	get := httptest.NewRequestWithContext(WithInstallation(context.Background(), cgInstA), http.MethodGet, clientjournal.ImportPath, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
}

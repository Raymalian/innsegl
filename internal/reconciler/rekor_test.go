// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/reconciler"
)

// The Rekor reader, against an HTTP server this test controls.
//
// A REAL Rekor holding a REAL gitsign signature is what proves REC-002 —
// integration_test.go does that, because IP §2 says a mocked log proves nothing.
// What a real log cannot conveniently produce is a malformed entry, a body that
// is not a hashedrekord, a certificate that will not parse, or an index that
// answers with an artifact hash other than the one asked for. Those are the
// paths a repair must refuse, and they are here.

// certFor mints a certificate carrying spiffeID as its URI SAN — the shape
// Fulcio issues and the only member of it this reader reads.
func certFor(t *testing.T, spiffeID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "innsegl test leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if spiffeID != "" {
		uri, perr := url.Parse(spiffeID)
		if perr != nil {
			t.Fatal(perr)
		}
		template.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func artifactHash(commitSHA string) string {
	digest := sha256.Sum256([]byte(commitSHA))
	return hex.EncodeToString(digest[:])
}

// hashedRekord is one entry body in the shape Rekor stores it.
func hashedRekord(t *testing.T, kind, algorithm, value string, certPEM []byte) string {
	t.Helper()
	body := map[string]any{
		"apiVersion": "0.0.1",
		"kind":       kind,
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{"algorithm": algorithm, "value": value},
			},
			"signature": map[string]any{
				"content": "c2lnbmF0dXJl",
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(certPEM),
				},
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// logServer is a Rekor v1 REST surface holding the entries a case plants.
type logServer struct {
	// byHash maps an artifact hash to the uuids the index answers with.
	byHash map[string][]string
	// entries maps a uuid to the JSON the entry endpoint returns.
	entries map[string]string
	// indexStatus and entryStatus override the success status when non-zero.
	indexStatus int
	entryStatus int
	indexBody   string
}

func (l *logServer) start(t *testing.T) *reconciler.RekorLog {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/index/retrieve", func(w http.ResponseWriter, r *http.Request) {
		if l.indexStatus != 0 {
			w.WriteHeader(l.indexStatus)
			ignore(w.Write([]byte("index refused")))
			return
		}
		if l.indexBody != "" {
			ignore(w.Write([]byte(l.indexBody)))
			return
		}
		var query struct {
			Hash string `json:"hash"`
		}
		ignore(json.NewDecoder(r.Body).Decode(&query))
		ignore(json.NewEncoder(w).Encode(l.byHash[strings.TrimPrefix(query.Hash, "sha256:")]))
	})
	mux.HandleFunc("/api/v1/log/entries/", func(w http.ResponseWriter, r *http.Request) {
		if l.entryStatus != 0 {
			w.WriteHeader(l.entryStatus)
			ignore(w.Write([]byte("entry refused")))
			return
		}
		uuid := strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/")
		raw, found := l.entries[uuid]
		if !found {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ignore(w.Write([]byte(raw)))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	log, err := reconciler.NewRekorLog(srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRekorLog: %v", err)
	}
	return log
}

// plant puts one entry in the log under uuid, indexed by the artifact hash of
// commitSHA.
func (l *logServer) plant(t *testing.T, uuid, commitSHA, body string, logIndex int64) {
	t.Helper()
	if l.byHash == nil {
		l.byHash = map[string][]string{}
		l.entries = map[string]string{}
	}
	hash := artifactHash(commitSHA)
	l.byHash[hash] = append(l.byHash[hash], uuid)
	raw, err := json.Marshal(map[string]any{uuid: map[string]any{
		"body":           body,
		"logIndex":       logIndex,
		"logID":          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		"integratedTime": time.Date(2026, 8, 30, 9, 15, 0, 0, time.UTC).Unix(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	l.entries[uuid] = string(raw)
}

// ignore discards a writer's or encoder's result. A test HTTP handler has no
// caller to report to and no decision that depends on the outcome.
func ignore(...any) {}

const testCertIdentity = "spiffe://innsegl.dev/agent/demo/rm-035/run-rekor"

func TestTheLogReaderReturnsTheEntryAndTheIdentityItWasSignedUnder(t *testing.T) {
	const uuid = "a8f225deef100e2a3cfd330abe728a747cdb5363e3d69433eda3930091c69909"
	l := &logServer{}
	l.plant(t, uuid, testCommit,
		hashedRekord(t, "hashedrekord", "sha256", artifactHash(testCommit),
			certFor(t, testCertIdentity)), 148203377)

	entry, err := l.start(t).EntryForCommit(context.Background(), testCommit)
	if err != nil {
		t.Fatalf("EntryForCommit: %v", err)
	}
	if entry.UUID != uuid {
		t.Errorf("uuid %q, want %q", entry.UUID, uuid)
	}
	if entry.LogIndex != 148203377 {
		t.Errorf("log index %d, want 148203377", entry.LogIndex)
	}
	if entry.CertificateIdentity != testCertIdentity {
		t.Errorf("certificate identity %q, want %q", entry.CertificateIdentity, testCertIdentity)
	}
	if entry.IntegratedAt.IsZero() {
		t.Error("the entry carries no integration time")
	}
}

func TestTheLogReaderReportsAnAbsenceAsAnAbsence(t *testing.T) {
	l := &logServer{byHash: map[string][]string{}, entries: map[string]string{}}
	_, err := l.start(t).EntryForCommit(context.Background(), testCommit)
	if !errors.Is(err, reconciler.ErrNoEntry) {
		t.Fatalf("error %v, want ErrNoEntry — an empty index is the log answering, "+
			"and only an answer may justify an expiry", err)
	}
}

// Every one of these is a way an entry can exist and not be this commit's
// signature. Each must be an absence rather than a match, because a match is
// a `commit_recorded` in an append-only chain.
func TestTheLogReaderRefusesAnEntryThatIsNotThisCommitsSignature(t *testing.T) {
	const uuid = "b8f225deef100e2a3cfd330abe728a747cdb5363e3d69433eda3930091c69909"
	cases := map[string]string{
		"another artifact hash": hashedRekord(t, "hashedrekord", "sha256",
			artifactHash("0000000000000000000000000000000000000000"), certFor(t, testCertIdentity)),
		"another entry kind": hashedRekord(t, "intoto", "sha256",
			artifactHash(testCommit), certFor(t, testCertIdentity)),
		"another hash algorithm": hashedRekord(t, "hashedrekord", "sha512",
			artifactHash(testCommit), certFor(t, testCertIdentity)),
		"a public key that is not a certificate": hashedRekord(t, "hashedrekord", "sha256",
			artifactHash(testCommit), []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")),
		"a certificate with no URI SAN": hashedRekord(t, "hashedrekord", "sha256",
			artifactHash(testCommit), certFor(t, "")),
		"a body that is not base64":   "not base64 at all !!!",
		"a body that is not a rekord": base64.StdEncoding.EncodeToString([]byte("{{{")),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			l := &logServer{}
			l.plant(t, uuid, testCommit, body, 7)
			_, err := l.start(t).EntryForCommit(context.Background(), testCommit)
			if !errors.Is(err, reconciler.ErrNoEntry) {
				t.Fatalf("error %v, want ErrNoEntry", err)
			}
		})
	}
}

func TestALogThatCannotBeAskedIsNotAnAbsence(t *testing.T) {
	for name, l := range map[string]*logServer{
		"the index refuses":          {indexStatus: http.StatusInternalServerError},
		"the index is not JSON":      {indexBody: "<html>"},
		"the entry endpoint refuses": {entryStatus: http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			if l.byHash == nil {
				l.byHash = map[string][]string{artifactHash(testCommit): {"deadbeef"}}
				l.entries = map[string]string{}
			}
			_, err := l.start(t).EntryForCommit(context.Background(), testCommit)
			if err == nil {
				t.Fatal("a log that could not answer produced no error")
			}
			if errors.Is(err, reconciler.ErrNoEntry) {
				t.Fatalf("a log that could not answer was reported as an absence: %v; "+
					"that is how an outage becomes a permanent commit_intent_expired", err)
			}
		})
	}
}

func TestTheLogReaderRefusesAnEntryKeyedUnderAnotherUUID(t *testing.T) {
	l := &logServer{byHash: map[string][]string{}, entries: map[string]string{}}
	hash := artifactHash(testCommit)
	l.byHash[hash] = []string{"aaaa"}
	l.entries["aaaa"] = `{"bbbb":{"body":"","logIndex":1}}`
	_, err := l.start(t).EntryForCommit(context.Background(), testCommit)
	if !errors.Is(err, reconciler.ErrNoEntry) {
		t.Fatalf("error %v, want ErrNoEntry", err)
	}
}

func TestNewRekorLogRefusesWhatItCannotUse(t *testing.T) {
	if _, err := reconciler.NewRekorLog("", nil); err == nil {
		t.Fatal("an empty base URL was accepted")
	}
	if _, err := reconciler.NewRekorLog("://not a url", nil); err == nil {
		t.Fatal("a malformed base URL was accepted")
	}
	if _, err := reconciler.NewRekorLog("ftp://rekor.example", nil); err == nil {
		t.Fatal("a non-HTTP base URL was accepted")
	}
}

func TestTheLogReaderRefusesAnArgumentThatIsNotACommitID(t *testing.T) {
	l := &logServer{byHash: map[string][]string{}, entries: map[string]string{}}
	if _, err := l.start(t).EntryForCommit(context.Background(), "nope"); err == nil {
		t.Fatal("a value that is not a git object id was accepted")
	}
}

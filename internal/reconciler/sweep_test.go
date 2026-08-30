// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/reconciler"
)

// The LOG-SIDE reader (RM-036, #44), against an HTTP server this test controls.
//
// The real rekor-server is what REC-003 and REC-004 are proved against
// (driftintegration_test.go), because IP §2 says a mocked log proves nothing.
// What a real log will not produce on demand is the set of answers this reader
// must not misread: an entry that is a segment anchor rather than a signature,
// a body that is not a hashedrekord, a certificate that will not parse, a
// retrieve response that answers with somebody else's uuid, and a log that is
// simply down. Every one of those is the difference between "the log says no"
// and "the log did not say", and getting it wrong writes a permanent alert
// against an innocent record.

// sweepServer is a Rekor v1 retrieve surface holding entries by index.
type sweepServer struct {
	// bodies maps a uuid to its base64 entry body; indexes maps a log index to
	// the uuid at it.
	bodies  map[string]string
	indexes map[int64]string

	// Overrides. Non-zero status replaces the success answer; a non-empty body
	// replaces the JSON.
	logInfoStatus   int
	logInfoBody     string
	retrieveStatus  int
	retrieveBody    string
	retrieveCalls   int
	treeSizeOveride *int64
}

func (s *sweepServer) plant(uuid string, index int64, body string) {
	if s.bodies == nil {
		s.bodies = map[string]string{}
		s.indexes = map[int64]string{}
	}
	s.bodies[uuid] = body
	s.indexes[index] = uuid
}

func (s *sweepServer) entryJSON(uuid string, index int64) map[string]any {
	return map[string]any{
		uuid: map[string]any{
			"body":           s.bodies[uuid],
			"logIndex":       index,
			"integratedTime": 1788102594,
		},
	}
}

func (s *sweepServer) start(t *testing.T) *reconciler.RekorLog {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/log", func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case s.logInfoStatus != 0:
			w.WriteHeader(s.logInfoStatus)
			ignore(w.Write([]byte("log info refused")))
		case s.logInfoBody != "":
			ignore(w.Write([]byte(s.logInfoBody)))
		default:
			size := int64(len(s.indexes))
			if s.treeSizeOveride != nil {
				size = *s.treeSizeOveride
			}
			ignore(fmt.Fprintf(w, `{"treeSize":%d,"treeID":"1"}`, size))
		}
	})
	mux.HandleFunc("/api/v1/log/entries/retrieve", func(w http.ResponseWriter, r *http.Request) {
		s.retrieveCalls++
		if s.retrieveStatus != 0 {
			w.WriteHeader(s.retrieveStatus)
			ignore(w.Write([]byte("retrieve refused")))
			return
		}
		if s.retrieveBody != "" {
			ignore(w.Write([]byte(s.retrieveBody)))
			return
		}
		var query struct {
			LogIndexes []int64  `json:"logIndexes"`
			EntryUUIDs []string `json:"entryUUIDs"`
		}
		ignore(json.NewDecoder(r.Body).Decode(&query))
		if len(query.LogIndexes) > 10 || len(query.EntryUUIDs) > 10 {
			// rekor-server's own bound, measured: HTTP 422 past ten.
			w.WriteHeader(http.StatusUnprocessableEntity)
			ignore(w.Write([]byte(`{"code":611,"message":"at most 10 items"}`)))
			return
		}
		out := []map[string]any{}
		for _, index := range query.LogIndexes {
			if uuid, held := s.indexes[index]; held {
				out = append(out, s.entryJSON(uuid, index))
			}
		}
		for _, uuid := range query.EntryUUIDs {
			for index, held := range s.indexes {
				if held == uuid {
					out = append(out, s.entryJSON(uuid, index))
				}
			}
		}
		ignore(json.NewEncoder(w).Encode(out))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	log, err := reconciler.NewRekorLog(srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRekorLog: %v", err)
	}
	return log
}

// anchorBody is ADR-0009's entry: a hashedrekord signed by a RAW P-256 key,
// with no certificate at all. Every sealed segment puts one of these in the
// same log the sweep reads, so "attributes nothing" has to be a real answer
// and not a parse failure — otherwise every anchor this deployment writes is
// an unattributed-signature alert.
func anchorBody(t *testing.T, artifact string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return hashedRekord(t, "hashedrekord", "sha256", artifact, keyPEM)
}

// ---------------------------------------------------------------------------
// TreeSize.
// ---------------------------------------------------------------------------

func TestSweepTreeSizeReadsTheLogsOwnCount(t *testing.T) {
	s := &sweepServer{}
	s.plant("aa", 0, hashedRekord(t, "hashedrekord", "sha256",
		artifactHash(testCommit), certFor(t, spiffeIDFor("run-a"))))
	s.plant("bb", 1, hashedRekord(t, "hashedrekord", "sha256",
		artifactHash(driftCommit), certFor(t, spiffeIDFor("run-b"))))

	got, err := s.start(t).TreeSize(context.Background())
	if err != nil {
		t.Fatalf("TreeSize: %v", err)
	}
	if got != 2 {
		t.Fatalf("TreeSize = %d, want 2", got)
	}
}

func TestSweepTreeSizeRefusesAnUnreadableAnswer(t *testing.T) {
	for name, s := range map[string]*sweepServer{
		"not json":     {logInfoBody: "{ this is not json"},
		"http failure": {logInfoStatus: http.StatusServiceUnavailable},
		"negative":     {treeSizeOveride: ptr(int64(-1))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.start(t).TreeSize(context.Background()); err == nil {
				t.Fatal("an unreadable log info answer was accepted as a tree size")
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// ---------------------------------------------------------------------------
// EntriesFrom.
// ---------------------------------------------------------------------------

func TestSweepEntriesFromBatchesPastRekorsTenItemBound(t *testing.T) {
	s := &sweepServer{}
	const planted = 25
	for i := range int64(planted) {
		s.plant(fmt.Sprintf("%064x", i), i, hashedRekord(t, "hashedrekord", "sha256",
			artifactHash(testCommit), certFor(t, spiffeIDFor("run-a"))))
	}

	got, err := s.start(t).EntriesFrom(context.Background(), 0, planted)
	if err != nil {
		t.Fatalf("EntriesFrom: %v", err)
	}
	if len(got) != planted {
		t.Fatalf("EntriesFrom returned %d entries, want %d", len(got), planted)
	}
	// Three requests of ten, ten and five: one request of 25 is an HTTP 422.
	if s.retrieveCalls != 3 {
		t.Fatalf("the reader made %d retrieve requests for %d indexes, want 3",
			s.retrieveCalls, planted)
	}
	for i, entry := range got {
		if entry.LogIndex != int64(i) {
			t.Fatalf("entry %d is at log index %d; the sweep must be in index order",
				i, entry.LogIndex)
		}
	}
}

func TestSweepEntriesFromSkipsIndexesTheLogDoesNotHold(t *testing.T) {
	s := &sweepServer{}
	s.plant("aa", 0, hashedRekord(t, "hashedrekord", "sha256",
		artifactHash(testCommit), certFor(t, spiffeIDFor("run-a"))))
	s.plant("bb", 3, hashedRekord(t, "hashedrekord", "sha256",
		artifactHash(driftCommit), certFor(t, spiffeIDFor("run-b"))))

	got, err := s.start(t).EntriesFrom(context.Background(), 0, 8)
	if err != nil {
		t.Fatalf("EntriesFrom: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("EntriesFrom returned %d entries, want 2 — an index the log does not hold "+
			"is the log answering, not an error", len(got))
	}
}

func TestSweepEntriesFromRefusesAnImpossibleRange(t *testing.T) {
	log := (&sweepServer{}).start(t)
	for name, call := range map[string][2]int64{
		"negative start": {-1, 10},
		"empty range":    {0, 0},
		"negative count": {0, -5},
		"over the bound": {0, 1 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := log.EntriesFrom(context.Background(), call[0], call[1]); err == nil {
				t.Fatalf("EntriesFrom(%d, %d) was accepted", call[0], call[1])
			}
		})
	}
}

func TestSweepEntriesFromReportsAnUnreadableLog(t *testing.T) {
	for name, s := range map[string]*sweepServer{
		"http failure": {retrieveStatus: http.StatusBadGateway},
		"not json":     {retrieveBody: "[[[not json"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.start(t).EntriesFrom(context.Background(), 0, 3); err == nil {
				t.Fatal("an unreadable log was reported as an empty range; an outage " +
					"laundered into an absence is how drift goes unreported")
			}
		})
	}
}

func TestSweepReadsWhatAnEntryAttributesAndToWhat(t *testing.T) {
	identity := spiffeIDFor("run-a")
	cases := map[string]struct {
		body         func(t *testing.T) string
		wantIdentity string
		wantArtifact string
	}{
		"a gitsign signature": {
			body: func(t *testing.T) string {
				return hashedRekord(t, "hashedrekord", "sha256",
					artifactHash(testCommit), certFor(t, identity))
			},
			wantIdentity: identity,
			wantArtifact: artifactHash(testCommit),
		},
		"a segment anchor, which attributes nothing": {
			body:         func(t *testing.T) string { return anchorBody(t, artifactHash(testCommit)) },
			wantIdentity: "",
			wantArtifact: artifactHash(testCommit),
		},
		"a certificate with no URI SAN": {
			body: func(t *testing.T) string {
				return hashedRekord(t, "hashedrekord", "sha256",
					artifactHash(testCommit), certFor(t, ""))
			},
			wantIdentity: "",
			wantArtifact: artifactHash(testCommit),
		},
		"another entry kind": {
			body: func(t *testing.T) string {
				return hashedRekord(t, "intoto", "sha256",
					artifactHash(testCommit), certFor(t, identity))
			},
			wantIdentity: "",
			wantArtifact: "",
		},
		"another hash algorithm": {
			body: func(t *testing.T) string {
				return hashedRekord(t, "hashedrekord", "sha512",
					artifactHash(testCommit), certFor(t, identity))
			},
			wantIdentity: identity,
			wantArtifact: "",
		},
		"a public key that is not PEM": {
			body: func(t *testing.T) string {
				return hashedRekord(t, "hashedrekord", "sha256",
					artifactHash(testCommit), []byte("not pem at all"))
			},
			wantIdentity: "",
			wantArtifact: artifactHash(testCommit),
		},
		"a public key that is PEM but not a certificate": {
			body: func(t *testing.T) string {
				return hashedRekord(t, "hashedrekord", "sha256", artifactHash(testCommit),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
			},
			wantIdentity: "",
			wantArtifact: artifactHash(testCommit),
		},
		"a body that is not base64": {
			body:         func(*testing.T) string { return "!!!not base64!!!" },
			wantIdentity: "",
			wantArtifact: "",
		},
		"a body that is not JSON": {
			body: func(*testing.T) string {
				return base64.StdEncoding.EncodeToString([]byte("{ not json"))
			},
			wantIdentity: "",
			wantArtifact: "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := &sweepServer{}
			s.plant("aa", 0, tc.body(t))
			got, err := s.start(t).EntriesFrom(context.Background(), 0, 1)
			if err != nil {
				t.Fatalf("EntriesFrom: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("EntriesFrom returned %d entries, want 1 — an entry that "+
					"attributes nothing is still an entry, and REC-004 needs to see it",
					len(got))
			}
			if got[0].CertificateIdentity != tc.wantIdentity {
				t.Errorf("identity = %q, want %q", got[0].CertificateIdentity, tc.wantIdentity)
			}
			if got[0].ArtifactHash != tc.wantArtifact {
				t.Errorf("artifact = %q, want %q", got[0].ArtifactHash, tc.wantArtifact)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EntryByUUID.
// ---------------------------------------------------------------------------

func TestSweepEntryByUUIDReturnsTheEntry(t *testing.T) {
	uuid := strings.Repeat("ab", 32)
	s := &sweepServer{}
	s.plant(uuid, 7, hashedRekord(t, "hashedrekord", "sha256",
		artifactHash(driftCommit), certFor(t, spiffeIDFor("run-a"))))

	got, err := s.start(t).EntryByUUID(context.Background(), uuid)
	if err != nil {
		t.Fatalf("EntryByUUID: %v", err)
	}
	if got.UUID != uuid || got.LogIndex != 7 {
		t.Fatalf("EntryByUUID returned %+v, want uuid %s at index 7", got, uuid)
	}
	if got.ArtifactHash != artifactHash(driftCommit) {
		t.Fatalf("EntryByUUID returned artifact %q, want %q",
			got.ArtifactHash, artifactHash(driftCommit))
	}
}

func TestSweepEntryByUUIDAnswersErrNoEntryForAnAbsentEntry(t *testing.T) {
	s := &sweepServer{}
	s.plant(strings.Repeat("ab", 32), 0, hashedRekord(t, "hashedrekord", "sha256",
		artifactHash(driftCommit), certFor(t, spiffeIDFor("run-a"))))

	_, err := s.start(t).EntryByUUID(context.Background(), strings.Repeat("cd", 32))
	if !errors.Is(err, reconciler.ErrNoEntry) {
		t.Fatalf("EntryByUUID for an absent entry = %v, want ErrNoEntry", err)
	}
}

func TestSweepEntryByUUIDNeverAsksTheLogAboutAnImpossibleUUID(t *testing.T) {
	// Measured against rekor-server v1.3.10: a uuid outside
	// ^([0-9a-fA-F]{64}|[0-9a-fA-F]{80})$ is answered with HTTP 422, which this
	// reader would have to call an outage — and an outage suppresses the
	// finding. So the shape is decided here and the answer is ErrNoEntry.
	s := &sweepServer{}
	for _, uuid := range []string{"", "short", strings.Repeat("z", 64), strings.Repeat("ab", 40) + "aa"} {
		_, err := s.start(t).EntryByUUID(context.Background(), uuid)
		if !errors.Is(err, reconciler.ErrNoEntry) {
			t.Fatalf("EntryByUUID(%q) = %v, want ErrNoEntry", uuid, err)
		}
	}
	if s.retrieveCalls != 0 {
		t.Fatalf("the log was asked %d times about a uuid no entry can carry", s.retrieveCalls)
	}
	if !reconciler.IsRekorEntryUUID(strings.Repeat("ab", 32)) ||
		!reconciler.IsRekorEntryUUID(strings.Repeat("AB", 40)) {
		t.Fatal("IsRekorEntryUUID refuses a 64- and an 80-hex uuid")
	}
}

func TestSweepEntryByUUIDReportsAnUnreadableLog(t *testing.T) {
	for name, s := range map[string]*sweepServer{
		"http failure": {retrieveStatus: http.StatusGatewayTimeout},
		"not json":     {retrieveBody: "not json"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.start(t).EntryByUUID(context.Background(), strings.Repeat("ab", 32))
			if err == nil || errors.Is(err, reconciler.ErrNoEntry) {
				t.Fatalf("an unreadable log answered %v; a log that could not be asked is "+
					"never a log that said no (I4)", err)
			}
		})
	}
}

func TestSweepEntryByUUIDRefusesAnAnswerAboutAnotherEntry(t *testing.T) {
	// A log that answers a question about one uuid with another entry is not
	// answering. Returning that entry would let a compromised log satisfy any
	// `commit_recorded` with any entry it holds.
	s := &sweepServer{retrieveBody: fmt.Sprintf(
		`[{%q:{"body":"","logIndex":4,"integratedTime":1}}]`, strings.Repeat("cd", 32))}
	_, err := s.start(t).EntryByUUID(context.Background(), strings.Repeat("ab", 32))
	if !errors.Is(err, reconciler.ErrNoEntry) {
		t.Fatalf("EntryByUUID = %v, want ErrNoEntry", err)
	}
}

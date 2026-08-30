// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// Fixtures for the proof BFF.
//
// WHAT IS REAL HERE AND WHAT IS NOT, stated plainly because IP §2 requires the
// distinction to be explicit. Every cryptographic object below is real: a real
// P-256 CA, real X.509 certificates, real ECDSA signatures over real SHA-256
// digests, a real RFC 6962 leaf hash and a real signed checkpoint that
// internal/segment's own verifier checks. What is faked is the SERVER — two
// httptest handlers standing in for Fulcio's rootCert endpoint and Rekor's
// index, entries and publicKey endpoints.
//
// That boundary is the same one internal/verify draws for the unit half of
// TC-VER, and it is drawn in the same place for the same reason. I5 — "a
// mocked Fulcio proves nothing about I5" — is demonstrated by VER-001, which
// runs against the shipped Fulcio, Rekor, SPIRE and gitsign from
// deploy/compose/. What TC-API's proof cases establish is different and
// narrower: that the BFF hands back the material its verdict was computed
// from, that a client can convict it with that material, and that it says
// "unavailable" rather than inventing an answer when an upstream is gone.
// Nothing here re-proves I5, and nothing here claims to.
//
// The degrade case does NOT mock a failure: it closes a real HTTP listener, so
// what the verifier meets is a real connection refused.

const (
	fixtureTrustDomain = "innsegl.dev"
	fixtureIssuer      = "http://spire-oidc:8080"
	fixtureOrigin      = "rekor.innsegl.dev"
	fixtureIdentity    = "spiffe://" + fixtureTrustDomain + "/agent/fix-ci/rm-040/run-1"
	fixtureRepo        = "github.com/innsegl/proof"
)

var fixtureOIDFulcioIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "innsegl test fulcio"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type leafCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func (ca *testCA) issue(t *testing.T, spiffeID string, notBefore, notAfter time.Time) *leafCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a leaf key: %v", err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("parsing %q: %v", spiffeID, err)
	}
	issuer, err := asn1.Marshal(fixtureIssuer)
	if err != nil {
		t.Fatalf("marshalling the issuer extension: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:                  []*url.URL{uri},
		ExtraExtensions:       []pkix.Extension{{Id: fixtureOIDFulcioIssuer, Value: issuer}},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issuing a leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the leaf certificate: %v", err)
	}
	return &leafCert{cert: cert, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// The CMS SignedData gitsign writes, as far as the certificate set. The
// signature itself is not modelled: internal/verify never re-verifies the CMS
// bytes in process (ADR-0034), so a fixture that carried one would be testing
// something no code reads.
type fixtureContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type fixtureSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue
}

func cmsPEM(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var der []byte
	for _, c := range certs {
		der = append(der, c.Raw...)
	}
	encap, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}})
	if err != nil {
		t.Fatalf("marshalling encapContentInfo: %v", err)
	}
	sd, err := asn1.Marshal(fixtureSignedData{
		Version: 1,
		DigestAlgorithms: asn1.RawValue{
			Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		},
		EncapContentInfo: asn1.RawValue{FullBytes: encap},
		Certificates: asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der,
		},
	})
	if err != nil {
		t.Fatalf("marshalling SignedData: %v", err)
	}
	ci, err := asn1.Marshal(fixtureContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd,
		},
	})
	if err != nil {
		t.Fatalf("marshalling ContentInfo: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: ci})
}

// ---------------------------------------------------------------------------
// A transparency log that really hashes, really builds a checkpoint, and
// really signs both the checkpoint and the entry timestamp.
// ---------------------------------------------------------------------------

type fakeLog struct {
	t       *testing.T
	key     *ecdsa.PrivateKey
	entries map[string]json.RawMessage
	index   map[string][]string
	server  *httptest.Server
	URL     string
}

func newFakeLog(t *testing.T) *fakeLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a log key: %v", err)
	}
	l := &fakeLog{t: t, key: key,
		entries: map[string]json.RawMessage{}, index: map[string][]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/index/retrieve", l.handleIndex)
	mux.HandleFunc("/api/v1/log/entries/", l.handleEntry)
	mux.HandleFunc("/api/v1/log/publicKey", l.handleKey)
	l.server = httptest.NewServer(mux)
	l.URL = l.server.URL
	t.Cleanup(l.server.Close)
	return l
}

// stop makes the log unreachable for the rest of the test. A closed listener,
// not a handler that returns an error: what the verifier meets is a real
// connection refused.
func (l *fakeLog) stop() { l.server.Close() }

func (l *fakeLog) publicKeyPEM() []byte {
	der, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		l.t.Fatalf("marshalling the log key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func (l *fakeLog) handleKey(w http.ResponseWriter, _ *http.Request) {
	writeAll(w.Write(l.publicKeyPEM()))
}

func (l *fakeLog) handleIndex(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	out := l.index[q.Hash]
	if out == nil {
		out = []string{}
	}
	encodeAll(json.NewEncoder(w).Encode(out))
}

func (l *fakeLog) handleEntry(w http.ResponseWriter, r *http.Request) {
	uuid := strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/")
	body, ok := l.entries[uuid]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeAll(w.Write(body))
}

func fixtureRekordBody(t *testing.T, artifactHashHex string, signature, certPEM []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{"algorithm": "sha256", "value": artifactHashHex},
			},
			"signature": map[string]any{
				"content": base64.StdEncoding.EncodeToString(signature),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(certPEM),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshalling the entry body: %v", err)
	}
	return raw
}

func signDigest(t *testing.T, key *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatalf("signing the digest: %v", err)
	}
	return sig
}

// add puts one entry in the log, with a real leaf hash, a real one-leaf tree, a
// real signed checkpoint and a real signed entry timestamp.
func (l *fakeLog) add(artifactHashHex string, signature, certPEM []byte, integrated time.Time) string {
	l.t.Helper()
	body := fixtureRekordBody(l.t, artifactHashHex, signature, certPEM)

	sum := sha256.New()
	sum.Write([]byte{segment.LeafPrefix})
	sum.Write(body)
	leafHash := sum.Sum(nil)
	uuid := hex.EncodeToString(leafHash)
	logID := strings.Repeat("ab", 32)
	logIndex := int64(len(l.entries))

	entry := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"integratedTime": integrated.Unix(),
		"logID":          logID,
		"logIndex":       logIndex,
		"verification": map[string]any{
			"signedEntryTimestamp": base64.StdEncoding.EncodeToString(
				l.signEntryTimestamp(body, integrated.Unix(), logID, logIndex)),
			"inclusionProof": map[string]any{
				"checkpoint": l.checkpoint(1, uuid),
				"hashes":     []string{},
				"logIndex":   0,
				"rootHash":   uuid,
				"treeSize":   1,
			},
		},
	}
	raw, err := json.Marshal(map[string]any{uuid: entry})
	if err != nil {
		l.t.Fatalf("marshalling the log entry: %v", err)
	}
	l.entries[uuid] = raw
	key := "sha256:" + artifactHashHex
	l.index[key] = append(l.index[key], uuid)
	return uuid
}

func (l *fakeLog) checkpoint(size int64, rootHex string) string {
	l.t.Helper()
	root, err := hex.DecodeString(rootHex)
	if err != nil {
		l.t.Fatalf("decoding the root: %v", err)
	}
	body := fmt.Sprintf("%s\n%d\n%s", fixtureOrigin, size, base64.StdEncoding.EncodeToString(root))
	digest := sha256.Sum256([]byte(body + "\n"))
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		l.t.Fatalf("signing the checkpoint: %v", err)
	}
	blob := append([]byte{0xde, 0xad, 0xbe, 0xef}, sig...)
	return body + "\n\n— " + fixtureOrigin + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
}

func (l *fakeLog) signEntryTimestamp(body []byte, integrated int64, logID string, logIndex int64) []byte {
	l.t.Helper()
	canonical := fmt.Sprintf(
		`{"body":"%s","integratedTime":%d,"logID":"%s","logIndex":%d}`,
		base64.StdEncoding.EncodeToString(body), integrated, logID, logIndex)
	digest := sha256.Sum256([]byte(canonical))
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		l.t.Fatalf("signing the entry timestamp: %v", err)
	}
	return sig
}

// ---------------------------------------------------------------------------
// Fulcio's /api/v1/rootCert.
// ---------------------------------------------------------------------------

type fakeCA struct {
	URL    string
	server *httptest.Server
}

func newFakeCA(t *testing.T, rootPEM []byte) *fakeCA {
	t.Helper()
	f := &fakeCA{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeAll(w.Write(rootPEM))
	}))
	f.URL = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCA) stop() { f.server.Close() }

// ---------------------------------------------------------------------------
// A real git repository with a hand-written commit object.
// ---------------------------------------------------------------------------

func gitIn(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "no-such-gitconfig"),
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(dir),
	)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

func newTestRepo(t *testing.T) (dir, tree string) {
	t.Helper()
	dir = t.TempDir()
	gitIn(t, dir, "", "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("innsegl RM-040\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "", "add", "work.txt")
	tree = gitIn(t, dir, "", "write-tree")
	return dir, tree
}

// writeCommit writes a raw commit object and returns its SHA. Written by hand
// because half of these cases are about commits git would never produce.
func writeCommit(t *testing.T, repo, tree, message string, gpgsig []byte) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "tree %s\n", tree)
	const who = "Innsegl Operator <operator@innsegl.invalid> 1700000000 +0000"
	fmt.Fprintf(&b, "author %s\ncommitter %s\n", who, who)
	if len(gpgsig) > 0 {
		lines := strings.Split(strings.TrimRight(string(gpgsig), "\n"), "\n")
		b.WriteString("gpgsig " + lines[0] + "\n")
		for _, l := range lines[1:] {
			b.WriteString(" " + l + "\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(message)
	return gitIn(t, repo, b.String(), "hash-object", "-t", "commit", "-w", "--stdin")
}

// ---------------------------------------------------------------------------
// One assembled scenario: a repository, a signed commit, a certificate and a
// log entry that all agree.
// ---------------------------------------------------------------------------

type proofScenario struct {
	repo       string
	commit     string
	claimed    string
	ca         *testCA
	leaf       *leafCert
	log        *fakeLog
	fulcio     *fakeCA
	integrated time.Time
}

type proofOptions struct {
	// trailerIdentity overrides the Agent-Identity trailer; empty means the
	// certificate's own SPIFFE ID.
	trailerIdentity string
	// unsigned omits the gpgsig header.
	unsigned bool
	// message replaces the whole commit message, trailers included.
	message string
}

func newProofScenario(t *testing.T, opt proofOptions) *proofScenario {
	t.Helper()
	integrated := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	ca := newTestCA(t)
	lf := ca.issue(t, fixtureIdentity, integrated.Add(-time.Minute), integrated.Add(9*time.Minute))

	claimed := opt.trailerIdentity
	if claimed == "" {
		claimed = fixtureIdentity
	}
	parts := strings.Split(claimed, "/")
	message := opt.message
	if message == "" {
		message = "RM-040: a commit under proof\n\n" +
			"Agent-Identity: " + claimed + "\n" +
			"Agent-Run: " + parts[len(parts)-1] + "\n" +
			"Agent-Task: rm-040\n"
	}

	repo, tree := newTestRepo(t)
	var sig []byte
	if !opt.unsigned {
		sig = cmsPEM(t, lf.cert, ca.cert)
	}
	commit := writeCommit(t, repo, tree, message, sig)

	log := newFakeLog(t)
	if !opt.unsigned {
		digest := sha256.Sum256([]byte(commit))
		log.add(hex.EncodeToString(digest[:]), signDigest(t, lf.key, digest[:]), lf.pem, integrated)
	}
	return &proofScenario{
		repo: repo, commit: commit, claimed: claimed,
		ca: ca, leaf: lf, log: log,
		fulcio:     newFakeCA(t, ca.pem),
		integrated: integrated,
	}
}

// prover builds the BFF under test against this scenario's endpoints, with a
// clock a year past the certificate's window so that nothing passes because
// the wall clock happened to agree.
func (s *proofScenario) prover(t *testing.T) *Prover {
	t.Helper()
	p, err := NewProver(ProofConfig{
		FulcioURL: s.fulcio.URL,
		RekorURL:  s.log.URL,
		Repos:     map[string]string{fixtureRepo: s.repo},
		Now:       func() time.Time { return s.integrated.Add(365 * 24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("NewProver: %v", err)
	}
	return p
}

func writeAll(int, error) {}

func encodeAll(error) {}

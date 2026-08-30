// SPDX-License-Identifier: Apache-2.0

package verify

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
	"io"
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

// Fixtures for the unit half of TC-VER.
//
// WHAT IS REAL HERE AND WHAT IS NOT. IP §2: "a mocked Fulcio proves nothing
// about I5", and the integration cases in verifyintegration_test.go run
// against the shipped Fulcio, Rekor, SPIRE and gitsign for exactly that
// reason. These fixtures exist for the other half of the same rule — the unit
// and contract tests, where mocks are allowed — and for the branch floor IP §2
// puts on signature verification, which cannot be reached through a container
// stack at all: there is no way to ask a real Fulcio for a certificate that
// expired last year, and no way to ask a real Rekor for a proof with one hash
// flipped.
//
// So every cryptographic object below is REAL — a real P-256 CA, real X.509
// certificates, real ECDSA signatures, a real RFC 6962 leaf hash and a real
// signed checkpoint note, verified by internal/segment's verifier rather than
// by a stub. What is faked is only the SERVER: two httptest handlers that
// return documents the verifier reads. A fixture that returned a canned
// "valid" verdict would test nothing; these force the verifier to do the
// arithmetic.

const (
	fixtureTrustDomain = "innsegl.dev"
	fixtureIssuer      = "http://spire-oidc:8080"
	fixtureOrigin      = "rekor.innsegl.dev"
)

// oidFulcioIssuerV2 is Fulcio's current OIDC-issuer extension (.8), the one
// internal/signing reads and the one these fixtures stamp.
var fixtureOIDFulcioIssuer = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

// ---------------------------------------------------------------------------
// A certificate authority that behaves like the shipped Fulcio.
// ---------------------------------------------------------------------------

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
	return &testCA{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// leaf is one short-lived signing certificate, with the key that goes with it.
type leaf struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
	pem  []byte
}

// issue mints a leaf shaped like Fulcio's: a URI SAN carrying the run's SPIFFE
// ID, code-signing EKU, the OIDC issuer extension, and NO SCT — this
// deployment operates no CT log (ADR-0029 decision 5), so a fixture that
// embedded one would be testing a certificate this system never issues.
func (ca *testCA) issue(t *testing.T, spiffeID string, notBefore, notAfter time.Time) *leaf {
	t.Helper()
	issuer, err := asn1.Marshal(fixtureIssuer)
	if err != nil {
		t.Fatalf("marshalling the issuer extension: %v", err)
	}
	return ca.issueWithExtensions(t, spiffeID, notBefore, notAfter,
		[]pkix.Extension{{Id: fixtureOIDFulcioIssuer, Value: issuer}})
}

// pkixExtension is an alias so a case can name an extension without importing
// crypto/x509/pkix for one literal.
type pkixExtension = pkix.Extension

// issueWithExtensions is issue with the certificate's extensions chosen by the
// caller, so a case can hand the reader an issuer extension it cannot parse.
func (ca *testCA) issueWithExtensions(t *testing.T, spiffeID string,
	notBefore, notAfter time.Time, extensions []pkix.Extension) *leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a leaf key: %v", err)
	}
	uri, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("parsing %q: %v", spiffeID, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:                  []*url.URL{uri},
		ExtraExtensions:       extensions,
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
	return &leaf{
		cert: cert,
		key:  key,
		der:  der,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// ---------------------------------------------------------------------------
// A CMS SignedData carrying certificates, in the shape gitsign writes.
// ---------------------------------------------------------------------------

// Both structures are marshalled with every tag spelled on the RawValue
// itself rather than through struct tags: `encoding/asn1` writes a RawValue
// that carries FullBytes verbatim and ignores an `explicit` struct tag around
// it, which silently produces a ContentInfo with no [0] wrapper at all.
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

// cmsPEM builds the `gpgsig` payload: a PEM "SIGNED MESSAGE" block whose CMS
// SignedData carries the given certificates, leaf first.
//
// The signature itself is not modelled, and that is a statement about the
// verifier rather than a shortcut. This verifier never re-verifies the CMS
// bytes in process — IP §7 forbids reimplementing Sigstore's crypto, and
// threat model §5.4 warns about hand-written ASN.1. What it does instead is
// require the transparency log to hold a signature over THIS commit's SHA
// under THIS certificate, which is a stronger statement and one made of
// stdlib primitives. See ADR-0034.
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
	t   *testing.T
	key *ecdsa.PrivateKey
	// entries maps uuid -> the JSON the entries endpoint returns.
	entries map[string]json.RawMessage
	// index maps "sha256:<hex>" -> uuids.
	index map[string][]string
	// server is the httptest server; URL is its base.
	server *httptest.Server
	URL    string
	// failIndex, failEntry and failKey make each endpoint unreachable-shaped.
	failIndex, failEntry, failKey bool
	// omitSET drops the signed entry timestamp from the response.
	omitSET bool
	// tamperProof flips one byte of the inclusion proof's root.
	tamperProof bool
	// mutateBody, mutateEntry and entryKey are the general-purpose seams the
	// error-path cases use. Each takes the document this log is about to
	// serve and breaks exactly one thing in it, so a case can name the byte
	// it changed rather than carrying a hand-written fixture per failure.
	mutateBody  func(map[string]any)
	mutateEntry func(map[string]any)
	entryKey    func(uuid string) string
	// rawIndex and rawKey replace a whole response.
	rawIndex *string
	rawKey   []byte
	calls    map[string]int
}

func newFakeLog(t *testing.T) *fakeLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a log key: %v", err)
	}
	l := &fakeLog{
		t:       t,
		key:     key,
		entries: map[string]json.RawMessage{},
		index:   map[string][]string{},
		calls:   map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/index/retrieve", l.handleIndex)
	mux.HandleFunc("/api/v1/log/entries/", l.handleEntry)
	mux.HandleFunc("/api/v1/log/publicKey", l.handleKey)
	l.server = httptest.NewServer(mux)
	l.URL = l.server.URL
	t.Cleanup(l.server.Close)
	return l
}

func (l *fakeLog) publicKeyPEM() []byte {
	der, err := x509.MarshalPKIXPublicKey(&l.key.PublicKey)
	if err != nil {
		l.t.Fatalf("marshalling the log key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func (l *fakeLog) handleKey(w http.ResponseWriter, _ *http.Request) {
	l.calls["key"]++
	if l.failKey {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if l.rawKey != nil {
		writeAll(w.Write(l.rawKey))
		return
	}
	writeAll(w.Write(l.publicKeyPEM()))
}

func (l *fakeLog) handleIndex(w http.ResponseWriter, r *http.Request) {
	l.calls["index"]++
	if l.failIndex {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if l.rawIndex != nil {
		writeAll(io.WriteString(w, *l.rawIndex))
		return
	}
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
	l.calls["entry"]++
	if l.failEntry {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	uuid := strings.TrimPrefix(r.URL.Path, "/api/v1/log/entries/")
	body, ok := l.entries[uuid]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	writeAll(w.Write(body))
}

// hashedRekordBody renders the entry body gitsign's online mode writes: a
// hashedrekord whose artifact is the commit SHA and whose public key is the
// signing certificate.
func fixtureRekordBody(t *testing.T, artifactHashHex string, signature []byte, certPEM []byte,
	mutate func(map[string]any)) []byte {
	t.Helper()
	body := map[string]any{
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
	}
	if mutate != nil {
		mutate(body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling the entry body: %v", err)
	}
	return raw
}

// signArtifact signs a sha256 digest the way a hashedrekord's signature is
// verified: ECDSA over the digest itself.
func signArtifact(t *testing.T, key *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatalf("signing the artifact digest: %v", err)
	}
	return sig
}

// add puts one entry in the log: it hashes the body as an RFC 6962 leaf, makes
// that leaf the root of a one-leaf tree, signs a checkpoint over it, and signs
// the entry timestamp. Everything the verifier checks about this entry is
// therefore arithmetic it can redo.
func (l *fakeLog) add(artifactHashHex string, signature, certPEM []byte, integrated time.Time) (uuid string, logIndex int64) {
	l.t.Helper()
	body := fixtureRekordBody(l.t, artifactHashHex, signature, certPEM, l.mutateBody)

	sum := sha256.New()
	sum.Write([]byte{segment.LeafPrefix})
	sum.Write(body)
	leafHash := sum.Sum(nil)
	uuid = hex.EncodeToString(leafHash)
	rootHex := uuid
	if l.tamperProof {
		flipped := append([]byte(nil), leafHash...)
		flipped[0] ^= 0x01
		rootHex = hex.EncodeToString(flipped)
	}

	logIndex = int64(len(l.entries))
	checkpoint := l.checkpoint(1, rootHex)
	entry := map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"integratedTime": integrated.Unix(),
		"logID":          strings.Repeat("ab", 32),
		"logIndex":       logIndex,
		"verification": map[string]any{
			"inclusionProof": map[string]any{
				"checkpoint": checkpoint,
				"hashes":     []string{},
				"logIndex":   0,
				"rootHash":   rootHex,
				"treeSize":   1,
			},
		},
	}
	if !l.omitSET {
		nested(entry, "verification")["signedEntryTimestamp"] =
			base64.StdEncoding.EncodeToString(l.signEntryTimestamp(
				body, integrated.Unix(), strings.Repeat("ab", 32), logIndex))
	}
	if l.mutateEntry != nil {
		l.mutateEntry(entry)
	}
	key := uuid
	if l.entryKey != nil {
		key = l.entryKey(uuid)
	}
	raw, err := json.Marshal(map[string]any{key: entry})
	if err != nil {
		l.t.Fatalf("marshalling the log entry: %v", err)
	}
	l.entries[uuid] = raw
	indexKey := "sha256:" + artifactHashHex
	l.index[indexKey] = append(l.index[indexKey], uuid)
	return uuid, logIndex
}

// checkpoint renders and signs the note format internal/segment parses.
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

// signEntryTimestamp signs the canonical JSON Rekor signs: the four members
// body, integratedTime, logID and logIndex, in RFC 8785 order, with no
// whitespace. This is what makes the integration time a statement BY THE LOG
// rather than a number in a response an attacker could edit (IP §6.8).
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
// A certificate authority endpoint that behaves like Fulcio's /api/v1/rootCert.
// ---------------------------------------------------------------------------

type fakeCA struct {
	URL  string
	fail bool
	body []byte
}

func newFakeCA(t *testing.T, rootPEM []byte) *fakeCA {
	t.Helper()
	f := &fakeCA{body: rootPEM}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f.fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeAll(w.Write(f.body))
	}))
	f.URL = srv.URL
	t.Cleanup(srv.Close)
	return f
}

// ---------------------------------------------------------------------------
// Real git repositories, and raw commit objects written by hand.
// ---------------------------------------------------------------------------

func gitIn(t *testing.T, dir string, stdin string, args ...string) string {
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

// newTestRepo returns a repository with one tree object already written, and
// the tree's SHA.
func newTestRepo(t *testing.T) (dir, tree string) {
	t.Helper()
	dir = t.TempDir()
	gitIn(t, dir, "", "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "work.txt"), []byte("innsegl RM-037\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "", "add", "work.txt")
	tree = gitIn(t, dir, "", "write-tree")
	return dir, tree
}

// writeCommit writes a raw commit object with the given message and optional
// gpgsig header, and returns its SHA.
//
// Written by hand rather than through `git commit` because half of TC-VER is
// about commits git would never produce: a signature copied onto a rewritten
// object, a message whose trailer was edited after the fact. `git hash-object`
// is still git's own object writer, so the SHA is git's.
func writeCommit(t *testing.T, repo, tree, parent, message string, gpgsig []byte) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "tree %s\n", tree)
	if parent != "" {
		fmt.Fprintf(&b, "parent %s\n", parent)
	}
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
// One assembled scenario: a repository, a commit, a certificate and a log
// entry that all agree — the shape everything else is a mutation of.
// ---------------------------------------------------------------------------

type scenario struct {
	repo   string
	tree   string
	commit string
	claim  string
	ca     *testCA
	leaf   *leaf
	log    *fakeLog
	fulcio *fakeCA
	// integrated is the moment the log says it integrated the entry.
	integrated time.Time
	// issuer is the OIDC issuer the verifier is told to expect, if any.
	issuer string
}

// scenarioOptions are the knobs each case turns exactly one of.
type scenarioOptions struct {
	// trailerIdentity overrides the Agent-Identity trailer; empty means the
	// certificate's own SPIFFE ID.
	trailerIdentity string
	// message replaces the whole commit message.
	message string
	// notBefore and notAfter set the certificate's validity window.
	notBefore, notAfter time.Time
	// integrated sets the log's integration time.
	integrated time.Time
	// unsigned omits the gpgsig header.
	unsigned bool
	// noEntry skips adding the log entry.
	noEntry bool
	// entryForOtherCommit logs the entry under a different artifact.
	entryForOtherCommit bool
	// entrySignedByAnother signs the artifact with a key that is not the
	// certificate's.
	entrySignedByAnother bool
	// tamperProof flips a byte of the inclusion proof.
	tamperProof bool
	// omitSET drops the signed entry timestamp.
	omitSET bool
	// foreignCA issues the leaf from a CA that Fulcio does not publish.
	foreignCA bool
	// identity overrides the certificate's URI SAN.
	identity string
	// logSetup runs against the fake log BEFORE its entry is added, so a case
	// can break one field of the document the log is about to serve.
	logSetup func(*fakeLog)
	// issuer, when set, is the issuer the verifier is told to expect.
	issuer string
}

const fixtureIdentity = "spiffe://" + fixtureTrustDomain + "/agent/demo/rm-037/run-1"

// newScenario assembles the good case, then applies the one mutation the
// caller asked for.
func newScenario(t *testing.T, opt scenarioOptions) *scenario {
	t.Helper()

	integrated := opt.integrated
	if integrated.IsZero() {
		integrated = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	}
	notBefore := opt.notBefore
	if notBefore.IsZero() {
		notBefore = integrated.Add(-1 * time.Minute)
	}
	notAfter := opt.notAfter
	if notAfter.IsZero() {
		notAfter = integrated.Add(9 * time.Minute)
	}
	identity := opt.identity
	if identity == "" {
		identity = fixtureIdentity
	}

	ca := newTestCA(t)
	issuing := ca
	if opt.foreignCA {
		issuing = newTestCA(t)
	}
	lf := issuing.issue(t, identity, notBefore, notAfter)

	claimed := opt.trailerIdentity
	if claimed == "" {
		claimed = identity
	}
	message := opt.message
	if message == "" {
		message = "VER: a commit under test\n\n" +
			"Agent-Identity: " + claimed + "\n" +
			"Agent-Run: " + lastSegment(claimed) + "\n" +
			"Agent-Task: rm-037\n"
	}

	repo, tree := newTestRepo(t)
	var sig []byte
	if !opt.unsigned {
		sig = cmsPEM(t, lf.cert, ca.cert)
	}
	commit := writeCommit(t, repo, tree, "", message, sig)

	log := newFakeLog(t)
	log.tamperProof = opt.tamperProof
	log.omitSET = opt.omitSET
	if opt.logSetup != nil {
		opt.logSetup(log)
	}
	if !opt.noEntry {
		artifact := sha256Hex(commit)
		if opt.entryForOtherCommit {
			artifact = sha256Hex(strings.Repeat("0", 40))
		}
		signingKey := lf.key
		if opt.entrySignedByAnother {
			other := ca.issue(t, identity, notBefore, notAfter)
			signingKey = other.key
		}
		digest, err := hex.DecodeString(sha256Hex(commit))
		if err != nil {
			t.Fatal(err)
		}
		log.add(artifact, signArtifact(t, signingKey, digest), lf.pem, integrated)
	}

	return &scenario{
		repo: repo, tree: tree, commit: commit, claim: claimed,
		ca: ca, leaf: lf, log: log,
		fulcio:     newFakeCA(t, ca.pem),
		integrated: integrated,
		issuer:     opt.issuer,
	}
}

func lastSegment(id string) string {
	parts := strings.Split(id, "/")
	return parts[len(parts)-1]
}

// verifier builds the verifier under test against this scenario's endpoints,
// with `now` far from the certificate's window so that nothing passes because
// the wall clock happened to agree.
func (s *scenario) verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := New(Config{
		FulcioURL: s.fulcio.URL,
		RekorURL:  s.log.URL,
		Issuer:    s.issuer,
		Now:       func() time.Time { return s.integrated.Add(365 * 24 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// report runs the verifier over the scenario's commit.
func (s *scenario) report(t *testing.T) Report {
	t.Helper()
	rep, err := s.verifier(t).Verify(t.Context(), s.repo, s.commit)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

// check returns the named check, failing if the report does not carry it.
func (r Report) check(t *testing.T, name string) Check {
	t.Helper()
	if len(r.Checks) != 3 {
		t.Fatalf("the report carries %d checks, doc 06 §4.1 requires three that never collapse: %+v",
			len(r.Checks), r.Checks)
	}
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, r.Checks)
	return Check{}
}

// onlyEntryUUID returns the uuid of the one entry this log holds.
func (l *fakeLog) onlyEntryUUID() string {
	l.t.Helper()
	if len(l.entries) != 1 {
		l.t.Fatalf("the fake log holds %d entries, want exactly 1", len(l.entries))
	}
	for uuid := range l.entries {
		return uuid
	}
	return ""
}

// writeAll and encodeAll swallow the one error a test handler cannot act on: a
// client that has gone away. errcheck's check-blank is on in this repository,
// so the discard is a named function rather than a blank assignment — the
// idiom internal/mcp's health harness already uses.
func writeAll(int, error) {}

func encodeAll(error) {}

// nested walks a JSON object the fixtures built, with the type assertion
// checked. A fixture that mutates the wrong path should say so loudly rather
// than panicking with a bare interface-conversion message.
func nested(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		next, ok := m[k].(map[string]any)
		if !ok {
			panic("fixtures: no JSON object at key " + k)
		}
		m = next
	}
	return m
}

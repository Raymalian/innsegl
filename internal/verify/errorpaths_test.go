// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every error return of this package, taken.
//
// IP §2 puts a 100% BRANCH floor on signature verification, and this file is
// what holds it: scripts/branch-coverage.sh runs gobco over internal/verify/
// and fails on any condition that was only ever evaluated in one direction. An
// error path nothing has taken is a line of code nobody has read carefully,
// and in a verifier it is worse than that — an error path that returns the
// wrong tri-state turns "we could not check" into "verified".

// ---------------------------------------------------------------------------
// A git that can be made to fail on demand, so the two-command paths in
// readCommit and the object walk in recover have both outcomes.
// ---------------------------------------------------------------------------

// fakeGit writes a git wrapper that refuses any invocation whose arguments
// contain $INNSEGL_FAKEGIT_FAIL and otherwise delegates to the real one.
func fakeGit(t *testing.T) string {
	t.Helper()
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skipf("no git on PATH: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "git")
	script := "#!/bin/sh\n" +
		"if [ -n \"$INNSEGL_FAKEGIT_FAIL\" ]; then\n" +
		"  case \"$*\" in\n" +
		"    *\"$INNSEGL_FAKEGIT_FAIL\"*) echo \"fakegit: refusing: $*\" >&2; exit 42 ;;\n" +
		"  esac\n" +
		"fi\n" +
		"exec " + realGit + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadCommitReportsAFailureOfEitherGitCommand(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	git := fakeGit(t)

	for _, tc := range []struct {
		name string
		fail string
	}{
		{"the revision cannot be resolved", "rev-parse"},
		{"the object cannot be read back", "cat-file commit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INNSEGL_FAKEGIT_FAIL", tc.fail)
			_, err := readCommit(t.Context(), git, s.repo, s.commit)
			if !errors.Is(err, ErrRevision) {
				t.Fatalf("readCommit err = %v, want ErrRevision", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// commitCertificate — every refusal.
// ---------------------------------------------------------------------------

func TestCommitCertificateRefusesEverySignatureItCannotRead(t *testing.T) {
	ca := newTestCA(t)
	leafCert := ca.issue(t, fixtureIdentity, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	junkCerts, jerr := asn1.Marshal(fixtureContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: mustMarshal(t, fixtureSignedData{
				Version:          1,
				DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
				EncapContentInfo: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true},
				Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0,
					IsCompound: true, Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x07}},
			})},
	})
	if jerr != nil {
		t.Fatal(jerr)
	}

	cases := []struct {
		name      string
		signature []byte
		want      string
	}{
		{"no signature at all", nil, "not signed"},
		{"not PEM", []byte("hello"), "not PEM"},
		{"a PEM block of the wrong type",
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
			"not a CMS"},
		{"a SIGNED MESSAGE that is not ASN.1",
			pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: []byte{1, 2, 3}}),
			"not a CMS ContentInfo"},
		{"a ContentInfo whose content is not a SignedData",
			pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: mustMarshal(t,
				fixtureContentInfo{
					ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
					Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0,
						IsCompound: true, Bytes: []byte{0x02, 0x01, 0x05}},
				})}),
			"not a SignedData"},
		{"a certificate set that does not parse",
			pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: junkCerts}),
			"does not parse"},
		{"a certificate set with no leaf", cmsPEM(t, ca.cert), "is a leaf with a URI SAN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := commitCertificate(tc.signature)
			if err == nil {
				t.Fatalf("commitCertificate accepted %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// The CA first, then the leaf: the walk must step past a certificate that
	// is not the signer rather than stopping at the first one.
	got, rest, cerr := commitCertificate(cmsPEM(t, ca.cert, leafCert.cert))
	if cerr != nil {
		t.Fatalf("commitCertificate: %v", cerr)
	}
	if got.SerialNumber.Cmp(leafCert.cert.SerialNumber) != 0 {
		t.Errorf("the leaf found is serial %s, want %s", got.SerialNumber, leafCert.cert.SerialNumber)
	}
	if len(rest) != 1 || rest[0].SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Errorf("the remaining chain is %v, want just the CA", rest)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestURISANOfACertificateWithoutOne(t *testing.T) {
	ca := newTestCA(t)
	if got := uriSANOf(ca.cert); got != "" {
		t.Errorf("uriSANOf(a CA certificate) = %q, want \"\"", got)
	}
}

// Fulcio has spelled its issuer extension two ways. A verifier that read only
// the current one would report an older certificate as naming no issuer.
func TestFulcioIssuerOfReadsBothSpellingsAndSurvivesNeither(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()

	deprecated := ca.issueWithExtensions(t, fixtureIdentity, now.Add(-time.Minute), now.Add(time.Hour),
		[]pkixExtension{{Id: oidFulcioIssuerV1, Value: []byte("http://legacy.example")}})
	if got := fulcioIssuerOf(deprecated.cert); got != "http://legacy.example" {
		t.Errorf("the deprecated .1 issuer extension was read as %q", got)
	}

	// A .8 extension whose value is not a DER UTF8String: unreadable, and the
	// certificate must be reported as naming no issuer rather than as naming
	// whatever the raw bytes happen to be.
	broken := ca.issueWithExtensions(t, fixtureIdentity, now.Add(-time.Minute), now.Add(time.Hour),
		[]pkixExtension{{Id: oidFulcioIssuerV2, Value: []byte{0x05, 0x00}}})
	if got := fulcioIssuerOf(broken.cert); got != "" {
		t.Errorf("an unreadable .8 issuer extension was read as %q, want \"\"", got)
	}
}

// ---------------------------------------------------------------------------
// The HTTP reader.
// ---------------------------------------------------------------------------

func TestTheHTTPReaderReportsEveryWayARequestCanFail(t *testing.T) {
	v, err := New(Config{FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := v.get(t.Context(), "://not-a-url"); err == nil {
		t.Error("get accepted a URL that cannot become a request")
	}
	if _, err := v.postJSON(t.Context(), "://not-a-url", nil); err == nil {
		t.Error("postJSON accepted a URL that cannot become a request")
	}
	if _, err := v.get(t.Context(), "http://127.0.0.1:1/"); err == nil {
		t.Error("get reported success against a port nothing listens on")
	}

	// A response that promises more body than it delivers. The status line
	// arrives, so the request succeeded and the READ is what fails — a
	// different path from an unreachable host, and one that must still be
	// reported rather than treated as an empty document.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, herr := hijacker.Hijack()
		if herr != nil {
			return
		}
		writeAll(bufrw.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nshort"))
		encodeAll(bufrw.Flush())
		encodeAll(conn.Close())
	}))
	defer srv.Close()
	if _, err := v.get(t.Context(), srv.URL); err == nil {
		t.Error("get reported success for a truncated response body")
	}
}

func TestTruncateShortensALongResponse(t *testing.T) {
	long := strings.Repeat("x", 1000)
	if got := truncate([]byte(long)); !strings.HasSuffix(got, "…") || len(got) >= len(long) {
		t.Errorf("truncate did not shorten a 1000-byte body: %d bytes", len(got))
	}
	if got := truncate([]byte("short")); got != "short" {
		t.Errorf("truncate(%q) = %q", "short", got)
	}
}

// ---------------------------------------------------------------------------
// Check 1's remaining refusals.
// ---------------------------------------------------------------------------

func TestCheckOneIsUnavailableWhenFulcioServesSomethingThatIsNotARoot(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	s.fulcio.body = []byte("this is not a certificate")

	rep := s.report(t)

	if c := rep.check(t, CheckCertificateChain); c.Result != Unavailable {
		t.Fatalf("check 1 = %s (%s), want %s", c.Result, c.Detail, Unavailable)
	}
}

func TestCheckOneBitesOnAnUnexpectedOIDCIssuer(t *testing.T) {
	s := newScenario(t, scenarioOptions{issuer: "http://somebody-elses-idp.example"})

	rep := s.report(t)

	if c := rep.check(t, CheckCertificateChain); c.Result != Failed {
		t.Fatalf("check 1 = %s (%s), want %s: the certificate names %s and the verifier "+
			"was told to expect another issuer", c.Result, c.Detail, Failed, fixtureIssuer)
	}
	// And it passes when told the right one, or the case above proves only
	// that a non-empty issuer always fails.
	ok := newScenario(t, scenarioOptions{issuer: fixtureIssuer})
	if c := ok.report(t).check(t, CheckCertificateChain); c.Result != Verified {
		t.Fatalf("check 1 = %s (%s) against the issuer the certificate names",
			c.Result, c.Detail)
	}
}

// ---------------------------------------------------------------------------
// Check 2's remaining refusals.
// ---------------------------------------------------------------------------

func TestCheckTwoIsUnavailableWhenTheSearchIndexAnswersWithNonsense(t *testing.T) {
	s := newScenario(t, scenarioOptions{logSetup: func(l *fakeLog) {
		raw := "this is not JSON"
		l.rawIndex = &raw
	}})

	if c := s.report(t).check(t, CheckRekorInclusion); c.Result != Unavailable {
		t.Fatalf("check 2 = %s (%s), want %s", c.Result, c.Detail, Unavailable)
	}
}

func TestCheckTwoIsUnavailableWhenTheLogsKeyDoesNotParse(t *testing.T) {
	s := newScenario(t, scenarioOptions{logSetup: func(l *fakeLog) {
		l.rawKey = []byte("-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n")
	}})

	if c := s.report(t).check(t, CheckRekorInclusion); c.Result != Unavailable {
		t.Fatalf("check 2 = %s (%s), want %s", c.Result, c.Detail, Unavailable)
	}
}

func TestCheckTwoIsUnavailableWhenTheEntryIsNotYetIntegrated(t *testing.T) {
	s := newScenario(t, scenarioOptions{logSetup: func(l *fakeLog) {
		l.mutateEntry = func(e map[string]any) {
			delete(nested(e, "verification"), "inclusionProof")
		}
	}})

	c := s.report(t).check(t, CheckRekorInclusion)
	if c.Result != Unavailable {
		t.Fatalf("check 2 = %s (%s), want %s", c.Result, c.Detail, Unavailable)
	}
	if !strings.Contains(c.Detail, "not yet integrated") {
		t.Errorf("detail = %q, want it to say the entry is not yet integrated", c.Detail)
	}
}

func TestCheckTwoBitesOnASignedEntryTimestampThatDoesNotVerify(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"not base64", "!!!not base64!!!"},
		{"a signature from nobody", base64.StdEncoding.EncodeToString([]byte("nope"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{logSetup: func(l *fakeLog) {
				l.mutateEntry = func(e map[string]any) {
					nested(e, "verification")["signedEntryTimestamp"] = tc.value
				}
			}})
			if c := s.report(t).check(t, CheckRekorInclusion); c.Result != Failed {
				t.Fatalf("check 2 = %s (%s), want %s", c.Result, c.Detail, Failed)
			}
		})
	}
}

func TestCheckTwoIsFailedWhenTheLogAnswersWithSomebodyElsesEntry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeLog)
	}{
		{"the response is not a log entry map", func(l *fakeLog) {
			l.mutateEntry = func(map[string]any) {}
		}},
		{"the response is keyed by another uuid", func(l *fakeLog) {
			l.entryKey = func(string) string { return strings.Repeat("cd", 32) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{logSetup: tc.setup})
			if tc.name == "the response is not a log entry map" {
				s.log.entries[s.log.onlyEntryUUID()] = json.RawMessage("not JSON at all")
			}
			if c := s.report(t).check(t, CheckRekorInclusion); c.Result != Failed {
				t.Fatalf("check 2 = %s (%s), want %s", c.Result, c.Detail, Failed)
			}
		})
	}
}

// entryIsForCommit is the join between a commit and the log, and it is the
// whole anti-vacuity argument for check 2. Each case breaks exactly one of the
// things it establishes.
func TestEntryIsForCommitRefusesEveryEntryThatIsNotThisCommits(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	lf := ca.issue(t, fixtureIdentity, now.Add(-time.Minute), now.Add(time.Hour))
	other := ca.issue(t, fixtureIdentity, now.Add(-time.Minute), now.Add(time.Hour))

	const commitSHA = "0123456789abcdef0123456789abcdef01234567"
	digest := sha256.Sum256([]byte(commitSHA))
	want := fmt.Sprintf("%x", digest)
	good := signArtifact(t, lf.key, digest[:])

	entryWith := func(mutate func(map[string]any)) logEntry {
		body := fixtureRekordBody(t, want, good, lf.pem, mutate)
		return logEntry{Body: base64.StdEncoding.EncodeToString(body)}
	}

	cases := []struct {
		name  string
		entry logEntry
		want  string
	}{
		{"the body is not base64", logEntry{Body: "!!!"}, "not base64"},
		{"the body is not JSON",
			logEntry{Body: base64.StdEncoding.EncodeToString([]byte("nope"))}, "not JSON"},
		{"the entry is another kind", entryWith(func(e map[string]any) {
			e["kind"] = "intoto"
		}), "not a hashedrekord"},
		{"the artifact is another commit's", entryWith(func(e map[string]any) {
			nested(e, "spec", "data", "hash")["value"] =
				strings.Repeat("aa", 32)
		}), "this commit's is"},
		{"the public key is not base64", entryWith(func(e map[string]any) {
			nested(e, "spec", "signature", "publicKey")["content"] = "!!!"
		}), "public key is not base64"},
		{"the public key is not PEM", entryWith(func(e map[string]any) {
			nested(e, "spec", "signature", "publicKey")["content"] =
				base64.StdEncoding.EncodeToString([]byte("nope"))
		}), "public key is not PEM"},
		{"the public key is not a certificate", entryWith(func(e map[string]any) {
			nested(e, "spec", "signature", "publicKey")["content"] =
				base64.StdEncoding.EncodeToString(pem.EncodeToMemory(
					&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
		}), "not a certificate"},
		{"the entry was logged under another certificate", entryWith(func(e map[string]any) {
			nested(e, "spec", "signature", "publicKey")["content"] =
				base64.StdEncoding.EncodeToString(other.pem)
		}), "logged under a different certificate"},
		{"the signature is not base64", entryWith(func(e map[string]any) {
			nested(e, "spec", "signature")["content"] = "!!!"
		}), "signature is not base64"},
		{"the signature is another key's", entryWith(func(e map[string]any) {
			nested(e, "spec", "signature")["content"] =
				base64.StdEncoding.EncodeToString(signArtifact(t, other.key, digest[:]))
		}), "does not verify under the certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := entryIsForCommit(tc.entry, want, digest[:], lf.cert)
			if err == nil {
				t.Fatalf("entryIsForCommit accepted an entry where %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// And the good one is accepted, or every case above passes vacuously.
	if _, err := entryIsForCommit(entryWith(nil), want, digest[:], lf.cert); err != nil {
		t.Fatalf("entryIsForCommit refused this commit's own entry: %v", err)
	}
}

// The signature over the artifact is checked with the standard library, under
// whatever key Fulcio issued. Three key types, three outcomes.
func TestVerifyDigestSignatureAcceptsWhatFulcioIssuesAndNothingElse(t *testing.T) {
	digest := sha256.Sum256([]byte("innsegl"))

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecSig, err := ecdsa.SignASN1(rand.Reader, ec, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if verr := verifyDigestSignature(&ec.PublicKey, digest[:], ecSig); verr != nil {
		t.Errorf("a valid ECDSA signature was refused: %v", verr)
	}
	if verr := verifyDigestSignature(&ec.PublicKey, digest[:], []byte("nope")); verr == nil {
		t.Error("an invalid ECDSA signature was accepted")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if verr := verifyDigestSignature(&rsaKey.PublicKey, digest[:], rsaSig); verr != nil {
		t.Errorf("a valid RSA signature was refused: %v", verr)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if verr := verifyDigestSignature(pub, digest[:], nil); verr == nil {
		t.Error("an Ed25519 key was accepted; the verifier must say it cannot check it " +
			"rather than report a verdict it did not reach")
	}
}

func TestVerifyEntryTimestampRefusesWhatItCannotRead(t *testing.T) {
	log := newFakeLog(t)
	if err := verifyEntryTimestamp(logEntry{}, &log.key.PublicKey); err == nil {
		t.Error("an entry with no signed timestamp was accepted")
	}
	entry := logEntry{Body: base64.StdEncoding.EncodeToString([]byte("{}"))}
	entry.Verification.SignedEntryTimestamp = "!!!"
	if err := verifyEntryTimestamp(entry, &log.key.PublicKey); err == nil {
		t.Error("a signed timestamp that is not base64 was accepted")
	}
}

// ---------------------------------------------------------------------------
// Check 3's remaining refusals, and the claim reader's.
// ---------------------------------------------------------------------------

func TestCheckThreeFailsOnASignedCommitWhoseClaimCannotBeResolved(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    string
	}{
		{"two claims", "subject\n\nAgent-Identity: " + fixtureIdentity +
			"\nAgent-Identity: spiffe://innsegl.dev/agent/demo/rm-037/run-2\n", "2 Agent-Identity"},
		{"no identity at all", "subject\n\nAgent-Run: run-1\n", "no Agent-Identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{message: tc.message})
			rep := s.report(t)
			c := rep.check(t, CheckTrailerIdentity)
			if c.Result != Failed {
				t.Fatalf("check 3 = %s (%s), want %s", c.Result, c.Detail, Failed)
			}
			if !strings.Contains(c.Detail, tc.want) {
				t.Errorf("detail = %q, want it to mention %q", c.Detail, tc.want)
			}
		})
	}
}

func TestCheckThreeFailsWhenTheRedundantTrailersDisagreeWithTheCertificate(t *testing.T) {
	cases := []struct {
		name    string
		run     string
		task    string
		wantKey string
	}{
		{"the run trailer names another run", "run-9", "rm-037", trailerAgentRun},
		{"the task trailer names another task", "run-1", "rm-999", trailerAgentTask},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{
				message: "subject\n\nAgent-Identity: " + fixtureIdentity +
					"\nAgent-Run: " + tc.run + "\nAgent-Task: " + tc.task + "\n",
			})
			c := s.report(t).check(t, CheckTrailerIdentity)
			if c.Result != Failed {
				t.Fatalf("check 3 = %s (%s), want %s", c.Result, c.Detail, Failed)
			}
			if !strings.Contains(c.Detail, tc.wantKey) {
				t.Errorf("detail = %q, want it to name the %s trailer", c.Detail, tc.wantKey)
			}
		})
	}
}

// A certificate whose SAN is not a SPIFFE ID at all: the redundant-trailer
// check has nothing to compare its Run/Task trailers' segments against, and
// (#137) must say so rather than treating an identity it cannot parse as one
// that agrees. A claim carrying neither trailer has nothing to check either
// way, parseable identity or not, and stays silent.
func TestTheRedundantTrailerCheckFailsClosedWhenTheSANHasNoGrammar(t *testing.T) {
	const nonSPIFFE = "https://example.com/not-spiffe"
	if got := (Claim{}).disagreesWith(nonSPIFFE); got != "" {
		t.Errorf("disagreesWith an empty claim against a non-SPIFFE SAN = %q, want \"\"", got)
	}
	if got := (Claim{}).disagreesWith(fixtureIdentity); got != "" {
		t.Errorf("disagreesWith an empty claim = %q, want \"\"", got)
	}

	cases := []struct {
		name  string
		claim Claim
	}{
		{"run trailer present", Claim{Run: "run-1"}},
		{"task trailer present", Claim{Task: "rm-037"}},
		{"both trailers present", Claim{Run: "run-1", Task: "rm-037"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.claim.disagreesWith(nonSPIFFE)
			if got == "" {
				t.Fatalf("disagreesWith(%q) = \"\", want a fail-closed message naming what "+
					"could not be checked", nonSPIFFE)
			}
			if strings.Contains(got, "disagree") {
				t.Errorf("message = %q, implies a disagreement that was never established", got)
			}
			if !strings.Contains(got, "SPIFFE") {
				t.Errorf("message = %q, want it to say the identity could not be read as a SPIFFE ID", got)
			}
		})
	}
}

// VER-008: check 3 fails closed end to end when the certificate's URI SAN is
// not a SPIFFE ID at all, so the redundant Agent-Run and Agent-Task trailers
// cannot be confirmed against it — the scenario ADR-0042 measured (#137):
// bogus Agent-Run and Agent-Task trailers next to an Agent-Identity trailer
// that is byte-identical to a non-SPIFFE SAN, which lets DiffIdentity's
// string-equality short circuit skip straight to disagreesWith. Before this
// fix, an identity disagreesWith could not parse was treated as one that
// agrees, and the commit verified with two of its three trailers never
// checked.
func TestCheckThreeFailsClosedWhenTheCertificateSANIsNotASPIFFEID(t *testing.T) {
	const nonSPIFFE = "https://github.com/Raymalian/innsegl/.github/workflows/sign.yml@refs/heads/main"
	s := newScenario(t, scenarioOptions{
		identity: nonSPIFFE,
		message: "VER-008: a commit signed under a non-SPIFFE certificate\n\n" +
			"Agent-Identity: " + nonSPIFFE + "\n" +
			"Agent-Run: totally-bogus-run\n" +
			"Agent-Task: totally-bogus-task\n",
	})
	c := s.report(t).check(t, CheckTrailerIdentity)
	if c.Result != Failed {
		t.Fatalf("check 3 = %s (%s), want %s: a non-SPIFFE certificate identity must not "+
			"let the Agent-Run and Agent-Task trailers go unchecked", c.Result, c.Detail, Failed)
	}
	if strings.Contains(c.Detail, "disagree") {
		t.Errorf("detail = %q, implies the trailers disagreed with something; they were "+
			"never checked", c.Detail)
	}
	if !strings.Contains(c.Detail, "SPIFFE") {
		t.Errorf("detail = %q, want it to say the certificate's identity could not be read "+
			"as a SPIFFE ID", c.Detail)
	}
	if !strings.Contains(c.Detail, trailerAgentRun) || !strings.Contains(c.Detail, trailerAgentTask) {
		t.Errorf("detail = %q, want it to name both trailers that could not be checked", c.Detail)
	}
}

func TestTheClaimReaderIgnoresALineThatOnlyLooksLikeATrailer(t *testing.T) {
	claim, err := ReadClaim("subject\n\nAgent-Identity has no colon on this line\n")
	if err != nil {
		t.Fatalf("ReadClaim: %v", err)
	}
	if claim.Present() {
		t.Errorf("a line with no separator was read as a trailer: %+v", claim)
	}
}

func TestDiffIdentityFallsBackWhenEitherSideHasNoGrammar(t *testing.T) {
	cases := []struct{ trailer, certificate string }{
		{"not-a-uri", fixtureIdentity},
		{fixtureIdentity, "not-a-uri"},
		{"spiffe://innsegl.dev/agent/demo", fixtureIdentity},
	}
	for _, tc := range cases {
		got := DiffIdentity(tc.trailer, tc.certificate)
		if !strings.Contains(got, "cannot be compared segment by segment") {
			t.Errorf("DiffIdentity(%q, %q) = %q, want the ungrammatical fallback",
				tc.trailer, tc.certificate, got)
		}
	}
}

// ---------------------------------------------------------------------------
// VER-003's recovery, in the small.
// ---------------------------------------------------------------------------

// recoveryScenario builds a repository with a signed commit and a rewritten
// one carrying the same tree, and a log that knows the original.
func recoveryScenario(t *testing.T) (*scenario, string) {
	t.Helper()
	s := newScenario(t, scenarioOptions{})
	// A third commit over a DIFFERENT tree — git's empty tree — so the walk
	// has something to step past rather than matching everything it sees.
	writeCommit(t, s.repo, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "",
		"an unrelated commit over another tree\n", nil)
	rewritten := writeCommit(t, s.repo, s.tree, "",
		"a rewrite of the same tree\n\nAgent-Identity: "+fixtureIdentity+"\n", nil)
	return s, rewritten
}

func TestRecoveryFindsTheOriginalThroughTheTreeHash(t *testing.T) {
	s, rewritten := recoveryScenario(t)

	rep, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
	if len(rep.Recovered) != 1 || rep.Recovered[0].CommitSHA != s.commit {
		t.Fatalf("recovered %+v, want the original %s\n%s", rep.Recovered, s.commit, Render(rep))
	}
	if rep.Recovered[0].Identity != fixtureIdentity {
		t.Errorf("the recovered identity is %q, want %q", rep.Recovered[0].Identity, fixtureIdentity)
	}
	if !strings.Contains(Render(rep), "recovered") {
		t.Errorf("the rendered report does not show the recovery:\n%s", Render(rep))
	}
}

func TestRecoveryReportsWhatItCouldNotDo(t *testing.T) {
	t.Run("the object database cannot be walked", func(t *testing.T) {
		s, rewritten := recoveryScenario(t)
		git := fakeGit(t)
		t.Setenv("INNSEGL_FAKEGIT_FAIL", "--batch-all-objects")
		v := s.verifier(t)
		v.cfg.GitPath = git
		rep, err := v.Verify(t.Context(), s.repo, rewritten)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !strings.Contains(strings.Join(rep.Notes, " "), "could not be walked") {
			t.Errorf("notes = %q, want one saying the object database could not be walked",
				rep.Notes)
		}
	})

	t.Run("a listed object cannot be read back", func(t *testing.T) {
		s, rewritten := recoveryScenario(t)
		git := fakeGit(t)
		t.Setenv("INNSEGL_FAKEGIT_FAIL", "cat-file commit "+s.commit)
		v := s.verifier(t)
		v.cfg.GitPath = git
		rep, err := v.Verify(t.Context(), s.repo, rewritten)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(rep.Recovered) != 0 {
			t.Errorf("an unreadable object was still recovered: %+v", rep.Recovered)
		}
	})

	t.Run("the walk is bounded", func(t *testing.T) {
		s, rewritten := recoveryScenario(t)
		old := maxTreeScan
		maxTreeScan = 1
		t.Cleanup(func() { maxTreeScan = old })
		if _, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("the same tree is in the repository but not in the log", func(t *testing.T) {
		s := newScenario(t, scenarioOptions{noEntry: true})
		rewritten := writeCommit(t, s.repo, s.tree, "",
			"a rewrite\n\nAgent-Identity: "+fixtureIdentity+"\n", nil)
		rep, err := s.verifier(t).Verify(t.Context(), s.repo, rewritten)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(rep.Recovered) != 0 {
			t.Errorf("attribution was recovered from a log that holds nothing: %+v", rep.Recovered)
		}
		if !strings.Contains(strings.Join(rep.Notes, " "), "holds no entry for any of them") {
			t.Errorf("notes = %q, want one saying the log holds nothing for the candidates",
				rep.Notes)
		}
	})
}

// attributionOf reads a certificate out of a log entry. Each case breaks one
// step of that read; none of them may be reported as a recovered attribution.
func TestAttributionOfRefusesEveryUnreadableEntry(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(*fakeLog)
		breakIt func(*testing.T, *fakeLog)
	}{
		{"the entry endpoint is unreachable", nil, func(_ *testing.T, l *fakeLog) { l.failEntry = true }},
		{"the entry response is not JSON", nil, func(_ *testing.T, l *fakeLog) {
			l.entries[l.onlyEntryUUID()] = json.RawMessage("not JSON")
		}},
		{"the entry is keyed by another uuid",
			func(l *fakeLog) { l.entryKey = func(string) string { return strings.Repeat("ef", 32) } },
			nil},
		{"the entry's certificate cannot be read",
			func(l *fakeLog) {
				l.mutateBody = func(e map[string]any) {
					nested(e, "spec", "signature", "publicKey")["content"] = "!!!"
				}
			}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{logSetup: tc.setup})
			if tc.breakIt != nil {
				tc.breakIt(t, s.log)
			}
			if _, ok := s.verifier(t).attributionOf(t.Context(), s.commit); ok {
				t.Fatalf("attributionOf claimed an attribution where %s", tc.name)
			}
		})
	}

	// The good case, so the refusals above are not vacuous.
	s := newScenario(t, scenarioOptions{})
	got, ok := s.verifier(t).attributionOf(t.Context(), s.commit)
	if !ok || got.Identity != fixtureIdentity {
		t.Fatalf("attributionOf(%s) = %+v, %v; want the identity the log holds", s.commit, got, ok)
	}
}

func TestIdentityOfEntryRefusesEveryUnreadableBody(t *testing.T) {
	ca := newTestCA(t)
	now := time.Now()
	lf := ca.issue(t, fixtureIdentity, now.Add(-time.Minute), now.Add(time.Hour))
	noSAN := ca.pem

	body := func(mutate func(map[string]any)) logEntry {
		raw := fixtureRekordBody(t, strings.Repeat("ab", 32), []byte("sig"), lf.pem, mutate)
		return logEntry{Body: base64.StdEncoding.EncodeToString(raw)}
	}
	pk := func(e map[string]any, value string) {
		nested(e, "spec", "signature", "publicKey")["content"] = value
	}

	cases := []struct {
		name  string
		entry logEntry
	}{
		{"the body is not base64", logEntry{Body: "!!!"}},
		{"the body is not JSON", logEntry{Body: base64.StdEncoding.EncodeToString([]byte("nope"))}},
		{"the key is not base64", body(func(e map[string]any) { pk(e, "!!!") })},
		{"the key is not PEM", body(func(e map[string]any) {
			pk(e, base64.StdEncoding.EncodeToString([]byte("nope")))
		})},
		{"the key is not a certificate", body(func(e map[string]any) {
			pk(e, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})))
		})},
		{"the certificate carries no URI SAN", body(func(e map[string]any) {
			pk(e, base64.StdEncoding.EncodeToString(noSAN))
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := identityOfEntry(tc.entry); err == nil {
				t.Fatalf("identityOfEntry accepted an entry where %s", tc.name)
			}
		})
	}
	if got, err := identityOfEntry(body(nil)); err != nil || got != fixtureIdentity {
		t.Fatalf("identityOfEntry(a good entry) = %q, %v", got, err)
	}
}

// ---------------------------------------------------------------------------
// Configuration and rendering.
// ---------------------------------------------------------------------------

func TestNewRefusesAnEndpointWithNoScheme(t *testing.T) {
	if _, err := New(Config{FulcioURL: "example.com", RekorURL: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("New accepted a Fulcio endpoint with no scheme")
	}
}

func TestNewKeepsWhatItIsGivenAndFillsInWhatItIsNot(t *testing.T) {
	given, err := New(Config{
		FulcioURL:  "http://127.0.0.1:1",
		RekorURL:   "http://127.0.0.1:2",
		GitPath:    "/usr/bin/git",
		Skew:       5 * time.Second,
		HTTPClient: &http.Client{Timeout: time.Second},
		Now:        func() time.Time { return time.Unix(0, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if given.cfg.GitPath != "/usr/bin/git" || given.cfg.Skew != 5*time.Second {
		t.Errorf("New overwrote what it was given: %+v", given.cfg)
	}
	if given.cfg.HTTPClient.Timeout != time.Second {
		t.Errorf("New replaced the HTTP client it was given")
	}

	filled, err := New(Config{FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:2"})
	if err != nil {
		t.Fatal(err)
	}
	if filled.cfg.GitPath != "git" || filled.cfg.Skew != DefaultSkew ||
		filled.cfg.Now == nil || filled.cfg.HTTPClient == nil {
		t.Errorf("New left a default unfilled: %+v", filled.cfg)
	}
}

func TestRenderJSONReportsAnEncoderFailureRatherThanReturningNothing(t *testing.T) {
	old := marshalIndent
	marshalIndent = func(any, string, string) ([]byte, error) {
		return nil, errors.New("the encoder refused")
	}
	t.Cleanup(func() { marshalIndent = old })

	if _, err := RenderJSON(Report{}); err == nil {
		t.Fatal("RenderJSON swallowed an encoder failure")
	}
}

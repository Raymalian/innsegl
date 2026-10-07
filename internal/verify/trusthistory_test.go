// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
)

// ADR-0073: trust roots are kept as an append-only history.
//
// Every case is a real rotation. Root A issued the commit's certificate; the
// deployment's Fulcio now publishes root B; the history is what says A was
// this deployment's too. Nothing is mocked but the two endpoints' transport.

// historyOf records the given material, in order, into a fresh history.
func historyOf(t *testing.T, at time.Time, items ...historyItem) *trusthistory.History {
	t.Helper()
	h := trusthistory.New()
	for _, it := range items {
		if _, err := h.Record(it.kind, it.pem, at); err != nil {
			t.Fatalf("recording %s: %v", it.kind, err)
		}
	}
	return h
}

type historyItem struct {
	kind trusthistory.Kind
	pem  []byte
}

func rootItem(ca *testCA) historyItem {
	return historyItem{trusthistory.KindFulcioRoot, ca.pem}
}

func logItem(l *fakeLog) historyItem {
	return historyItem{trusthistory.KindTransparencyLog, l.publicKeyPEM()}
}

// rotated is the commit signed under root A while Fulcio publishes root B.
func rotated(t *testing.T, opt scenarioOptions) *scenario {
	t.Helper()
	opt.foreignCA = true
	return newScenario(t, opt)
}

func TestACommitSignedUnderARetiredRootVerifiesOnceTheRootIsInTheHistory(t *testing.T) {
	s := rotated(t, scenarioOptions{})

	// Without the history this is exactly 2026-09-16: an unknown authority.
	if rep := s.report(t); rep.Verdict != VerdictFailed ||
		rep.check(t, CheckCertificateChain).Result != Failed {
		t.Fatalf("before the history: verdict %s, want failed on the chain\n%s", rep.Verdict, Render(rep))
	}

	s.history = historyOf(t, s.integrated, rootItem(s.issuing), rootItem(s.ca), logItem(s.log))
	rep := s.report(t)
	if rep.Verdict != VerdictVerified {
		t.Fatalf("verdict = %s, want verified\n%s", rep.Verdict, Render(rep))
	}
	chain := rep.check(t, CheckCertificateChain)
	if got := factValue(chain, FactTrustRootKeyID); got != keyID(t, s.issuing.pem) {
		t.Errorf("the chain check names root %q, want root A %s", got, keyID(t, s.issuing.pem))
	}
	if !strings.Contains(factValue(chain, "trust root"), "trust history") {
		t.Errorf("the chain check does not say the root came from the history: %+v", chain.Facts)
	}
}

func TestARootThatIsNotInTheHistoryStillFails(t *testing.T) {
	s := rotated(t, scenarioOptions{})
	stranger := newTestCA(t)
	s.history = historyOf(t, s.integrated, rootItem(stranger), rootItem(s.ca), logItem(s.log))

	rep := s.report(t)
	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed\n%s", rep.Verdict, Render(rep))
	}
	if c := rep.check(t, CheckCertificateChain); c.Result != Failed ||
		!strings.Contains(c.Detail, "chain to") {
		t.Errorf("chain check = %s (%s), want failed for an unknown authority", c.Result, c.Detail)
	}
}

func TestARevokedRootAcceptsOnlyWhatTheLogIntegratedBeforeTheRevocation(t *testing.T) {
	for _, c := range []struct {
		name    string
		revoked time.Duration // relative to the integration time
		want    Verdict
	}{
		{"revoked after the entry", time.Hour, VerdictVerified},
		{"revoked before the entry", -time.Hour, VerdictFailed},
		{"revoked at the entry", 0, VerdictFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := rotated(t, scenarioOptions{})
			h := historyOf(t, s.integrated, rootItem(s.issuing), rootItem(s.ca), logItem(s.log))
			at := s.integrated.Add(c.revoked)
			h.Entries[0].RevokedAt = &at
			s.history = h

			rep := s.report(t)
			if rep.Verdict != c.want {
				t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, c.want, Render(rep))
			}
			if c.want == VerdictFailed {
				chain := rep.check(t, CheckCertificateChain)
				if chain.Result != Failed || !strings.Contains(chain.Detail, "revoked") {
					t.Errorf("chain check = %s (%s), want failed naming the revocation", chain.Result, chain.Detail)
				}
			}
		})
	}
}

// The published root itself can be revoked: a compromised CA keeps serving
// its root until it is replaced, and the history is what says not to trust it.
func TestTheRevocationAppliesToThePublishedRootToo(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	h := historyOf(t, s.integrated, rootItem(s.ca), logItem(s.log))
	at := s.integrated.Add(-time.Hour)
	h.Entries[0].RevokedAt = &at
	s.history = h
	if rep := s.report(t); rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed\n%s", rep.Verdict, Render(rep))
	}
}

func TestARetiredRootRefusesWhatWasLoggedAfterItStoppedIssuing(t *testing.T) {
	s := rotated(t, scenarioOptions{})
	h := historyOf(t, s.integrated, rootItem(s.issuing), rootItem(s.ca), logItem(s.log))
	at := s.integrated.Add(-time.Hour)
	h.Entries[0].RetiredAt = &at
	s.history = h
	rep := s.report(t)
	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want failed\n%s", rep.Verdict, Render(rep))
	}
	if c := rep.check(t, CheckCertificateChain); !strings.Contains(c.Detail, "retired") {
		t.Errorf("chain detail %q does not name the retirement", c.Detail)
	}
}

// A root with an end date needs a time the log signed: without one there is
// no honest answer to "before or after".
func TestAnEndDatedRootWithNoSignedTimeIsUnavailable(t *testing.T) {
	s := rotated(t, scenarioOptions{omitSET: true})
	h := historyOf(t, s.integrated, rootItem(s.issuing), rootItem(s.ca), logItem(s.log))
	at := s.integrated.Add(time.Hour)
	h.Entries[0].RetiredAt = &at
	s.history = h
	rep := s.report(t)
	if c := rep.check(t, CheckCertificateChain); c.Result != Unavailable {
		t.Fatalf("chain check = %s (%s), want unavailable", c.Result, c.Detail)
	}
}

// otherLogKeyPEM is a log key the log does not sign with.
func otherLogKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestAnEntryUnderARotatedLogKeyVerifiesOnceTheKeyIsInTheHistory(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	signedWith := s.log.publicKeyPEM()
	// The log now publishes a different key. Its entries were signed under
	// the old one.
	s.log.rawKey = otherLogKeyPEM(t)

	if rep := s.report(t); rep.check(t, CheckRekorInclusion).Result != Failed {
		t.Fatalf("before the history the inclusion check = %s, want failed\n%s",
			rep.check(t, CheckRekorInclusion).Result, Render(rep))
	}

	s.history = historyOf(t, s.integrated, rootItem(s.ca),
		historyItem{trusthistory.KindTransparencyLog, signedWith})
	rep := s.report(t)
	if rep.Verdict != VerdictVerified {
		t.Fatalf("verdict = %s, want verified\n%s", rep.Verdict, Render(rep))
	}

	// Revoked before this entry was integrated: refused.
	at := s.integrated.Add(-time.Hour)
	s.history.Entries[1].RevokedAt = &at
	rep = s.report(t)
	if c := rep.check(t, CheckRekorInclusion); c.Result != Failed || !strings.Contains(c.Detail, "revoked") {
		t.Fatalf("inclusion check = %s (%s), want failed naming the revocation", c.Result, c.Detail)
	}
}

func TestAnEndDatedLogKeyWithNoSignedTimeIsUnavailable(t *testing.T) {
	s := newScenario(t, scenarioOptions{omitSET: true})
	h := historyOf(t, s.integrated, rootItem(s.ca), logItem(s.log))
	at := s.integrated.Add(time.Hour)
	h.Entries[1].RetiredAt = &at
	s.history = h
	if c := s.report(t).check(t, CheckRekorInclusion); c.Result != Unavailable {
		t.Fatalf("inclusion check = %s (%s), want unavailable", c.Result, c.Detail)
	}
}

// ---------------------------------------------------------------------------
// The pre-history verdict.
// ---------------------------------------------------------------------------

// preHistoryScenario is a commit signed under a root that is gone, whose log is gone,
// from before the history began.
func preHistoryScenario(t *testing.T, opt scenarioOptions) *scenario {
	t.Helper()
	opt.noEntry = true
	s := rotated(t, opt)
	// The history began a week after this commit was signed, with root B only.
	began := s.integrated.AddDate(0, 0, 7)
	s.history = trusthistory.New()
	s.history.Entries = append(s.history.Entries, trusthistory.Entry{
		Kind: trusthistory.KindFulcioRoot, KeyID: keyID(t, s.ca.pem),
		PublicPEM: string(s.ca.pem), FirstUsed: began,
	})
	// The operator named root A as lost: its key id is the Authority Key
	// Identifier A's certificates carry.
	if _, err := s.history.RecordLost(hex.EncodeToString(s.issuing.cert.SubjectKeyId), began,
		"the trust volumes were recreated"); err != nil {
		t.Fatal(err)
	}
	return s
}

func keyID(t *testing.T, p []byte) string {
	t.Helper()
	id, err := trusthistory.KeyIDOf(p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestACommitSignedBeforeTheHistoryBeganHasItsOwnVerdict(t *testing.T) {
	s := preHistoryScenario(t, scenarioOptions{})
	rep := s.report(t)

	if rep.Verdict != VerdictPreHistory {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictPreHistory, Render(rep))
	}
	// Not a pass and not a failure: the two checks whose evidence is gone are
	// unavailable, and the one that can still be checked still is.
	for name, want := range map[string]Result{
		CheckCertificateChain: Unavailable,
		CheckRekorInclusion:   Unavailable,
		CheckTrailerIdentity:  Verified,
	} {
		if got := rep.check(t, name); got.Result != want {
			t.Errorf("%s = %s (%s), want %s", name, got.Result, got.Detail, want)
		}
	}
	note := strings.Join(rep.Notes, "\n")
	began := s.history.Began().Format(time.DateOnly)
	if !strings.Contains(note, "signed before this deployment's trust history began ("+began+"); cannot be verified") {
		t.Errorf("the notes do not carry the pre-history wording:\n%s", note)
	}
	if out := Render(rep); !strings.Contains(out, "PRE-HISTORY") {
		t.Errorf("the rendered report does not show the verdict:\n%s", out)
	}
}

func TestThePreHistoryVerdictIsNeverGivenToTampering(t *testing.T) {
	cases := map[string]func(t *testing.T) *scenario{
		"signed inside the history": func(t *testing.T) *scenario {
			s := preHistoryScenario(t, scenarioOptions{})
			s.history.Entries[0].FirstUsed = s.integrated.AddDate(0, 0, -7)
			return s
		},
		"a trailer that does not match the certificate": func(t *testing.T) *scenario {
			return preHistoryScenario(t, scenarioOptions{
				trailerIdentity: "spiffe://" + fixtureTrustDomain + "/agent/demo/rm-037/run-2",
			})
		},
		// A forged, backdated certificate from a CA nobody named as lost: it
		// stays failed. Only a named era earns the pre-history label.
		"an unknown root that is not a lost one": func(t *testing.T) *scenario {
			s := preHistoryScenario(t, scenarioOptions{})
			s.history.Entries = s.history.Entries[:1]
			return s
		},
		"a lost root named for another key": func(t *testing.T) *scenario {
			s := preHistoryScenario(t, scenarioOptions{})
			s.history.Entries = s.history.Entries[:1]
			if _, err := s.history.RecordLost(strings.Repeat("ab", 20), s.integrated, "another era"); err != nil {
				t.Fatal(err)
			}
			return s
		},
		"no trust history at all": func(t *testing.T) *scenario {
			s := preHistoryScenario(t, scenarioOptions{})
			s.history = nil
			return s
		},
		"an empty trust history": func(t *testing.T) *scenario {
			s := preHistoryScenario(t, scenarioOptions{})
			s.history = trusthistory.New()
			return s
		},
		"a log entry whose signature is not the certificate's": func(t *testing.T) *scenario {
			s := rotated(t, scenarioOptions{entrySignedByAnother: true})
			s.history = trusthistory.New()
			s.history.Entries = append(s.history.Entries, trusthistory.Entry{
				Kind: trusthistory.KindFulcioRoot, KeyID: keyID(t, s.ca.pem),
				PublicPEM: string(s.ca.pem), FirstUsed: s.integrated.AddDate(0, 0, 7),
			})
			return s
		},
		"a log that could not be searched": func(t *testing.T) *scenario {
			s := preHistoryScenario(t, scenarioOptions{})
			s.log.failIndex = true
			return s
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			rep := build(t).report(t)
			if rep.Verdict == VerdictPreHistory || rep.Verdict == VerdictVerified {
				t.Fatalf("verdict = %s, want failed or unavailable\n%s", rep.Verdict, Render(rep))
			}
		})
	}
}

func factValue(c Check, name string) string {
	for _, f := range c.Facts {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// What the published root endpoint and the history may carry beside the
// material that matters: a block that is not a certificate, a certificate that
// does not parse, a log key segment's reader does not accept. Each is skipped,
// and the commit still verifies on what is real.
func TestMaterialThatIsNotARootOrALogKeyIsSkipped(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	var body []byte
	body = append(body, otherLogKeyPEM(t)...)
	body = append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}})...)
	body = append(body, s.ca.pem...)
	s.fulcio.body = body

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(edKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	s.history = historyOf(t, s.integrated, rootItem(s.ca), logItem(s.log),
		historyItem{trusthistory.KindTransparencyLog, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})})

	if rep := s.report(t); rep.Verdict != VerdictVerified {
		t.Fatalf("verdict = %s, want verified\n%s", rep.Verdict, Render(rep))
	}
}

// A proof that verifies under none of the keys fails, and the error reported
// is the published key's: that is the key a reader expects to be told about.
func TestAProofThatVerifiesUnderNoKeyInTheHistoryFails(t *testing.T) {
	s := newScenario(t, scenarioOptions{tamperProof: true})
	s.history = historyOf(t, s.integrated, rootItem(s.ca), logItem(s.log),
		historyItem{trusthistory.KindTransparencyLog, otherLogKeyPEM(t)})
	rep := s.report(t)
	if c := rep.check(t, CheckRekorInclusion); c.Result != Failed ||
		!strings.Contains(c.Detail, "inclusion proof does not verify") {
		t.Fatalf("inclusion check = %s (%s), want failed", c.Result, c.Detail)
	}
}

// WithHistory leaves the verifier it was called on as it was.
func TestWithHistoryDoesNotChangeTheReceiver(t *testing.T) {
	s := rotated(t, scenarioOptions{})
	base := s.verifier(t)
	h := historyOf(t, s.integrated, rootItem(s.issuing), logItem(s.log))
	if rep, err := base.WithHistory(h).Verify(t.Context(), s.repo, s.commit); err != nil || rep.Verdict != VerdictVerified {
		t.Fatalf("with the history: %v, %v", rep.Verdict, err)
	}
	if rep, err := base.Verify(t.Context(), s.repo, s.commit); err != nil || rep.Verdict != VerdictFailed {
		t.Fatalf("the receiver after WithHistory: %v, %v; want failed", rep.Verdict, err)
	}
}

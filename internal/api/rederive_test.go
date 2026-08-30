// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// API-005 — a tampered BFF is convicted by re-derivation from the material it
// returned.
//
// This is #48's headline criterion, and it is the one that decides whether the
// response is a proof or a press release: "a response whose 'proof' cannot
// convict a lying server is not a proof."
//
// Each case below takes an HONEST response, changes exactly one thing a lying
// server would want to change, and requires the named finding to contradict.
// The control case at the end is not optional: a checker that convicted
// everything would pass every row above and establish nothing.

// forged builds a scenario whose Agent-Identity trailer names a run the
// certificate does not prove — the forgery VER-002 is about.
func forgedTrailer(t *testing.T) *proofScenario {
	t.Helper()
	return newProofScenario(t, proofOptions{
		trailerIdentity: "spiffe://" + fixtureTrustDomain + "/agent/fix-ci/rm-040/run-999",
	})
}

func proofOf(t *testing.T, s *proofScenario) Proof {
	t.Helper()
	p, err := s.prover(t).Prove(t.Context(), fixtureRepo, s.commit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	return p
}

// findingNamed returns the named finding, failing if the re-derivation did not
// produce one.
func findingNamed(t *testing.T, findings []Finding, name string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.Name == name {
			return f
		}
	}
	var names []string
	for _, f := range findings {
		names = append(names, f.Name)
	}
	t.Fatalf("no finding named %q; the re-derivation produced %v", name, names)
	return Finding{}
}

func TestAPI005ATamperedBFFIsConvictedByRederivationFromItsOwnMaterial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		build  func(t *testing.T) *proofScenario
		tamper func(t *testing.T, s *proofScenario, p *Proof)
		expect string
	}{
		{
			name:  "the verdict is flipped to verified while a check says failed",
			build: forgedTrailer,
			tamper: func(t *testing.T, _ *proofScenario, p *Proof) {
				if p.Verdict != string(verify.VerdictFailed) {
					t.Fatalf("the honest verdict on a forged trailer is %q, want failed", p.Verdict)
				}
				p.Verdict = string(verify.VerdictVerified)
			},
			expect: FindingRollup,
		},
		{
			name:  "a failing check is reported as verified",
			build: forgedTrailer,
			tamper: func(t *testing.T, _ *proofScenario, p *Proof) {
				for i := range p.Checks {
					if p.Checks[i].Name == verify.CheckTrailerIdentity {
						p.Checks[i].Result = verify.Verified
					}
				}
				p.Verdict = string(verify.VerdictVerified)
			},
			expect: FindingIdentityCheck,
		},
		{
			name:  "the reported trailer is rewritten to match the certificate",
			build: forgedTrailer,
			tamper: func(_ *testing.T, s *proofScenario, p *Proof) {
				p.Claim.Identity = fixtureIdentity
				_ = s
			},
			expect: FindingTrailerClaim,
		},
		{
			name:  "the certificate is swapped for one the log never recorded",
			build: func(t *testing.T) *proofScenario { return newProofScenario(t, proofOptions{}) },
			tamper: func(t *testing.T, s *proofScenario, p *Proof) {
				other := s.ca.issue(t, "spiffe://"+fixtureTrustDomain+"/agent/fix-ci/rm-040/run-2",
					s.integrated.Add(-time.Minute), s.integrated.Add(time.Minute))
				p.Material.CertificatePEM = string(other.pem)
			},
			expect: FindingCertificate,
		},
		{
			name:  "the reported identity is rewritten under an honest certificate",
			build: func(t *testing.T) *proofScenario { return newProofScenario(t, proofOptions{}) },
			tamper: func(_ *testing.T, _ *proofScenario, p *Proof) {
				p.Certificate.SPIFFEID = "spiffe://" + fixtureTrustDomain + "/agent/fix-ci/rm-040/run-7"
			},
			expect: FindingCertificate,
		},
		{
			name:  "a different commit object is served under the requested SHA",
			build: func(t *testing.T) *proofScenario { return newProofScenario(t, proofOptions{}) },
			tamper: func(_ *testing.T, _ *proofScenario, p *Proof) {
				p.Material.CommitObject = strings.Replace(p.Material.CommitObject,
					"RM-040: a commit under proof", "RM-040: something else entirely", 1)
			},
			expect: FindingCommitObject,
		},
		{
			name:  "the log index is rewritten",
			build: func(t *testing.T) *proofScenario { return newProofScenario(t, proofOptions{}) },
			tamper: func(_ *testing.T, _ *proofScenario, p *Proof) {
				p.Entry.LogIndex += 41
			},
			expect: FindingLogIndex,
		},
		{
			name:  "the artifact the entry is keyed on is not this commit's",
			build: func(t *testing.T) *proofScenario { return newProofScenario(t, proofOptions{}) },
			tamper: func(_ *testing.T, _ *proofScenario, p *Proof) {
				p.CommitSHA = strings.Repeat("0", 40)
			},
			expect: FindingArtifact,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.build(t)
			p := proofOf(t, s)

			// The honest response first: it must not convict anybody.
			if bad := Contradictions(Rederive(p)); len(bad) != 0 {
				t.Fatalf("the honest response is convicted before any tampering: %+v", bad)
			}

			tc.tamper(t, s, &p)
			findings := Rederive(p)
			got := findingNamed(t, findings, tc.expect)
			if got.Result != Contradicts {
				t.Errorf("%q reads %q after the tamper; a proof that cannot convict a "+
					"lying server is not a proof.\ndetail: %s\nall findings: %+v",
					tc.expect, got.Result, got.Detail, findings)
			}
			if got.Detail == "" {
				t.Errorf("%q contradicts with no detail; a reader cannot act on "+
					"\"mismatch\"", tc.expect)
			}
			if len(Contradictions(findings)) == 0 {
				t.Error("Contradictions() is empty although a finding contradicts")
			}
		})
	}
}

// The control. A checker that always convicts proves nothing, so the honest
// response must come back clean AND with every finding actually derived —
// "underivable" everywhere would also pass a contradiction count of zero.
func TestAnHonestProofIsFullyRederivedAndConvictsNobody(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	p := proofOf(t, s)

	findings := Rederive(p)
	if len(findings) < 7 {
		t.Fatalf("the re-derivation produced %d findings; every step FD §3.6 names "+
			"has to be re-derivable: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Result != Agrees {
			t.Errorf("%q is %q on an honest response with every upstream up: %s",
				f.Name, f.Result, f.Detail)
		}
	}
}

// A degraded response is UNDERIVABLE, never a contradiction. Convicting a
// server for material it honestly could not collect would make the checker
// useless precisely when FD P2 matters most.
func TestMissingMaterialIsUnderivableRatherThanAContradiction(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	prover := s.prover(t)
	s.fulcio.stop()
	s.log.stop()

	p, err := prover.Prove(t.Context(), fixtureRepo, s.commit)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	findings := Rederive(p)
	if bad := Contradictions(findings); len(bad) != 0 {
		t.Fatalf("an honestly degraded response was convicted: %+v", bad)
	}
	var underivable int
	for _, f := range findings {
		if f.Result == Underivable {
			underivable++
			if f.Detail == "" {
				t.Errorf("%q is underivable with no reason", f.Name)
			}
		}
	}
	if underivable == 0 {
		t.Error("nothing was reported underivable although Rekor and Fulcio were " +
			"both unreachable; a checker that silently agrees with absent material " +
			"is the cached-verified anti-pattern in another costume (FD 8.1)")
	}
	// What survives without an upstream is exactly what can be settled
	// offline: the object binding and the trailer.
	if f := findingNamed(t, findings, FindingCommitObject); f.Result != Agrees {
		t.Errorf("%q is %q, but the commit object needs no network", FindingCommitObject, f.Result)
	}
}

// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/signing"
)

// TC-VER, the unit half. The integration half is verifyintegration_test.go.
//
// Every case here asserts two things: that the verdict is what doc 07 says,
// and that it is that verdict FOR THE RIGHT REASON — the named check, with the
// evidence that settles it. "Verification passed" is worthless if the verifier
// would pass anything, so each check has a paired case that mutates exactly
// the input that check reads and requires it to bite.

// ---------------------------------------------------------------------------
// The good case. Everything else is a mutation of this, so if this is not
// green nothing below proves anything.
// ---------------------------------------------------------------------------

func TestAGoodCommitVerifiesOnAllThreeChecks(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	rep := s.report(t)

	if rep.Verdict != VerdictVerified {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictVerified, Render(rep))
	}
	for _, name := range []string{CheckCertificateChain, CheckRekorInclusion, CheckTrailerIdentity} {
		if got := rep.check(t, name); got.Result != Verified {
			t.Errorf("check %q = %s (%s), want %s", name, got.Result, got.Detail, Verified)
		}
	}
	if rep.Entry.LogIndex < 0 {
		t.Errorf("the report carries no log index; doc 06 §4.1 requires check 2 to show it")
	}
	if !strings.Contains(Render(rep), "log index") {
		t.Errorf("the rendered panel does not show the log index:\n%s", Render(rep))
	}
}

// ---------------------------------------------------------------------------
// VER-002 — a forged trailer. Valid signature, hand-edited Agent-Identity.
// doc 07: "Check 3 FAILS loudly; differing segment identified in output".
// ---------------------------------------------------------------------------

func TestVER002AForgedTrailerFailsCheckThreeAndNamesTheDifferingSegment(t *testing.T) {
	forged := "spiffe://" + fixtureTrustDomain + "/agent/demo/rm-037/run-9999"
	s := newScenario(t, scenarioOptions{trailerIdentity: forged})
	rep := s.report(t)

	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
	c := rep.check(t, CheckTrailerIdentity)
	if c.Result != Failed {
		t.Fatalf("check 3 = %s (%s), want %s", c.Result, c.Detail, Failed)
	}

	out := Render(rep)
	// Both values, side by side (doc 06 §4.1).
	if !strings.Contains(out, forged) || !strings.Contains(out, fixtureIdentity) {
		t.Errorf("the output does not show both the trailer and the certificate identity:\n%s", out)
	}
	// The DIFFERING SEGMENT, named. "mismatch" is not enough.
	if !strings.Contains(out, "run-id") {
		t.Errorf("the output does not name the differing segment (run-id):\n%s", out)
	}
	if !strings.Contains(out, "run-9999") || !strings.Contains(out, "run-1") {
		t.Errorf("the output does not show the two differing segment values:\n%s", out)
	}
}

func TestTheDifferingSegmentIsNamedForEveryPositionInTheGrammar(t *testing.T) {
	const cert = "spiffe://innsegl.dev/agent/demo/rm-037/run-1"
	cases := []struct {
		name    string
		trailer string
		want    string
	}{
		{"trust domain", "spiffe://other.example/agent/demo/rm-037/run-1", "trust-domain"},
		{"agent type", "spiffe://innsegl.dev/agent/other/rm-037/run-1", "agent-type"},
		{"task id", "spiffe://innsegl.dev/agent/demo/rm-999/run-1", "task-id"},
		{"run id", "spiffe://innsegl.dev/agent/demo/rm-037/run-2", "run-id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DiffIdentity(tc.trailer, cert)
			if got == "" {
				t.Fatalf("DiffIdentity(%q, %q) found no difference", tc.trailer, cert)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("DiffIdentity(%q, %q) = %q, want it to name %q",
					tc.trailer, cert, got, tc.want)
			}
		})
	}
	if got := DiffIdentity(cert, cert); got != "" {
		t.Errorf("DiffIdentity of two equal identities = %q, want no difference", got)
	}
}

// ---------------------------------------------------------------------------
// VER-004 — an expired certificate with a valid Rekor entry verifies.
// doc 07: "Verifies (Rekor timestamp within cert validity); expiry alone never
// fails a historical commit." IP §6.8.
//
// This is the case that makes the system work a year later, so the fixture's
// `now` is deliberately a year after the certificate died.
// ---------------------------------------------------------------------------

func TestVER004AnExpiredCertificateWithAValidRekorEntryVerifies(t *testing.T) {
	integrated := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	s := newScenario(t, scenarioOptions{
		integrated: integrated,
		notBefore:  integrated.Add(-time.Minute),
		notAfter:   integrated.Add(9 * time.Minute), // long dead by `now`
	})

	rep := s.report(t)

	if rep.Verdict != VerdictVerified {
		t.Fatalf("a commit whose certificate expired inside its Rekor window verified as %s; "+
			"expiry alone must never fail a historical commit (IP §6.8)\n%s",
			rep.Verdict, Render(rep))
	}
	c := rep.check(t, CheckCertificateChain)
	if c.Result != Verified {
		t.Fatalf("check 1 = %s (%s), want %s", c.Result, c.Detail, Verified)
	}
	// And it must say WHEN it evaluated the window, or the pass is unreadable.
	if !strings.Contains(Render(rep), integrated.Format(time.RFC3339)) {
		t.Errorf("the output does not show the log's integration time, which is the "+
			"moment the validity window was evaluated at:\n%s", Render(rep))
	}
}

// AND IT BITES: a certificate that was already dead when the log integrated
// the entry must fail, or VER-004 is just "never check expiry".
func TestACertificateDeadBeforeItsOwnLogEntryFails(t *testing.T) {
	integrated := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	s := newScenario(t, scenarioOptions{
		integrated: integrated,
		notBefore:  integrated.Add(-2 * time.Hour),
		notAfter:   integrated.Add(-time.Hour),
	})

	rep := s.report(t)

	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s: the certificate expired an hour before the "+
			"log integrated the entry\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
	if c := rep.check(t, CheckCertificateChain); c.Result != Failed {
		t.Errorf("check 1 = %s (%s), want %s", c.Result, c.Detail, Failed)
	}
}

// ---------------------------------------------------------------------------
// VER-005 — the clock-skew boundary, on both sides.
// doc 07: "Inside bound passes, outside fails; both sides tested." IP §6.8.
//
// The bound is DefaultSkew. It is a VERIFIER's tolerance and it is applied to
// nothing else: ADR-0031 decision 7 established that widening a CREDENTIAL's
// window by the same amount is extending its TTL, which IP §6.2 forbids.
// ---------------------------------------------------------------------------

func TestVER005ClockSkewBoundaryOnBothSides(t *testing.T) {
	integrated := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	bound := DefaultSkew

	cases := []struct {
		name string
		// offset of the certificate window relative to the integration time.
		notBefore, notAfter time.Duration
		want                Result
	}{
		{"integrated exactly at the bound before NotBefore", bound, bound + time.Hour, Verified},
		{"integrated one second past the bound before NotBefore", bound + time.Second, bound + time.Hour, Failed},
		{"integrated exactly at the bound after NotAfter", -time.Hour, -bound, Verified},
		{"integrated one second past the bound after NotAfter", -time.Hour, -bound - time.Second, Failed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{
				integrated: integrated,
				notBefore:  integrated.Add(tc.notBefore),
				notAfter:   integrated.Add(tc.notAfter),
			})
			rep := s.report(t)
			got := rep.check(t, CheckCertificateChain)
			if got.Result != tc.want {
				t.Fatalf("check 1 = %s (%s), want %s with a %s bound\n%s",
					got.Result, got.Detail, tc.want, bound, Render(rep))
			}
		})
	}
}

// The bound is documented once. A verifier that quietly widened it would be
// widening the window on every historical commit at the same time.
func TestTheSkewBoundIsTheOneADR0031Documents(t *testing.T) {
	if DefaultSkew != signing.DefaultSkew {
		t.Fatalf("verify.DefaultSkew = %s, signing.DefaultSkew = %s; IP §6.8 asks for "+
			"one documented bound, not two", DefaultSkew, signing.DefaultSkew)
	}
	if DefaultSkew != 60*time.Second {
		t.Fatalf("DefaultSkew = %s, ADR-0031 decision 7 documents 60s", DefaultSkew)
	}
}

// ---------------------------------------------------------------------------
// VER-006 — an unsigned commit is UNATTRIBUTED, never failed-verification.
// doc 07: "Reported as unattributed, never as failed-verification (distinct
// states)". Doc 06 anti-pattern 2 is the collapse this refuses.
// ---------------------------------------------------------------------------

func TestVER006AnUnsignedCommitReportsUnattributed(t *testing.T) {
	s := newScenario(t, scenarioOptions{
		unsigned: true,
		noEntry:  true,
		message:  "VER-006: an ordinary human commit\n",
	})

	rep := s.report(t)

	if rep.Verdict == VerdictFailed {
		t.Fatalf("an unsigned commit that makes no claim verified as %s; doc 06 "+
			"anti-pattern 2 is exactly this collapse\n%s", rep.Verdict, Render(rep))
	}
	if rep.Verdict != VerdictUnattributed {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictUnattributed, Render(rep))
	}
	if len(rep.Checks) != 0 {
		t.Errorf("the report ran %d checks on a commit that makes no attribution claim: %+v",
			len(rep.Checks), rep.Checks)
	}
	out := Render(rep)
	if !strings.Contains(strings.ToLower(out), "unattributed") {
		t.Errorf("the output does not say unattributed:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "failed") {
		t.Errorf("the output for an unattributed commit says \"failed\":\n%s", out)
	}
}

// AND IT BITES the other way: a commit that CLAIMS an identity and carries no
// signature is not unattributed. It is a claim nothing proves, which is a
// failure — collapsing it into "unattributed" would let anyone opt out of
// verification by deleting a signature.
func TestAnUnsignedCommitThatClaimsAnIdentityFails(t *testing.T) {
	s := newScenario(t, scenarioOptions{unsigned: true, noEntry: true})

	rep := s.report(t)

	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s: the commit carries Agent-Identity and no "+
			"signature\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
}

// ---------------------------------------------------------------------------
// Three states, never two. If Fulcio or Rekor cannot be reached that is
// UNAVAILABLE — never "failed", and never a cached verdict (doc 06 P2,
// IP §6.11).
// ---------------------------------------------------------------------------

func TestAnUnreachableFulcioIsUnavailableAndNeverFailed(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	s.fulcio.fail = true

	rep := s.report(t)

	if c := rep.check(t, CheckCertificateChain); c.Result != Unavailable {
		t.Fatalf("check 1 = %s (%s), want %s when Fulcio cannot be reached",
			c.Result, c.Detail, Unavailable)
	}
	if rep.Verdict != VerdictUnavailable {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictUnavailable, Render(rep))
	}
}

func TestAnUnreachableRekorIsUnavailableAndNeverFailed(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakeLog)
	}{
		{"the search index", func(l *fakeLog) { l.failIndex = true }},
		{"the entry endpoint", func(l *fakeLog) { l.failEntry = true }},
		{"the log's public key", func(l *fakeLog) { l.failKey = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t, scenarioOptions{})
			tc.set(s.log)

			rep := s.report(t)

			if c := rep.check(t, CheckRekorInclusion); c.Result != Unavailable {
				t.Fatalf("check 2 = %s (%s), want %s when %s cannot be reached",
					c.Result, c.Detail, Unavailable, tc.name)
			}
			if rep.Verdict == VerdictVerified {
				t.Fatalf("verdict = %s: a check that errored must never roll up to verified "+
					"(doc 06 §4.1)\n%s", rep.Verdict, Render(rep))
			}
		})
	}
}

// The rollup rule of doc 06 §4.1, stated as a test: any single check failing
// makes the rollup failed; any check erroring makes it unavailable, never
// verified.
func TestFailedOutranksUnavailableInTheRollup(t *testing.T) {
	s := newScenario(t, scenarioOptions{
		trailerIdentity: "spiffe://" + fixtureTrustDomain + "/agent/demo/rm-037/run-2",
	})
	s.fulcio.fail = true

	rep := s.report(t)

	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s: check 3 failed, so the rollup fails even "+
			"though check 1 is unavailable\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
}

// ---------------------------------------------------------------------------
// Each check bites. One mutation each, of the input that check reads.
// ---------------------------------------------------------------------------

func TestCheckOneBitesOnACertificateFromAnotherAuthority(t *testing.T) {
	s := newScenario(t, scenarioOptions{foreignCA: true})

	rep := s.report(t)

	c := rep.check(t, CheckCertificateChain)
	if c.Result != Failed {
		t.Fatalf("check 1 = %s (%s), want %s: the leaf was issued by a CA this "+
			"deployment's Fulcio does not publish\n%s", c.Result, c.Detail, Failed, Render(rep))
	}
	if rep.Verdict != VerdictFailed {
		t.Errorf("verdict = %s, want %s", rep.Verdict, VerdictFailed)
	}
}

func TestCheckTwoBitesWhenTheLogHasNoEntryForThisCommit(t *testing.T) {
	s := newScenario(t, scenarioOptions{noEntry: true})

	rep := s.report(t)

	c := rep.check(t, CheckRekorInclusion)
	if c.Result != Failed {
		t.Fatalf("check 2 = %s (%s), want %s: the log answered, and it holds nothing "+
			"for this commit\n%s", c.Result, c.Detail, Failed, Render(rep))
	}
}

func TestCheckTwoBitesOnAnEntryForAnotherCommit(t *testing.T) {
	s := newScenario(t, scenarioOptions{entryForOtherCommit: true})

	rep := s.report(t)

	if c := rep.check(t, CheckRekorInclusion); c.Result != Failed {
		t.Fatalf("check 2 = %s (%s), want %s: the only entry in the log is for a "+
			"different artifact\n%s", c.Result, c.Detail, Failed, Render(rep))
	}
}

func TestCheckTwoBitesOnASignatureFromAnotherKey(t *testing.T) {
	s := newScenario(t, scenarioOptions{entrySignedByAnother: true})

	rep := s.report(t)

	if c := rep.check(t, CheckRekorInclusion); c.Result != Failed {
		t.Fatalf("check 2 = %s (%s), want %s: the entry's signature over this commit's "+
			"SHA does not verify under the certificate the commit is signed with\n%s",
			c.Result, c.Detail, Failed, Render(rep))
	}
}

func TestCheckTwoBitesOnATamperedInclusionProof(t *testing.T) {
	s := newScenario(t, scenarioOptions{tamperProof: true})

	rep := s.report(t)

	if c := rep.check(t, CheckRekorInclusion); c.Result != Failed {
		t.Fatalf("check 2 = %s (%s), want %s: one byte of the proof's root was flipped\n%s",
			c.Result, c.Detail, Failed, Render(rep))
	}
}

func TestAnEntryWithNoSignedTimestampLeavesTheWindowUnproven(t *testing.T) {
	s := newScenario(t, scenarioOptions{omitSET: true})

	rep := s.report(t)

	if c := rep.check(t, CheckCertificateChain); c.Result != Unavailable {
		t.Fatalf("check 1 = %s (%s), want %s: without a signed entry timestamp the "+
			"integration time is unattested, so the validity window cannot be "+
			"settled\n%s", c.Result, c.Detail, Unavailable, Render(rep))
	}
}

func TestCheckThreeBitesOnACertificateForAnotherIdentity(t *testing.T) {
	s := newScenario(t, scenarioOptions{
		identity: "spiffe://" + fixtureTrustDomain + "/agent/other/rm-037/run-1",
	})

	rep := s.report(t)

	if c := rep.check(t, CheckTrailerIdentity); c.Result != Verified {
		// The certificate AND the trailer moved together, so check 3 passes:
		// this case exists to prove the fixture's `identity` knob does not
		// secretly also move the trailer.
		t.Fatalf("check 3 = %s (%s); the trailer follows the certificate in this "+
			"fixture, so it should pass", c.Result, c.Detail)
	}
}

// ---------------------------------------------------------------------------
// The trailer reader is a VERIFIER's, and permissive where RM-031's writer is
// strict. A verifier that refuses to parse a commit it should have judged has
// failed differently from one that judges it wrong.
// ---------------------------------------------------------------------------

func TestTheTrailerReaderIsPermissiveWhereTheWriterIsStrict(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    string
	}{
		{
			"the writer's own rendering",
			"subject\n\nAgent-Identity: " + fixtureIdentity + "\n",
			fixtureIdentity,
		},
		{
			"whitespace before the separator, which git accepts and the writer refuses",
			"subject\n\nAgent-Identity : " + fixtureIdentity + "\n",
			fixtureIdentity,
		},
		{
			"a lowercased key",
			"subject\n\nagent-identity: " + fixtureIdentity + "\n",
			fixtureIdentity,
		},
		{
			"a trailer mixed into a prose paragraph the writer would have refused to place",
			"subject\n\nsome prose\nAgent-Identity: " + fixtureIdentity + "\nmore prose\n",
			fixtureIdentity,
		},
		{
			"a trailer past a --- divider, which git would not read but a verifier must still see",
			"subject\n\n---\nAgent-Identity: " + fixtureIdentity + "\n",
			fixtureIdentity,
		},
		{
			"trailing whitespace around the value",
			"subject\n\nAgent-Identity:   " + fixtureIdentity + "  \n",
			fixtureIdentity,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim, err := ReadClaim(tc.message)
			if err != nil {
				t.Fatalf("ReadClaim: %v", err)
			}
			if claim.Identity != tc.want {
				t.Errorf("Agent-Identity = %q, want %q", claim.Identity, tc.want)
			}
		})
	}
}

func TestTwoIdentityTrailersAreAnAmbiguityTheVerifierRefusesToResolve(t *testing.T) {
	msg := "subject\n\nAgent-Identity: " + fixtureIdentity + "\n" +
		"Agent-Identity: spiffe://innsegl.dev/agent/demo/rm-037/run-2\n"

	_, err := ReadClaim(msg)

	if err == nil {
		t.Fatal("ReadClaim resolved a message carrying two Agent-Identity trailers; " +
			"a verifier that picks one is choosing which claim to check")
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("the error does not say how many claims it found: %v", err)
	}
}

func TestAMessageWithNoAgentTrailersCarriesNoClaim(t *testing.T) {
	claim, err := ReadClaim("just a commit\n")
	if err != nil {
		t.Fatalf("ReadClaim: %v", err)
	}
	if claim.Present() {
		t.Errorf("ReadClaim found a claim in a message with no trailers: %+v", claim)
	}
}

// The trailer keys are a PROTECTED SURFACE (doc 08 §3). A verifier that read a
// different spelling would silently stop finding claims.
func TestTheReaderReadsTheProtectedTrailerKeys(t *testing.T) {
	for _, key := range []string{
		signing.TrailerAgentIdentity, signing.TrailerAgentRun, signing.TrailerAgentTask,
	} {
		msg := "subject\n\n" + key + ": value\n"
		claim, err := ReadClaim(msg)
		if err != nil {
			t.Fatalf("ReadClaim(%q): %v", key, err)
		}
		if !claim.Present() {
			t.Errorf("the reader did not find the %s trailer", key)
		}
	}
}

// ---------------------------------------------------------------------------
// The report is machine-readable, because doc 06 §4.1's panel renders what
// this computes and P5 requires a third party to be able to redo it.
// ---------------------------------------------------------------------------

func TestTheReportRendersAsJSONWithTheThreeChecksAndTheirEvidence(t *testing.T) {
	s := newScenario(t, scenarioOptions{})
	rep := s.report(t)

	out, err := RenderJSON(rep)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	for _, want := range []string{
		string(VerdictVerified), CheckCertificateChain, CheckRekorInclusion,
		CheckTrailerIdentity, s.commit,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the JSON report does not carry %q:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Configuration refusals.
// ---------------------------------------------------------------------------

func TestNewRefusesAConfigurationItCannotVerifyWith(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no Fulcio", Config{RekorURL: "http://127.0.0.1:1"}},
		{"no Rekor", Config{FulcioURL: "http://127.0.0.1:1"}},
		{"a Fulcio that is not a URL", Config{FulcioURL: "://x", RekorURL: "http://127.0.0.1:1"}},
		{"a Rekor that is not a URL", Config{FulcioURL: "http://127.0.0.1:1", RekorURL: "://x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatalf("New accepted %+v", tc.cfg)
			}
		})
	}
}

func TestVerifyRefusesARevisionThatIsNotACommit(t *testing.T) {
	s := newScenario(t, scenarioOptions{})

	if _, err := s.verifier(t).Verify(t.Context(), s.repo, "no-such-revision"); err == nil {
		t.Fatal("Verify accepted a revision that does not resolve")
	}
	if _, err := s.verifier(t).Verify(t.Context(), s.repo, s.tree); err == nil {
		t.Fatal("Verify accepted a tree object as a commit")
	}
}

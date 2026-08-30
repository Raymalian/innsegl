// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/signing"
)

// TC-SIG, layer F — Sigstore unavailable (RM-034, #42).
//
// IP §6.3 in full, because every assertion below is one clause of it:
//
//	Fulcio down -> SIGNING_UNAVAILABLE, retryable. The commit is not created.
//	There is no unsigned fallback, no local-key fallback, no "sign later"
//	queue. Test: with Fulcio blocked, assert the repo has no new commit object
//	at all.
//
//	Rekor down -> signing fails (TRANSPARENCY_UNAVAILABLE). A signature without
//	a transparency entry is not non-repudiable and must not exist. Test: block
//	only Rekor, assert no commit.
//
//	Slow Sigstore -> explicit timeouts, bounded retries with backoff and
//	jitter, then the error. No indefinite hangs holding repo locks.
//
// # The shape of the danger in this file
//
// "No commit object was created" is the easiest assertion in this repository
// to pass for the wrong reason. It is satisfied by a signer that never ran, by
// a fixture that failed to stage anything, by a repository that was never
// initialised, and by a harness that skipped. Twelve vacuous passes have
// already been caught on this project and this is the shape most likely to
// produce the thirteenth.
//
// Three things are done about it, in order of how much they are worth:
//
//  1. A POSITIVE CONTROL runs first and gates the rest. It is the same
//     fixture, the same wrapper, the same repository shape and the same claim,
//     with every dependency healthy, and it asserts that a real signed commit
//     appears and that the object count goes UP by exactly one. If the control
//     fails, nothing below is allowed to report a pass. It is in the parent's
//     body rather than a subtest of its own so that `-run` cannot filter the
//     gate out from under the case it is gating.
//  2. EVERY blocked case restores the dependency and signs again, in the same
//     repository, through the same Signer. A refusal followed by a success is
//     a refusal that was one healthy dependency away from a commit; a refusal
//     on its own is indistinguishable from a broken fixture.
//  3. THE OUTAGE IS CONFIRMED before it is relied on: stopSigService does not
//     return until the published port genuinely refuses connections, and each
//     case additionally asserts that the OTHER dependency is still serving,
//     because a case in which both are down proves nothing about which error
//     class belongs to which.
//
// # Why the cases are subtests of one parent
//
// The pair of compose projects is expensive and is torn down on the parent's
// cleanup. TestMain belongs to harness_test.go, which RM-034 does not own, so
// there is no process-exit hook to hang a `compose down` on; ADR-0032 records
// the constraint. It is also the right shape: the three cases share one
// positive control, and `-run 'TestTCSIG.../SIG-002'` still selects one — with
// the control still running, because it is not a subtest.

func TestTCSIGSigstoreUnavailableFailsClosed(t *testing.T) {
	s := requireSigStack(t)

	// The control is a precondition, not a case, and it is written in the
	// parent's body rather than as a subtest for one reason: a subtest can be
	// filtered out. `-run '.../SIG-003'` would skip a control subtest and run
	// the injection case anyway, which is precisely the state in which "no
	// commit object" means nothing. Here it runs whatever -run selects, and
	// its t.Fatalf stops the parent before any subtest starts.
	sigPositiveControl(t, s)

	t.Run("SIG-002 Fulcio blocked", func(t *testing.T) { sig002FulcioBlocked(t, s) })
	t.Run("SIG-003 only Rekor blocked", func(t *testing.T) { sig003OnlyRekorBlocked(t, s) })
	t.Run("SIG-004 slow Sigstore", func(t *testing.T) { sig004SlowSigstore(t, s) })
}

// sigPositiveControl signs one commit with every dependency healthy, through
// exactly the fixture, wrapper, repository shape and claim the failure cases
// use, and refuses to let the suite continue unless a real signed commit
// appeared.
//
// This is the anti-vacuity gate. Every case below asserts an ABSENCE, and an
// absence is satisfied by a signer that never ran, a fixture that staged
// nothing, a repository that was never initialised and a harness that skipped.
// What this establishes is the one thing that makes those assertions mean
// anything: that this exact arrangement, left alone, PRODUCES a commit.
func sigPositiveControl(t *testing.T, s *sigStack) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	claim := newSigRunClaim(t, "rm-034")
	cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 10*time.Minute)
	if err != nil {
		t.Fatalf("minting a JWT-SVID: %v", err)
	}
	signer := newSigSigner(t, s.sigConfig(), &sigCredential{cred: cred})
	repo := newSigRepo(t)

	before := sigCommitObjects(t, repo)
	if len(before) != 0 {
		t.Fatalf("a fresh repository already holds %d commit objects: %v", len(before), before)
	}

	res, err := signer.Sign(ctx, sigRequest(repo,
		"TC-SIG control: a real signed commit", claim))
	if err != nil {
		t.Fatalf("the control signature failed, so every \"no commit object\" "+
			"assertion below would be vacuous: %v", err)
	}

	after := sigCommitObjects(t, repo)
	if len(after) != 1 {
		t.Fatalf("the control produced %d commit objects, want exactly 1: %v", len(after), after)
	}
	if after[0] != res.CommitSHA {
		t.Fatalf("the object database holds commit %s; Sign reported %s", after[0], res.CommitSHA)
	}
	if head := sigHeadOr(t, repo, ""); head != res.CommitSHA {
		t.Fatalf("HEAD is %q, want the signed commit %s", head, res.CommitSHA)
	}
	if res.Certificate.SPIFFEID != claim.Identity {
		t.Fatalf("the commit is signed under %q, the run claims %q",
			res.Certificate.SPIFFEID, claim.Identity)
	}
	if res.Rekor.UUID == "" {
		t.Fatal("the control commit has no transparency-log entry, so this " +
			"fixture has not shown that Rekor participates at all")
	}
	t.Logf("control: commit %s, certificate %s, rekor entry %s (index %d)",
		res.CommitSHA, res.Certificate.SerialNumber, res.Rekor.UUID, res.Rekor.LogIndex)
}

// ---------------------------------------------------------------------------
// SIG-002 — Fulcio blocked.
//
// doc 07: "SIGNING_UNAVAILABLE; repo has no new commit object at all (assert
// via git plumbing)". Invariants: I2, IP §6.3.
// ---------------------------------------------------------------------------

func sig002FulcioBlocked(t *testing.T, s *sigStack) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	claim := newSigRunClaim(t, "rm-034")
	cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 20*time.Minute)
	if err != nil {
		t.Fatalf("minting a JWT-SVID: %v", err)
	}
	src := &sigCredential{cred: cred}
	signer := newSigSigner(t, s.sigConfig(), src)
	repo := newSigRepo(t)

	before := sigCommitObjects(t, repo)
	stagedBefore := sigGitOut(t, repo, "diff", "--cached", "--name-only")

	// THE OUTAGE. The container is stopped — not a stub, not an unroutable
	// address, not a fake transport. stopSigService does not return until the
	// published port genuinely refuses connections.
	s.stopSigService(t, "fulcio", s.fulcioPort)
	t.Cleanup(func() { s.startSigService(t, "fulcio") })

	// And it is Fulcio ALONE. A case in which both were down would satisfy
	// "SIGNING_UNAVAILABLE" and "TRANSPARENCY_UNAVAILABLE" equally well and
	// would prove neither.
	if perr := s.probeFulcio(ctx); perr == nil {
		t.Fatal("Fulcio is still serving its root certificate after being stopped; " +
			"nothing was injected")
	}
	if perr := s.probeRekor(ctx); perr != nil {
		t.Fatalf("Rekor is not serving either, so this case cannot distinguish "+
			"SIGNING_UNAVAILABLE from TRANSPARENCY_UNAVAILABLE: %v", perr)
	}

	start := time.Now()
	_, err = signer.Sign(ctx, sigRequest(repo, "SIG-002: must never exist", claim))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Sign succeeded with Fulcio stopped. There is no unsigned fallback, " +
			"no local-key fallback and no sign-later queue (IP §6.3)")
	}

	// The error class, and its opposite. doc 07 gives Fulcio SIGNING_UNAVAILABLE
	// and Rekor TRANSPARENCY_UNAVAILABLE; a case that accepted either would
	// prove neither, so both directions are asserted.
	if !errors.Is(err, signing.ErrSigningUnavailable) {
		t.Errorf("Sign error = %v, want it to wrap ErrSigningUnavailable "+
			"(SIGNING_UNAVAILABLE, retryable)", err)
	}
	if errors.Is(err, signing.ErrTransparencyUnavailable) {
		t.Errorf("Sign error = %v names the transparency log; Rekor is up and "+
			"Fulcio is down", err)
	}
	// Retryable, and that is the whole difference between this and an
	// invariant violation: nothing about the request was wrong.
	if errors.Is(err, signing.ErrIdentityMismatch) || errors.Is(err, signing.ErrConfig) {
		t.Errorf("Sign error = %v, want a retryable outage rather than a "+
			"configuration or identity fault", err)
	}
	t.Logf("SIG-002 refused in %s: %v", elapsed.Truncate(time.Millisecond), err)

	// IP §6.3's own words: "assert the repo has no new commit object at all".
	assertNoNewCommit(t, repo, before, "Fulcio was stopped")

	// The caller's staged index is untouched. "The commit is not created" is
	// not licence to reset somebody else's work.
	if got := sigGitOut(t, repo, "diff", "--cached", "--name-only"); got != stagedBefore {
		t.Errorf("the staged index is now %q, was %q before the refused signature",
			got, stagedBefore)
	}
	// And nothing is left holding the repository.
	assertRepoUnlocked(t, repo)

	// THE PER-CASE POSITIVE CONTROL. Same repository, same Signer, same claim,
	// same credential — only Fulcio changes. A refusal that becomes a commit
	// the moment the CA comes back is a refusal caused by the CA.
	s.startSigService(t, "fulcio")
	res, err := signer.Sign(ctx, sigRequest(repo, "SIG-002: after Fulcio returned", claim))
	if err != nil {
		t.Fatalf("with Fulcio restored the same Sign still fails, so the refusal "+
			"above cannot be attributed to the outage: %v", err)
	}
	if after := sigCommitObjects(t, repo); len(after) != len(before)+1 {
		t.Fatalf("after Fulcio returned the repository holds %d commit objects, "+
			"held %d before: the control did not produce exactly one", len(after), len(before))
	}
	t.Logf("SIG-002 control: with Fulcio restored the same request produced commit %s",
		res.CommitSHA)
}

// ---------------------------------------------------------------------------
// SIG-003 — only Rekor blocked.
//
// doc 07: "TRANSPARENCY_UNAVAILABLE; no commit exists". IP §6.3: "A signature
// without a transparency entry is not non-repudiable and must not exist."
//
// This is the sharper of the two, and the second arm is why. Fulcio is UP, so
// a certificate is obtainable — the natural implementation signs first and
// logs afterwards, and would leave a perfectly good signed commit behind with
// nothing in any log to make it non-repudiable. The first arm exercises the
// wrapper's pre-flight probe; the second defeats that probe on purpose, drives
// a certificate exchange that MEASURABLY SUCCEEDS at Fulcio, and asserts that
// the commit object still does not exist.
// ---------------------------------------------------------------------------

func sig003OnlyRekorBlocked(t *testing.T, s *sigStack) {
	t.Run("the pre-flight probe: TRANSPARENCY_UNAVAILABLE and no commit", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()

		claim := newSigRunClaim(t, "rm-034")
		cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 20*time.Minute)
		if err != nil {
			t.Fatalf("minting a JWT-SVID: %v", err)
		}
		signer := newSigSigner(t, s.sigConfig(), &sigCredential{cred: cred})
		repo := newSigRepo(t)
		before := sigCommitObjects(t, repo)

		s.stopSigService(t, "rekor", s.rekorPort)
		t.Cleanup(func() { s.startSigService(t, "rekor") })

		if perr := s.probeRekor(ctx); perr == nil {
			t.Fatal("Rekor is still serving its log key after being stopped; " +
				"nothing was injected")
		}
		if perr := s.probeFulcio(ctx); perr != nil {
			t.Fatalf("Fulcio is not serving either, so \"only Rekor blocked\" is "+
				"false and this case cannot distinguish the two classes: %v", perr)
		}

		_, err = signer.Sign(ctx, sigRequest(repo, "SIG-003: must never exist", claim))
		if err == nil {
			t.Fatal("Sign succeeded with Rekor stopped. A signature without a " +
				"transparency entry is not non-repudiable and must not exist (IP §6.3)")
		}
		if !errors.Is(err, signing.ErrTransparencyUnavailable) {
			t.Errorf("Sign error = %v, want it to wrap ErrTransparencyUnavailable "+
				"(TRANSPARENCY_UNAVAILABLE)", err)
		}
		if errors.Is(err, signing.ErrSigningUnavailable) {
			t.Errorf("Sign error = %v names the certificate authority; Fulcio is up "+
				"and Rekor is down", err)
		}
		t.Logf("SIG-003 pre-flight refused: %v", err)

		assertNoNewCommit(t, repo, before, "Rekor was stopped")
		assertRepoUnlocked(t, repo)

		s.startSigService(t, "rekor")
		if _, err := signer.Sign(ctx, sigRequest(repo, "SIG-003: after Rekor returned", claim)); err != nil {
			t.Fatalf("with Rekor restored the same Sign still fails, so the refusal "+
				"above cannot be attributed to the outage: %v", err)
		}
		if after := sigCommitObjects(t, repo); len(after) != len(before)+1 {
			t.Fatalf("after Rekor returned the repository holds %d commit objects, held %d",
				len(after), len(before))
		}
	})

	t.Run("a certificate is obtained and the commit still does not exist", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()

		// Fulcio is reached through a pass-through proxy for one reason: so
		// that "Fulcio issued a certificate during the outage" is a request
		// this test WATCHED succeed, rather than an inference from the absence
		// of a Fulcio error in gitsign's prose.
		fulcio := newSigFailProxy(t, s.fulcioURL)
		cfg := s.sigConfig()
		cfg.FulcioURL = fulcio.url()

		claim := newSigRunClaim(t, "rm-034")
		cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 20*time.Minute)
		if err != nil {
			t.Fatalf("minting a JWT-SVID: %v", err)
		}
		signer := newSigSigner(t, cfg, &sigCredential{cred: cred})
		repo := newSigRepo(t)

		// One healthy signature first. It warms the wrapper's trust-material
		// cache, which is what defeats the pre-flight probe on the next call —
		// the point of this arm is to reach the certificate exchange with the
		// log already down, which is precisely the ordering IP §6.3 says must
		// still leave no commit.
		warm, err := signer.Sign(ctx, sigRequest(repo, "SIG-003: the healthy commit", claim))
		if err != nil {
			t.Fatalf("the warm-up signature failed: %v", err)
		}
		before := sigCommitObjects(t, repo)
		if len(before) != 1 {
			t.Fatalf("after the warm-up the repository holds %d commit objects, want 1", len(before))
		}
		head := sigHeadOr(t, repo, "")
		mark := fulcio.mark()

		s.stopSigService(t, "rekor", s.rekorPort)
		t.Cleanup(func() { s.startSigService(t, "rekor") })
		if perr := s.probeFulcio(ctx); perr != nil {
			t.Fatalf("Fulcio must stay up for this arm: %v", perr)
		}

		stageSigFile(t, repo, "second.txt", "SIG-003\n")
		_, err = signer.Sign(ctx, sigRequest(repo, "SIG-003: signed but unlogged", claim))
		if err == nil {
			t.Fatal("Sign succeeded with Rekor stopped and Fulcio up: a signature " +
				"without a transparency entry must not exist (IP §6.3)")
		}
		t.Logf("SIG-003 warm refusal: %v", err)
		t.Logf("SIG-003 Fulcio wire log:%s", fulcio.describe())

		// THE MEASUREMENT THIS ARM EXISTS FOR. During the outage a certificate
		// request reached the real Fulcio and the real Fulcio ISSUED — 201 on
		// /api/v1/signingCert, watched on the wire, not inferred from the
		// absence of a Fulcio error in gitsign's prose. So the refusal is not
		// "no certificate could be had"; it is "a certificate was had, and the
		// commit was still not kept, because nothing could record it".
		var issued []sigWireCall
		for _, c := range fulcio.callsAfter(mark, sigFulcioCertPath) {
			if c.method == http.MethodPost && c.status >= 200 && c.status < 300 {
				issued = append(issued, c)
			}
		}
		if len(issued) == 0 {
			t.Errorf("Fulcio issued no certificate during the outage, so this arm "+
				"has not established that a certificate was obtainable and its "+
				"\"no commit\" assertion proves nothing sharper than the pre-flight "+
				"case above:%s", fulcio.describe())
		}

		// The refusal is attributable to the log and to nothing else. Asserted
		// against the URLs rather than against gitsign's wording, which is
		// upstream prose and may change: the error names Rekor's endpoint and
		// does not name Fulcio's.
		if !strings.Contains(err.Error(), s.rekorURL) {
			t.Errorf("Sign error = %v, want it to name the transparency log at %s",
				err, s.rekorURL)
		}
		if strings.Contains(err.Error(), cfg.FulcioURL) {
			t.Errorf("Sign error = %v names Fulcio at %s, which answered 201 during "+
				"this window", err, cfg.FulcioURL)
		}

		// And, still: no new commit object anywhere in the object database.
		assertNoNewCommit(t, repo, before, "Rekor was stopped after a certificate had been issued")
		if got := sigHeadOr(t, repo, ""); got != head {
			t.Errorf("HEAD moved to %s from %s", got, head)
		}
		if warm.CommitSHA != head {
			t.Errorf("HEAD is %s, the warm-up commit was %s", head, warm.CommitSHA)
		}
		assertRepoUnlocked(t, repo)
	})
}

// ---------------------------------------------------------------------------
// SIG-004 — slow Sigstore.
//
// doc 07: "Bounded retries then error; no repo lock held indefinitely (assert
// lock released)". IP §6.3: "explicit timeouts, bounded retries with backoff
// and jitter, then the error. No indefinite hangs holding repo locks."
//
// Latency is injected by a real HTTP proxy in front of a real, healthy Fulcio
// or Rekor, and the retries are COUNTED ON THE WIRE. "It took a while, so it
// must have retried" is not a measurement; internal/segment's anchor test
// counts round trips in an http.RoundTripper for the same reason.
// ---------------------------------------------------------------------------

func sig004SlowSigstore(t *testing.T, s *sigStack) {
	t.Run("Fulcio slow before the commit: one bounded attempt, then the error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()

		const injected = 30 * time.Second
		const clientTimeout = 2 * time.Second

		fulcio := newSigFailProxy(t, s.fulcioURL)
		cfg := s.sigConfig()
		cfg.FulcioURL = fulcio.url()
		// The explicit timeout IP §6.3 asks for, made short so the case does
		// not spend the wrapper's shipped 30 seconds proving it.
		cfg.HTTPClient = &http.Client{Timeout: clientTimeout}

		claim := newSigRunClaim(t, "rm-034")
		cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 20*time.Minute)
		if err != nil {
			t.Fatalf("minting a JWT-SVID: %v", err)
		}
		signer := newSigSigner(t, cfg, &sigCredential{cred: cred})
		repo := newSigRepo(t)
		before := sigCommitObjects(t, repo)

		fulcio.slow(injected, sigFulcioRootPath)

		start := time.Now()
		_, err = signer.Sign(ctx, sigRequest(repo, "SIG-004: must never exist", claim))
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("Sign succeeded with Fulcio answering 30s slower than the timeout")
		}
		if !errors.Is(err, signing.ErrSigningUnavailable) {
			t.Errorf("Sign error = %v, want it to wrap ErrSigningUnavailable", err)
		}

		// TERMINATION, not patience: the operation must end on the timeout, not
		// on the injected latency. This is the clause IP §6.3 spells "no
		// indefinite hangs".
		if elapsed >= injected {
			t.Errorf("Sign waited %s, and the injected latency is %s: the timeout "+
				"did not bound it", elapsed.Truncate(time.Millisecond), injected)
		}

		// THE BOUND, COUNTED ON THE WIRE.
		attempts := fulcio.calls(sigFulcioRootPath)
		if len(attempts) == 0 {
			t.Fatalf("nothing reached Fulcio at all, so the refusal above is not a "+
				"timeout — it is a request that was never made:%s", fulcio.describe())
		}
		if len(attempts) != 1 {
			t.Errorf("the reachability probe made %d attempts on the wire, and the "+
				"shipped wrapper makes exactly 1 (internal/signing.trustMaterial calls "+
				"fetchFulcioRoot once). If this changed, the change is the news:%s",
				len(attempts), fulcio.describe())
		}
		t.Logf("SIG-004 Fulcio: %d attempt(s) on the wire, refused after %s: %v",
			len(attempts), elapsed.Truncate(time.Millisecond), err)

		assertNoNewCommit(t, repo, before, "Fulcio answered slower than the timeout")
		assertRepoUnlocked(t, repo)
	})

	t.Run("Rekor slow after the commit: the bounded retry loop, counted", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()

		const injected = 8 * time.Second
		const clientTimeout = time.Second
		// internal/signing pins these: rekorLookupAttempts = 5,
		// rekorLookupDelay = 500ms. They are unexported, so they are written
		// out here — which is deliberate: a harness that read the bound out of
		// the code under test could not notice the bound changing.
		const wantAttempts = 5
		const wantDelay = 500 * time.Millisecond

		rekor := newSigFailProxy(t, s.rekorURL)
		cfg := s.sigConfig()
		cfg.RekorURL = rekor.url()
		cfg.HTTPClient = &http.Client{Timeout: clientTimeout}

		claim := newSigRunClaim(t, "rm-034")
		cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 20*time.Minute)
		if err != nil {
			t.Fatalf("minting a JWT-SVID: %v", err)
		}
		signer := newSigSigner(t, cfg, &sigCredential{cred: cred})
		repo := newSigRepo(t)

		// A healthy signature through the proxy first: it proves the proxy is
		// a transparent hop and not itself the failure, and it warms the trust
		// cache so the second call reaches the part of the wrapper that
		// retries.
		if _, werr := signer.Sign(ctx, sigRequest(repo, "SIG-004: the healthy commit", claim)); werr != nil {
			t.Fatalf("the warm-up signature through the pass-through proxy failed: %v", werr)
		}
		before := sigCommitObjects(t, repo)
		// Everything the healthy warm-up put on the wire is behind this mark,
		// INCLUDING the one successful search it made. Counting from zero
		// reported six attempts against a bound of five on the first run of
		// this case; the warm-up's own search is not a retry.
		mark := rekor.mark()

		// ONLY the wrapper's own search is slowed. gitsign's upload to
		// /api/v1/log/entries stays fast, so the entry really is written and
		// the only thing failing is the lookup that has to find it — which is
		// the one place in the shipped signing path that retries at all.
		rekor.slow(injected, sigRekorIndexPath)
		stageSigFile(t, repo, "second.txt", "SIG-004\n")

		start := time.Now()
		_, err = signer.Sign(ctx, sigRequest(repo, "SIG-004: the log went slow", claim))
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("Sign reported success while every lookup of the transparency " +
				"entry timed out")
		}
		if !errors.Is(err, signing.ErrTransparencyUnavailable) {
			t.Errorf("Sign error = %v, want it to wrap ErrTransparencyUnavailable", err)
		}
		if elapsed >= time.Duration(wantAttempts)*injected {
			t.Errorf("Sign waited %s; %d attempts at the injected %s would be %s. "+
				"The per-request timeout did not bound the retries",
				elapsed.Truncate(time.Millisecond), wantAttempts, injected,
				time.Duration(wantAttempts)*injected)
		}

		// THE RETRIES, COUNTED ON THE WIRE.
		attempts := rekor.callsAfter(mark, sigRekorIndexPath)
		if len(attempts) != wantAttempts {
			t.Errorf("%d searches reached Rekor, the shipped bound is %d "+
				"(internal/signing.rekorLookupAttempts):%s",
				len(attempts), wantAttempts, rekor.describe())
		}
		// THE WAIT BETWEEN THEM, MEASURED. Each gap must be at least the
		// shipped delay; a loop that hammered the log with no wait would show
		// gaps of about clientTimeout alone.
		//
		// What the measurement also shows is that this wait is CONSTANT. IP
		// §6.3 asks for "bounded retries with backoff and jitter"; the shipped
		// loop is bounded and waits, and the four gaps come out identical to
		// within a millisecond, so there is neither growth nor jitter. That is
		// recorded in ADR-0032 and left as a finding rather than asserted
		// here: a test that demanded jitter would fail against shipped code
		// this issue may not change, and a test that asserted the gaps are
		// equal would make the defect a requirement.
		gaps := rekor.gapsAfter(mark, sigRekorIndexPath)
		for i, g := range gaps {
			if g < wantDelay {
				t.Errorf("attempts %d and %d were %s apart, and the shipped delay "+
					"between them is %s: this loop is not waiting at all",
					i+1, i+2, g.Truncate(time.Millisecond), wantDelay)
			}
		}
		if uploads := rekor.callsAfter(mark, sigRekorEntryPath); len(uploads) == 0 {
			t.Errorf("gitsign made no request to %s, so the log was never asked "+
				"to record anything and this case slowed a lookup for an entry that "+
				"was never written:%s", sigRekorEntryPath, rekor.describe())
		}
		t.Logf("SIG-004 Rekor: %d searches on the wire in %s, gaps %v",
			len(attempts), elapsed.Truncate(time.Millisecond), gaps)

		// A COMMIT DOES EXIST HERE, AND THAT IS NOT A §6.3 VIOLATION. The
		// signature and its Rekor entry both exist; what failed is the
		// wrapper's read-back of the entry, after gitsign's own client had
		// already required an inclusion proof. That is IP §6.5's crash-between-
		// Phase-B-and-Phase-C window — the one the reconciler (RM-035) repairs
		// — and the assertion that belongs here is that the wrapper reported a
		// failure rather than a Result it could not substantiate.
		after := sigCommitObjects(t, repo)
		if len(after) != len(before)+1 {
			t.Errorf("the repository holds %d commit objects and held %d; the "+
				"signature itself should have succeeded here", len(after), len(before))
		}
		assertRepoUnlocked(t, repo)
	})

	t.Run("the repo lock is released when the signing child is timed out", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()

		// The clause of IP §6.3 that names a repository: "No indefinite hangs
		// holding repo locks."
		//
		// MEASURED, and it is the reason this case watches rather than merely
		// asserts. In the form the wrapper invokes it — `git commit --file`,
		// whole index, no pathspec — git takes .git/index.lock, writes the
		// index and RELEASES it BEFORE calling the signing program, so no
		// repository lock is held across the round trip to Fulcio at all.
		// "The lock was released" is therefore, on shipped code, a claim about
		// something that was never taken, which is the precise shape of a
		// vacuous pass.
		//
		// What makes it non-vacuous is that the property is a consequence of
		// HOW git is invoked and not of git. The same command with a pathspec
		// takes git's COMMIT_PARTIAL path, and that one holds BOTH
		// .git/index.lock and .git/next-index-<pid>.lock across the signature
		// and leaves them behind when the signer dies. MEASURED on
		// git 2.51.0 with a signing program that sleeps:
		//
		//	git commit --only b.txt   -> index.lock, next-index-30403.lock
		//	                             present for the whole sleep
		//	git commit                -> no lock at any point
		//
		// So this case does two things. It records every lock file that
		// appears WHILE the signature is in flight, which turns the assertion
		// below into a real one the moment anybody adds a pathspec or `-a` to
		// the wrapper's invocation; and it asserts that whatever was taken is
		// gone afterwards.
		const injected = 120 * time.Second
		const childTimeout = 8 * time.Second

		fulcio := newSigFailProxy(t, s.fulcioURL)
		cfg := s.sigConfig()
		cfg.FulcioURL = fulcio.url()
		cfg.Timeout = childTimeout

		claim := newSigRunClaim(t, "rm-034")
		cred, err := s.mintSigJWTSVID(ctx, claim.Identity, 20*time.Minute)
		if err != nil {
			t.Fatalf("minting a JWT-SVID: %v", err)
		}
		signer := newSigSigner(t, cfg, &sigCredential{cred: cred})
		repo := newSigRepo(t)

		if _, werr := signer.Sign(ctx, sigRequest(repo, "SIG-004: the healthy commit", claim)); werr != nil {
			t.Fatalf("the warm-up signature through the pass-through proxy failed: %v", werr)
		}
		before := sigCommitObjects(t, repo)
		head := sigHeadOr(t, repo, "")

		// Everything Fulcio serves is now two minutes late. The trust material
		// is already cached, so the wrapper goes straight to `git commit` and
		// the latency lands where the lock is held.
		fulcio.slow(injected, "")
		stageSigFile(t, repo, "second.txt", "SIG-004 lock\n")

		// Sign runs in a goroutine so this one can watch the repository while
		// it is in flight. Nothing in the goroutine touches t.
		done := make(chan error, 1)
		start := time.Now()
		go func() {
			_, serr := signer.Sign(ctx, sigRequest(repo,
				"SIG-004: the CA went away mid-commit", claim))
			done <- serr
		}()

		heldDuringSigning := map[string]bool{}
		for waiting := true; waiting; {
			select {
			case err = <-done:
				waiting = false
			case <-time.After(25 * time.Millisecond):
				for _, l := range sigStaleLocks(t, repo) {
					heldDuringSigning[l] = true
				}
			}
		}
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("Sign succeeded while Fulcio was two minutes late")
		}
		t.Logf("SIG-004 lock: refused after %s: %v", elapsed.Truncate(time.Millisecond), err)
		t.Logf("SIG-004 lock: Fulcio wire log:%s", fulcio.describe())
		if len(heldDuringSigning) == 0 {
			t.Logf("SIG-004 lock: no repository lock was held at any point during the " +
				"signature. That is a property of the shipped `git commit --file` " +
				"invocation, which releases .git/index.lock before calling the signing " +
				"program — see the comment above; a pathspec would change it")
		} else {
			t.Logf("SIG-004 lock: held while signing: %v", sortedKeys(heldDuringSigning))
		}

		if elapsed >= injected {
			t.Errorf("Sign waited %s and the injected latency is %s: the child "+
				"process was not bounded, which is the indefinite hang IP §6.3 forbids",
				elapsed.Truncate(time.Millisecond), injected)
		}

		// THE ASSERTION doc 07 NAMES: the lock is released. The non-mutating
		// checks first, so the object-database assertion below is about the
		// signature and not about the probe...
		assertRepoUnlocked(t, repo)
		assertNoNewCommit(t, repo, before, "the signing child was timed out")
		if got := sigHeadOr(t, repo, ""); got != head {
			t.Errorf("HEAD moved to %s from %s", got, head)
		}
		// ...and then the one an operator would perform: make a commit.
		assertRepoAcceptsACommit(t, repo)
	})
}

// ---------------------------------------------------------------------------
// Shared assertions.
// ---------------------------------------------------------------------------

// assertNoNewCommit is IP §6.3's "the repo has no new commit object at all",
// asserted against the object database rather than against refs.
//
// It compares the SET, not the count. A signer that created a commit and
// garbage-collected another would keep the count equal, and the assertion is
// about what exists, not how much of it there is.
func assertNoNewCommit(t *testing.T, repo string, before []string, because string) {
	t.Helper()
	after := sigCommitObjects(t, repo)
	known := make(map[string]bool, len(before))
	for _, c := range before {
		known[c] = true
	}
	var appeared []string
	for _, c := range after {
		if !known[c] {
			appeared = append(appeared, c)
		}
	}
	if len(appeared) > 0 {
		t.Errorf("the object database gained %d commit object(s) — %s — although %s. "+
			"IP §6.3: the commit is not created. There is no unsigned fallback, no "+
			"local-key fallback and no sign-later queue",
			len(appeared), strings.Join(appeared, ", "), because)
	}
	if len(after) != len(before) {
		t.Errorf("the repository holds %d commit objects and held %d although %s",
			len(after), len(before), because)
	}
}

// assertRepoUnlocked is IP §6.3's "no indefinite hangs holding repo locks".
//
// Two checks, neither of which writes anything the object-database assertions
// would see: no `*.lock` file survives anywhere under .git, and the index lock
// can be TAKEN — by git's own O_CREAT|O_EXCL protocol — and released again.
// The heavier operational check, an actual commit, is assertRepoAcceptsACommit
// and belongs at the end of a case.
//
// What this can and cannot catch is written out in the lock case above: on the
// shipped `git commit --file` invocation no repository lock is held across the
// signature at all, so on today's code this passes because nothing was ever
// taken. It bites against a realistic change — a pathspec puts git on its
// COMMIT_PARTIAL path, which holds .git/index.lock and a next-index lock for
// the whole of the signature and leaves both behind when the signer dies.
func assertRepoUnlocked(t *testing.T, repo string) {
	t.Helper()
	if stale := sigStaleLocks(t, repo); len(stale) > 0 {
		t.Errorf("the refused signature left %d lock file(s) behind: %s. "+
			"IP §6.3: no indefinite hangs holding repo locks",
			len(stale), strings.Join(stale, ", "))
	}
	if err := sigIndexLockIsFree(repo); err != nil {
		t.Errorf("the repository is still locked after the refused signature: %v", err)
	}
}

// sortedKeys renders a set for a failure message, in a stable order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assertRepoAcceptsACommit is the operational form of the same claim, and it
// mutates: exactly one new commit object. Only ever the last thing a case does.
func assertRepoAcceptsACommit(t *testing.T, repo string) {
	t.Helper()
	if err := sigRepoAcceptsACommit(t, repo); err != nil {
		t.Errorf("the repository is wedged after the refused signature: %v", err)
	}
}

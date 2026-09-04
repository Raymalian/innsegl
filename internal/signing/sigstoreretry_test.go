// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// RM-070 (#93): IP §6.3 asks the whole signing path for "explicit timeouts,
// bounded retries with backoff and jitter, then the error". RM-034 (#42)
// measured that the shipped Rekor lookup gave the first two thirds of that —
// bounded retries, a timeout on each request — and not the rest: four gaps
// between attempts, on the wire, identical to within a millisecond:
//
//	1.503149375s · 1.502406125s · 1.501886083s · 1.501726750s
//
// rekorLookupDelay was a constant, slept with a bare time.After. RM-034
// deliberately withheld two assertions rather than write a test that was red
// against code it had no mandate to change, or that turned the defect (equal
// gaps) into a requirement:
//
//   - intervals grow between attempts
//   - repeated runs do not produce identical interval sequences
//
// This file adds both, against the fix in sigstore.go (rekorLookupPolicy,
// rekorWait). "Make it deterministic where you can" (RM-070's brief) means
// neither assertion below waits real time or trusts a real random draw to
// happen to differ:
//
//   - growth is structural (TestRekorWaitJitteredGapsAlwaysGrow): the
//     equal-jitter construction with Multiplier=2 makes gap n < gap n+1 for
//     EVERY possible draw, so the test needs no seed and cannot flake.
//   - "different runs differ" is driven, not waited for
//     (TestRekorWaitJitterFollowsTheInjectedSource): two fixed, logged
//     sequences stand in for two runs' randomness — the pattern
//     internal/ledger/postgres_ambiguouscommit_test.go uses for a commit
//     acknowledgment, applied here to a source of floats, the way
//     test/chaos/kill_test.go seeds its own campaigns rather than trusting
//     wall-clock jitter to reproduce.
//
// TestFindRekorEntryRetriesWithGrowingJitteredIntervals then ties the math to
// the wire: the retry loop itself, counted, with the wait faked out so the
// case runs in milliseconds rather than the ~7.5s worst case the policy now
// allows.

// ---------------------------------------------------------------------------
// SIG-009 — growth is structural, not statistical.
// ---------------------------------------------------------------------------

// TestRekorWaitJitteredGapsAlwaysGrow is the assertion RM-034 withheld,
// first half: intervals grow.
//
// It runs the real, unfaked jitter (a zero-value rekorWait uses
// math/rand/v2's real source) many times and requires the growth property on
// every single draw, because the property is not probabilistic: with
// Multiplier pinned at 2, jittered(Backoff(n)) ∈ [Backoff(n)/2, Backoff(n))
// and jittered(Backoff(n+1)) ∈ [Backoff(n), 2·Backoff(n)) never overlap. A
// failure here would mean the construction itself is broken, not that this
// run got unlucky — which is what makes many trials safe to run without
// making the test flaky.
func TestRekorWaitJitteredGapsAlwaysGrow(t *testing.T) {
	w := rekorWait{}
	for trial := range 200 {
		var gaps []time.Duration
		for attempt := 1; attempt < rekorLookupPolicy.Attempts; attempt++ {
			gaps = append(gaps, w.jittered(rekorLookupPolicy.Backoff(attempt)))
		}
		for i := 1; i < len(gaps); i++ {
			if gaps[i-1] >= gaps[i] {
				t.Fatalf("trial %d: gap %d was %s, gap %d was %s — not strictly "+
					"increasing (full sequence %v)", trial, i, gaps[i], i+1, gaps[i-1], gaps)
			}
		}
	}
}

// TestRekorWaitJitteredNeverExceedsThePlainBackoff is the bound half of the
// same construction: equal jitter never reaches the ceiling it is jitter
// under, and never goes negative for a zero or negative input.
func TestRekorWaitJitteredNeverExceedsThePlainBackoff(t *testing.T) {
	w := rekorWait{}
	for attempt := 1; attempt < rekorLookupPolicy.Attempts; attempt++ {
		backoff := rekorLookupPolicy.Backoff(attempt)
		for trial := range 200 {
			got := w.jittered(backoff)
			if got < backoff/2 || got >= backoff {
				t.Fatalf("attempt %d, trial %d: jittered(%s) = %s, want [%s, %s)",
					attempt, trial, backoff, got, backoff/2, backoff)
			}
		}
	}
	if got := w.jittered(0); got != 0 {
		t.Errorf("jittered(0) = %s, want 0", got)
	}
	if got := w.jittered(-time.Second); got != 0 {
		t.Errorf("jittered(-1s) = %s, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// SIG-010 — "repeated runs do not produce identical interval sequences",
// driven rather than waited for.
// ---------------------------------------------------------------------------

// fixedSequence returns a randFn that replays a fixed list of [0,1) draws,
// standing in for "the randomness one run happened to get" the way
// test/chaos/kill_test.go's seeded splitmix64 stands in for one campaign's
// kill choices: reproducible on every re-run, and distinguishable from a
// different sequence by construction rather than by chance.
func fixedSequence(t *testing.T, draws []float64) func() float64 {
	t.Helper()
	i := 0
	return func() float64 {
		if i >= len(draws) {
			t.Fatalf("fixedSequence: %d draws requested, only %d supplied", i+1, len(draws))
		}
		v := draws[i]
		i++
		return v
	}
}

// TestRekorWaitJitterFollowsTheInjectedSource is the assertion RM-034
// withheld, second half: two runs' randomness produce two different interval
// sequences.
//
// "Repeated runs" is driven here rather than waited for: two fixed sequences
// stand in for two runs' draws, the way LED-012/LED-013
// (postgres_ambiguouscommit_test.go) drive the exact byte at which a commit's
// acknowledgment is withheld instead of racing for it across a SIGKILL
// campaign. A statistical version of this test — call the real source twice
// and hope the floats differ — was rejected by RM-070's own brief as a test
// that "flakes"; this version cannot, because the two sequences are chosen to
// differ and the wiring is what is under test, not the entropy.
func TestRekorWaitJitterFollowsTheInjectedSource(t *testing.T) {
	runA := rekorWait{randFn: fixedSequence(t, []float64{0.10, 0.90, 0.25, 0.75})}
	runB := rekorWait{randFn: fixedSequence(t, []float64{0.75, 0.25, 0.90, 0.10})}

	var gapsA, gapsB []time.Duration
	for attempt := 1; attempt < rekorLookupPolicy.Attempts; attempt++ {
		backoff := rekorLookupPolicy.Backoff(attempt)
		gapsA = append(gapsA, runA.jittered(backoff))
		gapsB = append(gapsB, runB.jittered(backoff))
	}

	identical := true
	for i := range gapsA {
		if gapsA[i] != gapsB[i] {
			identical = false
			break
		}
	}
	if identical {
		t.Fatalf("two different randFn sequences produced identical interval "+
			"sequences %v; the jitter is not consulting the injected source", gapsA)
	}
	t.Logf("run A: %v", gapsA)
	t.Logf("run B: %v", gapsB)

	// And the exact values are what equal jitter says they should be — proof
	// the source is actually being read, not merely that two runs disagree
	// for some unrelated reason.
	for i, r := range []float64{0.10, 0.90, 0.25, 0.75} {
		backoff := rekorLookupPolicy.Backoff(i + 1)
		want := time.Duration(float64(backoff)/2 + r*float64(backoff)/2)
		if gapsA[i] != want {
			t.Errorf("attempt %d: jittered = %s, want %s (backoff %s, draw %v)",
				i+1, gapsA[i], want, backoff, r)
		}
	}
}

// ---------------------------------------------------------------------------
// SIG-011 — the retry loop itself, counted on the wire, wait faked out.
// ---------------------------------------------------------------------------

// countingRekorIndex is a minimal Rekor search-index server that counts
// requests and always reports no match, so findRekorEntryWaiting exhausts
// its full retry budget every time. It is a purpose-built, single-endpoint
// fixture rather than a reuse of fakeSigstore: what this file tests is
// timing and attempt counts, and giving it its own small server keeps that
// separate from fakeSigstore's job of standing in for the whole of Fulcio and
// Rekor.
type countingRekorIndex struct {
	server *httptest.Server
	calls  atomic.Int32
}

func newCountingRekorIndex(t *testing.T) *countingRekorIndex {
	t.Helper()
	c := &countingRekorIndex{}
	mux := http.NewServeMux()
	mux.HandleFunc(rekorIndexPath, func(w http.ResponseWriter, r *http.Request) {
		c.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("[]")); err != nil {
			t.Errorf("writing the empty index response: %v", err)
		}
	})
	c.server = httptest.NewServer(mux)
	t.Cleanup(c.server.Close)
	return c
}

// TestFindRekorEntryRetriesWithGrowingJitteredIntervals ties the jitter math
// to the actual retry loop: the wire attempts are counted, the requested
// sleep durations are recorded (never actually slept, so the case runs in
// milliseconds rather than the worst-case ~7.5s the policy now allows), and
// both are checked against rekorLookupPolicy directly. The bound and the
// error class — both named in RM-070's acceptance criteria — are asserted
// alongside the new growth property, so this one case is what "the fix"
// means end to end.
func TestFindRekorEntryRetriesWithGrowingJitteredIntervals(t *testing.T) {
	idx := newCountingRekorIndex(t)
	leaf := staticSourceLeaf(t)

	var slept []time.Duration
	wait := rekorWait{
		randFn: fixedSequence(t, []float64{0.2, 0.4, 0.6, 0.8}),
		sleepFn: func(_ context.Context, d time.Duration) error {
			slept = append(slept, d)
			return nil
		},
	}

	start := time.Now()
	_, err := findRekorEntryWaiting(t.Context(), idx.server.Client(), idx.server.URL,
		"deadbeef", leaf, wait)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTransparencyUnavailable) {
		t.Fatalf("error = %v, want ErrTransparencyUnavailable (RM-070 acceptance: "+
			"the terminal error class is unchanged)", err)
	}

	// THE BOUND, COUNTED ON THE WIRE — unchanged by this fix.
	if got := int(idx.calls.Load()); got != rekorLookupPolicy.Attempts {
		t.Errorf("%d requests reached the index, want exactly %d "+
			"(rekorLookupPolicy.Attempts, RM-070 acceptance: the bound is still enforced)",
			got, rekorLookupPolicy.Attempts)
	}

	// THE WAITS REQUESTED — one less than the attempts, and each exactly what
	// equal jitter computes for the injected draw.
	if len(slept) != rekorLookupPolicy.Attempts-1 {
		t.Fatalf("%d waits were requested, want %d", len(slept), rekorLookupPolicy.Attempts-1)
	}
	for i, r := range []float64{0.2, 0.4, 0.6, 0.8} {
		backoff := rekorLookupPolicy.Backoff(i + 1)
		want := time.Duration(float64(backoff)/2 + r*float64(backoff)/2)
		if slept[i] != want {
			t.Errorf("wait %d = %s, want %s (backoff %s, draw %v)", i+1, slept[i], want, backoff, r)
		}
	}

	// GROWTH, AT THE INTEGRATION POINT rather than in isolation.
	for i := 1; i < len(slept); i++ {
		if slept[i-1] >= slept[i] {
			t.Errorf("wait %d was %s, wait %d was %s: not growing", i, slept[i-1], i+1, slept[i])
		}
	}

	// And because sleepFn never actually slept, this whole case — which the
	// production policy allows to take up to ~7.5s of real waiting — must
	// still be fast. A regression that started sleeping for real here would
	// be caught by this bound long before it cost a CI run seven seconds.
	if elapsed > 2*time.Second {
		t.Errorf("the case took %s with sleeping faked out; the wrapper is waiting "+
			"somewhere real", elapsed)
	}
}

// TestFindRekorEntryWaitAbortsOnContextCancellation is IP §6.3's "no
// indefinite hangs", exercised at the one place the fix touches: a context
// that ends during a backoff stops the retry immediately rather than
// finishing the budget. Mirrors internal/segment's
// TestSEG004CancellationStopsRetrying — the same shape, reused rather than
// reinvented, for the same reason RM-070's brief asks the fix itself to
// reuse anchor.go.
func TestFindRekorEntryWaitAbortsOnContextCancellation(t *testing.T) {
	idx := newCountingRekorIndex(t)
	leaf := staticSourceLeaf(t)

	ctx, cancel := context.WithCancel(t.Context())
	wait := rekorWait{
		sleepFn: func(context.Context, time.Duration) error {
			cancel()
			return context.Canceled
		},
	}

	_, err := findRekorEntryWaiting(ctx, idx.server.Client(), idx.server.URL, "deadbeef", leaf, wait)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want one wrapping context.Canceled", err)
	}
	if got := int(idx.calls.Load()); got != 1 {
		t.Errorf("%d requests reached the index before cancellation stopped the loop, want 1", got)
	}
}

// staticSourceLeaf builds a minimal, self-signed leaf certificate good
// enough to pass through findRekorEntryWaiting's matching step — which these
// cases never reach, since the index always reports no match, but the
// function's signature requires one.
func staticSourceLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	ca := newTestCA(t)
	return ca.leaf(t, unitIdentity, "http://spire-oidc:8080",
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
}

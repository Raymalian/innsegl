// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/identity"
)

// INIT-006 (proposed, doc 07 layer U): "Signs one real commit and verifies
// it with `innsegl verify` before reporting success... Measure, do not
// assert" (#117 point 4), and the trust-root branch that makes "anyone"
// (public Sigstore) an honest refusal rather than an attempted, doomed
// signature.
//
// # Why "anyone" refuses here rather than attempting a signature
//
// ADR-0010, measured 2026-08-28 against the live public Fulcio configuration
// endpoint: "The live allowlist contains no SPIFFE issuer at all... Public
// Sigstore is not reachable by substituting a CI token... the Fulcio
// certificate would then attest the workflow, not the run." This project's
// SPIFFE-ID pipeline — the one #116 pseudonymises and the one
// internal/verify's commitCertificate requires a URI SAN from — has no path
// to a certificate public Fulcio will issue. Attempting it here would not be
// "hard", it would be certain, reproducible failure against a real CA, and
// #117 point 4 requires refusing to report success rather than trying and
// discovering that. This is reported to the human as a known conflict
// between #117 and ADR-0010 rather than resolved by inventing a workaround
// (e.g. treating a non-SPIFFE certificate as attributed, which would be
// internal/verify accepting a claim it was built to refuse).

func TestINIT006PublicTrustRootRefusesWithoutAttemptingASignature(t *testing.T) {
	called := false
	fake := fakeSignVerifier{run: func(context.Context, smokeTestRequest) (smokeTestResult, error) {
		called = true
		return smokeTestResult{}, nil
	}}

	_, err := runSmokeTest(context.Background(), smokeTestRequest{TrustRoot: trustRootPublic}, fake)
	if err == nil {
		t.Fatal("runSmokeTest under trustRootPublic: want an error, got nil")
	}
	if !errors.Is(err, errPublicSigningUnsupported) {
		t.Fatalf("error = %v, want it to wrap errPublicSigningUnsupported", err)
	}
	if called {
		t.Fatal("runSmokeTest attempted a signature under trustRootPublic; it must refuse first")
	}
	if !strings.Contains(err.Error(), "ADR-0010") {
		t.Errorf("error %q does not cite the measured reason (ADR-0010)", err)
	}
}

func TestINIT006SelfHostedTrustRootCallsTheSignVerifier(t *testing.T) {
	called := false
	want := smokeTestResult{CommitSHA: "abc123", Ref: "refs/innsegl/init-verify"}
	fake := fakeSignVerifier{run: func(context.Context, smokeTestRequest) (smokeTestResult, error) {
		called = true
		return want, nil
	}}

	got, err := runSmokeTest(context.Background(), smokeTestRequest{TrustRoot: trustRootSelfHosted}, fake)
	if err != nil {
		t.Fatalf("runSmokeTest: %v", err)
	}
	if !called {
		t.Fatal("runSmokeTest under trustRootSelfHosted did not call the sign-and-verify seam")
	}
	if got != want {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
}

func TestINIT006SelfHostedPropagatesAVerificationFailure(t *testing.T) {
	// "It refuses to report success if the test signature does not verify."
	fake := fakeSignVerifier{run: func(context.Context, smokeTestRequest) (smokeTestResult, error) {
		return smokeTestResult{}, errors.New("innsegl verify: VERDICT: FAILED")
	}}
	_, err := runSmokeTest(context.Background(), smokeTestRequest{TrustRoot: trustRootSelfHosted}, fake)
	if err == nil {
		t.Fatal("runSmokeTest with a failing verifier: want an error, got nil")
	}
}

type fakeSignVerifier struct {
	run func(context.Context, smokeTestRequest) (smokeTestResult, error)
}

func (f fakeSignVerifier) Run(ctx context.Context, req smokeTestRequest) (smokeTestResult, error) {
	return f.run(ctx, req)
}

// buildInitClaim is pure — no network, no SPIRE, no gitsign — and it is
// where #116's Pseudonymiser is CONFIGURED, not reimplemented: init supplies
// the raw agent_type/task_ref for its own verification identity and asks
// the SAME package #116 built to render the SPIFFE ID and the trailers.

func TestINIT006ClaimIsPseudonymousByDefault(t *testing.T) {
	pseudonyms, err := identity.New(identity.ModePseudonymous, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	claim, spiffeID, err := buildInitClaim(pseudonyms, "innsegl.dev", "run-deadbeefcafef00d")
	if err != nil {
		t.Fatalf("buildInitClaim: %v", err)
	}
	if strings.Contains(spiffeID, initSmokeAgentType) || strings.Contains(spiffeID, initSmokeTaskRef) {
		t.Fatalf("pseudonymous SPIFFE ID %q leaks the literal agent type or task ref", spiffeID)
	}
	if claim.Identity != spiffeID {
		t.Errorf("claim.Identity = %q, want %q", claim.Identity, spiffeID)
	}
	if claim.Run != "run-deadbeefcafef00d" {
		t.Errorf("claim.Run = %q, want the run id", claim.Run)
	}
	// ClaimedTask under pseudonymous mode is the pseudonym itself (#116:
	// "pseudonymous: the pseudonym, identical to TaskID").
	if claim.Task == initSmokeTaskRef {
		t.Errorf("claim.Task = %q, the literal task ref leaked into the trailer under pseudonymous mode", claim.Task)
	}
	if _, err := claim.Trailers(); err != nil {
		t.Errorf("claim.Trailers(): %v (the claim #116 and #117 must agree on must satisfy ADR-0018 §6)", err)
	}
}

func TestINIT006ClaimIsLiteralOnRequest(t *testing.T) {
	pseudonyms, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatal(err)
	}
	claim, spiffeID, err := buildInitClaim(pseudonyms, "innsegl.dev", "run-deadbeefcafef00d")
	if err != nil {
		t.Fatalf("buildInitClaim: %v", err)
	}
	if !strings.Contains(spiffeID, initSmokeAgentType) || !strings.Contains(spiffeID, initSmokeTaskRef) {
		t.Fatalf("literal SPIFFE ID %q does not carry the literal agent type and task ref", spiffeID)
	}
	if claim.Task != initSmokeTaskRef {
		t.Errorf("claim.Task = %q, want the literal task ref %q under literal mode", claim.Task, initSmokeTaskRef)
	}
}

func TestINIT006NewSmokeRunIDIsFreshEveryCall(t *testing.T) {
	a := newSmokeRunID()
	b := newSmokeRunID()
	if a == b {
		t.Fatalf("newSmokeRunID returned the same value twice: %q", a)
	}
	if !strings.HasPrefix(a, "run-") {
		t.Fatalf("newSmokeRunID() = %q, want a run- prefix", a)
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/identity"
)

// INIT-008 and INIT-009 (both proposed, doc 07 layer U; doc 07 is not
// modified by this change).
//
// #134 (RM-089): spireSignVerifier.Run and createVerificationCommit —
// initsign.go's production sign-and-verify path, step 4 of #117 — sat at 0%
// coverage. Every other layer of `innsegl init` is tested against real
// temporary git repositories and a real HTTP checksum fetch (INIT-001
// through INIT-007); this file is the one that drives the signing path
// itself against a real SPIRE, Fulcio and Rekor, using
// initsignharness_test.go's stack. See that file for why the stack is
// opt-in (INNSEGL_RUN_INIT_E2E) rather than automatic like every other
// container harness here.
//
// # The boundary: what this proves, and what only a human running the
// command can prove
//
// #117 is explicit that the OIDC browser flow IS the identity proof — "remove
// it and the signature attests to nothing" — and a headless test cannot
// complete a human's browser login. This test does not attempt to. It drives
// spireSignVerifier.Run through initsign.go's OTHER credential path: the
// three-PEM-file "bootstrapping a trust domain" branch of
// openInitCredentialSource, the same branch a real operator's `innsegl init
// -admin-svid ... -admin-key ... -admin-bundle ...` takes on a fresh
// deployment before `innsegl init` itself is an attested workload. That
// branch, the SPIRE admin gRPC dial, minting a JWT-SVID over it, handing that
// credential to signing.Signer, the real gitsign binary, a real Fulcio
// certificate issuance, a real Rekor transparency-log entry, the linked-
// worktree isolation, the trailer rendering, and a real, independent
// `innsegl verify` — every one of those is exercised for real here, with no
// fake at any position.
//
// What is NOT exercised, and cannot be by any automated test: a human
// completing an interactive OIDC login and gitsign caching that token. The
// PEM-file branch and the Workload-API branch converge on the exact same
// downstream code (buildInitClaim, spire.Dial, mcp.NewSPIREMinter,
// signing.NewSigner, createVerificationCommit, verifyCommand) — this test
// covers all of that shared downstream machinery — but the OIDC round trip
// itself, and gitsign's own token cache, are upstream of the seam this test
// enters at and remain provable only by a human running `innsegl init` (or
// `innsegl serve`) and completing the login. Coverage of
// spireSignVerifier.Run and createVerificationCommit closes #134's stated
// gap; it does not and cannot substitute for that manual check, and this
// comment is the place that says so rather than letting a green CI run imply
// it.
func TestINIT008SigningPathAgainstRealSPIREFulcioRekor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	stack := startSignE2EStack(ctx, t)

	pseudonyms, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}

	baseReq := smokeTestRequest{
		TrustRoot:    trustRootSelfHosted,
		FulcioURL:    stack.fulcioURL,
		RekorURL:     stack.rekorURL,
		OIDCIssuer:   signE2EIssuer,
		Pseudonyms:   pseudonyms,
		AuthorName:   "Innsegl Operator",
		AuthorEmail:  "operator@innsegl.invalid",
		GitsignPath:  stack.gitsignPath,
		SpireAddress: stack.adminAddr,
		TrustDomain:  signE2ETrustDomain,
		ServerID:     signE2EServerID,
		SVIDFile:     stack.svidPath,
		KeyFile:      stack.keyPath,
		BundleFile:   stack.bundlePath,
	}

	// ---------------------------------------------------------------------
	// INIT-008 — the happy path. doc 07 layer U (proposed): "a real commit is
	// signed and `innsegl verify` accepts it; the operator's own HEAD, branch
	// and staged index never move; the trailers are correct".
	// ---------------------------------------------------------------------
	t.Run("INIT-008 a real commit is signed and innsegl verify accepts it", func(t *testing.T) {
		repo := initTestRepo(t)
		writeInitTestCommit(t, repo)
		headBefore := signE2EGitOutput(t, repo, "rev-parse", "HEAD")
		branchBefore := signE2EGitOutput(t, repo, "branch", "--show-current")

		req := baseReq
		req.Repo = repo

		result, err := (spireSignVerifier{}).Run(ctx, req)
		if err != nil {
			t.Fatalf("spireSignVerifier.Run: %v", err)
		}
		if result.CommitSHA == "" {
			t.Fatal("Run reported no commit SHA")
		}
		if result.Ref != initVerifyRef {
			t.Errorf("Ref = %q, want %q", result.Ref, initVerifyRef)
		}

		// 1. The commit object is real, and it carries a signature.
		if got := signE2EGitOutput(t, repo, "cat-file", "-t", result.CommitSHA); strings.TrimSpace(got) != "commit" {
			t.Fatalf("object %s is a %q, not a commit", result.CommitSHA, strings.TrimSpace(got))
		}
		raw := signE2EGitOutput(t, repo, "cat-file", "commit", result.CommitSHA)
		if !strings.Contains(raw, "gpgsig") {
			t.Fatalf("commit %s carries no gpgsig header:\n%s", result.CommitSHA, raw)
		}

		// 2. Run's own bookkeeping: initVerifyRef points at the commit it made.
		atRef := strings.TrimSpace(signE2EGitOutput(t, repo, "rev-parse", initVerifyRef))
		if atRef != result.CommitSHA {
			t.Errorf("%s resolves to %s, want %s", initVerifyRef, atRef, result.CommitSHA)
		}

		// 3. The operator's own HEAD, branch and staged index never moved —
		// createVerificationCommit's linked-worktree isolation, checked from
		// outside rather than assumed.
		if got := strings.TrimSpace(signE2EGitOutput(t, repo, "rev-parse", "HEAD")); got != strings.TrimSpace(headBefore) {
			t.Errorf("the repository's own HEAD moved from %s to %s", strings.TrimSpace(headBefore), got)
		}
		if got := strings.TrimSpace(signE2EGitOutput(t, repo, "branch", "--show-current")); got != strings.TrimSpace(branchBefore) {
			t.Errorf("the operator's checked-out branch changed from %q to %q", strings.TrimSpace(branchBefore), got)
		}

		// 4. Trailers, read back with git's own parser. ModeLiteral makes the
		// identity predictable: buildInitClaim embeds initSmokeAgentType and
		// initSmokeTaskRef literally rather than pseudonymising them.
		trailers := signE2EGitOutput(t, repo, "log", "-1", "--format=%(trailers:only,unfold)", result.CommitSHA)
		wantIdentityPrefix := "Agent-Identity: spiffe://" + signE2ETrustDomain +
			"/agent/" + initSmokeAgentType + "/" + initSmokeTaskRef + "/run-"
		if !strings.Contains(trailers, wantIdentityPrefix) {
			t.Errorf("commit trailers do not carry the expected Agent-Identity prefix %q:\n%s",
				wantIdentityPrefix, trailers)
		}
		if !strings.Contains(trailers, "Agent-Run: run-") {
			t.Errorf("commit trailers carry no Agent-Run trailer:\n%s", trailers)
		}
		if !strings.Contains(trailers, "Agent-Task: "+initSmokeTaskRef) {
			t.Errorf("commit trailers do not carry Agent-Task: %s:\n%s", initSmokeTaskRef, trailers)
		}

		// 5. A FRESH, independent `innsegl verify` call — not the one
		// spireSignVerifier.Run already ran internally as part of its own
		// success criterion — confirms the artifact durably verifies on its
		// own account, rather than trusting Run's report of its own check.
		var vout, verr bytes.Buffer
		code := verifyCommand([]string{result.CommitSHA,
			"-repo", repo,
			"-fulcio-url", stack.fulcioURL,
			"-rekor-url", stack.rekorURL,
			"-issuer", signE2EIssuer,
		}, &vout, &verr)
		if code != exitOK {
			t.Fatalf("a second, independent `innsegl verify` on %s failed (exit %d):\n%s%s",
				result.CommitSHA, code, vout.String(), verr.String())
		}

		t.Logf("INIT-008 artifact\n  commit   %s\n  ref      %s\n  trailers %s",
			result.CommitSHA, result.Ref, strings.ReplaceAll(strings.TrimSpace(trailers), "\n", " | "))
	})

	// ---------------------------------------------------------------------
	// INIT-009 — a real misconfiguration is refused, not silently accepted.
	// doc 07 layer U (proposed): "an unreachable SPIRE admin address fails
	// loudly and creates no commit object and no verification ref", the
	// anti-vacuity check on the happy path above: if Run cannot fail against
	// this real stack, its earlier success proves nothing.
	// ---------------------------------------------------------------------
	t.Run("INIT-009 an unreachable SPIRE admin address is refused, not silently accepted", func(t *testing.T) {
		repo := initTestRepo(t)
		writeInitTestCommit(t, repo)
		before := strings.TrimSpace(signE2EGitOutput(t, repo, "rev-list", "--all", "--count"))

		req := baseReq
		req.Repo = repo
		// Everything else about this request is real; only the admin address
		// is wrong — port 1 is never SPIRE's, on 127.0.0.1 or anywhere else.
		req.SpireAddress = "127.0.0.1:1"

		_, err := (spireSignVerifier{}).Run(ctx, req)
		if err == nil {
			t.Fatal("spireSignVerifier.Run succeeded while pointed at an unreachable SPIRE admin address")
		}
		t.Logf("INIT-009 observed failure (expected): %v", err)

		after := strings.TrimSpace(signE2EGitOutput(t, repo, "rev-list", "--all", "--count"))
		if before != after {
			t.Errorf("commit object count changed from %s to %s after a refused signature", before, after)
		}
		if out, verifyErr := exec.CommandContext(ctx, "git", "-C", repo,
			"show-ref", "--verify", "--quiet", initVerifyRef).CombinedOutput(); verifyErr == nil {
			t.Errorf("%s exists after a refused signature: %s", initVerifyRef, out)
		}
	})
}

// signE2EGitOutput runs one read-only git command and returns its combined
// output, failing the test on a non-zero exit.
func signE2EGitOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

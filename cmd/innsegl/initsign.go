// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/spire"
)

// "Signs one real commit and verifies it with `innsegl verify` before
// reporting success... Measure, do not assert." (#117 point 4) This file is
// that step, and the trust-root branch that makes it honest.
//
// # Why "anyone" (public Sigstore) refuses here rather than attempting a
// signature
//
// ADR-0010 measured, 2026-08-28, against the live public Fulcio
// configuration endpoint: the public allowlist accepts issuers of type
// `ci-provider`, `kubernetes`, `email` and `chainguard-identity` — ZERO of
// type `spiffe`. This project's SPIFFE-ID pipeline (the one #116
// pseudonymises, the one internal/verify.commitCertificate requires a URI
// SAN from) has no path to a certificate public Fulcio will issue: there is
// no OIDC token this deployment can present that a `spiffe`-typed issuer
// entry does not exist to accept. ADR-0010's own Decision section states the
// adjacent trap explicitly — "Public Sigstore is not reachable by
// substituting a CI token... the Fulcio certificate would then attest the
// workflow, not the run" — which is precisely what an attempt here would
// have to do to produce ANY certificate at all.
//
// Attempting the signature anyway would not fail "sometimes" in a way a
// retry could paper over; it would fail the same way every time, against a
// real CA, for a documented and already-measured reason. #117 point 4
// requires refusing to report success rather than discovering that failure
// live, so this returns a clear, cited refusal instead. This is a genuine
// conflict between #117 (which frames "anyone" as a working, symmetric
// alternative to "only us") and ADR-0010 (which forecloses the SPIFFE
// pipeline against public Fulcio outright); it is reported as a question for
// the human, not resolved by inventing a workaround here — see this
// package's init.go top-level comment and the implementation report.
//
// The rest of #117 point 3 (writing the deployment config for a public
// trust root) still runs: an operator can configure a FUTURE deployment for
// public Sigstore, e.g. for release-artifact signing in the shape
// .github/workflows/release.yml already uses. What `init` refuses is
// claiming to have PROVEN that configuration signs and verifies a commit,
// because it cannot.
var errPublicSigningUnsupported = errors.New("innsegl init: a public Sigstore trust root cannot " +
	"sign a SPIFFE-attributed test commit under this project's current architecture (ADR-0010: " +
	"public Fulcio's allowlist accepts no issuer of type `spiffe`, measured 2026-08-28). init will " +
	"not attempt a signature it already knows will fail, and will not report success it cannot " +
	"prove. See ADR-0010 and internal/verify's requirement of a URI SAN")

// The verification commit's synthetic identity. Neither value is meant to be
// legible in the way a real agent's is — it names WHAT RAN (`innsegl init`'s
// own smoke test), not a ticket or a kind of work — and it is still run
// through #116's Pseudonymiser exactly like any other agent_type/task_ref,
// because that package does not get a second, unpseudonymised caller.
const (
	initSmokeAgentType = "innsegl-init"
	initSmokeTaskRef   = "verify-signing-setup"
)

// initVerifyRef is where the verification commit lives: never a branch, so
// it is never mistaken for part of the repository's real history, and
// always found again by `--undo` through the git-config bookkeeping in
// initgit.go.
const initVerifyRef = "refs/innsegl/init-verify"

// newSmokeRunID mints a fresh run id for one smoke test. It does not need to
// be a digest of anything (unlike a real run's, RunRef.SPIFFEID.md1) —
// opacity is already RunRef's own requirement, and 128 bits of randomness
// satisfies it as well as an HMAC would, more simply, for a value nothing
// downstream of this process needs to reproduce.
func newSmokeRunID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns a short read or a non-nil error on any supported platform
	return "run-" + hex.EncodeToString(b[:])
}

// buildInitClaim renders the smoke test's claim through #116's own
// Pseudonymiser — configuring it, not reimplementing it. Pure: no network, no
// SPIRE, no gitsign.
func buildInitClaim(pseudonyms *identity.Pseudonymiser, trustDomain, runID string) (signing.Claim, string, error) {
	agentType, err := pseudonyms.AgentType(initSmokeAgentType)
	if err != nil {
		return signing.Claim{}, "", fmt.Errorf("innsegl init: rendering the verification agent type: %w", err)
	}
	taskID, err := pseudonyms.TaskID(initSmokeTaskRef)
	if err != nil {
		return signing.Claim{}, "", fmt.Errorf("innsegl init: rendering the verification task id: %w", err)
	}
	claimedTask, err := pseudonyms.ClaimedTask(initSmokeTaskRef)
	if err != nil {
		return signing.Claim{}, "", fmt.Errorf("innsegl init: rendering the Agent-Task trailer: %w", err)
	}
	ref := spire.RunRef{AgentType: agentType, TaskID: taskID, RunID: runID}
	spiffeID, err := ref.SPIFFEID(trustDomain)
	if err != nil {
		return signing.Claim{}, "", fmt.Errorf("innsegl init: building the verification SPIFFE ID: %w", err)
	}
	return signing.Claim{Identity: spiffeID, Run: runID, Task: claimedTask}, spiffeID, nil
}

// smokeTestRequest is everything the sign-and-verify step needs.
type smokeTestRequest struct {
	TrustRoot trustRoot

	Repo       string
	FulcioURL  string
	RekorURL   string
	OIDCIssuer string

	Pseudonyms *identity.Pseudonymiser

	AuthorName  string
	AuthorEmail string

	GitPath     string
	GitsignPath string

	// SPIRE admin connection — the established dual shape servewiring.go
	// resolves for `innsegl serve`, matched here rather than invented anew.
	SpireAddress string
	TrustDomain  string
	ServerID     string
	WorkloadAPI  string
	SVIDFile     string
	KeyFile      string
	BundleFile   string
}

// smokeTestResult is what a successful smoke test proved.
type smokeTestResult struct {
	CommitSHA string
	Ref       string
}

// signAndVerifier is the seam. *spireSignVerifier is production; tests
// inject a fake so the trust-root branch is provable without a network.
type signAndVerifier interface {
	Run(ctx context.Context, req smokeTestRequest) (smokeTestResult, error)
}

// runSmokeTest is the whole of point 4: refuse outright for a public trust
// root (see errPublicSigningUnsupported above), or delegate to sv for a
// self-hosted one. sv is never called in the public case — the acceptance
// criterion is "refuses to report success", and a call that always fails the
// same measured way is not a smoke test, it is theatre.
func runSmokeTest(ctx context.Context, req smokeTestRequest, sv signAndVerifier) (smokeTestResult, error) {
	if req.TrustRoot == trustRootPublic {
		return smokeTestResult{}, errPublicSigningUnsupported
	}
	return sv.Run(ctx, req)
}

// ---------------------------------------------------------------------------
// Production wiring: SPIRE admin, a minted JWT-SVID, gitsign, `innsegl verify`.
// ---------------------------------------------------------------------------

// spireSignVerifier is the production signAndVerifier. It mirrors
// servewiring.go's own admin-credential resolution exactly (Workload API by
// default; three explicit PEM files for the "not yet an attested workload"
// case servewiring.go documents — bootstrapping a trust domain, which is
// what a fresh `innsegl init` on a new deployment IS) rather than inventing
// a third way to get one.
type spireSignVerifier struct{}

func (spireSignVerifier) Run(ctx context.Context, req smokeTestRequest) (smokeTestResult, error) {
	claim, spiffeID, err := buildInitClaim(req.Pseudonyms, req.TrustDomain, newSmokeRunID())
	if err != nil {
		return smokeTestResult{}, err
	}

	source, sourceClose, err := openInitCredentialSource(ctx, req)
	if err != nil {
		return smokeTestResult{}, err
	}
	defer sourceClose()

	admin, err := spire.Dial(ctx, spire.Config{
		Address:     req.SpireAddress,
		TrustDomain: req.TrustDomain,
		ServerID:    req.ServerID,
		Source:      source,
	})
	if err != nil {
		return smokeTestResult{}, fmt.Errorf("innsegl init: dial the SPIRE admin API at %s: %w", req.SpireAddress, err)
	}
	defer func() { _ = admin.Close() }()

	mintConn, err := dialInitSVIDAPI(req, source)
	if err != nil {
		return smokeTestResult{}, err
	}
	defer func() { _ = mintConn.Close() }()

	minter := mcp.NewSPIREMinter(mintConn)
	minted, err := minter.MintJWTSVID(ctx, spiffeID, signing.AudienceSigstore)
	if err != nil {
		return smokeTestResult{}, fmt.Errorf("innsegl init: minting a verification credential: %w", err)
	}
	cred := signing.Credential{
		Token: minted.Token, SPIFFEID: minted.SPIFFEID,
		Audience: minted.Audience, ExpiresAt: minted.ExpiresAt,
	}

	authorPolicy := signing.AuthorPolicy{Operators: []string{req.AuthorEmail}}
	signer, err := signing.NewSigner(signing.Config{
		FulcioURL: req.FulcioURL, RekorURL: req.RekorURL, Issuer: req.OIDCIssuer,
		GitsignPath: req.GitsignPath, GitPath: req.GitPath, Author: authorPolicy,
	}, staticCredentialSource{cred})
	if err != nil {
		return smokeTestResult{}, fmt.Errorf("innsegl init: preparing the signer: %w", err)
	}
	defer func() { _ = signer.Close() }()

	sha, cleanup, err := createVerificationCommit(ctx, req.GitPath, req.Repo, signer, claim, req.AuthorName, req.AuthorEmail)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return smokeTestResult{}, err
	}

	if err := runGit(ctx, req.GitPath, req.Repo, "update-ref", initVerifyRef, sha); err != nil {
		return smokeTestResult{}, fmt.Errorf("innsegl init: recording %s: %w", initVerifyRef, err)
	}

	var vout, verr bytes.Buffer
	// verifyCommand is cmd/innsegl/verify.go's own subcommand body, reused
	// exactly as `innsegl verify` runs it rather than reimplemented (#117
	// point 4: "the verification you must call to prove setup worked"). Its
	// signature takes no context — it builds its own bounded one internally
	// (verifyTimeout) — matching every other subcommand entry point in this
	// package, so there is nothing of ctx to propagate into it.
	code := verifyCommand([]string{sha, //nolint:contextcheck // see the comment above
		"-repo", req.Repo,
		"-fulcio-url", req.FulcioURL,
		"-rekor-url", req.RekorURL,
		"-issuer", req.OIDCIssuer,
	}, &vout, &verr)
	if code != exitOK {
		return smokeTestResult{}, fmt.Errorf("innsegl init: the test commit %s did not verify "+
			"(innsegl verify exit %d) — setup is NOT complete:\n%s%s",
			sha, code, vout.String(), verr.String())
	}

	return smokeTestResult{CommitSHA: sha, Ref: initVerifyRef}, nil
}

// staticCredentialSource hands back one already-minted credential. It exists
// because signing.Signer wants a CredentialSource that can re-fetch on
// expiry (ADR-0031 decision, IP §6.2); a smoke test's single commit never
// lives long enough to need that, so re-fetching here would be dead code
// nothing exercises.
type staticCredentialSource struct{ cred signing.Credential }

func (s staticCredentialSource) Credential(context.Context) (signing.Credential, error) {
	return s.cred, nil
}

// openInitCredentialSource mirrors servewiring.go's openCredentialSource
// exactly: the Workload API by default (init is an attested workload like
// any other), or three explicit PEM files, all-or-none, for bootstrapping a
// trust domain before init itself is attested.
func openInitCredentialSource(ctx context.Context, req smokeTestRequest) (spire.Source, func(), error) {
	if req.SVIDFile == "" {
		source, err := workloadapi.NewX509Source(ctx,
			workloadapi.WithClientOptions(workloadapi.WithAddr(req.WorkloadAPI)))
		if err != nil {
			return nil, nil, fmt.Errorf("innsegl init: no SVID from the Workload API at %s: "+
				"without an identity this process holds no SPIRE admin (IP §1): %w", req.WorkloadAPI, err)
		}
		return source, func() { _ = source.Close() }, nil
	}

	svid, err := x509svid.Load(req.SVIDFile, req.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("innsegl init: load the admin SVID from %s: %w", req.SVIDFile, err)
	}
	td, err := spiffeid.TrustDomainFromString(req.TrustDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("innsegl init: trust domain %q: %w", req.TrustDomain, err)
	}
	raw, err := os.ReadFile(req.BundleFile)
	if err != nil {
		return nil, nil, fmt.Errorf("innsegl init: read the trust bundle %s: %w", req.BundleFile, err)
	}
	var roots []*x509.Certificate
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, cerr := x509.ParseCertificate(blk.Bytes)
		if cerr != nil {
			return nil, nil, fmt.Errorf("innsegl init: parse the trust bundle %s: %w", req.BundleFile, cerr)
		}
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		return nil, nil, fmt.Errorf("innsegl init: %s holds no PEM certificate", req.BundleFile)
	}
	return initFileSource{svid: svid, bundle: x509bundle.FromX509Authorities(td, roots)}, func() {}, nil
}

type initFileSource struct {
	svid   *x509svid.SVID
	bundle *x509bundle.Bundle
}

func (s initFileSource) GetX509SVID() (*x509svid.SVID, error) { return s.svid, nil }
func (s initFileSource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return s.bundle, nil
}

// dialInitSVIDAPI opens the second connection get_credential's minter needs
// (*spire.Client keeps its own unexported), over the SAME credential and
// server authorization as the admin dial above — never a second credential.
func dialInitSVIDAPI(req smokeTestRequest, source spire.Source) (*grpc.ClientConn, error) {
	want := req.ServerID
	if want == "" {
		want = "spiffe://" + req.TrustDomain + "/spire/server"
	}
	serverID, err := spiffeid.FromString(want)
	if err != nil {
		return nil, fmt.Errorf("innsegl init: SPIRE server id %q: %w", want, err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(req.SpireAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, fmt.Errorf("innsegl init: dial %s for MintJWTSVID: %w", req.SpireAddress, err)
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// The verification commit itself: isolated by a linked git worktree so the
// operator's own branch, HEAD and staged index are never touched.
// ---------------------------------------------------------------------------

// createVerificationCommit signs one commit in a DETACHED, LINKED worktree —
// never the operator's own working tree or branch. A linked worktree shares
// the same object database as the repository it belongs to (`git help
// worktree`), so the resulting commit is immediately readable by
// `innsegl verify --repo <repo>` without any push, fetch or merge; nothing
// about the operator's current branch, HEAD or staged changes moves.
//
// signing.Signer.Sign (ADR-0031) commits WHATEVER IS STAGED, onto the
// worktree's own HEAD — exactly right for a temporary worktree, and exactly
// why this is never called against the operator's real one.
func createVerificationCommit(ctx context.Context, gitPath, repo string, signer *signing.Signer,
	claim signing.Claim, authorName, authorEmail string,
) (sha string, cleanup func(), err error) {
	base, err := runGitOutput(ctx, gitPath, repo, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", nil, fmt.Errorf("innsegl init: this repository has no commit to verify "+
			"against yet (HEAD does not resolve): %w", err)
	}
	base = strings.TrimSpace(base)

	tmp, mkErr := os.MkdirTemp("", "innsegl-init-verify-")
	if mkErr != nil {
		return "", nil, fmt.Errorf("innsegl init: preparing a scratch worktree: %w", mkErr)
	}
	// context.Background(), deliberately: cleanup runs from a `defer` in the
	// caller and must still remove the scratch worktree even when ctx is
	// already cancelled or its deadline has passed — an orphaned worktree
	// left behind by a timed-out run is a worse outcome than one more
	// second spent tidying up after it.
	cleanup = func() { //nolint:contextcheck // deliberate: see the comment above
		removeErr := runGit(context.Background(), gitPath, repo, "worktree", "remove", "--force", tmp)
		rmErr := os.RemoveAll(tmp)
		if removeErr != nil || rmErr != nil {
			// Best-effort: nothing downstream depends on this cleanup having
			// fully succeeded, and there is no caller left to report to by
			// the time a deferred cleanup runs. A leftover scratch worktree
			// is a stale directory, not a security or correctness problem.
			_ = removeErr
			_ = rmErr
		}
	}

	if addErr := runGit(ctx, gitPath, repo, "worktree", "add", "--detach", tmp, base); addErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("innsegl init: creating a scratch worktree: %w", addErr)
	}

	marker := filepath.Join(tmp, ".innsegl-init-verify")
	body := fmt.Sprintf("innsegl init verification commit\nclaim: %s\n", claim.Identity)
	if writeErr := os.WriteFile(marker, []byte(body), 0o600); writeErr != nil {
		return "", cleanup, fmt.Errorf("innsegl init: writing the verification marker: %w", writeErr)
	}
	// -f because this repository's own .gitignore may cover the marker, and
	// most do: a leading-dot name is exactly what a `.*` rule catches, and
	// `.*` is a common policy — this project ships it. Without -f, `git add`
	// refuses a file init created itself, for its own use, seconds earlier,
	// and the verification commit never happens. The file is init's, it is
	// written into a throwaway worktree, and it is gone when this returns, so
	// there is nothing here for an ignore rule to protect (#117).
	if stageErr := runGit(ctx, gitPath, tmp, "add", "-f", ".innsegl-init-verify"); stageErr != nil {
		return "", cleanup, fmt.Errorf("innsegl init: staging the verification marker: %w", stageErr)
	}

	result, err := signer.Sign(ctx, signing.Request{
		Repo: tmp,
		Message: "innsegl init: verify signing setup\n\n" +
			"Throwaway commit created by `innsegl init` to prove gitsign, Fulcio and\n" +
			"Rekor are reachable and correctly configured. It is not part of this\n" +
			"repository's history: it lives only under " + initVerifyRef + ",\n" +
			"never under a branch, and `innsegl init --undo` removes it.\n",
		AuthorName:  authorName,
		AuthorEmail: authorEmail,
		Claim:       claim,
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("innsegl init: signing the verification commit: %w", err)
	}
	return result.CommitSHA, cleanup, nil
}

// runGit runs one git command for its side effect, discarding output on
// success and reporting it on failure.
func runGit(ctx context.Context, gitPath, dir string, args ...string) error {
	_, err := runGitOutput(ctx, gitPath, dir, args...)
	return err
}

func runGitOutput(ctx context.Context, gitPath, dir string, args ...string) (string, error) {
	if gitPath == "" {
		gitPath = "git"
	}
	//nolint:gosec // G204: gitPath is configuration, args are literals or already-resolved SHAs/paths
	cmd := exec.CommandContext(ctx, gitPath, append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// SPDX-License-Identifier: Apache-2.0

// Package verify performs IP §1's three checks on a signed commit, using
// nothing but git, Fulcio and Rekor.
//
// # This is the package that proves I5
//
//	I5: Verification never trusts this system. Every attribution claim must be
//	checkable against Fulcio/Rekor by a third party with no access to our
//	database.
//
// So the shape of this package is a consequence of one negative requirement:
// there must be no way for it to consult the ledger. It imports no ledger, no
// database driver and no MCP client, and VER-001 asserts that from the import
// graph as well as from a container that has no route to a running Postgres.
// "Does not query the database" would be a property of the current code;
// "cannot" is a property of the package.
//
// # The three checks, and what each one actually establishes
//
//  1. FULCIO CERTIFICATE CHAIN VALID. The certificate the commit is signed
//     under chains to the root this deployment's Fulcio publishes, and it was
//     inside its validity window AT THE MOMENT THE LOG INTEGRATED THE ENTRY —
//     not now. That distinction is IP §6.8 and it is what lets a commit from
//     last year still verify: Fulcio certificates live for ten minutes, so a
//     verifier that evaluated them against the wall clock would report every
//     historical commit as failed.
//
//  2. REKOR INCLUSION PROVEN. The log holds an entry whose artifact is
//     sha256 of THIS commit's SHA, logged under THIS commit's certificate,
//     carrying a signature over that artifact that verifies under the
//     certificate's own public key, whose inclusion path reaches a root, and
//     whose checkpoint is signed by the log's key. The log index is shown.
//
//  3. TRAILER MATCHES CERTIFICATE IDENTITY. The Agent-Identity trailer and the
//     certificate's URI SAN, side by side; on a mismatch, the segment of the
//     SPIFFE ID that differs is named. "Mismatch" is not an answer a reader
//     can act on.
//
// # What is NOT done here, and why that is not a gap
//
// This verifier does not re-verify the CMS signature in the commit's `gpgsig`
// header in process. IP §7 forbids reimplementing Sigstore's crypto and threat
// model §5.4 warns about hand-written ASN.1; the structure walk needed to
// reach the certificate is already one ASN.1 reader more than this project
// wanted. What stands in its place is check 2, and it is stronger rather than
// weaker: gitsign's online mode logs a hashedrekord whose ARTIFACT IS THE
// COMMIT SHA (ADR-0031 decision 6), so an entry exists only for the exact
// object that was signed. Alter one byte of the commit — a trailer, the tree,
// the parent — and the SHA changes and there is no entry. That is what makes
// VER-003's rewritten commit fail.
//
// # There is no SCT, and this verifier says so out loud
//
// ADR-0029 decision 5 runs Fulcio with `--ct-log-url=` empty: this deployment
// operates no certificate transparency log, so its certificates carry no SCT.
// RM-032 measured what that costs a cosign-based verifier — `cosign.GetCTLogPubs`
// runs BEFORE the ignore-SCT flag is consulted, refuses an empty key set, and
// falls back to fetching keys from the public-good TUF mirror. This package
// avoids that entirely by not using cosign: X.509 path validation is
// crypto/x509's, against a root fetched from the deployment's own Fulcio. No
// TUF fetch, no placeholder key, no network beyond the two endpoints named in
// the configuration. The absence of an SCT is reported as an evidence line on
// check 1 rather than ignored silently.
//
// # Three states, never two
//
// Every check is `verified`, `failed` or `unavailable`, and the rollup follows
// doc 06 §4.1: any check failing makes the verdict failed; any check erroring
// makes it unavailable, never verified. An unreachable Fulcio or Rekor is
// UNAVAILABLE. There is no cache, so there is no cached verdict to fall back
// to — doc 06 anti-pattern 1 is unreachable by construction.
//
// A fourth verdict, `unattributed`, describes the COMMIT rather than a check:
// a commit that carries neither a signature nor an Agent-* trailer makes no
// attribution claim, so no check runs and none is reported. VER-006 requires
// that state to be distinct from failed-verification, and doc 06 anti-pattern
// 2 is the collapse it refuses.
package verify

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Errors a caller can act on. A malformed request is an error; a commit that
// does not verify is a Report.
var (
	// ErrConfig is a verifier that cannot be built from the given Config.
	ErrConfig = errors.New("verify: invalid configuration")

	// ErrRevision is a revision that does not resolve to a commit in the
	// repository.
	ErrRevision = errors.New("verify: no such commit")
)

// Result is one check's outcome. Doc 06 §4.1 requires exactly these three and
// forbids collapsing any two of them.
type Result string

const (
	// Verified: the check ran and the claim holds.
	Verified Result = "verified"
	// Failed: the check ran and the claim does not hold.
	Failed Result = "failed"
	// Unavailable: the check could not run. NEVER rendered as either of the
	// other two (doc 06 P2, IP §6.11).
	Unavailable Result = "unavailable"
)

// Verdict is the rollup, plus the commit-level state VER-006 requires.
type Verdict string

const (
	VerdictVerified    Verdict = "verified"
	VerdictFailed      Verdict = "failed"
	VerdictUnavailable Verdict = "unavailable"
	// VerdictUnattributed is a commit that makes no attribution claim: no
	// signature and no Agent-* trailer. It is not a failure, and reporting it
	// as one would make every pre-adoption commit look like an attack (E7).
	VerdictUnattributed Verdict = "unattributed"
)

// The three check names, spelled as doc 06 §4.1 spells them.
const (
	CheckCertificateChain = "Fulcio certificate chain valid"
	CheckRekorInclusion   = "Rekor inclusion proven"
	CheckTrailerIdentity  = "Trailer matches certificate identity"
)

// DefaultSkew is IP §6.8's "NTP-scale" tolerance: the bound within which a
// certificate's validity window is treated as covering the log's integration
// time even though the two clocks disagree.
//
// SIXTY SECONDS, and it is the same number ADR-0031 decision 7 documents for
// the signing side's certificate check — one bound, written down once.
// TestTheSkewBoundIsTheOneADR0031Documents holds the two together.
//
// It applies to a VERIFIER reading somebody else's certificate and to nothing
// else. ADR-0031 decision 7: widening a CREDENTIAL's window by the same amount
// is extending its TTL, which IP §6.2 forbids in terms. The asymmetry is
// deliberate and it is not exposed as a flag — a verifier whose tolerance can
// be widened from the command line has no bound at all.
const DefaultSkew = 60 * time.Second

// maxTreeScan bounds VER-003's recovery walk. A repository with more commit
// objects than this is not searched exhaustively, and the report says so
// rather than reporting an absence it did not establish.
//
// A var rather than a const, behind a seam, so the bound itself is reachable
// from a test without building a repository of five thousand commits. It is
// never reassigned outside tests — the same idiom internal/segment uses for
// validateDigest, and for the same reason: a limit nothing exercises is a
// limit nobody has checked.
var maxTreeScan = 5000

// Fact is one piece of evidence behind a check. Doc 06 P1: a badge with no
// expandable proof is an assertion, not evidence.
type Fact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Check is one of the three, with its tri-state result and its evidence.
type Check struct {
	Name   string `json:"name"`
	Result Result `json:"result"`
	Detail string `json:"detail"`
	Facts  []Fact `json:"facts,omitempty"`
}

// CertificateInfo is what the commit's certificate says about itself.
type CertificateInfo struct {
	SPIFFEID     string    `json:"spiffe_id,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	SerialNumber string    `json:"serial_number,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	Fingerprint  string    `json:"fingerprint,omitempty"`
}

// EntryInfo is the transparency-log entry check 2 found.
type EntryInfo struct {
	UUID         string    `json:"uuid,omitempty"`
	LogIndex     int64     `json:"log_index"`
	LogID        string    `json:"log_id,omitempty"`
	IntegratedAt time.Time `json:"integrated_at,omitempty"`
	// TimeAttested is whether the log SIGNED the integration time. Without it
	// the timestamp is a number in a response rather than a statement by the
	// log, and check 1's validity window cannot be settled against it.
	TimeAttested bool `json:"time_attested"`
}

// Recovered is an attribution rescued from a rewritten commit's tree hash.
type Recovered struct {
	CommitSHA    string    `json:"commit_sha"`
	Identity     string    `json:"identity"`
	LogIndex     int64     `json:"log_index"`
	IntegratedAt time.Time `json:"integrated_at"`
}

// Report is one verification, in full. It is the input doc 06 §4.1's panel
// renders and the thing RenderJSON hands a third party to re-check.
type Report struct {
	Repo        string          `json:"repo"`
	CommitSHA   string          `json:"commit_sha"`
	TreeHash    string          `json:"tree_hash"`
	Verdict     Verdict         `json:"verdict"`
	Checks      []Check         `json:"checks"`
	Claim       Claim           `json:"claim"`
	Certificate CertificateInfo `json:"certificate"`
	Entry       EntryInfo       `json:"entry"`
	Recovered   []Recovered     `json:"recovered,omitempty"`
	Notes       []string        `json:"notes,omitempty"`
}

// Config is everything the verifier is allowed to know. Two URLs, a clock and
// a skew bound — deliberately not a database, not a trust bundle from disk,
// and not the signer's configuration (ADR-0031's Consequences: RM-037 "must
// build its own trust material from the endpoints an outsider can reach").
type Config struct {
	// FulcioURL and RekorURL are the deployment's published endpoints.
	FulcioURL string
	RekorURL  string
	// Issuer, when set, is the OIDC issuer the certificate must name. Left
	// empty the issuer is reported as evidence and not constrained, because a
	// stranger may not know it; a report that silently accepted any issuer
	// while claiming to have checked one would be worse.
	Issuer string
	// GitPath is the git binary; empty means a PATH lookup.
	GitPath string
	// Skew is IP §6.8's bound; zero means DefaultSkew.
	Skew time.Duration
	// Now is the clock. It is used ONLY to report how long ago a commit was
	// signed — never to decide a validity window, which is what makes VER-004
	// pass.
	Now func() time.Time
	// HTTPClient bounds the two network calls.
	HTTPClient *http.Client
}

// Verifier performs the three checks. It holds no state between calls: there
// is no cache, so there is no cached verdict.
//
// The four endpoints are resolved once, in New, and never rebuilt. That is not
// a micro-optimisation: a URL that could fail to join halfway through a
// verification would be an error path in the middle of a check, reported as
// though the log had answered badly. Resolving them up front makes a
// misconfiguration a construction failure, which is the only honest place for
// it.
type Verifier struct {
	cfg Config

	fulcioRoot   string
	rekorIndex   string
	rekorEntries string
	rekorKey     string
}

// New builds a verifier, refusing a configuration it could not verify with.
func New(cfg Config) (*Verifier, error) {
	if cfg.FulcioURL == "" || cfg.RekorURL == "" {
		return nil, fmt.Errorf("%w: both a Fulcio and a Rekor URL are required; "+
			"a verifier with only one of them can settle at most one of the three checks",
			ErrConfig)
	}
	v := &Verifier{}
	for _, e := range []struct {
		base, path string
		into       *string
	}{
		{cfg.FulcioURL, fulcioRootPath, &v.fulcioRoot},
		{cfg.RekorURL, rekorIndexPath, &v.rekorIndex},
		{cfg.RekorURL, rekorEntriesPath, &v.rekorEntries},
		{cfg.RekorURL, rekorPublicKeyPath, &v.rekorKey},
	} {
		resolved, err := joinURL(e.base, e.path)
		if err != nil {
			return nil, err
		}
		*e.into = resolved
	}
	if cfg.GitPath == "" {
		cfg.GitPath = "git"
	}
	if cfg.Skew <= 0 {
		cfg.Skew = DefaultSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	v.cfg = cfg
	return v, nil
}

// Verify reads one commit out of a repository and reports on it.
//
// The only error it returns is a request it could not act on — a repository it
// cannot read, a revision that is not a commit. A commit that does not verify
// is a Report with a verdict, because "this does not verify" is an answer and
// not a failure to answer.
func (v *Verifier) Verify(ctx context.Context, repo, revision string) (Report, error) {
	commit, err := readCommit(ctx, v.cfg.GitPath, repo, revision)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Repo: repo, CommitSHA: commit.SHA, TreeHash: commit.Tree}
	claim, claimErr := ReadClaim(commit.Message)
	rep.Claim = claim

	claims := claim.Present() || claimErr != nil
	if len(commit.Signature) == 0 && !claims {
		rep.Verdict = VerdictUnattributed
		rep.Notes = append(rep.Notes,
			"This commit carries no signature and no Agent-* trailer, so it makes no "+
				"attribution claim. That is not a verification result: it is a commit "+
				"nobody claimed, and E7 says commits from before adoption are simply "+
				"unattributed.")
		return rep, nil
	}

	leaf, intermediates, certErr := commitCertificate(commit.Signature)
	if certErr != nil {
		rep.Checks = refusedChecks(certErr)
		rep.Verdict = VerdictFailed
		rep.Recovered, rep.Notes = v.recover(ctx, repo, commit, rep.Notes)
		return rep, nil
	}
	rep.Certificate = describeCertificate(leaf)

	entry, rekorCheck := v.checkInclusion(ctx, commit.SHA, leaf)
	rep.Entry = entry
	chainCheck := v.checkChain(ctx, leaf, intermediates, entry)
	identityCheck := checkIdentity(claim, claimErr, leaf)

	rep.Checks = []Check{chainCheck, rekorCheck, identityCheck}
	rep.Verdict = rollup(rep.Checks)
	if rekorCheck.Result == Failed {
		rep.Recovered, rep.Notes = v.recover(ctx, repo, commit, rep.Notes)
	}
	return rep, nil
}

// refusedChecks is the report for a commit whose attribution cannot be checked
// at all: it claims an identity and carries no readable certificate. All three
// checks fail for the one reason, and they are all reported rather than
// collapsed, because doc 06 §4.1 forbids the collapse even when the answer is
// the same three times.
func refusedChecks(err error) []Check {
	detail := err.Error()
	out := make([]Check, 0, 3)
	for _, name := range []string{CheckCertificateChain, CheckRekorInclusion, CheckTrailerIdentity} {
		out = append(out, Check{Name: name, Result: Failed, Detail: detail})
	}
	return out
}

// rollup is doc 06 §4.1's rule, and nothing else: "Any single check failing
// makes the rollup failed. Any check erroring (not failing) makes the rollup
// verification unavailable, never verified."
func rollup(checks []Check) Verdict {
	verdict := VerdictVerified
	for _, c := range checks {
		if c.Result == Failed {
			return VerdictFailed
		}
		if c.Result == Unavailable {
			verdict = VerdictUnavailable
		}
	}
	return verdict
}

// checkIdentity is IP §1's check 3: the claim against the proof.
func checkIdentity(claim Claim, claimErr error, leaf *x509.Certificate) Check {
	c := Check{Name: CheckTrailerIdentity}
	san := uriSANOf(leaf)
	c.Facts = append(c.Facts, Fact{"certificate URI SAN", san})

	if claimErr != nil {
		c.Result = Failed
		c.Detail = claimErr.Error()
		return c
	}
	if claim.Identity == "" {
		c.Result = Failed
		c.Detail = "the commit is signed but carries no " + trailerAgentIdentity +
			" trailer, so there is no claim for the certificate to match"
		return c
	}
	c.Facts = append([]Fact{{trailerAgentIdentity + " trailer", claim.Identity}}, c.Facts...)

	if diff := DiffIdentity(claim.Identity, san); diff != "" {
		c.Result = Failed
		c.Detail = "the trailer claims one identity and the certificate proves another"
		c.Facts = append(c.Facts, Fact{"differing segment", diff})
		return c
	}
	if inner := claim.disagreesWith(san); inner != "" {
		c.Result = Failed
		c.Detail = inner
		return c
	}
	c.Result = Verified
	c.Detail = "the " + trailerAgentIdentity + " trailer is the certificate's URI SAN"
	return c
}

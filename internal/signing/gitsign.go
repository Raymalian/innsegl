// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The gitsign wrapper — IP §1 component 3, end to end:
//
//	JWT-SVID (audience-bound to Sigstore)
//	  -> SIGSTORE_ID_TOKEN
//	    -> Fulcio short-lived certificate
//	      -> signed commit
//	        -> Rekor transparency entry
//
// # What this is, and what it refuses to become
//
// IP §7 is the constraint that shapes every decision here: "SPIRE and Sigstore
// (gitsign/Fulcio/Rekor) are used as released upstream components — do not
// fork, do not reimplement their crypto. Configuration and orchestration
// only." So this file contains no CMS, no certificate request, no signature
// and no key. It obtains a credential, points a released `gitsign` at the
// deployment's own Fulcio and Rekor, invokes it through `git commit`, and then
// reads back what was produced. The ephemeral signing key is generated inside
// gitsign and discarded there; it never crosses this boundary in either
// direction. That is E8 — "the MCP never holds, caches or proxies agent
// private keys" — implemented as an absence rather than a promise, and
// TestE8TheWrapperHoldsNoKeyMaterial is what holds it to it.
//
// # Four configuration facts that are not obvious and cost real time
//
//  1. THERE IS NO CT LOG, SO THERE IS NO SCT. ADR-0029 decision 5 runs Fulcio
//     with `--ct-log-url=` empty. gitsign must therefore be told not to
//     require one, and cosign's CT-key loader must be given a file or it
//     reaches for the public-good TUF mirror. See placeholderCTLogKey.
//
//  2. THE TRUST ROOT IS THIS DEPLOYMENT'S, NOT SIGSTORE'S. Left alone, gitsign
//     verifies against the public-good TUF root: the wrong CA and, worse, the
//     wrong log key. GITSIGN_FULCIO_ROOT and SIGSTORE_REKOR_PUBLIC_KEY point
//     it at the material this stack publishes, which is also what makes the
//     run hermetic (IP §7: "CI needs no external dependencies").
//
//  3. THE TOKEN ARRIVES BY ENVIRONMENT, EXPLICITLY. GITSIGN_TOKEN_PROVIDER is
//     pinned to `envvar` rather than left to cosign's provider auto-detection,
//     which would otherwise be free to pick up a GitHub Actions token, a
//     workload SPIFFE socket or a file on disk — any of which would sign a
//     commit as somebody other than this run.
//
//  4. THE CHILD ENVIRONMENT IS BUILT, NOT INHERITED. Nothing from os.Environ
//     reaches gitsign or git. ADR-0028 refused to let ambient git
//     configuration rewrite a protected trailer key; the same reasoning
//     applies with more force to `gpg.x509.program`, to `user.email` and to
//     GITSIGN_CREDENTIAL_CACHE, whose whole purpose is to keep a signing key
//     alive in a daemon (E8).
//
// # Ordering: nothing that can fail cheaply happens after the commit exists
//
// IP §6.3 requires that a failed signature leave "no new commit object at
// all". Everything that can be checked before `git commit` runs is checked
// before it runs — the author policy, the message, the claim, the credential's
// validity window, and Fulcio's and Rekor's reachability. What remains after
// the commit object exists is reading it back, which is why Sign's late
// failures are INVARIANT_VIOLATION-shaped rather than retryable.

// Errors. Every one of them is what an MCP tool has to render as an IP §4
// error class; the mapping belongs to RM-033's sign_commit, which is why these
// are sentinels rather than a second error vocabulary living here (ADR-0028
// decision 8).
var (
	// ErrConfig is a wrapper that cannot be built from the given Config.
	ErrConfig = errors.New("signing: invalid gitsign configuration")

	// ErrCredentialUnavailable is no usable credential: none could be
	// fetched, or the one fetched is expired, for the wrong run, or for the
	// wrong audience. IP §6.2 — never sign with an expired credential, never
	// extend a TTL to help. Renders as CREDENTIAL_EXPIRED / AUDIENCE_MISMATCH.
	ErrCredentialUnavailable = errors.New("signing: no usable credential for this run")

	// ErrSigningUnavailable is Fulcio unreachable or not serving trust
	// material. Renders as SIGNING_UNAVAILABLE, retryable (IP §6.3).
	ErrSigningUnavailable = errors.New("signing: the certificate authority is unavailable")

	// ErrTransparencyUnavailable is Rekor unreachable, or an entry that never
	// appeared. A signature without a transparency entry is not
	// non-repudiable and must not exist. Renders as TRANSPARENCY_UNAVAILABLE.
	ErrTransparencyUnavailable = errors.New("signing: the transparency log is unavailable")

	// ErrSigning is gitsign or git itself refusing. The combined output is
	// attached, because that is where Fulcio's and Rekor's own words are.
	ErrSigning = errors.New("signing: gitsign refused to sign")

	// ErrSignature is a signature that cannot be read back off the commit.
	ErrSignature = errors.New("signing: unreadable commit signature")

	// ErrIdentityMismatch is a certificate that does not attest this run.
	// INVARIANT_VIOLATION: the trailer would claim one identity and the proof
	// would carry another (IP §6.9).
	ErrIdentityMismatch = errors.New("signing: the certificate does not attest this run")

	// ErrVerification is `gitsign verify` reporting a commit as unverified.
	ErrVerification = errors.New("signing: the commit does not verify")
)

// AudienceSigstore is the audience a credential for Fulcio is minted with, and
// the `client-id` Fulcio's own config names. IP §4 puts it on get_credential's
// allowlist as the initial member. It is spelled here rather than imported so
// that internal/signing does not depend on internal/mcp, which will depend on
// it (RM-033).
const AudienceSigstore = "sigstore"

// Defaults. Each is a bound rather than a preference; IP §6.3 forbids
// indefinite hangs and IP §6.8 requires a documented skew bound.
const (
	// DefaultTimeout bounds one `git commit` or `gitsign verify`. It is
	// generous because the operation contains two network round trips and a
	// transparency-log integration, and short enough that a wedged Sigstore
	// does not hold a repository lock for a working day.
	DefaultTimeout = 2 * time.Minute

	// DefaultSkew is IP §6.8's "NTP-scale" tolerance, and it applies to ONE
	// thing: reading back the validity window of a certificate somebody else
	// issued. Sixty seconds is the bound this project documents — large enough
	// for unsynchronised container clocks, small enough that a ten-minute
	// Fulcio certificate cannot be stretched into an eleven-minute one by
	// clock drift alone. It deliberately does NOT loosen the credential check;
	// see Credential.usableAt.
	DefaultSkew = 60 * time.Second

	// DefaultMinValidity is how much life a credential must have left before
	// it is handed to gitsign. A token that expires between our check and
	// Fulcio's is a token Fulcio refuses, so the wrapper re-fetches rather
	// than racing. This is a refusal threshold, never an extension: IP §6.2's
	// "never extend TTLs to help" is about the credential's own expiry, which
	// nothing here touches.
	DefaultMinValidity = 30 * time.Second
)

// Credential is one audience-bound JWT-SVID, as `get_credential` returns it
// (IP §4). No private key is present and none is possible: a JWT-SVID is a
// bearer token minted by the SPIRE server for one identity and one audience
// (ADR-0019).
type Credential struct {
	// Token is the raw JWT-SVID. It becomes SIGSTORE_ID_TOKEN in gitsign's
	// environment and goes nowhere else.
	Token string
	// SPIFFEID is the identity the token's `sub` claim names.
	SPIFFEID string
	// Audience is the single audience it was minted for.
	Audience string
	// ExpiresAt is when it stops being usable. Server-assigned; the wrapper
	// reads it and never adjusts it.
	ExpiresAt time.Time
}

// CredentialSource mints or returns a credential for the run being signed for.
//
// In the deployment this is the MCP's get_credential (RM-033). The interface
// is declared here, and implemented there, so that internal/signing depends on
// nothing: a package that reached into internal/mcp could not be imported by
// it.
type CredentialSource interface {
	Credential(ctx context.Context) (Credential, error)
}

// Config is where the deployment's Sigstore lives and how strict the wrapper
// is about time.
type Config struct {
	// FulcioURL and RekorURL are this deployment's own, per ADR-0010:
	// self-hosted is the shipped default, and public Sigstore accepts no
	// issuer of type `spiffe` at all.
	FulcioURL string
	RekorURL  string

	// Issuer is the OIDC issuer both stacks agree on — the `iss` claim SPIRE
	// stamps, the discovery document spire-oidc serves, and the issuer Fulcio
	// believes (ADR-0029 decision 3). It is also what `gitsign verify` is told
	// to expect in the certificate.
	Issuer string

	// Audience defaults to AudienceSigstore. A credential minted for anything
	// else is refused here as well as at get_credential, so a mis-scoped token
	// cannot reach Fulcio (IP §6.2, both directions).
	Audience string

	// GitsignPath and GitPath name the two binaries. Both default to a PATH
	// lookup, resolved once at construction so a later PATH change cannot
	// swap the signer out mid-run.
	GitsignPath string
	GitPath     string

	// WorkDir holds the fetched trust material and the child processes' HOME.
	// Empty means a directory of the Signer's own, removed by Close.
	WorkDir string

	// Author is the I6 gate from RM-031. Its ZERO VALUE ADMITS NOTHING, on
	// purpose: a deployment that forgets to configure it blocks its first
	// signature loudly instead of signing with an unguarded author (ADR-0028
	// decision 6).
	Author AuthorPolicy

	// Timeout bounds one child process. Skew is IP §6.8's tolerance when
	// reading a certificate's validity window back. MinValidity is how much
	// credential life a signature requires before it will be spent.
	Timeout     time.Duration
	Skew        time.Duration
	MinValidity time.Duration

	// Now and HTTPClient exist so time and transport can be substituted in
	// tests. Now defaults to time.Now.
	Now        func() time.Time
	HTTPClient *http.Client
}

func (c Config) withDefaults() Config {
	if c.Audience == "" {
		c.Audience = AudienceSigstore
	}
	if c.GitsignPath == "" {
		c.GitsignPath = "gitsign"
	}
	if c.GitPath == "" {
		c.GitPath = "git"
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.Skew <= 0 {
		c.Skew = DefaultSkew
	}
	if c.MinValidity == 0 {
		c.MinValidity = DefaultMinValidity
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return c
}

// Request is one commit to be signed — `sign_commit`'s arguments (IP §4) minus
// the ledger's.
type Request struct {
	// Repo is the working tree whose index is already staged. The wrapper
	// stages nothing: what is committed is the caller's decision.
	Repo string
	// Message is the caller's commit message, before trailers.
	Message string
	// AuthorName and AuthorEmail become the commit's author AND committer.
	// Both are gated by Config.Author: a committer I6 does not admit is a
	// contributor I6 does not admit.
	AuthorName  string
	AuthorEmail string
	// Claim is what the trailers will say (RM-031).
	Claim Claim
}

// Certificate is the short-lived Fulcio certificate a commit was signed under,
// as read back off the commit itself.
type Certificate struct {
	// SPIFFEID is the URI SAN — the field IP §1's check 3 compares against the
	// Agent-Identity trailer.
	SPIFFEID string
	// Issuer is the OIDC issuer Fulcio recorded (extension .8, or the
	// deprecated .1).
	Issuer string
	// SerialNumber, NotBefore, NotAfter and Fingerprint are the certificate's
	// own. The validity window is what IP §6.2 asks a caller to assert.
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	// Fingerprint is sha256 of the DER, hex — this project's identifier for a
	// certificate, used to tie a Rekor entry to a commit.
	Fingerprint string
}

// RekorEntry is `sign_commit`'s `rekor_entry` (IP §4).
type RekorEntry struct {
	UUID         string
	LogIndex     int64
	LogID        string
	IntegratedAt time.Time
}

// Result is what one signature produced.
type Result struct {
	CommitSHA   string
	Trailers    []Trailer
	Certificate Certificate
	Rekor       RekorEntry
	// CredentialSPIFFEID and CredentialExpires say which credential was used.
	// THE TOKEN IS DELIBERATELY ABSENT: a caller that wants to record what
	// signed a commit wants the identity, and a struct that carried the bearer
	// token back out would be one copy of it too many.
	CredentialSPIFFEID string
	CredentialExpires  time.Time
}

// Verification is what `gitsign verify` reported.
type Verification struct {
	// LogIndex is the transparency-log index gitsign resolved, or -1.
	LogIndex int64
	// Claims are gitsign's own claim lines, e.g. "Validated Rekor entry".
	Claims map[string]bool
	// Output is everything gitsign printed, kept so a failure report can quote
	// the verifier rather than paraphrase it.
	Output string
}

// Signer signs commits for one run.
//
// It caches the run's credential and reuses it while it is live — IP §6.2's
// replay rule, "allowed only within validity and same run" — and drops it the
// moment it is not. Nothing else is cached: no key, no certificate, no
// Sigstore session.
type Signer struct {
	cfg Config
	src CredentialSource

	workDir string
	ownDir  bool

	mu    sync.Mutex
	cred  Credential
	trust *trustFiles
}

// trustFiles are the on-disk copies gitsign is pointed at.
type trustFiles struct {
	fulcioRoot string
	rekorKey   string
	ctLogKey   string
}

// NewSigner resolves the binaries and prepares a working directory. It
// performs no network I/O: Fulcio and Rekor are contacted at the first Sign,
// so an unreachable Sigstore is a per-operation failure with an error class
// rather than a construction failure at start-up.
func NewSigner(cfg Config, src CredentialSource) (*Signer, error) {
	cfg = cfg.withDefaults()
	if src == nil {
		return nil, fmt.Errorf("%w: no credential source", ErrConfig)
	}
	if cfg.FulcioURL == "" || cfg.RekorURL == "" {
		return nil, fmt.Errorf("%w: both a Fulcio and a Rekor URL are required", ErrConfig)
	}
	if _, err := joinURL(cfg.FulcioURL, fulcioRootPath); err != nil {
		return nil, err
	}
	if _, err := joinURL(cfg.RekorURL, rekorPubKeyPath); err != nil {
		return nil, err
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("%w: no OIDC issuer; Fulcio believes exactly one and "+
			"a verifier has to be told which (ADR-0029 decision 3)", ErrConfig)
	}
	gitsignPath, err := exec.LookPath(cfg.GitsignPath)
	if err != nil {
		return nil, fmt.Errorf("%w: gitsign: %w", ErrConfig, err)
	}
	gitPath, err := exec.LookPath(cfg.GitPath)
	if err != nil {
		return nil, fmt.Errorf("%w: git: %w", ErrConfig, err)
	}
	cfg.GitsignPath, cfg.GitPath = gitsignPath, gitPath

	s := &Signer{cfg: cfg, src: src, workDir: cfg.WorkDir}
	if s.workDir == "" {
		dir, err := os.MkdirTemp("", "innsegl-gitsign-")
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
		s.workDir, s.ownDir = dir, true
	}
	for _, sub := range []string{"home", "tuf"} {
		if err := os.MkdirAll(filepath.Join(s.workDir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
	}
	return s, nil
}

// Close removes the working directory when the Signer made one.
func (s *Signer) Close() error {
	if !s.ownDir {
		return nil
	}
	return os.RemoveAll(s.workDir)
}

// ---------------------------------------------------------------------------
// Credentials — IP §6.2.
// ---------------------------------------------------------------------------

// usableAt reports whether the credential can still be used at now.
//
// NOTE WHAT IS ABSENT: Config.Skew plays no part here, and that asymmetry is
// the point. IP §6.8's clock tolerance is a VERIFIER's rule — a party checking
// somebody else's certificate must forgive NTP-scale disagreement, and
// checkCertificate applies it in both directions. A SIGNER has no such licence:
// widening a credential's window by a minute so it can still be used is
// indistinguishable from extending its TTL by a minute, which IP §6.2 forbids
// in terms ("never extend TTLs to 'help'"). So the only adjustment made here
// narrows the window: MinValidity requires a margin of life, because a token
// that expires between our check and Fulcio's produces a failure attributed to
// the wrong component. Both rules push the same way — toward re-fetching — and
// neither can make an expired token usable.
func (c Credential) usableAt(now time.Time, minValidity time.Duration) error {
	if c.Token == "" {
		return errors.New("the credential carries no token")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("the credential carries no expiry")
	}
	if !now.Add(minValidity).Before(c.ExpiresAt) {
		return fmt.Errorf("the credential expires at %s and it is %s (%s of life left, "+
			"%s required)",
			c.ExpiresAt.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339),
			c.ExpiresAt.Sub(now).Truncate(time.Second), minValidity)
	}
	return nil
}

// credential returns a live credential for the claim, re-fetching
// transparently when the cached one has expired.
//
// IP §6.2, both halves in order:
//
//	SVID expires mid-run -> get_credential re-fetches transparently; if
//	re-fetch fails, signing blocks. Never sign with an expired credential;
//	never extend TTLs to "help."
//
// The expired credential is dropped BEFORE the re-fetch is attempted, so a
// failed re-fetch cannot fall back to it. That ordering is the whole of "if
// re-fetch fails, signing blocks".
func (s *Signer) credential(ctx context.Context, claim Claim) (Credential, error) {
	now := s.cfg.Now()
	if s.cred.SPIFFEID == claim.Identity &&
		s.cred.usableAt(now, s.cfg.MinValidity) == nil {
		return s.cred, nil
	}
	// Unreachable from the cache from here on, whatever happens next.
	s.cred = Credential{}

	fresh, err := s.src.Credential(ctx)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: the re-fetch was refused: %w",
			ErrCredentialUnavailable, err)
	}
	if err := s.checkCredential(fresh, claim, now); err != nil {
		return Credential{}, err
	}
	s.cred = fresh
	return fresh, nil
}

// checkCredential holds a freshly fetched credential to the run it is for.
func (s *Signer) checkCredential(c Credential, claim Claim, now time.Time) error {
	if c.SPIFFEID != claim.Identity {
		// IP §6.2: "a credential from run A used in a sign_commit for run B ->
		// INVARIANT_VIOLATION". Caught here, before Fulcio would mint a
		// certificate naming the wrong run.
		return fmt.Errorf("%w: the credential is for %q; this commit claims %q",
			ErrCredentialUnavailable, c.SPIFFEID, claim.Identity)
	}
	if c.Audience != s.cfg.Audience {
		return fmt.Errorf("%w: the credential's audience is %q, Fulcio's is %q",
			ErrCredentialUnavailable, c.Audience, s.cfg.Audience)
	}
	if err := c.usableAt(now, s.cfg.MinValidity); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialUnavailable, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Trust material — ADR-0024, ADR-0029 decision 5.
// ---------------------------------------------------------------------------

// trustMaterial fetches Fulcio's root and Rekor's log key and writes them where
// gitsign can be pointed at them. It doubles as the reachability probe: this is
// the one place that can tell "Fulcio is down" (SIGNING_UNAVAILABLE) from
// "Rekor is down" (TRANSPARENCY_UNAVAILABLE) without reading a subprocess's
// prose, and it runs BEFORE git does, so neither failure can leave a commit
// object behind (IP §6.3).
//
// # Why this makes exactly one attempt at each endpoint (RM-070, #93)
//
// IP §6.3 lists three Sigstore failure modes: "Fulcio down" and "Rekor down"
// each get one clean, immediate, correctly-classed error — RETRYABLE as a
// property of the error class, which is a statement about the CALLER, not a
// promise that this function loops. "Slow Sigstore" is the third and
// separate clause, and it is the one that asks for "explicit timeouts,
// bounded retries with backoff and jitter" — which #93 gives the Rekor
// lookup below findRekorEntry, the operation that is actually racing an
// eventually-consistent write (see rekorLookupPolicy's comment in
// sigstore.go). This probe is not racing anything: it is asking "is the
// service here right now", once, with an explicit timeout (the ctx this
// function is given, bounded by Config.Timeout), which already satisfies
// §6.3's "explicit timeouts" half on its own.
//
// Retrying that question would trade away the property the "down" clauses
// exist for — a caller gets a clean, fast, correctly-classed refusal it can
// itself retry (sign_commit's error class is documented as retryable for
// exactly this) — in exchange for absorbing single-request network blips at
// the cost of doing so inside every first Sign() call, since this result is
// cached per Signer for its lifetime (line above: `if s.trust != nil`) and
// so pays this cost once, not once per signature.
//
// The conclusion drawn here is that a single attempt is correct, not an
// oversight — but IP §6.3's text does not say so: a reader could plausibly
// take "bounded retries with backoff and jitter" as covering every Sigstore
// interaction, this probe included. That reading gap is a finding for
// doc 01's maintainer to resolve in the spec, not something resolved by
// changing this function to match one interpretation of an ambiguous
// sentence.
func (s *Signer) trustMaterial(ctx context.Context) (*trustFiles, error) {
	if s.trust != nil {
		return s.trust, nil
	}
	root, err := fetchFulcioRoot(ctx, s.cfg.HTTPClient, s.cfg.FulcioURL)
	if err != nil {
		return nil, err
	}
	logKey, err := fetchRekorPublicKey(ctx, s.cfg.HTTPClient, s.cfg.RekorURL)
	if err != nil {
		return nil, err
	}
	ctKey, err := placeholderCTLogKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	files := &trustFiles{
		fulcioRoot: filepath.Join(s.workDir, "fulcio-root.pem"),
		rekorKey:   filepath.Join(s.workDir, "rekor-log-key.pem"),
		ctLogKey:   filepath.Join(s.workDir, "no-ct-log.pub.pem"),
	}
	for _, w := range []struct {
		path    string
		content []byte
	}{
		{files.fulcioRoot, root},
		{files.rekorKey, logKey},
		{files.ctLogKey, ctKey},
	} {
		if err := os.WriteFile(w.path, w.content, 0o600); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConfig, err)
		}
	}
	s.trust = files
	return files, nil
}

// ---------------------------------------------------------------------------
// The child environment.
// ---------------------------------------------------------------------------

// baseEnv is everything gitsign and git are given, and it is a whitelist: no
// variable from this process's environment reaches either child.
//
// GITSIGN_CREDENTIAL_CACHE is the one absence worth naming. It points gitsign
// at a daemon that keeps the ephemeral PRIVATE KEY and its certificate alive
// between signatures — precisely the key custody E8 forbids. Building the
// environment rather than inheriting it means an operator who exports it for
// their own interactive use cannot silently turn it on for the MCP.
func (s *Signer) baseEnv(t *trustFiles) []string {
	return []string{
		// A minimal PATH: both binaries are already absolute, and git needs
		// one to find its own helpers.
		"PATH=" + strings.Join([]string{
			filepath.Dir(s.cfg.GitPath), filepath.Dir(s.cfg.GitsignPath), "/usr/bin", "/bin",
		}, string(os.PathListSeparator)),
		"HOME=" + filepath.Join(s.workDir, "home"),
		"TMPDIR=" + os.TempDir(),
		// cosign caches a TUF root under this path. Nothing here needs TUF —
		// every trust anchor is supplied below — but pointing it inside the
		// work directory keeps a stray fetch out of the operator's home.
		"TUF_ROOT=" + filepath.Join(s.workDir, "tuf"),

		// ADR-0028's reasoning, applied to the whole of git's configuration:
		// the bytes that get signed must be a function of our inputs, not of
		// whatever a ~/.gitconfig says. Repository-local configuration is
		// overridden per-invocation with `-c`, which outranks it.
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(s.workDir, "no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",

		// Where this deployment's Sigstore is.
		"GITSIGN_FULCIO_URL=" + s.cfg.FulcioURL,
		"GITSIGN_REKOR_URL=" + s.cfg.RekorURL,
		"GITSIGN_OIDC_ISSUER=" + s.cfg.Issuer,
		"GITSIGN_OIDC_CLIENT_ID=" + s.cfg.Audience,

		// The trust root. Without these gitsign uses the public-good TUF root:
		// the wrong CA, and the wrong transparency-log key.
		"GITSIGN_FULCIO_ROOT=" + t.fulcioRoot,
		"SIGSTORE_REKOR_PUBLIC_KEY=" + t.rekorKey,
		// See placeholderCTLogKey: this deployment issues no SCT, and cosign
		// will not accept an empty CT key set.
		"SIGSTORE_CT_LOG_PUBLIC_KEY_FILE=" + t.ctLogKey,

		// The token comes from the environment and from nowhere else.
		"GITSIGN_TOKEN_PROVIDER=envvar",
	}
}

// signEnv adds the credential and the author identity.
func (s *Signer) signEnv(t *trustFiles, cred Credential, req Request) []string {
	return append(s.baseEnv(t),
		"SIGSTORE_ID_TOKEN="+cred.Token,
		"GIT_AUTHOR_NAME="+req.AuthorName,
		"GIT_AUTHOR_EMAIL="+req.AuthorEmail,
		"GIT_COMMITTER_NAME="+req.AuthorName,
		"GIT_COMMITTER_EMAIL="+req.AuthorEmail,
	)
}

// run executes one child process with a built environment and a bounded life.
func (s *Signer) run(ctx context.Context, dir string, env []string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ---------------------------------------------------------------------------
// Sign.
// ---------------------------------------------------------------------------

// Sign renders the commit message with its trailers, obtains a live
// credential, and has gitsign sign the commit against this deployment's Fulcio
// and Rekor. It returns the commit, the certificate it was signed under and
// the transparency-log entry that records it.
//
// The staged index is the caller's. Sign adds nothing to it and resets
// nothing: what is committed is what `sign_commit`'s caller staged.
func (s *Signer) Sign(ctx context.Context, req Request) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Repo == "" {
		return Result{}, fmt.Errorf("%w: no repository", ErrConfig)
	}

	// 1. The message and the trailers, from RM-031's writer. CommitMessage
	//    runs the I6 author gate first and returns nothing at all on refusal,
	//    so an unconfigured AuthorPolicy blocks here — before a credential is
	//    spent, and long before a commit object could exist.
	trailers, err := req.Claim.Trailers()
	if err != nil {
		return Result{}, err
	}
	message, err := CommitMessage(s.cfg.Author, Commit{
		Message:     req.Message,
		AuthorEmail: req.AuthorEmail,
		Claim:       req.Claim,
	})
	if err != nil {
		return Result{}, err
	}

	// 2. A live credential for THIS run, re-fetched if the cached one died.
	cred, err := s.credential(ctx, req.Claim)
	if err != nil {
		return Result{}, err
	}

	// 3. Sigstore's trust material, which is also the reachability probe.
	trust, err := s.trustMaterial(ctx)
	if err != nil {
		return Result{}, err
	}

	// 4. The signature. Everything that could have failed cheaply has.
	messagePath := filepath.Join(s.workDir, "commit-message")
	if werr := os.WriteFile(messagePath, []byte(message), 0o600); werr != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrConfig, werr)
	}
	out, err := s.run(ctx, req.Repo, s.signEnv(trust, cred, req), s.cfg.GitPath,
		// `-c` outranks repository configuration, so a repository that sets
		// gpg.x509.program cannot substitute another signer.
		"-c", "gpg.format=x509",
		"-c", "gpg.x509.program="+s.cfg.GitsignPath,
		"-c", "commit.gpgsign=true",
		"commit",
		"--file", messagePath,
		// The message is already normalised by RM-031's writer and is the
		// preimage of the signature. `verbatim` stops git editing the bytes we
		// are about to sign.
		"--cleanup=verbatim",
		"--no-edit",
	)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w\n%s", ErrSigning, err, strings.TrimSpace(out))
	}

	// 5. Read back what was produced. From here on a failure means the commit
	//    exists but cannot be attributed, which is an invariant violation
	//    rather than a retryable outage.
	commitSHA, err := s.revParse(ctx, req.Repo, trust, "HEAD")
	if err != nil {
		return Result{}, err
	}
	cert, err := s.certificateOf(ctx, req.Repo, trust, commitSHA)
	if err != nil {
		return Result{}, err
	}
	if cerr := s.checkCertificate(cert, req.Claim, cred); cerr != nil {
		return Result{}, cerr
	}
	entry, err := findRekorEntry(ctx, s.cfg.HTTPClient, s.cfg.RekorURL, commitSHA, cert)
	if err != nil {
		return Result{}, err
	}

	return Result{
		CommitSHA:          commitSHA,
		Trailers:           trailers,
		Certificate:        describeCertificate(cert),
		Rekor:              entry,
		CredentialSPIFFEID: cred.SPIFFEID,
		CredentialExpires:  cred.ExpiresAt,
	}, nil
}

// revParse resolves a revision in the repository.
func (s *Signer) revParse(ctx context.Context, repo string, t *trustFiles, rev string) (string, error) {
	out, err := s.run(ctx, repo, s.baseEnv(t), s.cfg.GitPath, "rev-parse", rev)
	if err != nil {
		return "", fmt.Errorf("%w: resolving %s: %w\n%s",
			ErrSignature, rev, err, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

// certificateOf reads the signing certificate off a commit object.
//
// The certificate comes from the COMMIT, not from the exchange with Fulcio.
// That is the difference between "we asked for a certificate naming this run"
// and "the object in this repository is signed under one" — and only the
// second is a fact about the artifact a third party will verify.
func (s *Signer) certificateOf(ctx context.Context, repo string, t *trustFiles, rev string) (*x509.Certificate, error) {
	out, err := s.run(ctx, repo, s.baseEnv(t), s.cfg.GitPath, "cat-file", "commit", rev)
	if err != nil {
		return nil, fmt.Errorf("%w: reading commit %s: %w\n%s",
			ErrSignature, rev, err, strings.TrimSpace(out))
	}
	armored, err := gpgsigOf(out)
	if err != nil {
		return nil, err
	}
	certs, err := certificatesFromSignature(armored)
	if err != nil {
		return nil, err
	}
	return leafOf(certs)
}

// gpgsigOf lifts the PEM signature out of a raw commit object.
//
// A commit header's continuation lines are indented by exactly one space, and
// the header ends at the first line that is not — git's own rule. Nothing else
// about the object is interpreted here.
func gpgsigOf(object string) ([]byte, error) {
	const header = "gpgsig "
	lines := strings.Split(object, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, header) {
			continue
		}
		var b strings.Builder
		b.WriteString(strings.TrimPrefix(line, header))
		b.WriteString("\n")
		for _, cont := range lines[i+1:] {
			if !strings.HasPrefix(cont, " ") {
				break
			}
			b.WriteString(cont[1:])
			b.WriteString("\n")
		}
		return []byte(b.String()), nil
	}
	return nil, fmt.Errorf("%w: the commit object carries no gpgsig header, so it is "+
		"not signed at all", ErrSignature)
}

// checkCertificate holds the certificate to the claim the trailers make and to
// the credential it was obtained with.
//
// IP §1's check 3 is a verifier's job (RM-037), and this is not it: a verifier
// trusts nothing about this system, whereas this runs inside it. What this is,
// is the wrapper refusing to report a success it cannot stand behind — if the
// SAN is not this run's, the commit that now exists claims one identity in its
// trailers and proves another, which is IP §6.9's trailer spoofing arriving
// from our own side.
func (s *Signer) checkCertificate(cert *x509.Certificate, claim Claim, cred Credential) error {
	got := describeCertificate(cert)
	if got.SPIFFEID != claim.Identity {
		return fmt.Errorf("%w: the certificate's URI SAN is %q; the %s trailer claims %q",
			ErrIdentityMismatch, got.SPIFFEID, TrailerAgentIdentity, claim.Identity)
	}
	if got.SPIFFEID != cred.SPIFFEID {
		return fmt.Errorf("%w: the certificate's URI SAN is %q; the credential was for %q",
			ErrIdentityMismatch, got.SPIFFEID, cred.SPIFFEID)
	}
	if got.Issuer != s.cfg.Issuer {
		return fmt.Errorf("%w: the certificate names issuer %q, this deployment's is %q",
			ErrIdentityMismatch, got.Issuer, s.cfg.Issuer)
	}
	// IP §6.2, the assertion doc 07 names for SIG-005: the certificate must be
	// live at the moment it was used. IP §6.8's skew bound applies on both
	// sides — a certificate that is not yet valid is as wrong as an expired
	// one, and both are refused past the bound.
	now := s.cfg.Now()
	if now.Add(s.cfg.Skew).Before(got.NotBefore) {
		return fmt.Errorf("%w: the certificate is not valid until %s and it is %s "+
			"(%s skew allowed)", ErrIdentityMismatch,
			got.NotBefore.Format(time.RFC3339), now.UTC().Format(time.RFC3339), s.cfg.Skew)
	}
	if now.Add(-s.cfg.Skew).After(got.NotAfter) {
		return fmt.Errorf("%w: the certificate expired at %s and it is %s "+
			"(%s skew allowed)", ErrIdentityMismatch,
			got.NotAfter.Format(time.RFC3339), now.UTC().Format(time.RFC3339), s.cfg.Skew)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verify.
// ---------------------------------------------------------------------------

// Verify runs the released `gitsign verify` over a commit and requires it to
// report the given identity.
//
// The identity argument is not optional and there is no "any identity" mode.
// `gitsign verify` refuses to run in keyless mode without one, and that
// refusal is correct: a verifier that reports "signed by somebody" answers a
// question nobody asked. IP §1's check 3 is a comparison, so this wrapper only
// ever performs it as one.
//
// This is the wrapper's own check, not the third-party verifier: RM-037's
// `innsegl verify` is the one that proves I5 by trusting nothing about this
// system. What the two share is the configuration — the same trust root, the
// same absent CT log — which is why this lives beside Sign rather than in a
// test.
func (s *Signer) Verify(ctx context.Context, repo, revision, identity string) (Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if repo == "" || revision == "" {
		return Verification{}, fmt.Errorf("%w: a repository and a revision are required", ErrConfig)
	}
	if identity == "" {
		return Verification{}, fmt.Errorf("%w: no identity to check the certificate against; "+
			"a verification that accepts any signer establishes nothing", ErrConfig)
	}
	trust, err := s.trustMaterial(ctx)
	if err != nil {
		return Verification{}, err
	}
	out, err := s.run(ctx, repo, s.baseEnv(trust), s.cfg.GitsignPath,
		"verify",
		"--certificate-identity="+identity,
		"--certificate-oidc-issuer="+s.cfg.Issuer,
		// ADR-0029 decision 5: this deployment's Fulcio issues no SCT, so a
		// verifier that requires one refuses every certificate it ever made.
		"--insecure-ignore-sct",
		revision,
	)
	v := parseVerification(out)
	if err != nil {
		return v, fmt.Errorf("%w: %s: %w\n%s", ErrVerification, revision, err, strings.TrimSpace(out))
	}
	for name, ok := range v.Claims {
		if !ok {
			return v, fmt.Errorf("%w: %s: gitsign reported %q = false\n%s",
				ErrVerification, revision, name, strings.TrimSpace(out))
		}
	}
	return v, nil
}

// parseVerification reads gitsign's report. The exit status is the verdict;
// the claim lines are read so a caller can say WHICH check failed.
func parseVerification(out string) Verification {
	v := Verification{Claims: map[string]bool{}, Output: out, LogIndex: -1}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "tlog index:"):
			if n, err := strconv.ParseInt(
				strings.TrimSpace(strings.TrimPrefix(line, "tlog index:")), 10, 64); err == nil {
				v.LogIndex = n
			}
		case strings.HasSuffix(line, ": true"), strings.HasSuffix(line, ": false"):
			name, value, ok := strings.Cut(line, ": ")
			if ok && strings.HasPrefix(name, "Validated ") {
				v.Claims[name] = value == "true"
			}
		}
	}
	return v
}

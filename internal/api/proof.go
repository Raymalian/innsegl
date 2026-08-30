// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// The backend-for-frontend, and the exact shape of what it is allowed to do.
//
// FD §7: "Live verification is server-assisted but reproducible: proof checks
// may execute in a backend-for-frontend for CORS/performance, but the response
// includes the raw inputs and outputs so the client (and the user) can
// re-derive the verdict."
//
// So this file does two things and refuses a third.
//
//  1. IT RUNS internal/verify. There is one verifier in this repository and
//     this is not a second one. Every verdict, every check result and every
//     piece of evidence in a Proof comes out of verify.Report; nothing here
//     computes, adjusts, upgrades or downgrades one. The rollup rule of FD
//     §4.1 is applied in exactly one place, and that place is
//     internal/verify's `rollup`.
//
//  2. IT COLLECTS MATERIAL. The bytes of the commit object, Fulcio's published
//     root, the log's public key and the log entry, each fetched verbatim and
//     passed through untouched. Fetching bytes is not verification, and none
//     of these documents is interpreted here.
//
//  3. IT NEVER CONSULTS THE LEDGER. A Prover holds no Store, no pool and no
//     DSN, and there is no field it could be given one through. IP §6.11 and
//     FD P2 forbid a database-only answer; the surest way not to give one is
//     to be structurally incapable of it. API-006 measures this the other way
//     round: it puts a `commit_recorded` for the commit under test into the
//     ledger, takes both upstreams away, and requires the answer to still be
//     "unavailable".
//
// # WHAT internal/verify DOES NOT EXPOSE, AND WHAT THAT COSTS
//
// verify.Report carries the verifier's READING of its inputs — a certificate's
// SPIFFE ID, fingerprint and validity window, an entry's uuid and log index —
// and none of the inputs themselves. There is no leaf DER, no intermediate, no
// Fulcio root as fetched, no entry body, no inclusion proof, no log key. FD §7
// asks for the raw inputs and outputs, so this file collects them separately,
// through its own HTTP client, immediately after the verdict is computed.
//
// That is honest but it is not ideal, and the difference is worth naming: the
// material is what the BFF fetched, not literally the bytes the verifier
// hashed, so an upstream that changed its answer between the two reads would
// produce a response whose material and verdict disagree. The window is one
// request wide and the material is self-authenticating against the user's own
// input — the commit object hashes to the SHA that was asked about, the entry
// is keyed on sha256 of that SHA, and the certificate is the one inside that
// entry — so a disagreement is detectable rather than silent. The proper fix
// is for verify.Report to carry the material it read. That is a change to
// internal/verify, which #48 does not own, and it is reported rather than made.

// ProofConfig is everything the BFF is allowed to know: two upstream URLs, the
// repositories it serves, and a clock. Deliberately not a database.
type ProofConfig struct {
	// FulcioURL and RekorURL are the deployment's published endpoints — the
	// same two a stranger is given (I5).
	FulcioURL string
	RekorURL  string
	// Issuer, when set, is the OIDC issuer certificates must name.
	Issuer string
	// GitPath is the git binary; empty means a PATH lookup.
	GitPath string
	// Repos maps the repository name a caller uses to a local path holding
	// its objects. A name that is not in this map is ErrNotFound: the public
	// page answers about what this deployment serves, and guessing is not one
	// of the states FD §4.6 allows.
	Repos map[string]string
	// HTTPClient bounds the material fetches. The verifier is given the same
	// one.
	HTTPClient *http.Client
	// Now is the clock, used only for timestamps in the response.
	Now func() time.Time
}

// Upstream is one dependency the BFF spoke to, and what it said. Reported on
// every response, reachable or not: FD §6.1 wants errors that state what
// failed, and "which of the two was gone" is the first thing a reader needs.
type Upstream struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Reachable bool      `json:"reachable"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Upstream names, spelled once.
const (
	UpstreamFulcio = "fulcio"
	UpstreamRekor  = "rekor"
)

// Gap is one piece of material the BFF could not collect, and why.
//
// A gap is stated rather than left as an absence. Silence about missing
// evidence reads as "collected and fine", which is FD anti-pattern 1 wearing
// the material's clothes instead of the badge's.
type Gap struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Material is the raw input and output FD §7 requires in the response, and
// FD §3.6 names by hand: "cert PEM, log index ... for offline re-verification".
type Material struct {
	// CommitObject is `git cat-file commit <sha>` verbatim: the header block
	// with its gpgsig, and the message with its trailers. Re-hashing it
	// reproduces CommitObjectID, which is what binds every other piece of
	// material below to the commit the caller asked about.
	CommitObject   string `json:"commit_object"`
	CommitObjectID string `json:"commit_object_id"`
	// CertificatePEM is the signing certificate AS THE TRANSPARENCY LOG
	// RECORDED IT — read out of the entry's publicKey member, not out of the
	// commit. That provenance is the point: it is bound to the entry, and the
	// entry is bound to the commit, so a swapped certificate is detectable.
	CertificatePEM       string          `json:"certificate_pem,omitempty"`
	FulcioRootPEM        string          `json:"fulcio_root_pem,omitempty"`
	RekorEntry           json.RawMessage `json:"rekor_entry,omitempty"`
	RekorLogPublicKeyPEM string          `json:"rekor_log_public_key_pem,omitempty"`
	CollectedAt          time.Time       `json:"collected_at"`
	Gaps                 []Gap           `json:"gaps,omitempty"`
}

// Proof is one live verification plus everything needed to re-derive it.
type Proof struct {
	Repo        string                 `json:"repo"`
	CommitSHA   string                 `json:"commit_sha"`
	TreeHash    string                 `json:"tree_hash"`
	Verdict     string                 `json:"verdict"`
	Checks      []verify.Check         `json:"checks"`
	Claim       verify.Claim           `json:"claim"`
	Certificate verify.CertificateInfo `json:"certificate"`
	Entry       verify.EntryInfo       `json:"entry"`
	Recovered   []verify.Recovered     `json:"recovered,omitempty"`
	Notes       []string               `json:"notes,omitempty"`
	Upstreams   []Upstream             `json:"upstreams"`
	Material    Material               `json:"material"`
	DataAsOf    time.Time              `json:"data_as_of"`
}

// The upstream paths this BFF fetches material from.
//
// They are the same four paths internal/verify reads, spelled again because
// that package keeps them unexported. Duplicated constants are a liability and
// this one is recorded as such: if verify's Report ever carries its own
// material, these go away with the fetches below.
const (
	fulcioRootPath     = "/api/v1/rootCert"
	rekorPublicKeyPath = "/api/v1/log/publicKey"
	rekorEntriesPath   = "/api/v1/log/entries"

	// materialTimeout bounds one material fetch. Shorter than the verifier's
	// own bound: by the time this runs the verdict already exists, and a slow
	// upstream must cost a gap rather than the whole response.
	materialTimeout = 15 * time.Second

	// maxMaterial caps one fetched document.
	maxMaterial = 1 << 22

	// gitTimeout bounds one git invocation.
	gitTimeout = 30 * time.Second
)

// Prover is the backend-for-frontend. It holds a verifier and an HTTP client,
// and — see the file comment — nothing that could reach a database.
type Prover struct {
	cfg      ProofConfig
	verifier *verify.Verifier
	client   *http.Client
	gitPath  string
	now      func() time.Time

	fulcioRoot   string
	rekorKey     string
	rekorEntries string
}

// NewProver builds the BFF, refusing a configuration it could not answer with.
func NewProver(cfg ProofConfig) (*Prover, error) {
	if len(cfg.Repos) == 0 {
		return nil, fmt.Errorf("%w: a proof BFF that serves no repository can answer "+
			"nothing; give it at least one", ErrBadRequest)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: materialTimeout}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	gitPath := cfg.GitPath
	if gitPath == "" {
		gitPath = "git"
	}
	v, err := verify.New(verify.Config{
		FulcioURL:  cfg.FulcioURL,
		RekorURL:   cfg.RekorURL,
		Issuer:     cfg.Issuer,
		GitPath:    gitPath,
		Now:        now,
		HTTPClient: client,
	})
	if err != nil {
		return nil, err
	}
	p := &Prover{cfg: cfg, verifier: v, client: client, gitPath: gitPath, now: now}
	for _, e := range []struct {
		base, path string
		into       *string
	}{
		{cfg.FulcioURL, fulcioRootPath, &p.fulcioRoot},
		{cfg.RekorURL, rekorPublicKeyPath, &p.rekorKey},
		{cfg.RekorURL, rekorEntriesPath, &p.rekorEntries},
	} {
		joined, jerr := joinURL(e.base, e.path)
		if jerr != nil {
			return nil, jerr
		}
		*e.into = joined
	}
	return p, nil
}

// Repos returns the repository names this BFF serves, sorted. The public page
// needs them to say what it can answer about.
func (p *Prover) Repos() []string {
	out := make([]string, 0, len(p.cfg.Repos))
	for name := range p.cfg.Repos {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Prove runs the three checks live and returns them with their material.
//
// repo may be empty, in which case every served repository is searched for the
// revision. A commit no served repository holds is ErrNotFound — never an
// empty proof, which a reader would take for a verdict.
//
// The only error is a request that could not be acted on. A commit that does
// not verify, and a commit whose upstreams are unreachable, are both Proofs
// with a verdict, because both are answers.
func (p *Prover) Prove(ctx context.Context, repo, revision string) (Proof, error) {
	if revision == "" {
		return Proof{}, fmt.Errorf("%w: no commit was named", ErrBadRequest)
	}
	name, path, object, sha, err := p.locate(ctx, repo, revision)
	if err != nil {
		return Proof{}, err
	}

	// The verdict, and nothing else, comes from here.
	rep, verr := p.verifier.Verify(ctx, path, sha)
	if verr != nil {
		if errors.Is(verr, verify.ErrRevision) {
			return Proof{}, fmt.Errorf("%w: %s in %s: %w", ErrNotFound, revision, name, verr)
		}
		return Proof{}, verr
	}

	out := Proof{
		Repo:        name,
		CommitSHA:   rep.CommitSHA,
		TreeHash:    rep.TreeHash,
		Verdict:     string(rep.Verdict),
		Checks:      rep.Checks,
		Claim:       rep.Claim,
		Certificate: rep.Certificate,
		Entry:       rep.Entry,
		Recovered:   rep.Recovered,
		Notes:       rep.Notes,
		DataAsOf:    p.now().UTC(),
	}
	out.Material, out.Upstreams = p.collect(ctx, object, sha, rep)
	return out, nil
}

// locate finds the repository holding revision and reads its commit object.
func (p *Prover) locate(ctx context.Context, repo, revision string) (
	name, path string, object []byte, sha string, err error) {

	if repo != "" {
		path, ok := p.cfg.Repos[repo]
		if !ok {
			return "", "", nil, "", fmt.Errorf("%w: this deployment serves no repository "+
				"named %q; it serves %v", ErrNotFound, repo, p.Repos())
		}
		object, sha, err := p.readCommitObject(ctx, path, revision)
		if err != nil {
			return "", "", nil, "", fmt.Errorf("%w: %s holds no commit %s: %w",
				ErrNotFound, repo, revision, err)
		}
		return repo, path, object, sha, nil
	}

	// No repository named: search the ones this deployment serves, in a stable
	// order so the same request gets the same answer.
	var last error
	for _, candidate := range p.Repos() {
		object, sha, rerr := p.readCommitObject(ctx, p.cfg.Repos[candidate], revision)
		if rerr == nil {
			return candidate, p.cfg.Repos[candidate], object, sha, nil
		}
		last = rerr
	}
	return "", "", nil, "", fmt.Errorf("%w: no repository this deployment serves holds "+
		"%s (searched %v): %w", ErrNotFound, revision, p.Repos(), last)
}

// readCommitObject resolves a revision and reads the object behind it, BYTE
// FOR BYTE. The bytes are the point: they are what a third party re-hashes to
// establish that the material is about the commit they asked about, and
// internal/verify keeps its own copy private (see the file comment).
//
// Nothing here interprets the object. It is fetched and passed on.
func (p *Prover) readCommitObject(ctx context.Context, repo, revision string) ([]byte, string, error) {
	raw, err := p.git(ctx, repo, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return nil, "", err
	}
	sha := strings.TrimSpace(string(raw))
	object, err := p.git(ctx, repo, "cat-file", "commit", sha)
	if err != nil {
		return nil, "", err
	}
	return object, sha, nil
}

// git runs one read-only git command and returns its stdout untrimmed.
func (p *Prover) git(ctx context.Context, repo string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	// The binary is configuration and the arguments are literals; the one
	// caller-supplied value is a revision, passed after --end-of-options so it
	// cannot become a flag.
	//nolint:gosec // G204: gitPath is configuration, the arguments are literals
	cmd := exec.CommandContext(ctx, p.gitPath, append([]string{"-C", repo}, args...)...)
	cmd.Env = os.Environ()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// collect gathers the raw material behind the verdict.
//
// It never changes the verdict and it cannot: the Report is read, not written.
// What it can do is report a gap, and it does so for every document it failed
// to fetch, naming the reason.
func (p *Prover) collect(ctx context.Context, object []byte, sha string,
	rep verify.Report) (Material, []Upstream) {

	now := p.now().UTC()
	m := Material{
		CommitObject:   string(object),
		CommitObjectID: gitObjectName(object, sha),
		CollectedAt:    now,
	}
	fulcio := Upstream{Name: UpstreamFulcio, URL: p.fulcioRoot, CheckedAt: now}
	rekor := Upstream{Name: UpstreamRekor, URL: p.rekorEntries, CheckedAt: now}

	if root, err := p.fetch(ctx, p.fulcioRoot); err != nil {
		m.Gaps = append(m.Gaps, Gap{"fulcio_root_pem",
			"the certificate authority could not be reached, so the root a third " +
				"party would chain to is not in this response: " + err.Error()})
		fulcio.Error = err.Error()
	} else {
		m.FulcioRootPEM = string(root)
		fulcio.Reachable = true
	}

	if key, err := p.fetch(ctx, p.rekorKey); err != nil {
		m.Gaps = append(m.Gaps, Gap{"rekor_log_public_key_pem",
			"the transparency log's public key could not be fetched, so its proof " +
				"cannot be checked against anything: " + err.Error()})
		rekor.Error = err.Error()
	} else {
		m.RekorLogPublicKeyPEM = string(key)
		rekor.Reachable = true
	}

	switch {
	case rep.Entry.UUID == "":
		m.Gaps = append(m.Gaps, Gap{"rekor_entry",
			"no transparency-log entry was resolved for this commit, so there is " +
				"none to hand over. The checks above say why."})
	default:
		entry, err := p.fetch(ctx, p.rekorEntries+"/"+url.PathEscape(rep.Entry.UUID))
		if err != nil {
			m.Gaps = append(m.Gaps, Gap{"rekor_entry",
				"the log entry could not be fetched: " + err.Error()})
			rekor.Reachable = false
			if rekor.Error == "" {
				rekor.Error = err.Error()
			}
			break
		}
		m.RekorEntry = json.RawMessage(entry)
		if cert, cerr := certificateFromEntry(entry, rep.Entry.UUID); cerr != nil {
			m.Gaps = append(m.Gaps, Gap{"certificate_pem",
				"the log entry carries no readable certificate: " + cerr.Error()})
		} else {
			m.CertificatePEM = string(cert)
		}
	}
	return m, []Upstream{fulcio, rekor}
}

// fetch reads one document from an upstream, verbatim and bounded.
func (p *Prover) fetch(ctx context.Context, endpoint string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, materialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMaterial))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("GET %s: HTTP %d", endpoint, resp.StatusCode)
	}
	return body, nil
}

// joinURL is the same join internal/verify makes, for the same reason: a URL
// that could fail to build halfway through a request would be an error in the
// middle of collecting evidence.
func joinURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a URL: %w", ErrBadRequest, base, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%w: %q has no scheme or host", ErrBadRequest, base)
	}
	return strings.TrimSuffix(u.String(), "/") + path, nil
}

// certificateFromEntry reads the certificate a hashedrekord entry was logged
// under, out of the entry's own bytes.
//
// This is a field read and not a check: nothing here decides whether the
// certificate is good, only which certificate the LOG holds for this entry.
// The deciding is internal/verify's, and it has already happened by the time
// this runs.
func certificateFromEntry(entry []byte, uuid string) ([]byte, error) {
	body, err := entryBody(entry, uuid)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(body.certificatePEM, []byte("BEGIN CERTIFICATE")) {
		return nil, errors.New("the entry's public key is not a PEM certificate")
	}
	return body.certificatePEM, nil
}

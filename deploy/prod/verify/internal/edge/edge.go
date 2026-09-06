// SPDX-License-Identifier: Apache-2.0

// Package edge is the public proof surface's own logic: turning an HTTP
// request for a repository and a commit SHA into a call against
// internal/verify, and turning the Report it returns into an HTTP response.
//
// # The one rule this package exists to honour
//
// RM-061 (#69): "The same Go binary as the CLI — never a second verifier
// implementation at the edge." Divergent verifiers would be a divergence in
// what verified means (threat model §5.4). So nothing in this package parses
// a certificate, checks an inclusion proof, or compares a trailer to a SAN —
// every one of those calls is internal/verify's, reached through
// verify.Verifier.VerifyCommit. What this package adds is entirely at the
// boundary: reading a request, fetching a commit's three verification-
// relevant pieces from the host's API, and mapping a Report onto an HTTP
// response.
//
// # Why VerifyCommit rather than Verify
//
// A serverless function has no git working copy (doc 05 §3.1 records this as
// unsolved, and ADR-0042's hosting note names it explicitly). internal/verify's
// Verify shells out to git to read one; VerifyCommit is the narrower seam
// RM-061 asked for: the SHA (the Rekor artifact itself, ADR-0031 decision 6),
// the message (the Agent-* trailers) and the raw gpgsig signature (the
// certificate) — the three things the checks actually read, none of which
// requires a repository on disk. GitHub's commits API
// (GET /repos/{owner}/{repo}/commits/{sha}) hands back exactly these three
// verbatim: commit.sha, commit.commit.message, and
// commit.commit.verification.signature (the raw signature block GitHub
// extracted from the commit — not conditioned on GitHub itself being able to
// classify or verify it). This package therefore needs no git binary, no
// clone, and no working tree: fetchCommit is the entire "read a commit"
// surface, and it is one HTTP call.
package edge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// DefaultRepo is this deployment's own repository — the one verify.innsegl.dev
// exists to serve (doc 05 §3.1). A caller may still name a different public
// GitHub repository: the certificate chain check is against THIS
// deployment's Fulcio root regardless of which repository a commit was
// fetched from, so the repository is a fetch address, not a trust boundary.
const DefaultRepo = "Raymalian/innsegl"

// defaultGitHubAPIBase is GitHub's REST API. A field on Config rather than a
// hardcoded constant so a test can point it at an httptest server without
// touching the network — the same seam internal/verify's own Config uses for
// FulcioURL and RekorURL.
const defaultGitHubAPIBase = "https://api.github.com"

const (
	defaultHTTPTimeout    = 10 * time.Second
	defaultRequestTimeout = 20 * time.Second
	// maxGitHubBody bounds how much of a GitHub response this handler reads.
	// A commit message and a PEM certificate chain are kilobytes; anything
	// past a megabyte is not a commit this handler was built to serve.
	maxGitHubBody = 1 << 20
)

// shaPattern accepts a GitHub-abbreviated-or-full commit SHA: 7 to 40 hex
// characters. internal/verify's checks need the FULL sha (it is hashed as
// the Rekor artifact), so fetchCommit trusts GitHub's own "sha" field in the
// response rather than the caller's input, exactly as git itself would
// resolve an abbreviation before hashing.
var shaPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// repoPattern accepts "owner/name", GitHub's own shape for a repository path
// segment.
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?/[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// errCommitNotFound marks a 404 from GitHub, distinct from every other
// failure to reach or read GitHub.
var errCommitNotFound = errors.New("edge: no such commit")

// Config is everything Handler needs. Like verify.Config, it is deliberately
// small: two Sigstore endpoints, an optional issuer, and the GitHub side of
// the fetch — nothing that would let this handler consult a ledger (I5).
type Config struct {
	// Repo is served when a request names none. Defaults to DefaultRepo.
	Repo string
	// FulcioURL and RekorURL are handed straight to verify.Config. Under
	// ADR-0042, RekorURL is the public anchor (rekor.sigstore.dev) and
	// FulcioURL remains this deployment's own root.
	FulcioURL string
	RekorURL  string
	// Issuer, when set, is handed straight to verify.Config.
	Issuer string
	// GitHubToken, when set, is sent as a bearer token on the commits-API
	// request. Optional: public commits are readable unauthenticated: this
	// only raises GitHub's rate limit from 60/hour to 5000/hour per RM-061's
	// report §3 (the handler's own answer on rate limiting).
	GitHubToken string
	// GitHubAPIBase overrides GitHub's API origin. Empty means the real one;
	// tests point this at an httptest server.
	GitHubAPIBase string
	// HTTPClient bounds both the GitHub fetch and (via verify.Config) the
	// Fulcio/Rekor calls.
	HTTPClient *http.Client
	// Now is verify.Config's clock seam, passed through unchanged.
	Now func() time.Time
	// RequestTimeout bounds one HTTP request end to end: the GitHub fetch
	// plus the three checks. Defaults to defaultRequestTimeout.
	RequestTimeout time.Duration
}

// Handler serves the public proof surface. It holds no state between
// requests beyond its configuration — like verify.Verifier, there is nothing
// here that could serve a stale verdict, because nothing is cached.
type Handler struct {
	cfg      Config
	verifier *verify.Verifier
}

// New builds a Handler, refusing a configuration internal/verify itself
// would refuse.
func New(cfg Config) (*Handler, error) {
	if cfg.Repo == "" {
		cfg.Repo = DefaultRepo
	}
	if cfg.GitHubAPIBase == "" {
		cfg.GitHubAPIBase = defaultGitHubAPIBase
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}
	v, err := verify.New(verify.Config{
		FulcioURL:  cfg.FulcioURL,
		RekorURL:   cfg.RekorURL,
		Issuer:     cfg.Issuer,
		HTTPClient: cfg.HTTPClient,
		Now:        cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	return &Handler{cfg: cfg, verifier: v}, nil
}

// ServeHTTP is the whole surface: GET /?sha=<sha>[&repo=<owner/name>].
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A public, read-only, no-cookie endpoint answering a question about
	// public data (a commit, a public certificate, a public log entry) —
	// there is no session or credential here for a cross-origin caller to
	// steal, so the paste-a-SHA page does not have to share this handler's
	// origin.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "only GET is served")
		return
	}

	q := r.URL.Query()
	sha := strings.TrimSpace(q.Get("sha"))
	repo := strings.TrimSpace(q.Get("repo"))
	if repo == "" {
		repo = h.cfg.Repo
	}
	if !shaPattern.MatchString(sha) {
		writeError(w, http.StatusBadRequest,
			"sha must be a 7-40 character hexadecimal commit SHA")
		return
	}
	if !repoPattern.MatchString(repo) {
		writeError(w, http.StatusBadRequest,
			"repo must be an owner/name GitHub repository")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()

	cd, err := h.fetchCommit(ctx, repo, sha)
	if err != nil {
		if errors.Is(err, errCommitNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		// Anything else fetching from GitHub is GitHub's fault or the
		// network's, not the commit's and not ours: 502, not 500.
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	rep, err := h.verifier.VerifyCommit(ctx, "https://github.com/"+repo,
		cd.SHA, cd.Tree, cd.Message, cd.Signature)
	if err != nil {
		// The only errors VerifyCommit returns are requests it could not act
		// on (ErrRevision, on an empty SHA — unreachable here since sha
		// already matched shaPattern and cd.SHA comes from GitHub's own
		// response) — never a verification outcome. Anything reaching this
		// branch is this handler's own construction, hence 500.
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, statusFor(rep.Verdict), rep)
}

// statusFor is RM-061's report §2, in code: the three verdicts a completed
// verification can reach — VERIFIED, FAILED, UNATTRIBUTED — are all
// successful answers and all 200; a commit was read and a verdict was
// reached about it. Only UNAVAILABLE, which means a check could not run at
// all (Fulcio or Rekor unreachable), is a 503: the fault is this
// deployment's own dependency, not the commit, and 503 tells a cache or a
// retrying client so — where a FAILED verdict must never be treated as
// retryable, an UNAVAILABLE one might resolve on retry.
func statusFor(v verify.Verdict) int {
	switch v {
	case verify.VerdictVerified, verify.VerdictFailed, verify.VerdictUnattributed:
		return http.StatusOK
	case verify.VerdictUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// commitData is the narrower-than-a-repository shape VerifyCommit needs; see
// the package doc for why these three fields (plus Tree, carried only for
// VER-003's best-effort recovery) are everything the checks read.
type commitData struct {
	SHA       string
	Tree      string
	Message   string
	Signature []byte
}

// ghCommitResponse is the subset of GitHub's commits-API response this
// handler reads. See
// https://docs.github.com/en/rest/commits/commits#get-a-commit.
type ghCommitResponse struct {
	SHA    string `json:"sha"`
	Commit struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
		Message      string `json:"message"`
		Verification struct {
			Signature string `json:"signature"`
		} `json:"verification"`
	} `json:"commit"`
}

// fetchCommit is the entire "read a commit" surface for a repository this
// handler has no working copy of: one call to GitHub's commits API.
//
// repo and sha have already passed repoPattern/shaPattern by the time this
// is called (ServeHTTP is the only caller), so the request URL below is
// built from validated, non-shell, non-path-traversing segments joined onto
// GitHubAPIBase — a deployment-configured value, never a caller-supplied
// one.
func (h *Handler) fetchCommit(ctx context.Context, repo, sha string) (commitData, error) {
	target := h.cfg.GitHubAPIBase + "/repos/" + repo + "/commits/" + sha
	//nolint:gosec // G704: target is GitHubAPIBase (deployment config) plus repo/sha,
	// both already matched against repoPattern/shaPattern before this call
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return commitData{}, fmt.Errorf("edge: building the GitHub request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if h.cfg.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.cfg.GitHubToken)
	}

	//nolint:gosec // G704: see the note on target above; req's URL carries the same guarantee
	resp, err := h.cfg.HTTPClient.Do(req)
	if err != nil {
		return commitData{}, fmt.Errorf("edge: reaching GitHub: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubBody))
	if err != nil {
		return commitData{}, fmt.Errorf("edge: reading GitHub's response for %s@%s: %w", repo, sha, err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return commitData{}, fmt.Errorf("%w: %s@%s", errCommitNotFound, repo, sha)
	}
	if resp.StatusCode != http.StatusOK {
		return commitData{}, fmt.Errorf("edge: GitHub returned %s for %s@%s: %s",
			resp.Status, repo, sha, strings.TrimSpace(string(body)))
	}

	var parsed ghCommitResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return commitData{}, fmt.Errorf("edge: GitHub's commit response did not parse: %w", err)
	}
	if parsed.SHA == "" {
		return commitData{}, fmt.Errorf("edge: GitHub's commit response for %s@%s carries no sha",
			repo, sha)
	}

	var sig []byte
	if parsed.Commit.Verification.Signature != "" {
		sig = []byte(parsed.Commit.Verification.Signature)
	}
	return commitData{
		SHA:       parsed.SHA,
		Tree:      parsed.Commit.Tree.SHA,
		Message:   parsed.Commit.Message,
		Signature: sig,
	}, nil
}

type errorBody struct {
	Error string `json:"error"`
}

// marshalIndent is json.MarshalIndent behind a seam, mirroring
// internal/verify's own idiom (render.go's marshalIndent): every value this
// handler encodes is a verify.Report or an errorBody, both encoder-safe by
// construction, so the failure branch below is unreachable in production —
// which is exactly why it is reached from a test rather than left as a
// branch nobody has checked. Never reassigned outside tests.
var marshalIndent = json.MarshalIndent

func writeJSON(w http.ResponseWriter, status int, v any) {
	out, err := marshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("edge: encoding a response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(out); err != nil {
		log.Printf("edge: writing a response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/mirror"
	"innsegl.dev/innsegl/internal/trusthistory"
	"innsegl.dev/innsegl/internal/trustwatch"
	"innsegl.dev/innsegl/internal/verify"
)

// The trust watch (ADR-0073), as a pass of `innsegl reconcile`: on its first
// cycle and daily after, record the trust material in use, verify the
// sentinel commits, and warn about CAs near expiry. It is a reconcile pass
// because reconcile is the companion that already runs on a schedule inside
// the core, with the mirror and the transparency log in reach.

// envTrustSentinels is the sentinel list; empty means trust-sentinels.json
// beside the history.
const envTrustSentinels = "INNSEGL_TRUST_SENTINELS"

// trustFetchTimeout bounds one read of a published root or key.
const trustFetchTimeout = 30 * time.Second

// trustSentinelsFor is the sentinel list's default: beside the history.
func trustSentinelsFor(history, explicit string) string {
	if explicit != "" || history == "" {
		return explicit
	}
	return filepath.Join(filepath.Dir(history), trustwatch.SentinelsFileName)
}

// openTrustWatch builds the watch, or nil when no history is configured.
func openTrustWatch(opts reconcileOptions) (*trustwatch.Watch, error) {
	if opts.trustHistory == "" {
		return nil, nil
	}
	client := &http.Client{Timeout: trustFetchTimeout}
	v, err := verify.New(verify.Config{FulcioURL: opts.fulcioURL, RekorURL: opts.rekorURL, HTTPClient: client})
	if err != nil {
		return nil, fmt.Errorf("the trust watch needs a Fulcio and a Rekor URL: %w", err)
	}
	sources := map[trusthistory.Kind]trustwatch.Source{
		trusthistory.KindFulcioRoot:      fetchPEM(client, strings.TrimSuffix(opts.fulcioURL, "/")+"/api/v1/rootCert"),
		trusthistory.KindTransparencyLog: fetchPEM(client, strings.TrimSuffix(opts.rekorURL, "/")+"/api/v1/log/publicKey"),
	}
	if opts.gatewayCADir != "" {
		sources[trusthistory.KindGatewayCA] = readPEM(filepath.Join(opts.gatewayCADir, gateway.CACertFileName))
	}
	if socketPresent(opts.workloadAPI) {
		sources[trusthistory.KindSPIREUpstreamCA] = spireUpstream(opts.workloadAPI, opts.trustDomain)
	}
	dir := filepath.Dir(opts.trustHistory)
	return trustwatch.New(trustwatch.Config{
		HistoryFile:       opts.trustHistory,
		SentinelsFile:     opts.trustSentinels,
		AutoSentinelsFile: filepath.Join(dir, trustwatch.AutoSentinelsFileName),
		LostRootsFile:     filepath.Join(dir, trusthistory.LostRootsFileName),
		StatusFile:        filepath.Join(dir, trustwatch.StatusFileName),
		Sources:           sources,
		Candidates:        sentinelCandidates(opts),
		RepoDir:           trustRepoDir(opts),
		Verify: func(ctx context.Context, h *trusthistory.History, dir, sha string) (trustwatch.Outcome, error) {
			rep, err := v.WithHistory(h).Verify(ctx, dir, sha)
			return outcomeOf(rep), err
		},
	}), nil
}

// outcomeOf is a report as the trust watch reads it: the verdict, and for a
// verified commit the key id of the root its certificate chained to.
func outcomeOf(rep verify.Report) trustwatch.Outcome {
	out := trustwatch.Outcome{Verdict: rep.Verdict}
	if rep.Verdict != verify.VerdictVerified {
		return out
	}
	for _, c := range rep.Checks {
		for _, f := range c.Facts {
			if f.Name == verify.FactTrustRootKeyID {
				out.RootKeyID = f.Value
			}
		}
	}
	return out
}

// candidatesPerRepo is how many of each repository's newest commits are
// offered as sentinel candidates.
const candidatesPerRepo = 5

// sentinelCandidates lists the newest commits of every repository the mirror
// holds. With no mirror there are none: a single-host fixture's working trees
// are not a deployment's record.
func sentinelCandidates(opts reconcileOptions) func(context.Context) ([]trustwatch.Candidate, error) {
	return func(ctx context.Context) ([]trustwatch.Candidate, error) {
		if opts.mirrorDir == "" {
			return nil, nil
		}
		store, err := mirror.Open(opts.mirrorDir)
		if err != nil {
			return nil, err
		}
		repos, err := store.Repos()
		if err != nil {
			return nil, err
		}
		var out []trustwatch.Candidate
		for _, repo := range repos {
			dir, err := store.Dir(repo)
			if err != nil {
				continue
			}
			raw, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-list",
				"--max-count="+strconv.Itoa(candidatesPerRepo), "--all").Output()
			if err != nil {
				continue
			}
			for _, sha := range strings.Fields(string(raw)) {
				out = append(out, trustwatch.Candidate{Repo: repo, Commit: sha})
			}
		}
		return out, nil
	}
}

// trustRepoDir finds a sentinel's repository where every other pass reads
// one: the mirror when configured, else a single-host fixture's working trees.
func trustRepoDir(opts reconcileOptions) func(string) (string, error) {
	return func(repo string) (string, error) {
		if opts.mirrorDir == "" {
			return filepath.Join(opts.workspace, filepath.FromSlash(repo)), nil
		}
		store, err := mirror.Open(opts.mirrorDir)
		if err != nil {
			return "", err
		}
		return store.Dir(repo)
	}
}

// fetchPEM reads a published root or key over HTTP.
func fetchPEM(client *http.Client, url string) trustwatch.Source {
	return func(ctx context.Context) ([][]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
		}
		return splitPEM(body), nil
	}
}

// readPEM reads a certificate file the core writes.
func readPEM(path string) trustwatch.Source {
	return func(context.Context) ([][]byte, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return splitPEM(raw), nil
	}
}

// splitPEM is each PEM block of a document on its own. A document with none
// is returned whole, so Record says what is wrong with it.
func splitPEM(raw []byte) [][]byte {
	var out [][]byte
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		out = append(out, pem.EncodeToMemory(block))
	}
	if len(out) == 0 {
		return [][]byte{raw}
	}
	return out
}

// socketPresent says whether a Workload API address can be dialled at all. An
// absent unix socket is a container that holds no SPIRE identity, which is a
// configuration, not an outage to report every day.
func socketPresent(addr string) bool {
	if addr == "" {
		return false
	}
	path, ok := strings.CutPrefix(addr, "unix://")
	if !ok {
		return true
	}
	_, err := os.Stat(path)
	return err == nil
}

// minUpstreamLifetime separates SPIRE's upstream CA from its own rotating
// CAs: an upstream root lives for years, SPIRE's own for hours or days, and
// recording each of those would grow the history every day.
const minUpstreamLifetime = 365 * 24 * time.Hour

// spireUpstream reads the SPIRE upstream CA from the trust bundle.
func spireUpstream(addr, trustDomain string) trustwatch.Source {
	return func(ctx context.Context) ([][]byte, error) {
		td, err := spiffeid.TrustDomainFromString(trustDomain)
		if err != nil {
			return nil, err
		}
		set, err := workloadapi.FetchX509Bundles(ctx, workloadapi.WithAddr(addr))
		if err != nil {
			return nil, err
		}
		bundle, ok := set.Get(td)
		if !ok {
			return nil, fmt.Errorf("the Workload API returned no bundle for %s", td)
		}
		return upstreamRoots(bundle.X509Authorities()), nil
	}
}

// upstreamRoots keeps the self-signed, long-lived authorities.
func upstreamRoots(authorities []*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range authorities {
		if c.CheckSignatureFrom(c) != nil || c.NotAfter.Sub(c.NotBefore) < minUpstreamLifetime {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return out
}

// trust reports one trust watch pass. Alerts go to stderr, one ALERT line
// each, which is where every other alert-level finding of this command goes.
func (r reconcileReporter) trust(res trustwatch.Result) {
	for _, e := range res.Recorded {
		fprintf(r.stdout, "innsegl reconcile: trust history recorded %s %s (first used %s)\n",
			e.Kind, e.KeyID, e.FirstUsed.Format(time.RFC3339))
	}
	for _, a := range res.Alerts() {
		fprintf(r.stderr, "innsegl reconcile: TRUST ALERT - %s\n", a)
	}
}

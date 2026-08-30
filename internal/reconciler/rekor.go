// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// The transparency-log half of the join.
//
// # Which question is asked, and why that one
//
// gitsign's online mode writes a `hashedrekord` whose artifact is the COMMIT
// SHA — the entry's `data.hash.value` is sha256 of the commit's hex id, and its
// public key is the Fulcio certificate the signature was made under. So an
// entry with this commit's artifact hash, under a certificate naming this run,
// is this commit's signature and no other's. That is the join
// `internal/signing` already uses to prove the entry it reports belongs to the
// commit it made (ADR-0031 decision 6), and reading it the same way here is
// what keeps the reconciler and the tool from disagreeing about what "this
// commit's entry" means.
//
// It is deliberately NOT read out of anything the MCP said. The whole reason
// the reconciler exists is that the MCP crashed before it could say anything.
//
// # ErrNoEntry is a finding; anything else is an outage
//
// The distinction is the most consequential one in this file. `ErrNoEntry`
// means the log answered and holds no such entry, and that answer is what lets
// `Reconcile` append a `commit_intent_expired` — a permanent record (I4) that
// no signature exists. Every other error means the log could not be asked, and
// the intent stays open. An outage laundered into an absence is how a Rekor
// restart becomes a chain full of false expiries.
//
// An entry that exists but is not this commit's signature — the wrong kind,
// the wrong artifact, a public key that is not a certificate, a certificate
// with no URI SAN — is ALSO `ErrNoEntry`. Those are the log answering too: it
// holds nothing that attributes this commit.

const (
	rekorIndexPath    = "/api/v1/index/retrieve"
	rekorEntriesPath  = "/api/v1/log/entries"
	rekorHashedRekord = "hashedrekord"
	rekorSHA256       = "sha256"

	// defaultRekorTimeout bounds one request. IP §6.3: no indefinite hangs.
	defaultRekorTimeout = 30 * time.Second
	// maxRekorResponse bounds one response body. A log that streams gigabytes
	// at a reconciler is a denial of service and no legitimate answer is large.
	maxRekorResponse = 4 << 20
	// maxIndexCandidates bounds how many uuids one artifact hash may resolve
	// to before the answer is treated as untrustworthy rather than walked.
	maxIndexCandidates = 64
)

// RekorLog reads a Rekor v1 REST API. It holds no key and signs nothing:
// everything below is what a stranger can ask the log (I5).
type RekorLog struct {
	base string
	http *http.Client
}

var _ TransparencyLog = (*RekorLog)(nil)

// NewRekorLog builds a reader for the log at base. A nil client gets one
// bounded by defaultRekorTimeout.
func NewRekorLog(base string, client *http.Client) (*RekorLog, error) {
	if base == "" {
		return nil, fmt.Errorf("reconciler: no rekor base url; without the log every " +
			"expiry would be a negative nobody established (IP §6.5)")
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("reconciler: rekor base url %q: %w", base, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("reconciler: rekor base url %q is %q, want http or https",
			base, parsed.Scheme)
	}
	if client == nil {
		client = &http.Client{Timeout: defaultRekorTimeout}
	}
	return &RekorLog{base: strings.TrimRight(base, "/"), http: client}, nil
}

// EntryForCommit returns the log entry whose artifact is sha256(commitSHA) and
// whose certificate names an identity, or ErrNoEntry.
func (l *RekorLog) EntryForCommit(ctx context.Context, commitSHA string) (LogEntry, error) {
	if err := event.ValidateGitObjectID(commitSHA); err != nil {
		return LogEntry{}, fmt.Errorf("reconciler: %q is not a git object id: %w", commitSHA, err)
	}
	digest := sha256.Sum256([]byte(commitSHA))
	want := hex.EncodeToString(digest[:])

	// Written rather than marshalled: `want` is hex from a SHA-256 digest, so
	// there is nothing in it to escape, and a marshal error here would be an
	// error branch no test could ever reach.
	raw, err := l.post(ctx, rekorIndexPath, []byte(`{"hash":"`+rekorSHA256+":"+want+`"}`))
	if err != nil {
		return LogEntry{}, err
	}
	var uuids []string
	if jerr := json.Unmarshal(raw, &uuids); jerr != nil {
		return LogEntry{}, fmt.Errorf("reconciler: the rekor search index answered %s: %w",
			truncate(raw), jerr)
	}
	if len(uuids) > maxIndexCandidates {
		return LogEntry{}, fmt.Errorf(
			"reconciler: the rekor search index returned %d entries for one artifact hash, "+
				"over the %d bound", len(uuids), maxIndexCandidates)
	}

	for _, uuid := range uuids {
		entry, ok, ferr := l.entry(ctx, uuid, want)
		if ferr != nil {
			return LogEntry{}, ferr
		}
		if ok {
			return entry, nil
		}
	}
	return LogEntry{}, fmt.Errorf("%w: no entry whose artifact is %s:%s",
		ErrNoEntry, rekorSHA256, want)
}

// entry fetches one candidate and decides whether it is the commit's.
//
// The boolean rather than a sentinel: "the log holds this entry and it is not
// the one" is not an error at all, and the caller keeps looking.
func (l *RekorLog) entry(ctx context.Context, uuid, wantHash string) (LogEntry, bool, error) {
	raw, err := l.get(ctx, rekorEntriesPath+"/"+url.PathEscape(uuid))
	if err != nil {
		return LogEntry{}, false, err
	}
	var entries map[string]struct {
		Body           string `json:"body"`
		LogIndex       int64  `json:"logIndex"`
		IntegratedTime int64  `json:"integratedTime"`
	}
	if jerr := json.Unmarshal(raw, &entries); jerr != nil {
		return LogEntry{}, false, fmt.Errorf(
			"reconciler: the rekor entry %s did not decode: %w", uuid, jerr)
	}
	got, present := entries[uuid]
	if !present {
		// The log answered with something that is not the entry asked for.
		// Not an outage and not a match.
		return LogEntry{}, false, nil
	}
	identity, ok := attributionOf(got.Body, wantHash)
	if !ok {
		return LogEntry{}, false, nil
	}
	return LogEntry{
		UUID:                uuid,
		LogIndex:            got.LogIndex,
		IntegratedAt:        time.Unix(got.IntegratedTime, 0).UTC(),
		CertificateIdentity: identity,
	}, true, nil
}

// rekorBody is the entry content this reader needs: a hashedrekord whose
// artifact is the commit SHA and whose public key is the signing certificate.
type rekorBody struct {
	Kind string `json:"kind"`
	Spec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// attributionOf reads the identity an entry attributes its artifact to, or
// reports that the entry is not one.
//
// Five conditions, all of them the log's own bytes rather than anything this
// process supplied: the body decodes; the entry is a hashedrekord; its artifact
// is sha256 and is the one asked for; its public key is a certificate; and that
// certificate carries a URI SAN, which is the SPIFFE ID Fulcio issued it for.
//
// Every failure is `false` rather than an error, and that is the point: each
// one means the log holds nothing that attributes this commit, which is the
// same finding as no entry at all. Only a log that could not be ASKED is an
// error, and none of these is that.
func attributionOf(bodyBase64, wantHash string) (string, bool) {
	body, err := base64.StdEncoding.DecodeString(bodyBase64)
	if err != nil {
		return "", false
	}
	var got rekorBody
	if jerr := json.Unmarshal(body, &got); jerr != nil {
		return "", false
	}
	if got.Kind != rekorHashedRekord {
		return "", false
	}
	if got.Spec.Data.Hash.Algorithm != rekorSHA256 || got.Spec.Data.Hash.Value != wantHash {
		return "", false
	}
	pemBytes, err := base64.StdEncoding.DecodeString(got.Spec.Signature.PublicKey.Content)
	if err != nil {
		return "", false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", false
	}
	if len(cert.URIs) == 0 {
		// A certificate with no URI SAN attributes nothing. gitsign's Fulcio
		// certificates carry the SPIFFE ID there, and it is the only member of
		// the certificate a repair reads.
		return "", false
	}
	return cert.URIs[0].String(), true
}

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

func (l *RekorLog) get(ctx context.Context, path string) ([]byte, error) {
	return l.do(ctx, http.MethodGet, path, nil)
}

func (l *RekorLog) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	return l.do(ctx, http.MethodPost, path, body)
}

// do runs one request. Every failure it returns is an outage rather than an
// absence: a status this reader did not expect is a log it could not read, and
// the caller must never turn that into a `commit_intent_expired`.
func (l *RekorLog) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, l.base+path, reader)
	if err != nil {
		return nil, fmt.Errorf("reconciler: rekor %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := l.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reconciler: rekor %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRekorResponse))
	if err != nil {
		return nil, fmt.Errorf("reconciler: reading the response to rekor %s %s: %w",
			method, path, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("reconciler: rekor %s %s: HTTP %d: %s",
			method, path, resp.StatusCode, truncate(raw))
	}
	return raw, nil
}

// truncate bounds a log line quoting a response body.
func truncate(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 256 {
		return s[:256] + " […truncated]"
	}
	return s
}

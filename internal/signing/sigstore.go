// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/segment"
)

// What this file does, and what it deliberately does not.
//
// IP §7: "SPIRE and Sigstore (gitsign/Fulcio/Rekor) are used as released
// upstream components — do not fork, do not reimplement their crypto.
// Configuration and orchestration only." Nothing here signs, verifies a
// signature, or builds a certificate. What it does is read three documents
// over HTTP and walk two structures:
//
//   - Fulcio's root certificate and Rekor's log key, because gitsign has to be
//     POINTED at them (see the trust-root discussion in gitsign.go) and
//     because ADR-0024 defines "Sigstore is reachable" as those bytes parsing.
//   - The certificate inside a commit's CMS signature, so the wrapper can say
//     WHICH run signed a commit without asking a verifier. The walk stops at
//     the `certificates [0]` field of SignedData and hands the DER to
//     crypto/x509; the signature itself is gitsign's business.
//   - The Rekor entry for a commit, found by the artifact hash gitsign logged,
//     so `sign_commit` can return the `rekor_entry` IP §4 requires.

const (
	// The Sigstore endpoints this wrapper reads. ADR-0024 fixes the first two
	// as the definition of Sigstore readiness: bytes that parse as the trust
	// material, never a status code, because a TCP dial or an unexamined 200
	// passes against any listening socket.
	fulcioRootPath   = "/api/v1/rootCert"
	rekorPubKeyPath  = "/api/v1/log/publicKey"
	rekorEntriesPath = "/api/v1/log/entries"
	rekorIndexPath   = "/api/v1/index/retrieve"

	// The entry kind gitsign writes in Rekor's "online" mode: a hashedrekord
	// whose artifact is the commit SHA. Spelled the way Rekor spells it.
	rekorHashedRekord = "hashedrekord"
	rekorSHA256       = "sha256"

	// defaultHTTPTimeout bounds one request to Fulcio or Rekor. IP §6.3: "No
	// indefinite hangs holding repo locks."
	defaultHTTPTimeout = 30 * time.Second

	// rekorLookupAttempts bounds the poll for the search index to catch up.
	// The entry is already integrated by the time gitsign returns — its own
	// Rekor v1 client refuses a response with no inclusion proof — but the
	// index is a separate write, so a first miss is not yet an absence. A few
	// attempts is the right size: this is a race with a write that has already
	// been acknowledged, not a wait for work that has not started.
	rekorLookupAttempts = 5
	rekorLookupDelay    = 500 * time.Millisecond

	// rekorLookupMaxDelay and rekorLookupMultiplier turn rekorLookupDelay from
	// a flat wait into the Base of an exponential backoff (IP §6.3: "bounded
	// retries with backoff and jitter"). RM-034 (#42) measured the flat wait
	// on the wire: four gaps identical to within a millisecond, no growth, no
	// jitter (#93) — against exactly the reasoning above. A race with an
	// already-acknowledged write does not, on its own, need either. What does
	// need it is doc 05 §2's fact that every MCP replica shares one Rekor: a
	// fleet retrying the same write on the same fixed schedule can still
	// synchronise into the thundering herd doc 04 lists under asset A5.
	//
	// Multiplier is pinned at 2: rekorWait.jittered's equal-jitter
	// construction only guarantees non-overlapping, strictly growing
	// intervals when the multiplier is at least 2 — see the comment there.
	// Lowering it would turn TestRekorWaitJitteredGapsAlwaysGrow's guarantee
	// from structural into merely statistical.
	rekorLookupMaxDelay   = 5 * time.Second
	rekorLookupMultiplier = 2.0
)

// rekorLookupPolicy is the Rekor lookup's retry policy.
// internal/segment/anchor.go already defines this exact shape for Rekor
// anchoring (RM-012, ADR-0009) — Attempts, a Base, a Max and a Multiplier,
// walked by Backoff — and it is reused here rather than reinvented: two
// retry policies against the same log is exactly the divergence doc 04 §5.4
// warns about. What anchor.go's shape does not carry is jitter — ADR-0009's
// anchoring is a background retry with no sibling racing it moment to
// moment, so it never needed any — and rekorWait below adds the half
// anchor.go's shape does not supply.
var rekorLookupPolicy = segment.RetryPolicy{
	Attempts:   rekorLookupAttempts,
	Base:       rekorLookupDelay,
	Max:        rekorLookupMaxDelay,
	Multiplier: rekorLookupMultiplier,
}

// rekorWait turns one plain backoff into the interval a lookup attempt
// actually waits, adding the jitter anchor.go's RetryPolicy does not.
//
// Equal jitter — wait = backoff/2 + rand()·backoff/2 — rather than full
// jitter: it keeps a hard floor under every attempt, so a real blip still
// gets a real wait, while still de-synchronising a fleet of replicas. And
// because Multiplier is pinned at 2, the floor of attempt n+1 is exactly the
// ceiling of attempt n:
//
//	jittered(Backoff(n))   ∈ [Backoff(n)/2, Backoff(n))
//	jittered(Backoff(n+1)) ∈ [Backoff(n),   2·Backoff(n))
//
// so gap n is always strictly less than gap n+1, for ANY draw from Rand.
// That is what makes "intervals grow" a structural fact rather than a
// statistical one — TestRekorWaitJitteredGapsAlwaysGrow needs no seed and
// cannot flake.
//
// randFn and sleepFn are substitutable for the reason
// internal/segment.Anchorer.Sleep is substitutable: a test drives the wait
// rather than living through it — postgres_ambiguouscommit_test.go's
// pattern, applied to time instead of a commit acknowledgment — and drives
// the randomness with an injected, logged sequence rather than trusting a
// flake to reproduce — test/chaos/kill_test.go's pattern, applied to one
// float instead of a kill target. nil means the real thing: math/rand/v2's
// auto-seeded, concurrency-safe top-level source, and a real context-aware
// timer.
type rekorWait struct {
	randFn  func() float64
	sleepFn func(context.Context, time.Duration) error
}

func (w rekorWait) rand() float64 {
	if w.randFn != nil {
		return w.randFn()
	}
	return mathrand.Float64() //nolint:gosec // G404: jitter timing, not a security decision — predictability here costs nothing an attacker could use
}

func (w rekorWait) sleep(ctx context.Context, d time.Duration) error {
	if w.sleepFn != nil {
		return w.sleepFn(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// jittered applies equal jitter to one plain backoff. A non-positive backoff
// waits zero rather than going negative.
func (w rekorWait) jittered(backoff time.Duration) time.Duration {
	if backoff <= 0 {
		return 0
	}
	half := float64(backoff) / 2
	return time.Duration(half + w.rand()*half)
}

// Fulcio's certificate extensions, from
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md. Only the two
// issuer spellings are read here; .24 (OIDTokenSubject) duplicates the URI SAN
// for a `spiffe` issuer and the SAN is the field IP §1's check 3 names.
var (
	oidFulcioIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// httpGet fetches one document with a bounded body.
func httpGet(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", endpoint, resp.StatusCode, truncate(body))
	}
	return body, nil
}

func httpPostJSON(ctx context.Context, client *http.Client, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("POST %s: HTTP %d: %s", endpoint, resp.StatusCode, truncate(got))
	}
	return got, nil
}

func truncate(b []byte) string {
	const limit = 512
	if len(b) > limit {
		return string(b[:limit]) + "…"
	}
	return string(b)
}

func joinURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a URL: %w", ErrConfig, base, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%w: %q has no scheme or host", ErrConfig, base)
	}
	return strings.TrimSuffix(u.String(), "/") + path, nil
}

// fetchFulcioRoot returns Fulcio's root certificate, PEM, and refuses anything
// that is not a CA certificate. ADR-0024: "must decode as a PEM CA
// certificate" — the CA half is the part a status check would miss.
func fetchFulcioRoot(ctx context.Context, client *http.Client, base string) ([]byte, error) {
	endpoint, err := joinURL(base, fulcioRootPath)
	if err != nil {
		return nil, err
	}
	body, err := httpGet(ctx, client, endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSigningUnavailable, err)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: %s did not return a PEM certificate", ErrSigningUnavailable, endpoint)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s returned bytes that are not a certificate: %w",
			ErrSigningUnavailable, endpoint, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%w: %s returned a certificate that is not a CA",
			ErrSigningUnavailable, endpoint)
	}
	return body, nil
}

// fetchRekorPublicKey returns the transparency log's public key, PEM, and
// refuses anything that is not a PKIX public key (ADR-0024).
//
// This key is not decoration: it is what gitsign checks the signed entry
// timestamp against, and ADR-0009's chain terminates on it. A wrapper that let
// gitsign fall back to the public-good TUF root here would be verifying our
// entries against somebody else's log key.
func fetchRekorPublicKey(ctx context.Context, client *http.Client, base string) ([]byte, error) {
	endpoint, err := joinURL(base, rekorPubKeyPath)
	if err != nil {
		return nil, err
	}
	body, err := httpGet(ctx, client, endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTransparencyUnavailable, err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("%w: %s did not return PEM", ErrTransparencyUnavailable, endpoint)
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, fmt.Errorf("%w: %s did not return a PKIX public key: %w",
			ErrTransparencyUnavailable, endpoint, err)
	}
	return body, nil
}

// placeholderCTLogKey returns a PEM public key whose private half is generated
// and discarded inside this function.
//
// WHY THIS EXISTS. ADR-0029 decision 5: this deployment runs Fulcio with
// `--ct-log-url=` empty, so its certificates carry no SCT, and the compose
// README states the consequence — "a verifier configured to require one will
// refuse them". gitsign is told not to require one (`--insecure-ignore-sct`).
// But cosign's GetCTLogPubs, which gitsign calls on its way to building a
// verifier, refuses to return an EMPTY set of CT log keys and falls back to
// fetching them from the public-good TUF mirror when
// SIGSTORE_CT_LOG_PUBLIC_KEY_FILE is unset. MEASURED: with the network
// blocked, `gitsign verify` fails with
//
//	error getting CT log public key: updating local metadata and targets:
//	  error updating to TUF remote mirror: tuf: failed to download
//	  13.root.json
//
// which would make every TC-SIG case depend on reaching tuf-repo-cdn.sigstore.dev
// — the opposite of IP §7's "integration tests must run against local
// containerized instances so CI needs no external dependencies".
//
// So the set is made non-empty with a key that CANNOT have signed anything.
// The private half never leaves this function and is never used, so no SCT can
// verify under it: if the ignore-SCT flag were ever dropped, verification
// fails closed rather than silently trusting whatever key a TUF fetch
// returned. Naming Rekor's key or Fulcio's here would be one line shorter and
// would assert something untrue about who operates a CT log.
func placeholderCTLogKey() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ---------------------------------------------------------------------------
// The certificate inside a commit's signature.
// ---------------------------------------------------------------------------

// cmsContentInfo is RFC 5652 §3's outer wrapper.
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// cmsSignedData is RFC 5652 §5.1, read only as far as the certificates. Go's
// encoding/asn1 allows extra elements at the end of a SEQUENCE, so the crls
// and signerInfos that follow are left unparsed — they are the signature's
// business and gitsign's.
type cmsSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
}

// certificatesFromSignature extracts the certificates carried in a commit's
// `gpgsig` header. It parses structure, never signatures.
func certificatesFromSignature(armored []byte) ([]*x509.Certificate, error) {
	block, _ := pem.Decode(armored)
	if block == nil {
		return nil, fmt.Errorf("%w: the signature is not PEM", ErrSignature)
	}
	if block.Type != "SIGNED MESSAGE" {
		return nil, fmt.Errorf("%w: the signature is a %q block, not a CMS SIGNED MESSAGE",
			ErrSignature, block.Type)
	}
	var outer cmsContentInfo
	if _, err := asn1.Unmarshal(block.Bytes, &outer); err != nil {
		return nil, fmt.Errorf("%w: the signature is not a CMS ContentInfo: %w", ErrSignature, err)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("%w: the CMS content is not a SignedData: %w", ErrSignature, err)
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("%w: the signature carries no certificate", ErrSignature)
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the CMS certificate set does not parse: %w", ErrSignature, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: the signature carries no certificate", ErrSignature)
	}
	return certs, nil
}

// leafOf picks the signing certificate out of a CMS certificate set: the one
// that is not a CA and carries a URI SAN, which for this deployment is the
// run's SPIFFE ID.
func leafOf(certs []*x509.Certificate) (*x509.Certificate, error) {
	for _, c := range certs {
		if !c.IsCA && len(c.URIs) > 0 {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%w: none of the %d certificates in the signature is a "+
		"leaf with a URI SAN; a commit this system signed is attributed by that SAN",
		ErrSignature, len(certs))
}

// describeCertificate renders the fields a ledger event and a report need.
func describeCertificate(cert *x509.Certificate) Certificate {
	out := Certificate{
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UTC(),
		NotAfter:     cert.NotAfter.UTC(),
		Fingerprint:  fingerprintOf(cert),
	}
	if len(cert.URIs) > 0 {
		out.SPIFFEID = cert.URIs[0].String()
	}
	out.Issuer = fulcioIssuerOf(cert)
	return out
}

// fulcioIssuerOf reads the OIDC issuer Fulcio recorded. .8 is the current
// spelling (a DER UTF8String); .1 is the deprecated raw one, read as a
// fallback so an older Fulcio is not silently reported as having no issuer.
func fulcioIssuerOf(cert *x509.Certificate) string {
	var deprecated string
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidFulcioIssuerV2):
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
				return s
			}
		case ext.Id.Equal(oidFulcioIssuerV1):
			deprecated = string(ext.Value)
		}
	}
	return deprecated
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// fingerprintOfCertPEM is the same identifier for a certificate that arrived
// as PEM — which is how Rekor stores the key an entry was accepted under.
func fingerprintOfCertPEM(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("%w: not PEM", ErrSignature)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return fingerprintOf(cert), nil
}

// ---------------------------------------------------------------------------
// The Rekor entry for a commit.
// ---------------------------------------------------------------------------

// rekorEntry is the part of Rekor's log entry this wrapper reads.
type rekorEntry struct {
	Body           string `json:"body"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`
	IntegratedTime int64  `json:"integratedTime"`
}

// rekorBody is the entry's canonical content: a hashedrekord whose artifact is
// the commit SHA and whose public key is the signing certificate.
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

// findRekorEntry locates the entry gitsign wrote for one commit.
//
// It searches by the artifact hash rather than reading gitsign's stdout,
// because the search is also the PROOF: gitsign's online mode logs a
// hashedrekord over the commit SHA, so an entry whose `data.hash.value` is
// sha256 of this commit's SHA and whose public key is this commit's
// certificate is this commit's entry and no other's. A log index scraped out
// of a subprocess's output would name an entry without establishing anything
// about it.
func findRekorEntry(ctx context.Context, client *http.Client, base, commitSHA string, leaf *x509.Certificate) (RekorEntry, error) {
	return findRekorEntryWaiting(ctx, client, base, commitSHA, leaf, rekorWait{})
}

// findRekorEntryWaiting is findRekorEntry with the wait between attempts
// substitutable (see rekorWait). Production signing goes through
// findRekorEntry, which uses the real clock and real randomness; only tests
// construct a rekorWait directly.
func findRekorEntryWaiting(ctx context.Context, client *http.Client, base, commitSHA string, leaf *x509.Certificate, wait rekorWait) (RekorEntry, error) {
	digest := sha256.Sum256([]byte(commitSHA))
	want := hex.EncodeToString(digest[:])

	indexURL, err := joinURL(base, rekorIndexPath)
	if err != nil {
		return RekorEntry{}, err
	}
	// Written rather than marshalled: `want` is hex from a SHA-256 digest, so
	// there is nothing in it to escape, and a marshal error here would be an
	// error branch no test could ever reach.
	query := []byte(`{"hash":"` + rekorSHA256 + ":" + want + `"}`)

	var last error
	for attempt := range rekorLookupPolicy.Attempts {
		if attempt > 0 {
			d := wait.jittered(rekorLookupPolicy.Backoff(attempt))
			if serr := wait.sleep(ctx, d); serr != nil {
				return RekorEntry{}, serr
			}
		}
		raw, err := httpPostJSON(ctx, client, indexURL, query)
		if err != nil {
			last = err
			continue
		}
		var uuids []string
		if err := json.Unmarshal(raw, &uuids); err != nil {
			last = fmt.Errorf("the search index returned %s: %w", truncate(raw), err)
			continue
		}
		if len(uuids) == 0 {
			last = fmt.Errorf("the log has no entry whose artifact is %s:%s", rekorSHA256, want)
			continue
		}
		entry, ferr := matchRekorEntry(ctx, client, base, uuids, want, leaf)
		if ferr == nil {
			return entry, nil
		}
		last = ferr
	}
	return RekorEntry{}, fmt.Errorf("%w: no Rekor entry for commit %s: %w",
		ErrTransparencyUnavailable, commitSHA, last)
}

// matchRekorEntry fetches each candidate and returns the one that is this
// commit's: the right artifact hash, under the right certificate.
func matchRekorEntry(ctx context.Context, client *http.Client, base string, uuids []string, wantHash string, leaf *x509.Certificate) (RekorEntry, error) {
	// Seeded rather than nil: findRekorEntry only calls this with candidates,
	// so an empty list is a programming error rather than a log outage, and it
	// should say so instead of returning a nil error with a zero entry.
	last := fmt.Errorf("no candidate entries for %s:%s", rekorSHA256, wantHash)
	for _, uuid := range uuids {
		endpoint, err := joinURL(base, rekorEntriesPath+"/"+url.PathEscape(uuid))
		if err != nil {
			return RekorEntry{}, err
		}
		raw, err := httpGet(ctx, client, endpoint)
		if err != nil {
			last = err
			continue
		}
		var entries map[string]rekorEntry
		if derr := json.Unmarshal(raw, &entries); derr != nil {
			last = fmt.Errorf("entry %s: %w", uuid, derr)
			continue
		}
		entry, ok := entries[uuid]
		if !ok {
			last = fmt.Errorf("the log returned no entry for %s", uuid)
			continue
		}
		body, err := base64.StdEncoding.DecodeString(entry.Body)
		if err != nil {
			last = fmt.Errorf("entry %s: body is not base64: %w", uuid, err)
			continue
		}
		if err := entryMatches(body, wantHash, leaf); err != nil {
			last = fmt.Errorf("entry %s: %w", uuid, err)
			continue
		}
		return RekorEntry{
			UUID:         uuid,
			LogIndex:     entry.LogIndex,
			LogID:        entry.LogID,
			IntegratedAt: time.Unix(entry.IntegratedTime, 0).UTC(),
		}, nil
	}
	return RekorEntry{}, last
}

// entryMatches is the join between the commit and the log.
func entryMatches(body []byte, wantHash string, leaf *x509.Certificate) error {
	var got rekorBody
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Errorf("the entry body is not JSON: %w", err)
	}
	if got.Kind != rekorHashedRekord {
		return fmt.Errorf("the entry is a %q, not a %s", got.Kind, rekorHashedRekord)
	}
	if got.Spec.Data.Hash.Algorithm != rekorSHA256 || got.Spec.Data.Hash.Value != wantHash {
		return fmt.Errorf("the entry's artifact is %s:%s, this commit's is %s:%s",
			got.Spec.Data.Hash.Algorithm, got.Spec.Data.Hash.Value, rekorSHA256, wantHash)
	}
	pemBytes, err := base64.StdEncoding.DecodeString(got.Spec.Signature.PublicKey.Content)
	if err != nil {
		return fmt.Errorf("the entry's public key is not base64: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("the entry's public key is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("the entry's public key is not a certificate: %w", err)
	}
	if !bytes.Equal(cert.Raw, leaf.Raw) {
		return fmt.Errorf("the entry was logged under a different certificate")
	}
	return nil
}

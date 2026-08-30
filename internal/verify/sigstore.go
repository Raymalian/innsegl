// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
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

	"innsegl.dev/innsegl/internal/segment"
)

// The two endpoints a stranger is given, and the reads this verifier makes of
// them. Nothing here is configuration of ours: a Fulcio root fetched over the
// wire and a Rekor log key fetched over the wire are what a third party has,
// and pinning either from a file we ship would make the verification depend on
// trusting us — which is the thing I5 forbids.
//
// (Pinning them is what a serious verifier does NEXT: the key it pins has to
// come from somewhere the first time, and this is that somewhere. ADR-0034
// records the boundary.)

const (
	fulcioRootPath     = "/api/v1/rootCert"
	rekorPublicKeyPath = "/api/v1/log/publicKey"
	rekorEntriesPath   = "/api/v1/log/entries"
	rekorIndexPath     = "/api/v1/index/retrieve"

	// The entry kind gitsign's online mode writes (ADR-0031 decision 6).
	rekorHashedRekord = "hashedrekord"
	rekorSHA256       = "sha256"

	// defaultHTTPTimeout bounds one request. A verifier that hangs is a
	// verifier that has not said "unavailable" yet.
	defaultHTTPTimeout = 30 * time.Second

	// maxBody caps a response. Rekor's entries are small; a log that answers
	// with a gigabyte is a log that is answering wrongly.
	maxBody = 1 << 22
)

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

func (v *Verifier) get(ctx context.Context, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return v.do(req, endpoint)
}

func (v *Verifier) postJSON(ctx context.Context, endpoint string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return v.do(req, endpoint)
}

func (v *Verifier) do(req *http.Request, endpoint string) ([]byte, error) {
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%s %s: HTTP %d: %s",
			req.Method, endpoint, resp.StatusCode, truncate(body))
	}
	return body, nil
}

func truncate(b []byte) string {
	const limit = 256
	if len(b) > limit {
		return string(b[:limit]) + "…"
	}
	return string(b)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// Check 1 — the Fulcio certificate chain.
// ---------------------------------------------------------------------------

// checkChain is IP §1's first check, evaluated at the moment the log says it
// integrated the entry rather than at the wall clock.
//
// It has two halves and they fail differently, which is why they are reported
// as separate evidence. The PATH is time-independent: either the certificate
// chains to the root this Fulcio publishes or it does not, and that answer
// does not change next year. The WINDOW needs a trusted timestamp, and if the
// log did not sign one there is no honest answer — which is `unavailable`, not
// a guess against `now`. Guessing against `now` is precisely what would make
// VER-004 fail, and VER-004 is the case that makes the system work a year
// later.
func (v *Verifier) checkChain(ctx context.Context, leaf *x509.Certificate,
	intermediates []*x509.Certificate, entry EntryInfo) Check {

	c := Check{Name: CheckCertificateChain, Facts: []Fact{
		{"certificate identity", uriSANOf(leaf)},
		{"certificate issuer", fulcioIssuerOf(leaf)},
		{"certificate validity", leaf.NotBefore.UTC().Format(time.RFC3339) + " .. " +
			leaf.NotAfter.UTC().Format(time.RFC3339)},
		{"certificate fingerprint", "sha256:" + fingerprintOf(leaf)},
		// Stated, never assumed. ADR-0029 decision 5 runs Fulcio with no CT
		// log, so these certificates carry no SCT and no verifier can check
		// one. Silence here would read as "checked and fine".
		{"signed certificate timestamp", "none — this deployment operates no certificate " +
			"transparency log (ADR-0029 decision 5); the transparency this system offers " +
			"is the Rekor entry in check 2"},
	}}

	body, err := v.get(ctx, v.fulcioRoot)
	if err != nil {
		return unavailable(c, fmt.Sprintf("the certificate authority could not be reached: %v", err))
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(body) {
		return unavailable(c, fmt.Sprintf("%s did not return a PEM certificate, so there is "+
			"no root to chain to", v.fulcioRoot))
	}
	c.Facts = append(c.Facts, Fact{"trust root", v.fulcioRoot})

	pool := x509.NewCertPool()
	for _, i := range intermediates {
		pool.AddCert(i)
	}
	// Evaluated at the certificate's own NotBefore: this half of the check is
	// about the PATH, and mixing the validity window into it would report a
	// chain problem for an expired certificate.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		CurrentTime:   leaf.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return failed(c, fmt.Sprintf("the certificate does not chain to the root this "+
			"deployment's Fulcio publishes: %v", err))
	}
	if v.cfg.Issuer != "" && fulcioIssuerOf(leaf) != v.cfg.Issuer {
		return failed(c, fmt.Sprintf("the certificate names the OIDC issuer %q; this "+
			"verifier was told to expect %q", fulcioIssuerOf(leaf), v.cfg.Issuer))
	}

	if !entry.TimeAttested {
		return unavailable(c, "the certificate chains to Fulcio's root, but the transparency "+
			"log did not sign an integration time for this commit, so there is no trusted "+
			"moment to evaluate the validity window at. Evaluating it against this machine's "+
			"clock would fail every historical commit (IP §6.8)")
	}
	at := entry.IntegratedAt.UTC()
	c.Facts = append(c.Facts,
		Fact{"validity evaluated at", at.Format(time.RFC3339) +
			" (the log's signed integration time)"},
		Fact{"clock skew allowed", v.cfg.Skew.String()})

	if at.Before(leaf.NotBefore.Add(-v.cfg.Skew)) {
		return failed(c, fmt.Sprintf("the log integrated this entry at %s, before the "+
			"certificate became valid at %s, by more than the %s bound",
			at.Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339), v.cfg.Skew))
	}
	if at.After(leaf.NotAfter.Add(v.cfg.Skew)) {
		return failed(c, fmt.Sprintf("the log integrated this entry at %s, after the "+
			"certificate expired at %s, by more than the %s bound",
			at.Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), v.cfg.Skew))
	}
	return verified(c, "the certificate chains to Fulcio's published root and was inside "+
		"its validity window when the log integrated this commit")
}

// ---------------------------------------------------------------------------
// Check 2 — Rekor inclusion.
// ---------------------------------------------------------------------------

// logEntry is the part of a Rekor log entry this verifier reads.
type logEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
		InclusionProof       *struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
	} `json:"verification"`
}

// hashedRekordBody is the entry's canonical content.
type hashedRekordBody struct {
	Kind string `json:"kind"`
	Spec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// checkInclusion is IP §1's second check.
//
// It is also, and this is the part worth saying out loud, what stands in for
// verifying the CMS signature over the commit object. gitsign's online mode
// logs a hashedrekord whose ARTIFACT IS THE COMMIT SHA, so an entry that
// carries a signature over sha256(this commit's SHA), verifying under the
// certificate this commit is signed with, is a third party's record that the
// holder of that certificate's private key signed THIS object and no other.
// Change one byte of the commit and its SHA changes and there is no entry.
func (v *Verifier) checkInclusion(ctx context.Context, commitSHA string,
	leaf *x509.Certificate) (EntryInfo, Check) {

	info := EntryInfo{LogIndex: -1}
	digest := sha256.Sum256([]byte(commitSHA))
	want := hex.EncodeToString(digest[:])
	c := Check{Name: CheckRekorInclusion, Facts: []Fact{
		{"artifact", rekorSHA256 + ":" + want + " (sha256 of the commit SHA)"},
	}}

	uuids, err := v.searchLog(ctx, want)
	if err != nil {
		return info, unavailable(c, fmt.Sprintf("the transparency log could not be searched: %v", err))
	}
	if len(uuids) == 0 {
		return info, failed(c, fmt.Sprintf("the log answered, and it holds no entry whose "+
			"artifact is %s:%s. Nothing ever logged a signature over this commit object.",
			rekorSHA256, want))
	}

	uuid, entry, body, reach, mismatch := v.matchEntry(ctx, uuids, want, digest[:], leaf)
	if entry == nil && reach != nil {
		return info, unavailable(c, fmt.Sprintf("the log's entry could not be read: %v", reach))
	}
	if entry == nil {
		return info, failed(c, fmt.Sprintf("the log holds %d entry(s) for this artifact and "+
			"none of them is this commit's: %v", len(uuids), mismatch))
	}

	info.UUID = uuid
	info.LogIndex = entry.LogIndex
	info.LogID = entry.LogID
	info.IntegratedAt = time.Unix(entry.IntegratedTime, 0).UTC()
	c.Facts = append(c.Facts,
		Fact{"log index", fmt.Sprintf("%d", entry.LogIndex)},
		Fact{"entry uuid", uuid})

	logKey, err := v.logPublicKey(ctx)
	if err != nil {
		return info, unavailable(c, fmt.Sprintf("the log's public key could not be fetched, "+
			"so its proof cannot be checked against anything: %v", err))
	}
	proof := entry.Verification.InclusionProof
	if proof == nil {
		return info, unavailable(c, "the entry carries no inclusion proof: it has been "+
			"accepted and not yet integrated into the tree")
	}
	if err := (segment.InclusionProof{
		EntryUUID:  uuid,
		Body:       body,
		LogIndex:   proof.LogIndex,
		TreeSize:   proof.TreeSize,
		RootHash:   proof.RootHash,
		Hashes:     proof.Hashes,
		Checkpoint: proof.Checkpoint,
	}).Verify(logKey); err != nil {
		return info, failed(c, fmt.Sprintf("the log's inclusion proof does not verify: %v", err))
	}
	c.Facts = append(c.Facts,
		Fact{"tree size", fmt.Sprintf("%d", proof.TreeSize)},
		Fact{"tree root", proof.RootHash})

	if entry.Verification.SignedEntryTimestamp == "" {
		c.Facts = append(c.Facts, Fact{"integration time",
			"UNATTESTED — the log returned no signed entry timestamp"})
		info.TimeAttested = false
		return info, verified(c, "the entry is this commit's and its inclusion proof "+
			"verifies under the log's key, but the log signed no integration time")
	}
	if err := verifyEntryTimestamp(*entry, logKey); err != nil {
		return info, failed(c, fmt.Sprintf("the log's signature over this entry's timestamp "+
			"does not verify: %v", err))
	}
	info.TimeAttested = true
	c.Facts = append(c.Facts, Fact{"integration time",
		info.IntegratedAt.Format(time.RFC3339) + " (signed by the log)"})
	return info, verified(c, "the entry is this commit's, logged under this commit's "+
		"certificate, and its inclusion proof verifies under the log's key")
}

func (v *Verifier) searchLog(ctx context.Context, artifactHash string) ([]string, error) {
	// Written rather than marshalled: the value is hex from a SHA-256 digest,
	// so there is nothing in it to escape and no marshal error to handle.
	raw, err := v.postJSON(ctx, v.rekorIndex,
		[]byte(`{"hash":"`+rekorSHA256+":"+artifactHash+`"}`))
	if err != nil {
		return nil, err
	}
	var uuids []string
	if err := json.Unmarshal(raw, &uuids); err != nil {
		return nil, fmt.Errorf("the search index returned %s: %w", truncate(raw), err)
	}
	return uuids, nil
}

// matchEntry fetches each candidate and returns the one that is this commit's.
//
// Two error returns, because they are different answers: `reach` is the log
// not answering (unavailable) and `mismatch` is the log answering with
// something that is not this commit's (failed).
func (v *Verifier) matchEntry(ctx context.Context, uuids []string, wantHash string,
	digest []byte, leaf *x509.Certificate) (uuid string, out *logEntry, body []byte,
	reach error, mismatch error) {

	for _, id := range uuids {
		raw, err := v.get(ctx, v.rekorEntries+"/"+url.PathEscape(id))
		if err != nil {
			reach = err
			continue
		}
		var entries map[string]logEntry
		if uerr := json.Unmarshal(raw, &entries); uerr != nil {
			mismatch = fmt.Errorf("entry %s is not a log entry map: %w", id, uerr)
			continue
		}
		entry, ok := entries[id]
		if !ok {
			mismatch = fmt.Errorf("the log returned no entry for %s", id)
			continue
		}
		decoded, cerr := entryIsForCommit(entry, wantHash, digest, leaf)
		if cerr != nil {
			mismatch = fmt.Errorf("entry %s: %w", id, cerr)
			continue
		}
		return id, &entry, decoded, nil, nil
	}
	return "", nil, nil, reach, mismatch
}

// entryIsForCommit is the join between the commit and the log, and it is the
// whole anti-vacuity argument for check 2.
func entryIsForCommit(entry logEntry, wantHash string, digest []byte,
	leaf *x509.Certificate) ([]byte, error) {

	raw, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return nil, fmt.Errorf("the entry body is not base64: %w", err)
	}
	var got hashedRekordBody
	if uerr := json.Unmarshal(raw, &got); uerr != nil {
		return nil, fmt.Errorf("the entry body is not JSON: %w", uerr)
	}
	if got.Kind != rekorHashedRekord {
		return nil, fmt.Errorf("the entry is a %q, not a %s", got.Kind, rekorHashedRekord)
	}
	if got.Spec.Data.Hash.Algorithm != rekorSHA256 || got.Spec.Data.Hash.Value != wantHash {
		return nil, fmt.Errorf("the entry's artifact is %s:%s, this commit's is %s:%s",
			got.Spec.Data.Hash.Algorithm, got.Spec.Data.Hash.Value, rekorSHA256, wantHash)
	}
	certPEM, err := base64.StdEncoding.DecodeString(got.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, fmt.Errorf("the entry's public key is not base64: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("the entry's public key is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the entry's public key is not a certificate: %w", err)
	}
	if !bytes.Equal(cert.Raw, leaf.Raw) {
		return nil, fmt.Errorf("the entry was logged under a different certificate (%s), "+
			"the commit is signed under %s", fingerprintOf(cert), fingerprintOf(leaf))
	}
	signature, err := base64.StdEncoding.DecodeString(got.Spec.Signature.Content)
	if err != nil {
		return nil, fmt.Errorf("the entry's signature is not base64: %w", err)
	}
	// The log verified this on insertion. Verifying it again is the difference
	// between "Rekor says so" and knowing: I5 does not let this verifier take
	// the log's word for the one fact the whole attribution rests on.
	if err := verifyDigestSignature(cert.PublicKey, digest, signature); err != nil {
		return nil, fmt.Errorf("the entry's signature over this commit's SHA does not verify "+
			"under the certificate the commit is signed with: %w", err)
	}
	return raw, nil
}

// verifyDigestSignature checks a signature made directly over a SHA-256
// digest, which is how a hashedrekord's signature is formed.
func verifyDigestSignature(pub any, digest, signature []byte) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, signature) {
			return fmt.Errorf("the ECDSA signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature)
	default:
		return fmt.Errorf("the certificate carries a %T public key, which this verifier "+
			"does not check; Fulcio issues ECDSA and RSA", pub)
	}
}

// verifyEntryTimestamp checks the log's signature over (body, integratedTime,
// logID, logIndex) — Rekor's signed entry timestamp.
//
// WHY THIS MATTERS MORE THAN IT LOOKS. Check 1 evaluates the certificate's
// validity window at the integration time, and a ten-minute certificate is
// worth nothing if that timestamp is a number an attacker can choose. The SET
// is what makes it the log's statement. The canonicalization is RFC 8785's:
// the four members sorted, no whitespace — which for four members of these
// types is a string this function can write directly rather than pulling in a
// canonicalizer for one object shape.
func verifyEntryTimestamp(entry logEntry, logKey *ecdsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(entry.Verification.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("the signed entry timestamp is not base64: %w", err)
	}
	canonical := fmt.Sprintf(`{"body":"%s","integratedTime":%d,"logID":"%s","logIndex":%d}`,
		entry.Body, entry.IntegratedTime, entry.LogID, entry.LogIndex)
	digest := sha256.Sum256([]byte(canonical))
	if !ecdsa.VerifyASN1(logKey, digest[:], sig) {
		return fmt.Errorf("no signature over %s verifies under the log's key",
			truncate([]byte(canonical)))
	}
	return nil
}

// logPublicKey fetches the key the log signs its checkpoints and entry
// timestamps with, and parses it with internal/segment's reader — the same one
// ADR-0009's anchoring chain terminates on.
func (v *Verifier) logPublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	body, err := v.get(ctx, v.rekorKey)
	if err != nil {
		return nil, err
	}
	return segment.ParseLogPublicKey(body)
}

// Small constructors, so a check's three outcomes are spelled the same way
// everywhere and none of them can be built by accident.
func verified(c Check, detail string) Check    { c.Result, c.Detail = Verified, detail; return c }
func failed(c Check, detail string) Check      { c.Result, c.Detail = Failed, detail; return c }
func unavailable(c Check, detail string) Check { c.Result, c.Detail = Unavailable, detail; return c }

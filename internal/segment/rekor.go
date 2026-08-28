// SPDX-License-Identifier: Apache-2.0

package segment

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// The Rekor v1 REST client.
//
// Hand-written against the API rather than pulling in Rekor's generated
// go-swagger client, for two reasons that both matter here. The client drags
// in a large dependency tree for four requests, which is a poor trade for a
// module whose entire dependency set is currently five entries. And the point
// of an anchor is that a third party can check it with nothing of ours — a
// verifier that can only be built by importing our vendor tree is a verifier
// nobody else will build. What this file speaks is the documented wire format;
// see ADR-0007.
//
// # What is anchored
//
// One `hashedrekord` entry per sealed segment, whose `data.hash.value` is the
// segment's Merkle root and whose signature is over that root by the ledger's
// anchoring key. Rekor verifies the signature before it will accept the entry,
// so an anchor is a statement by a named key that this root was sealed — not an
// anonymous 32 bytes anyone could have posted.

const (
	// The entry kind and version. Protected in the same sense as a wire
	// format: every anchor ever written names them, and changing either
	// changes what a historical anchor has to be read as.
	rekorHashedRekordKind       = "hashedrekord"
	rekorHashedRekordAPIVersion = "0.0.1"

	// hashAlgorithmSHA256 is the one hash in this system (doc 02 §4.3),
	// spelled the way Rekor spells it.
	hashAlgorithmSHA256 = "sha256"

	// defaultRekorTimeout bounds one request. Anchoring is a background
	// activity whose failure is survivable, so it waits briefly and reports
	// rather than holding a sealer thread open.
	defaultRekorTimeout = 30 * time.Second

	entriesPath   = "/api/v1/log/entries"
	publicKeyPath = "/api/v1/log/publicKey"

	// Rekor serves the entry API as JSON and the log's key as a PEM file, and
	// answers the wrong Accept with the wrong thing rather than an error.
	acceptJSON = "application/json"
	acceptPEM  = "application/x-pem-file"
)

// ErrAnchorRejected reports an entry the log refused on its merits — a
// malformed body, a signature that does not verify. Unlike an unreachable log
// this does not get better by waiting, so the retry loop stops on it rather
// than spending its budget re-sending something already judged.
var ErrAnchorRejected = errors.New("transparency log rejected the entry")

// ErrAnchorSigner reports a missing or unusable anchoring key.
var ErrAnchorSigner = errors.New("anchoring signer unusable")

// AnchorSigner signs the segment root that goes into the log entry.
//
// An interface rather than a concrete key because the production signer is a
// KMS or HSM handle (doc 04 §7) and this package must not care which.
type AnchorSigner interface {
	// SignDigest returns an ASN.1 ECDSA signature over a 32-byte digest.
	SignDigest(digest []byte) ([]byte, error)
	// PublicKeyPEM returns the PEM-encoded SubjectPublicKeyInfo of the
	// verifying key, which travels in the entry so the log — and any later
	// reader — can check the signature.
	PublicKeyPEM() ([]byte, error)
}

// ECDSAAnchorSigner is an in-process ECDSA P-256 AnchorSigner.
type ECDSAAnchorSigner struct{ key *ecdsa.PrivateKey }

var _ AnchorSigner = (*ECDSAAnchorSigner)(nil)

// NewECDSAAnchorSigner wraps a P-256 key.
//
// P-256 only, and deliberately: the digest being signed is always a SHA-256
// segment root, and Rekor pairs each curve with a matching hash. A P-384 key
// would be verified against a SHA-384 digest that this system never produces,
// so the entry would be refused — better to refuse the key here, where the
// error says why.
func NewECDSAAnchorSigner(key *ecdsa.PrivateKey) (*ECDSAAnchorSigner, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: no key", ErrAnchorSigner)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf(
			"%w: the anchoring key is on %s; segment roots are SHA-256 and Rekor pairs that with P-256",
			ErrAnchorSigner, key.Curve.Params().Name)
	}
	return &ECDSAAnchorSigner{key: key}, nil
}

// GenerateAnchorSigner makes a fresh P-256 anchoring key.
func GenerateAnchorSigner() (*ECDSAAnchorSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnchorSigner, err)
	}
	return NewECDSAAnchorSigner(key)
}

// SignDigest signs a 32-byte digest.
func (s *ECDSAAnchorSigner) SignDigest(digest []byte) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, fmt.Errorf("%w: no key", ErrAnchorSigner)
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("%w: signing a %d-byte digest, want the 32 bytes of a SHA-256 root",
			ErrAnchorSigner, len(digest))
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnchorSigner, err)
	}
	return sig, nil
}

// PublicKeyPEM returns the PEM SubjectPublicKeyInfo.
func (s *ECDSAAnchorSigner) PublicKeyPEM() ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, fmt.Errorf("%w: no key", ErrAnchorSigner)
	}
	der, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAnchorSigner, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// RekorClient talks to a Rekor v1 REST API.
type RekorClient struct {
	// BaseURL is the log's root, e.g. https://rekor.sigstore.dev.
	BaseURL string
	// HTTP is the client to use; nil means one with defaultRekorTimeout.
	HTTP *http.Client
	// Signer signs the root. Only anchoring needs it: reading a proof back is
	// something a stranger does, and a stranger has no key of ours (I5).
	Signer AnchorSigner
}

var _ TransparencyLog = (*RekorClient)(nil)

func (c *RekorClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultRekorTimeout}
}

func (c *RekorClient) endpoint(path string) (string, error) {
	if c.BaseURL == "" {
		return "", fmt.Errorf("%w: no rekor base url configured", ErrAnchorUnavailable)
	}
	return strings.TrimRight(c.BaseURL, "/") + path, nil
}

// do runs one request and returns the status and body.
//
// A transport error and a 5xx are both ErrAnchorUnavailable: from the caller's
// side "the log did not answer" and "the log answered that it is broken" are
// the same condition and take the same retry. A 4xx is not.
func (c *RekorClient) do(ctx context.Context, method, path, accept string, body []byte) (int, []byte, error) {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return 0, nil, err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", ErrAnchorUnavailable, err)
	}
	req.Header.Set("Accept", accept)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		// A cancelled or expired context is the caller's decision, not the
		// log's condition, and must not be laundered into "unavailable" —
		// the retry loop stops on one and continues on the other.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, fmt.Errorf("rekor %s %s: %w", method, path, ctxErr)
		}
		return 0, nil, fmt.Errorf("%w: %s %s: %w", ErrAnchorUnavailable, method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded: a log that streams gigabytes at an anchoring worker is a denial
	// of service, and no legitimate response here is large.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf(
			"%w: reading the response to %s %s: %w", ErrAnchorUnavailable, method, path, err)
	}
	return resp.StatusCode, raw, nil
}

// statusError turns a non-success status into the right kind of error.
func statusError(method, path string, status int, body []byte) error {
	detail := strings.TrimSpace(string(body))
	if len(detail) > 512 {
		detail = detail[:512] + " […truncated]"
	}
	if status >= 400 && status < 500 {
		return fmt.Errorf("%w: %s %s: %d: %s", ErrAnchorRejected, method, path, status, detail)
	}
	return fmt.Errorf("%w: %s %s: %d: %s", ErrAnchorUnavailable, method, path, status, detail)
}

// rekorEntry is the part of Rekor's log entry this package reads.
type rekorEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof *struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
	} `json:"verification"`
}

// decodeEntries reads Rekor's uuid-keyed response and returns the single entry
// it should contain.
func decodeEntries(raw []byte) (string, rekorEntry, error) {
	var entries map[string]rekorEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return "", rekorEntry{}, fmt.Errorf("%w: response is not a log entry map: %w",
			ErrAnchorUnavailable, err)
	}
	if len(entries) != 1 {
		return "", rekorEntry{}, fmt.Errorf("%w: response holds %d entries, want exactly 1",
			ErrAnchorUnavailable, len(entries))
	}
	for uuid, entry := range entries {
		return uuid, entry, nil
	}
	return "", rekorEntry{}, fmt.Errorf("%w: empty log entry map", ErrAnchorUnavailable)
}

// hashedRekord is the entry body, in the shape Rekor's schema requires.
type hashedRekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
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

func newHashedRekord(rootHex string, signature, publicKeyPEM []byte) hashedRekord {
	var e hashedRekord
	e.APIVersion = rekorHashedRekordAPIVersion
	e.Kind = rekorHashedRekordKind
	e.Spec.Data.Hash.Algorithm = hashAlgorithmSHA256
	e.Spec.Data.Hash.Value = rootHex
	e.Spec.Signature.Content = base64.StdEncoding.EncodeToString(signature)
	e.Spec.Signature.PublicKey.Content = base64.StdEncoding.EncodeToString(publicKeyPEM)
	return e
}

// AnchorRoot submits a sealed segment's Merkle root to the log.
//
// # At-least-once, deliberately
//
// Sealing is idempotent because a segment object is addressed by its content
// (ADR-0006); anchoring is not, and cannot be made so cheaply. ECDSA nonces are
// random, so two submissions of one root are two different entry bodies and
// Rekor stores both. A submission that succeeds at the log but times out at the
// client therefore leaves an entry the caller never learned the id of, and the
// retry adds a second.
//
// That is a cost, not a fault. The two entries attest the same root under the
// same key within seconds of each other; either one proves what the anchor is
// for. The ledger records exactly one — the id the successful attempt returned —
// and a second entry nothing references is a few hundred bytes in a log that is
// append-only by design. Deduplicating would mean either a stateful client
// remembering unacknowledged submissions across restarts, or a search of the
// log before every anchor, and both buy less than they cost. ADR-0007 records
// this.
func (c *RekorClient) AnchorRoot(ctx context.Context, merkleRoot string) (Anchor, error) {
	if err := event.ValidateDigest(merkleRoot); err != nil {
		return Anchor{}, fmt.Errorf("%w: %s: %w", ErrAnchorMismatch, event.FieldSegmentMerkleRoot, err)
	}
	rootHex := strings.TrimPrefix(merkleRoot, event.HashPrefix)
	rootBytes, err := hex.DecodeString(rootHex)
	if err != nil {
		return Anchor{}, fmt.Errorf("%w: %s: %w", ErrAnchorMismatch, event.FieldSegmentMerkleRoot, err)
	}
	if c.Signer == nil {
		return Anchor{}, fmt.Errorf("%w: anchoring needs a signing key", ErrAnchorSigner)
	}

	signature, err := c.Signer.SignDigest(rootBytes)
	if err != nil {
		return Anchor{}, err
	}
	publicKey, err := c.Signer.PublicKeyPEM()
	if err != nil {
		return Anchor{}, err
	}

	proposed, err := json.Marshal(newHashedRekord(rootHex, signature, publicKey))
	if err != nil {
		return Anchor{}, fmt.Errorf("%w: encoding the entry: %w", ErrAnchorRejected, err)
	}

	status, raw, err := c.do(ctx, http.MethodPost, entriesPath, acceptJSON, proposed)
	if err != nil {
		return Anchor{}, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return Anchor{}, statusError(http.MethodPost, entriesPath, status, raw)
	}
	uuid, entry, err := decodeEntries(raw)
	if err != nil {
		return Anchor{}, err
	}
	return anchorFrom(merkleRoot, uuid, entry), nil
}

func isHexUUID(s string) bool {
	if len(s) != 64 && len(s) != 80 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func anchorFrom(merkleRoot, uuid string, entry rekorEntry) Anchor {
	anchor := Anchor{
		MerkleRoot: merkleRoot,
		LogIndex:   entry.LogIndex,
		EntryUUID:  uuid,
	}
	if entry.IntegratedTime > 0 {
		anchor.IntegratedAt = time.Unix(entry.IntegratedTime, 0).UTC()
	}
	return anchor
}

// entry fetches one log entry by uuid.
func (c *RekorClient) entry(ctx context.Context, entryUUID string) (rekorEntry, error) {
	if !isHexUUID(entryUUID) {
		return rekorEntry{}, fmt.Errorf(
			"%w: %q is not a rekor entry uuid (64 or 80 hex characters)",
			ErrAnchorRejected, entryUUID)
	}
	path := entriesPath + "/" + entryUUID
	status, raw, err := c.do(ctx, http.MethodGet, path, acceptJSON, nil)
	if err != nil {
		return rekorEntry{}, err
	}
	if status != http.StatusOK {
		return rekorEntry{}, statusError(http.MethodGet, path, status, raw)
	}
	uuid, entry, err := decodeEntries(raw)
	if err != nil {
		return rekorEntry{}, err
	}
	if uuid != entryUUID {
		return rekorEntry{}, fmt.Errorf("%w: asked for entry %s, the log returned %s",
			ErrAnchorUnavailable, entryUUID, uuid)
	}
	return entry, nil
}

// InclusionProof fetches the log's proof that an entry is in it.
func (c *RekorClient) InclusionProof(ctx context.Context, entryUUID string) (InclusionProof, error) {
	entry, err := c.entry(ctx, entryUUID)
	if err != nil {
		return InclusionProof{}, err
	}
	proof := entry.Verification.InclusionProof
	if proof == nil {
		return InclusionProof{}, fmt.Errorf(
			"%w: entry %s carries no inclusion proof; it is accepted but not yet integrated",
			ErrAnchorUnavailable, entryUUID)
	}
	body, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return InclusionProof{}, fmt.Errorf("%w: entry %s body is not base64: %w",
			ErrInclusionProof, entryUUID, err)
	}
	return InclusionProof{
		EntryUUID:  entryUUID,
		Body:       body,
		LogIndex:   proof.LogIndex,
		TreeSize:   proof.TreeSize,
		RootHash:   proof.RootHash,
		Hashes:     append([]string(nil), proof.Hashes...),
		Checkpoint: proof.Checkpoint,
	}, nil
}

// PublicKey fetches the key the log signs its checkpoints with.
//
// Fetching a trust root over the wire is only sound for a log you are about to
// pin: in production this key is configuration (doc 05 §1 names the log
// endpoint as rendered state), and the fetch exists so a test against a
// freshly-generated in-memory log has something to pin.
func (c *RekorClient) PublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	status, raw, err := c.do(ctx, http.MethodGet, publicKeyPath, acceptPEM, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(http.MethodGet, publicKeyPath, status, raw)
	}
	return ParseLogPublicKey(raw)
}

// ParseLogPublicKey reads a PEM-encoded ECDSA log key.
func ParseLogPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%w: the log's key is not PEM", ErrInclusionProof)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the log's key does not parse: %w", ErrInclusionProof, err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: the log's key is %T, want an ECDSA key", ErrInclusionProof, parsed)
	}
	return key, nil
}

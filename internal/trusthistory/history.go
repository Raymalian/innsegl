// SPDX-License-Identifier: Apache-2.0

// Package trusthistory is the record of every trust root a deployment has
// used (ADR-0073).
//
// # Why it exists
//
// A verifier that knows only the CURRENT Fulcio root and the CURRENT log key
// fails every commit signed before a rotation. On 2026-09-16 the trust
// volumes were recreated, the CA and the log were replaced, and every commit
// signed under the old ones stopped verifying. Nothing recorded which roots
// the deployment had used, so nothing could say "that root was ours".
//
// This file is that record: one append-only list of every Fulcio root and
// every transparency-log key, plus the other CAs in use (the SPIRE upstream
// CA and the gateway CA) so their expiry can be watched from the same place.
//
// # Public material only
//
// An entry holds a certificate or a public key, a key id and dates. Parse
// refuses anything else, so a private key cannot end up here by mistake.
//
// # Append-only
//
// Save is the only writer. It refuses a history that drops, reorders or
// alters an entry the file already holds. The one change it allows to an
// existing entry is setting `retired_at` or `revoked_at`, and
// `retired_reason`, where it was unset (ADR-0075). End is how a rotation
// sets them.
//
// # What the verifier does with it
//
// internal/verify accepts a certificate that chains to ANY Fulcio root in the
// history, and an inclusion proof under ANY log key in it, subject to the
// entry's end dates. Nothing else about verification changes.
package trusthistory

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// FormatVersion is the file format this package reads and writes.
const FormatVersion = 1

// FileName is the history's name on the trust volume.
const FileName = "trust-history.json"

// Kind is what an entry is.
type Kind string

const (
	// KindFulcioRoot is a certificate authority commit certificates chain to.
	KindFulcioRoot Kind = "fulcio_root"
	// KindTransparencyLog is a key a transparency log signed checkpoints and
	// entry timestamps with.
	KindTransparencyLog Kind = "transparency_log"
	// KindSPIREUpstreamCA is the root SPIRE's identities chain to. Recorded
	// for its expiry; the verifier never reads it.
	KindSPIREUpstreamCA Kind = "spire_upstream_ca"
	// KindGatewayCA is the gateway's TLS certificate authority. Recorded for
	// its expiry; the verifier never reads it.
	KindGatewayCA Kind = "gateway_ca"
	// KindLostRoot is a Fulcio root this deployment used and no longer has:
	// known by the key id its certificates name as their Authority Key
	// Identifier, with no public material, because that is what was lost. It
	// is never trusted; it only names the era a pre-history commit came from.
	KindLostRoot Kind = "lost_root"
)

// isCertificate reports whether a kind's material is a certificate. The only
// other kind is a log key, which is a bare public key.
func (k Kind) isCertificate() bool { return k != KindTransparencyLog }

func (k Kind) valid() bool {
	switch k {
	case KindFulcioRoot, KindTransparencyLog, KindSPIREUpstreamCA, KindGatewayCA, KindLostRoot:
		return true
	}
	return false
}

// Errors a caller can act on.
var (
	// ErrInvalid is a history, or an entry, this package will not trust.
	ErrInvalid = errors.New("trusthistory: invalid")
	// ErrRewrite is a Save that would change what the file already records.
	ErrRewrite = errors.New("trusthistory: the history is append-only")
)

// Entry is one root or key the deployment has used.
type Entry struct {
	Kind Kind `json:"kind"`
	// KeyID is hex sha256 of the DER SubjectPublicKeyInfo.
	KeyID     string    `json:"key_id"`
	PublicPEM string    `json:"public_pem"`
	FirstUsed time.Time `json:"first_used"`
	// RetiredAt is when the root stopped issuing. It stays trusted for what
	// was logged before that.
	RetiredAt     *time.Time `json:"retired_at,omitempty"`
	RetiredReason string     `json:"retired_reason,omitempty"`
	// RevokedAt is a compromise: only entries the log integrated BEFORE it
	// are accepted.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// TreeID is the transparency log's tree, where known.
	TreeID string `json:"tree_id,omitempty"`
	// LostAt and Reason are a lost root's: when it stopped being available,
	// and why. Set on lost_root entries and on no other kind.
	LostAt *time.Time `json:"lost_at,omitempty"`
	Reason string     `json:"reason,omitempty"`
}

// History is the whole file.
type History struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// New is an empty history.
func New() *History { return &History{Version: FormatVersion, Entries: []Entry{}} }

// KeyIDOf is the key id of PEM material: hex sha256 of its
// SubjectPublicKeyInfo. A certificate and a bare public key for the same key
// have the same id.
func KeyIDOf(pemBytes []byte) (string, error) {
	_, spki, err := decode(pemBytes)
	if err != nil {
		return "", err
	}
	return idOfSPKI(spki), nil
}

func idOfSPKI(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// decode reads one PEM block: a certificate or a public key, and nothing else.
func decode(pemBytes []byte) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("%w: not PEM", ErrInvalid)
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: a certificate that does not parse: %w", ErrInvalid, err)
		}
		return cert, cert.RawSubjectPublicKeyInfo, nil
	case "PUBLIC KEY":
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			return nil, nil, fmt.Errorf("%w: a public key that does not parse: %w", ErrInvalid, err)
		}
		return nil, block.Bytes, nil
	default:
		return nil, nil, fmt.Errorf("%w: a %q block; the history holds certificates and "+
			"public keys only", ErrInvalid, block.Type)
	}
}

// Certificate parses a certificate entry's material.
func (e Entry) Certificate() (*x509.Certificate, error) {
	cert, _, err := decode([]byte(e.PublicPEM))
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("%w: entry %s is a public key, not a certificate", ErrInvalid, e.KeyID)
	}
	return cert, nil
}

// AcceptsAt says whether this entry vouches for something the log integrated
// at t. A retirement allows the skew bound; a revocation does not, because it
// is a compromise and the bound would be a window for whoever holds the key.
func (e Entry) AcceptsAt(t time.Time, skew time.Duration) error {
	if e.RevokedAt != nil && !t.Before(*e.RevokedAt) {
		return fmt.Errorf("it was revoked at %s and the log integrated this entry at %s",
			e.RevokedAt.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	if e.RetiredAt != nil && t.After(e.RetiredAt.Add(skew)) {
		return fmt.Errorf("it was retired at %s and the log integrated this entry at %s, "+
			"after it stopped issuing", e.RetiredAt.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
	}
	return nil
}

// validate checks one entry on its own.
func (e Entry) validate() error {
	if !e.Kind.valid() {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalid, e.Kind)
	}
	if e.Kind == KindLostRoot {
		return e.validateLost()
	}
	if e.LostAt != nil || e.Reason != "" {
		return fmt.Errorf("%w: entry %s is a %s and carries a lost root's fields", ErrInvalid, e.KeyID, e.Kind)
	}
	cert, spki, err := decode([]byte(e.PublicPEM))
	if err != nil {
		return fmt.Errorf("entry %s: %w", e.KeyID, err)
	}
	if e.Kind.isCertificate() != (cert != nil) {
		return fmt.Errorf("%w: entry %s is a %s and its material is the wrong shape for it",
			ErrInvalid, e.KeyID, e.Kind)
	}
	if id := idOfSPKI(spki); id != e.KeyID {
		return fmt.Errorf("%w: entry says key id %s, its material is %s", ErrInvalid, e.KeyID, id)
	}
	if e.FirstUsed.IsZero() {
		return fmt.Errorf("%w: entry %s has no first_used", ErrInvalid, e.KeyID)
	}
	for name, at := range map[string]*time.Time{"retired_at": e.RetiredAt, "revoked_at": e.RevokedAt} {
		if at != nil && at.Before(e.FirstUsed) {
			return fmt.Errorf("%w: entry %s has %s before its first_used", ErrInvalid, e.KeyID, name)
		}
	}
	return nil
}

// validate checks the whole history.
func (h *History) validate() error {
	if h.Version != FormatVersion {
		return fmt.Errorf("%w: format version %d, this reader knows %d", ErrInvalid, h.Version, FormatVersion)
	}
	seen := map[string]bool{}
	for _, e := range h.Entries {
		if err := e.validate(); err != nil {
			return err
		}
		k := string(e.Kind) + "/" + e.KeyID
		if seen[k] {
			return fmt.Errorf("%w: %s %s is listed twice", ErrInvalid, e.Kind, e.KeyID)
		}
		seen[k] = true
	}
	return nil
}

// Parse reads a history, strictly: an unknown member, a wrong key id or a
// private key is refused rather than ignored.
func Parse(raw []byte) (*History, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var h History
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after the history", ErrInvalid)
	}
	if h.Entries == nil {
		h.Entries = []Entry{}
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

// Load reads the history at path. An absent file is an error wrapping
// os.ErrNotExist, which a caller treats as "no history yet".
func Load(path string) (*History, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

// Save writes h to path, atomically, refusing any change to what the file
// already records (see the package comment).
func Save(path string, h *History) error {
	if err := h.validate(); err != nil {
		return err
	}
	if existing, err := Load(path); err == nil {
		if rerr := appendOnly(existing, h); rerr != nil {
			return rerr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The types above marshal without error; validate has already proved
	// every value in them.
	out, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	// Written beside the file and renamed over it, so a reader sees the old
	// history or the new one and never half of either. One writer (the core)
	// means one temporary name is enough.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil { //nolint:gosec // G306: public material, read by the services that verify with it
		return err
	}
	return os.Rename(tmp, path)
}

// appendOnly is the rule Save enforces: every entry the old history holds is
// still there, at the same position, unchanged except for an end date being
// set where there was none.
func appendOnly(old, next *History) error {
	if len(next.Entries) < len(old.Entries) {
		return fmt.Errorf("%w: the file holds %d entries and this history %d",
			ErrRewrite, len(old.Entries), len(next.Entries))
	}
	for i, o := range old.Entries {
		n := next.Entries[i]
		if o.Kind != n.Kind || o.KeyID != n.KeyID || o.PublicPEM != n.PublicPEM ||
			!o.FirstUsed.Equal(n.FirstUsed) || o.TreeID != n.TreeID ||
			!sameTime(o.LostAt, n.LostAt) || o.Reason != n.Reason {
			return fmt.Errorf("%w: entry %d (%s %s) would change", ErrRewrite, i, o.Kind, o.KeyID)
		}
		if !endKept(o.RetiredAt, n.RetiredAt) || !endKept(o.RevokedAt, n.RevokedAt) ||
			(o.RetiredReason != "" && o.RetiredReason != n.RetiredReason) {
			return fmt.Errorf("%w: entry %d (%s %s) would lose or move an end date",
				ErrRewrite, i, o.Kind, o.KeyID)
		}
	}
	return nil
}

// sameTime: both unset, or both set to the same moment.
func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// endKept: an end date may be set where there was none, and never moved or
// removed.
func endKept(old, next *time.Time) bool {
	if old == nil {
		return true
	}
	return next != nil && old.Equal(*next)
}

// Record appends material the deployment is using, if the history does not
// already hold it, and reports whether it did.
//
// first_used is chosen so an existing deployment's history begins when its
// trust did, not on the day this code first ran:
//   - a certificate's is its own NotBefore;
//   - a log key recorded into a history with no log key yet, after a Fulcio
//     root, began with that root (the two are minted together);
//   - any other log key's is now.
func (h *History) Record(kind Kind, pemBytes []byte, now time.Time) (bool, error) {
	if !kind.valid() {
		return false, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
	}
	cert, spki, err := decode(pemBytes)
	if err != nil {
		return false, err
	}
	id := idOfSPKI(spki)
	if _, ok := h.Lookup(kind, id); ok {
		return false, nil
	}
	first := now.UTC()
	switch {
	case cert != nil:
		first = cert.NotBefore.UTC()
	case len(h.OfKind(KindTransparencyLog)) == 0 && len(h.OfKind(KindFulcioRoot)) > 0:
		first = h.Began()
	}
	e := Entry{Kind: kind, KeyID: id, PublicPEM: string(pem.EncodeToMemory(firstBlock(pemBytes))), FirstUsed: first}
	if err := e.validate(); err != nil {
		return false, err
	}
	h.Entries = append(h.Entries, e)
	return true, nil
}

// firstBlock is the one PEM block Record keeps, so stray text around it is
// never written into the history. decode has already proved there is one.
func firstBlock(pemBytes []byte) *pem.Block {
	block, _ := pem.Decode(pemBytes)
	return block
}

// OfKind lists the entries of one kind, in the order they were recorded.
func (h *History) OfKind(kind Kind) []Entry {
	if h == nil {
		return nil
	}
	var out []Entry
	for _, e := range h.Entries {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// Lookup finds one entry by kind and key id.
func (h *History) Lookup(kind Kind, keyID string) (Entry, bool) {
	for _, e := range h.OfKind(kind) {
		if e.KeyID == keyID {
			return e, true
		}
	}
	return Entry{}, false
}

// Current is the entry of a kind the deployment uses now: the one first used
// most recently that is not revoked.
func (h *History) Current(kind Kind) (Entry, bool) {
	var best Entry
	found := false
	for _, e := range h.OfKind(kind) {
		if e.RevokedAt != nil {
			continue
		}
		if !found || e.FirstUsed.After(best.FirstUsed) {
			best, found = e, true
		}
	}
	return best, found
}

// Began is when the verifiable history begins: the earliest first_used of any
// Fulcio root or log key. Zero for a history with neither. A commit signed
// before it was signed before this deployment kept a record.
func (h *History) Began() time.Time {
	var began time.Time
	for _, kind := range []Kind{KindFulcioRoot, KindTransparencyLog} {
		for _, e := range h.OfKind(kind) {
			if began.IsZero() || e.FirstUsed.Before(began) {
				began = e.FirstUsed
			}
		}
	}
	return began
}

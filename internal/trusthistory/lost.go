// SPDX-License-Identifier: Apache-2.0

package trusthistory

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

// LostRootsFileName is the operator's seed of roots this deployment used and
// lost before it kept a history. It belongs to one deployment, never to the
// product: a fresh deployment has none. The trust pass imports it into the
// history; importing it again changes nothing.
const LostRootsFileName = "trust-lost-roots.json"

// keyIDHex is an Authority Key Identifier: 20 bytes (SHA-1, RFC 5280's usual
// method) or 32 (SHA-256), in hex.
var keyIDHex = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

func (e Entry) validateLost() error {
	switch {
	case !keyIDHex.MatchString(e.KeyID):
		return fmt.Errorf("%w: lost root %q: a key id is 40 or 64 lower-case hex digits", ErrInvalid, e.KeyID)
	case e.PublicPEM != "":
		return fmt.Errorf("%w: lost root %s carries public material; a root with its "+
			"certificate is a fulcio_root, not a lost one", ErrInvalid, e.KeyID)
	case e.LostAt == nil || e.LostAt.IsZero():
		return fmt.Errorf("%w: lost root %s has no lost_at", ErrInvalid, e.KeyID)
	case e.Reason == "":
		return fmt.Errorf("%w: lost root %s has no reason", ErrInvalid, e.KeyID)
	}
	return nil
}

// RecordLost appends a lost root, if the history does not already hold it,
// and reports whether it did. The key id is normalised to lower case.
func (h *History) RecordLost(keyID string, lostAt time.Time, reason string) (bool, error) {
	id := strings.ToLower(keyID)
	if _, ok := h.Lookup(KindLostRoot, id); ok {
		return false, nil
	}
	at := lostAt.UTC()
	e := Entry{Kind: KindLostRoot, KeyID: id, LostAt: &at, Reason: reason}
	if err := e.validate(); err != nil {
		return false, err
	}
	h.Entries = append(h.Entries, e)
	return true, nil
}

// LostRoot finds the lost root a certificate's Authority Key Identifier names.
//
// THE MATCH IS NOT CRYPTOGRAPHIC. Anyone minting a certificate can write any
// Authority Key Identifier into it. A match narrows a label to an era the
// operator named; it never proves the certificate came from that root, and
// nothing that matches is ever trusted (ADR-0073).
func (h *History) LostRoot(aki []byte) (Entry, bool) {
	if len(aki) == 0 {
		return Entry{}, false
	}
	return h.Lookup(KindLostRoot, hex.EncodeToString(aki))
}

// LostRootSeed is one entry of the operator's seed file.
type LostRootSeed struct {
	KeyID  string    `json:"key_id"`
	LostAt time.Time `json:"lost_at"`
	Reason string    `json:"reason"`
}

// LoadLostRoots reads the operator's seed, strictly. An absent file is an
// error wrapping os.ErrNotExist: no seed, which is a fresh deployment's state.
// The entries themselves are checked when they are recorded.
func LoadLostRoots(path string) ([]LostRootSeed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f struct {
		Version   int            `json:"version"`
		LostRoots []LostRootSeed `json:"lost_roots"`
	}
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: trailing data", path)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("%s: version %d, this reader knows 1", path, f.Version)
	}
	return f.LostRoots, nil
}

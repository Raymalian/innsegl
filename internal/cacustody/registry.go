// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// The custodian's record of who the unlock material is sealed to, beside
// MaterialFile (ADR-0082 decision 7). All three are public or one-way: no
// file here opens anything.
const (
	// RecipientsFile is the applied set, one recipient per line, in the
	// format the trust backup reads and joins to its own list (ADR-0082,
	// amendment to ADR-0074 decision 2).
	RecipientsFile = trustbackup.RecipientsFile
	// SetCommitmentFile is SetDigest of RecipientsFile's set. A recipients
	// file that does not match it is not trusted as the set.
	SetCommitmentFile = "recipients.sha256"
	// MaterialCommitmentFile is the sha256 of the material, written when
	// the store proved it: at init, and at every unlock of a sealed store.
	// An unsealed store cannot test an unseal key; this can.
	MaterialCommitmentFile = "unlock.sha256"
)

// ErrBadRecipient is a set member that is no recipient the core seals to.
var ErrBadRecipient = errors.New("ca custody: the set holds something that is not a recipient")

// canonicalSet trims, drops duplicates and sorts list, and parses each
// member as the trust backup does. An empty set is ErrEmptySet.
func canonicalSet(list []string) ([]string, []age.Recipient, error) {
	set := normalise(list)
	if len(set) == 0 {
		return nil, nil, ErrEmptySet
	}
	rs, err := trustbackup.ParseRecipients(strings.Join(set, " "))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrBadRecipient, err)
	}
	return set, rs, nil
}

func normalise(list []string) []string {
	var set []string
	for _, r := range list {
		if r = strings.TrimSpace(r); r != "" && !slices.Contains(set, r) {
			set = append(set, r)
		}
	}
	slices.Sort(set)
	return set
}

// SetDigest is the commitment to a set of recipients: the sha256 of its
// members, trimmed, each once, sorted, one per line. The operator confirms a
// set by its digest, and the custodian seals to no other.
func SetDigest(list []string) string {
	sum := sha256.Sum256([]byte(strings.Join(normalise(list), "\n") + "\n"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func materialDigest(m Material) string {
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func equalDigest(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (c *Custodian) recipientsPath() string {
	return filepath.Join(filepath.Dir(c.materialPath()), RecipientsFile)
}

func (c *Custodian) setCommitmentPath() string {
	return filepath.Join(filepath.Dir(c.materialPath()), SetCommitmentFile)
}

func (c *Custodian) materialDigestPath() string {
	return filepath.Join(filepath.Dir(c.materialPath()), MaterialCommitmentFile)
}

// writeSet records set as the applied one: the recipients file, then its
// commitment, each replaced whole.
func (c *Custodian) writeSet(set []string) error {
	body := "# The recipients the CA custody unlock material is sealed to.\n" +
		"# Written by the custodian at init and at each confirmed reseal; never by hand.\n" +
		strings.Join(set, "\n") + "\n"
	if err := writeAtomic(c.recipientsPath(), []byte(body)); err != nil {
		return fmt.Errorf("ca custody: writing %s: %w", RecipientsFile, err)
	}
	if err := writeAtomic(c.setCommitmentPath(), []byte(SetDigest(set)+"\n")); err != nil {
		return fmt.Errorf("ca custody: writing %s: %w", SetCommitmentFile, err)
	}
	return nil
}

func (c *Custodian) writeMaterialCommitment(m Material) error {
	return writeAtomic(c.materialDigestPath(), []byte(materialDigest(m)+"\n"))
}

// CurrentRecipients answers the set the material is sealed to. With no
// recipients file (a store initialised before the reseal existed) it is the
// configured set, Recorded false. A file that does not match its commitment
// is an error, never a set.
func (c *Custodian) CurrentRecipients() (RecipientSet, error) {
	data, err := os.ReadFile(c.recipientsPath())
	if errors.Is(err, os.ErrNotExist) {
		var list []string
		for _, r := range c.Recipients {
			if s, ok := r.(fmt.Stringer); ok {
				list = append(list, s.String())
			}
		}
		set := normalise(list)
		return RecipientSet{Recipients: set, Digest: SetDigest(set)}, nil
	}
	if err != nil {
		return RecipientSet{}, fmt.Errorf("ca custody: reading %s: %w", RecipientsFile, err)
	}
	var list []string
	for _, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		list = append(list, line)
	}
	set := normalise(list)
	commit, err := os.ReadFile(c.setCommitmentPath())
	if err != nil {
		return RecipientSet{}, fmt.Errorf("ca custody: reading %s: %w", SetCommitmentFile, err)
	}
	digest := SetDigest(set)
	if !equalDigest(strings.TrimSpace(string(commit)), digest) {
		return RecipientSet{}, fmt.Errorf("ca custody: %s does not match %s; the recorded set is not trusted",
			RecipientsFile, SetCommitmentFile)
	}
	return RecipientSet{Recipients: set, Digest: digest, Recorded: true}, nil
}

// recordInit records what init sealed: the material's commitment and the
// set. A failure is logged, not fatal: the material is kept, an unlock of a
// sealed store writes the commitment again, and the set falls back to the
// configured one.
func (c *Custodian) recordInit(m Material) {
	if err := c.writeMaterialCommitment(m); err != nil {
		c.logf("the material's commitment was not written (%v); the next unlock of a sealed store writes it", err)
	}
	var list []string
	for _, r := range c.Recipients {
		s, ok := r.(fmt.Stringer)
		if !ok {
			c.logf("a recipient has no text form; %s is not written until a reseal", RecipientsFile)
			return
		}
		list = append(list, s.String())
	}
	if err := c.writeSet(normalise(list)); err != nil {
		c.logf("%v; the configured set stands until a reseal", err)
	}
}

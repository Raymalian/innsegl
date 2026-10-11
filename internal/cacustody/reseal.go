// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
)

// The reseal (ADR-0082 decision 7) re-seals the SAME unlock material to a
// new set of recipients, in two steps:
//
//  1. Reseal: the opener sends the material it opened, its own recipient,
//     the set and the set's digest. The custodian proves the material
//     against the store, seals it to the set with a fresh check inside, and
//     keeps that copy staged. The sealed material on disk is not touched.
//  2. ConfirmReseal: the opener opens the staged copy, which needs its touch
//     again, and sends back the check it found inside with the material.
//     Only then is the staged copy swapped in, and the set recorded.
//
// A staged copy not confirmed within ResealWindow is dropped. The CA key,
// the store, the unseal key and the secret ids never change.

// ResealWindow is how long a staged copy waits for the opener's confirm.
const ResealWindow = 10 * time.Minute

// The refusals. Each leaves the sealed material as it was.
var (
	ErrEmptySet       = errors.New("ca custody: reseal refused: the set is empty, and nobody could open the material")
	ErrOpenerNotInSet = errors.New("ca custody: reseal refused: the set does not hold the device that opened the material")
	ErrSetMismatch    = errors.New("ca custody: reseal refused: the set is not the one confirmed")
	// ErrNoMaterialCommitment is an unsealed store with no commitment yet:
	// its unseal key cannot be tested, and nothing is sealed untested.
	ErrNoMaterialCommitment = errors.New("ca custody: reseal refused: the store is unsealed and its material " +
		"has no commitment yet; it is written at the next unlock of a sealed store")
	ErrNothingStaged = errors.New("ca custody: reseal refused: no reseal is waiting for a confirm, or it expired; start again")
	ErrNotOpened     = errors.New("ca custody: reseal refused: the confirm does not carry the staged copy's check")
)

type stagedReseal struct {
	sealed   []byte
	set      []string
	digest   string
	check    string
	material string
	opener   string
	expires  time.Time
}

// sealedPlain is what a reseal seals: the material, plus the check that
// proves its copy was opened. Open reads the material and ignores the check.
type sealedPlain struct {
	Material
	Check string `json:"reseal_check"`
}

// OpenStaged opens a staged copy: the material, and the check a confirm
// sends back.
func OpenStaged(sealed []byte, identities []age.Identity) (Material, string, error) {
	r, err := age.Decrypt(bytes.NewReader(sealed), identities...)
	if err != nil {
		return Material{}, "", fmt.Errorf("ca custody: opening the staged material: %w", err)
	}
	var p sealedPlain
	if err := json.NewDecoder(io.LimitReader(r, maxUnlockBody)).Decode(&p); err != nil {
		return Material{}, "", fmt.Errorf("ca custody: the staged material is not readable: %w", err)
	}
	if !p.Valid() {
		return Material{}, "", ErrIncomplete
	}
	return p.Material, p.Check, nil
}

// Reseal stages the material, sealed to req's set. It refuses an empty set,
// a set without the opener, a digest other than the set's, and material the
// store does not accept. A second Reseal replaces a staged copy.
func (c *Custodian) Reseal(ctx context.Context, req ResealRequest) (ResealStaged, error) {
	set, recipients, err := canonicalSet(req.Recipients)
	if err != nil {
		c.logf("reseal refused: %v", err)
		return ResealStaged{}, err
	}
	opener := strings.TrimSpace(req.Opener)
	if !slices.Contains(set, opener) {
		c.logf("reseal refused: the opener %q is not in the set %s", opener, SetDigest(set))
		return ResealStaged{}, ErrOpenerNotInSet
	}
	digest := SetDigest(set)
	if !equalDigest(digest, req.SetDigest) {
		c.logf("reseal refused: the set %s is not the one confirmed", digest)
		return ResealStaged{}, ErrSetMismatch
	}

	c.resealMu.Lock()
	defer c.resealMu.Unlock()
	if err = c.prove(ctx, req.Material); err != nil {
		c.logf("reseal refused: the material was not proven: %v", err)
		return ResealStaged{}, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return ResealStaged{}, err
	}
	check := hex.EncodeToString(nonce[:])
	sealed, err := sealValue(sealedPlain{Material: req.Material, Check: check}, recipients)
	if err != nil {
		return ResealStaged{}, err
	}
	if c.staged != nil {
		c.logf("reseal: the unconfirmed reseal to %s is replaced", c.staged.digest)
	}
	expires := c.clock().Add(ResealWindow)
	c.staged = &stagedReseal{sealed: sealed, set: set, digest: digest, check: check,
		material: materialDigest(req.Material), opener: opener, expires: expires}
	c.logf("reseal staged: %d recipient(s), set %s, opened by %s; the material on disk is unchanged until the opener confirms, within %s",
		len(set), digest, opener, ResealWindow)
	return ResealStaged{Sealed: sealed, Recipients: set, SetDigest: digest, ExpiresAt: expires}, nil
}

// ConfirmReseal swaps the staged copy in once its opener has opened it: the
// check from inside it, the same material, the same set. Then it records
// the set in RecipientsFile.
func (c *Custodian) ConfirmReseal(ctx context.Context, req ResealConfirm) error {
	c.resealMu.Lock()
	defer c.resealMu.Unlock()
	s := c.staged
	if s == nil {
		c.logf("reseal confirm refused: nothing is staged")
		return ErrNothingStaged
	}
	if c.clock().After(s.expires) {
		c.staged = nil
		c.logf("reseal expired: the reseal to %s was not confirmed within %s; the material is unchanged", s.digest, ResealWindow)
		return ErrNothingStaged
	}
	if !equalDigest(s.digest, req.SetDigest) {
		c.logf("reseal confirm refused: the set is not the staged one %s", s.digest)
		return ErrSetMismatch
	}
	if !equalDigest(s.check, req.Check) {
		c.logf("reseal confirm refused: the check is not the staged copy's")
		return ErrNotOpened
	}
	if !equalDigest(s.material, materialDigest(req.Material)) {
		c.logf("reseal confirm refused: the material is not the staged material")
		return errNotAccepted
	}
	if err := c.prove(ctx, req.Material); err != nil {
		c.logf("reseal confirm refused: the material was not proven: %v", err)
		return err
	}
	if err := writeAtomic(c.materialPath(), s.sealed); err != nil {
		return fmt.Errorf("ca custody: swapping in the resealed material: %w; the old copy is still the material", err)
	}
	if err := c.writeSet(s.set); err != nil {
		// The new material is in place and the reseal stays staged, so a
		// second confirm writes both again.
		c.logf("resealed, but the set was not recorded: %v", err)
		return err
	}
	c.staged = nil
	if err := c.Snapshot(ctx); err != nil {
		c.logf("the snapshot after the reseal failed (%v); the next scheduled one tries again", err)
	}
	c.logf("resealed: the unlock material is sealed to %d recipient(s), set %s, confirmed by %s; the CA key and the store are unchanged",
		len(s.set), s.digest, s.opener)
	return nil
}

// prove makes the store accept m before anything is sealed with it. A sealed
// store is unsealed with it. An unsealed store cannot test an unseal key, so
// m must match the commitment written when the store last proved it. Both
// roles must log in (the unlock path).
func (c *Custodian) prove(ctx context.Context, m Material) error {
	if !m.Valid() {
		return ErrIncomplete
	}
	st, err := c.Store.SealStatus(ctx)
	if err != nil {
		return err
	}
	if st.Initialized && !st.Sealed {
		want, err := os.ReadFile(c.materialDigestPath())
		if errors.Is(err, os.ErrNotExist) {
			return ErrNoMaterialCommitment
		}
		if err != nil {
			return fmt.Errorf("ca custody: reading %s: %w", MaterialCommitmentFile, err)
		}
		if !equalDigest(strings.TrimSpace(string(want)), materialDigest(m)) {
			return errNotAccepted
		}
	}
	return c.Unlock(ctx, m)
}

func (c *Custodian) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

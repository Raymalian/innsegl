// SPDX-License-Identifier: Apache-2.0

package trusthistory

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// EndMode is how a root stops being used (#533).
type EndMode string

const (
	// EndRetire is a planned stop: the root stopped issuing, and stays
	// trusted, within the skew bound, for what the log integrated before.
	EndRetire EndMode = "retire"
	// EndRevoke is a compromise, or a key that may have been exposed: only
	// what the log integrated strictly before the date is accepted. A revoked
	// root has stopped issuing too, so it is retired at the same moment where
	// it was not retired already.
	EndRevoke EndMode = "revoke"
)

// ErrNotFound is an End for an entry the history does not hold.
var ErrNotFound = errors.New("trusthistory: no such entry")

// End sets an entry's end date. It is the only way a rotation writes one, and
// it refuses anything the append-only file could never take back by mistake:
// an unknown mode, no reason, no time, a date before the root's first use, an
// end date that is already set, or a lost root, which has no dates to set.
// A refusal leaves the history unchanged.
//
// The reason goes in retired_reason where that is empty. A root retired
// first and revoked later keeps its first reason; the file has one reason
// field, and the revocation's own reason is the caller's to report.
func (h *History) End(kind Kind, keyID string, mode EndMode, at time.Time, reason string) error {
	if mode != EndRetire && mode != EndRevoke {
		return fmt.Errorf("%w: end mode %q; it is %q or %q", ErrInvalid, mode, EndRetire, EndRevoke)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: an end date needs a reason", ErrInvalid)
	}
	if at.IsZero() {
		return fmt.Errorf("%w: an end date needs a time", ErrInvalid)
	}
	if kind == KindLostRoot {
		return fmt.Errorf("%w: a lost root has no dates to set", ErrInvalid)
	}
	i := h.index(kind, keyID)
	if i < 0 {
		return fmt.Errorf("%w: %s %s", ErrNotFound, kind, keyID)
	}
	e := h.Entries[i]
	when := at.UTC()
	switch {
	case e.RevokedAt != nil:
		return fmt.Errorf("%w: %s %s was revoked at %s already", ErrRewrite, kind, keyID,
			e.RevokedAt.UTC().Format(time.RFC3339))
	case mode == EndRetire && e.RetiredAt != nil:
		return fmt.Errorf("%w: %s %s was retired at %s already", ErrRewrite, kind, keyID,
			e.RetiredAt.UTC().Format(time.RFC3339))
	}
	if mode == EndRevoke {
		e.RevokedAt = &when
	}
	if e.RetiredAt == nil {
		e.RetiredAt = &when
		e.RetiredReason = reason
	}
	if err := e.validate(); err != nil {
		return err
	}
	h.Entries[i] = e
	return nil
}

// index is the position of one entry, or -1.
func (h *History) index(kind Kind, keyID string) int {
	for i, e := range h.Entries {
		if e.Kind == kind && e.KeyID == keyID {
			return i
		}
	}
	return -1
}

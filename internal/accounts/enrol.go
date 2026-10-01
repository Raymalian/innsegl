// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Enrolment and renewal (RM-284, #460; ADR-0063 decisions 2 and 6).
//
// Both run the certificate issue INSIDE the transaction that records them.
// A failed issue rolls the transaction back, so an enrolment whose
// certificate could not be minted leaves the token unspent and no
// installation behind, and a failed renewal leaves last_renewed_at as it
// was. A concurrent second use of the same token waits on the first one's
// row lock and then finds the token spent (or, if the first rolled back,
// spends it itself).
//
// The cost is a transaction held open across one call to the identity
// authority, which its own client bounds (spire.DefaultTimeout).

// installationIDPattern is the id grammar the installations table enforces.
var installationIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// IssueFunc mints the certificate for an installation inside the
// transaction that records it. An error rolls the transaction back.
type IssueFunc func(ctx context.Context, inst Installation) error

// EnrolParams is one enrolment. InstallationID is chosen by the client: a
// certificate request must name its own SPIFFE ID, so the client picks the
// 32-hex id before it asks.
type EnrolParams struct {
	Token          string
	InstallationID string
	Name           string
}

// Enrol spends a token exactly once and creates the installation it
// describes (account, creator, repositories and kind come from the token),
// then calls issue. Every token problem is ErrTokenInvalid; a malformed id or
// name, or an id already in use, is ErrInvalid and leaves the token unspent.
func (s *Store) Enrol(ctx context.Context, p EnrolParams, issue IssueFunc) (Installation, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > 256 {
		return Installation{}, fmt.Errorf("%w: an installation needs a name of 1 to 256 bytes", ErrInvalid)
	}
	if !installationIDPattern.MatchString(p.InstallationID) {
		return Installation{}, fmt.Errorf("%w: an installation id is 32 lowercase hex characters", ErrInvalid)
	}
	if issue == nil {
		return Installation{}, fmt.Errorf("%w: no certificate issuer", ErrInvalid)
	}
	tokenID, stored, err := s.lookupToken(ctx, p.Token)
	if err != nil {
		return Installation{}, err
	}
	var out Installation
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		en, cerr := consumeTokenTx(ctx, tx, tokenID, stored)
		if cerr != nil {
			return cerr
		}
		repos, rerr := normaliseRepos(en.Repos)
		if rerr != nil {
			return rerr
		}
		kind, kerr := normaliseKind(en.Kind)
		if kerr != nil {
			return kerr
		}
		inst, ierr := insertInstallationTx(ctx, tx, p.InstallationID, en.AccountID, en.CreatedBy, name, kind, repos, tokenID)
		if ierr != nil {
			return ierr
		}
		if serr := issue(ctx, inst); serr != nil {
			return serr
		}
		out = inst
		return nil
	})
	if err != nil {
		return Installation{}, err
	}
	return out, nil
}

// Renew stamps last_renewed_at on an ACTIVE installation and calls issue.
// An unknown, suspended or revoked installation is ErrNotFound and issue is
// never called.
func (s *Store) Renew(ctx context.Context, installationID string, issue IssueFunc) (Installation, error) {
	if issue == nil {
		return Installation{}, fmt.Errorf("%w: no certificate issuer", ErrInvalid)
	}
	var out Installation
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		inst, qerr := scanInstallation(tx.QueryRow(ctx,
			`UPDATE innsegl_auth.installations SET last_renewed_at = clock_timestamp()
			  WHERE installation_id = $1 AND status = 'active'
			  RETURNING `+installationColumns, installationID))
		if errors.Is(qerr, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if qerr != nil {
			return fmt.Errorf("accounts: renewing the installation: %w", qerr)
		}
		if err := appendAudit(ctx, tx, AuditEntry{AccountID: inst.AccountID,
			Action: "installation.renewed", Subject: inst.ID}); err != nil {
			return err
		}
		if err := issue(ctx, inst); err != nil {
			return err
		}
		out = inst
		return nil
	})
	if err != nil {
		return Installation{}, err
	}
	return out, nil
}

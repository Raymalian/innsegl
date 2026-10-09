// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/signing"
)

// An installation's operator author, pinned on first use (#545, GH-008).
//
// A repository the operator sets to operator mode authors agent commits as
// the operator: I6 allows "the human operator" as author, and the agent stays
// in the trailers and the signature. The operator's machine reads who it
// pushes as from git and reports it; the first report is pinned here, so no
// one types a name or an address. The core's I6 gate admits that pair for
// commits signed for this installation.
//
// A different report later is refused (ErrAuthorPinned): the machine's git
// config is within an agent's reach, the pin on the core is not. An operator
// changes it on the core host (ResetOperatorAuthor).

// ErrAuthorPinned is a report that differs from the pair already pinned.
var ErrAuthorPinned = errors.New("accounts: this installation's operator author is already pinned to a different identity")

// IsNoreplyAddress reports whether email is a GitHub account's noreply
// address, the only kind pinned automatically (signing.NoreplyLogin's rule;
// migration 0015 holds the same one).
func IsNoreplyAddress(email string) bool {
	_, ok := signing.NoreplyLogin(email)
	return ok
}

// OperatorAuthor answers the installation's pinned operator author, ok false
// when none is pinned or the installation is unknown.
func (s *Store) OperatorAuthor(ctx context.Context, installationID string) (name, email string, ok bool, err error) {
	var n, e *string
	err = s.pool.QueryRow(ctx,
		`SELECT operator_author_name, operator_author_email
		   FROM innsegl_auth.installations WHERE installation_id = $1`, installationID).Scan(&n, &e)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("accounts: reading the operator author: %w", err)
	}
	if n == nil || e == nil {
		return "", "", false, nil
	}
	return *n, *e, true, nil
}

// PinOperatorAuthor pins name and email as the installation's operator author
// when none is pinned. The same pair again is a no-op; a different one is
// ErrAuthorPinned. Only an active installation pins, only a GitHub noreply
// address, and only with that address's own login as the name: a pinned name
// is published on every commit it authors, so it is never a person's name.
func (s *Store) PinOperatorAuthor(ctx context.Context, installationID, name, email string) error {
	login, ok := signing.NoreplyLogin(email)
	if !ok {
		return fmt.Errorf("%w: only a GitHub noreply address (<id>+<login>@users.noreply.github.com) is "+
			"pinned automatically; set that address as this repository's git user.email", ErrInvalid)
	}
	if name != login {
		return fmt.Errorf("%w: an operator author's name is its noreply address's login", ErrInvalid)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var account, status string
		var n, e *string
		err := tx.QueryRow(ctx,
			`SELECT account_id, status, operator_author_name, operator_author_email
			   FROM innsegl_auth.installations WHERE installation_id = $1 FOR UPDATE`,
			installationID).Scan(&account, &status, &n, &e)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("accounts: reading the installation: %w", err)
		}
		if status == StatusRevoked {
			return ErrRevoked
		}
		if status != StatusActive {
			return fmt.Errorf("%w: the installation is %s", ErrInvalid, status)
		}
		if n != nil && e != nil {
			if *n == name && *e == email {
				return nil
			}
			return ErrAuthorPinned
		}
		if _, err := tx.Exec(ctx,
			`UPDATE innsegl_auth.installations
			    SET operator_author_name = $2, operator_author_email = $3
			  WHERE installation_id = $1`, installationID, name, email); err != nil {
			return fmt.Errorf("accounts: pinning the operator author: %w", err)
		}
		// The pair itself is not in the audit detail: a display name is a
		// person's, and the row is enough to say a pin happened and when.
		return appendAudit(ctx, tx, AuditEntry{Actor: ClaimActor(installationID), AccountID: account,
			Action: "installation.operator_author_pinned", Subject: installationID,
			Detail: map[string]any{"source": "first use"}})
	})
}

// ResetOperatorAuthor clears the installation's pinned operator author, so
// the next report pins again. It is the operator's, run on the core host.
func (s *Store) ResetOperatorAuthor(ctx context.Context, installationID, actor string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var account string
		err := tx.QueryRow(ctx,
			`SELECT account_id FROM innsegl_auth.installations WHERE installation_id = $1 FOR UPDATE`,
			installationID).Scan(&account)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("accounts: reading the installation: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE innsegl_auth.installations
			    SET operator_author_name = NULL, operator_author_email = NULL
			  WHERE installation_id = $1`, installationID); err != nil {
			return fmt.Errorf("accounts: resetting the operator author: %w", err)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: account,
			Action: "installation.operator_author_reset", Subject: installationID})
	})
}

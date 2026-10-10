// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// FoundOperator creates the deployment's own organisation when it has none
// and at least one user: named after the deployment's first user, who is
// made its owner. It answers whether it created one. Nothing else made
// this organisation, so a fresh install's first user belonged to none, and
// the account page could connect no machine. The API calls it when the
// first user enrols and when it starts, which also covers a deployment
// installed before this existed. Running it again changes nothing.
func (s *Store) FoundOperator(ctx context.Context) (created bool, err error) {
	id, err := newID(16)
	if err != nil {
		return false, err
	}
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var exists bool
		if qerr := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM innsegl_auth.accounts WHERE operator)`).Scan(&exists); qerr != nil {
			return fmt.Errorf("accounts: looking for the operator organisation: %w", qerr)
		}
		if exists {
			return nil
		}
		var userID, name string
		qerr := tx.QueryRow(ctx,
			`SELECT user_id, display_name FROM innsegl_auth.users
			 ORDER BY created_at, user_id LIMIT 1`).Scan(&userID, &name)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return nil
		}
		if qerr != nil {
			return fmt.Errorf("accounts: finding the first user: %w", qerr)
		}
		if _, xerr := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.accounts (account_id, name, operator) VALUES ($1, $2, true)`,
			id, name); xerr != nil {
			return fmt.Errorf("accounts: creating the operator organisation: %w", xerr)
		}
		if xerr := appendAudit(ctx, tx, AuditEntry{AccountID: id, Action: "account.created",
			Subject: id, Detail: map[string]any{"operator": true}}); xerr != nil {
			return xerr
		}
		if _, xerr := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.memberships (user_id, account_id, role) VALUES ($1, $2, $3)`,
			userID, id, RoleOwner); xerr != nil {
			return fmt.Errorf("accounts: making the first user its owner: %w", xerr)
		}
		created = true
		return appendAudit(ctx, tx, AuditEntry{AccountID: id, Action: "membership.added",
			Subject: userID, Detail: map[string]any{"role": RoleOwner}})
	})
	if pgCode(err) == "23505" {
		// Another caller founded it first: the unique index admits one.
		return false, nil
	}
	return created, err
}

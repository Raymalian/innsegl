// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/api"
)

// Members and roles (RM-301, #480). Three roles, scope checks only
// (Authorization E1): the table is api.RoleMay, shared with the dashboard's
// handlers. A role decides what a person may change in the accounts spine;
// it never decides what an agent may do. InScope and ClaimRepo read no role
// (ACC-007).

// Errors the member and invitation changes answer. They are the API's own
// values, so a caller of either package switches on one set.
var (
	// ErrForbidden: the actor's role does not allow the change.
	ErrForbidden = api.ErrOrgForbidden
	// ErrLastOwner: the change would leave the organisation with no owner.
	ErrLastOwner = api.ErrLastOwner
	// ErrAlreadyMember: the user already holds a live membership.
	ErrAlreadyMember = api.ErrAlreadyMember
)

// errNoSuchMember is ErrNotFound as both packages name it.
var errNoSuchMember = fmt.Errorf("%w: no such live member (%w)", ErrNotFound, api.ErrOrgNotFound)

// Querier is the transaction AcceptInvitationAsNewUser lends.
type Querier = api.Querier

func validRole(role string) error {
	switch role {
	case RoleOwner, RoleAdmin, RoleMember:
		return nil
	}
	return fmt.Errorf("%w: role %q is not owner, admin or member", ErrInvalid, role)
}

// roleOf answers a user's live role in an account, "" for none.
func roleOf(ctx context.Context, q Querier, accountID, userID string) (string, error) {
	var role string
	err := q.QueryRow(ctx, `SELECT role FROM innsegl_auth.memberships
		WHERE account_id = $1 AND user_id = $2 AND until IS NULL`, accountID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("accounts: reading the role: %w", err)
	}
	return role, nil
}

// authorise refuses an actor whose live role in the account does not allow
// action. An empty actor is the operator's core CLI, the deployment's admin
// path (it holds the auth-writer credential), and is not asked.
func authorise(ctx context.Context, q Querier, accountID, actor, action string) error {
	if actor == "" {
		return nil
	}
	role, err := roleOf(ctx, q, accountID, actor)
	if err != nil {
		return err
	}
	if role == "" || !api.RoleMay(role, action) {
		return ErrForbidden
	}
	return nil
}

// Authorise answers nil when userID may take action in the account, and
// ErrForbidden when their live role (or the lack of one) does not allow it.
func (s *Store) Authorise(ctx context.Context, accountID, userID, action string) error {
	return authorise(ctx, s.pool, accountID, userID, action)
}

// memberAction is the privilege a change to a member needs: the owner's own
// when the owner role is given or taken, an admin's otherwise.
func memberAction(roles ...string) string {
	if slices.Contains(roles, RoleOwner) {
		return api.PrivilegeManageOwners
	}
	return api.PrivilegeManageMembers
}

// AddMember gives a user a live membership. A second live membership for the
// same pair is ErrAlreadyMember. A named actor needs the privilege the role
// takes (memberAction); an empty one is the operator's CLI.
func (s *Store) AddMember(ctx context.Context, accountID, userID, role, actor string) error {
	if err := validRole(role); err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := authorise(ctx, tx, accountID, actor, memberAction(role)); err != nil {
			return err
		}
		return insertMemberTx(ctx, tx, accountID, userID, role, actor, nil)
	})
}

func insertMemberTx(ctx context.Context, tx Querier, accountID, userID, role, actor string, detail map[string]any) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO innsegl_auth.memberships (user_id, account_id, role) VALUES ($1, $2, $3)`,
		userID, accountID, role); err != nil {
		switch pgCode(err) {
		case "23505":
			return ErrAlreadyMember
		case "23503":
			return fmt.Errorf("%w: no user %q, or no organisation %q", ErrInvalid, userID, accountID)
		}
		return fmt.Errorf("accounts: adding the member: %w", err)
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["role"] = role
	return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "membership.added",
		Subject: userID, Detail: detail})
}

// liveMembersTx locks the account's live memberships, so two changes that
// each check "is there another owner" cannot both pass, and answers role by
// user.
func liveMembersTx(ctx context.Context, tx pgx.Tx, accountID string) (map[string]string, int, error) {
	rows, err := tx.Query(ctx, `SELECT user_id, role FROM innsegl_auth.memberships
		WHERE account_id = $1 AND until IS NULL FOR UPDATE`, accountID)
	if err != nil {
		return nil, 0, fmt.Errorf("accounts: reading the members: %w", err)
	}
	defer rows.Close()
	roles := map[string]string{}
	owners := 0
	for rows.Next() {
		var u, r string
		if err := rows.Scan(&u, &r); err != nil {
			return nil, 0, fmt.Errorf("accounts: reading a member: %w", err)
		}
		roles[u] = r
		if r == RoleOwner {
			owners++
		}
	}
	return roles, owners, rows.Err()
}

// Members answers an account's live members with their display names,
// oldest first.
func (s *Store) Members(ctx context.Context, accountID string) ([]api.OrgMember, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT m.user_id, u.display_name, m.role, m.since
		  FROM innsegl_auth.memberships m
		  JOIN innsegl_auth.users u USING (user_id)
		 WHERE m.account_id = $1 AND m.until IS NULL
		 ORDER BY m.since, m.user_id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("accounts: listing members: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.OrgMember, error) {
		var m api.OrgMember
		err := row.Scan(&m.UserID, &m.DisplayName, &m.Role, &m.Since)
		return m, err
	})
}

// SetRole gives a live member another role. The membership row is ended and
// a new one begun, so the table keeps the history. Setting the role a member
// already holds changes nothing and records nothing.
func (s *Store) SetRole(ctx context.Context, accountID, userID, role, actor string) error {
	if err := validRole(role); err != nil {
		return err
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		roles, owners, err := liveMembersTx(ctx, tx, accountID)
		if err != nil {
			return err
		}
		current, ok := roles[userID]
		if !ok {
			return errNoSuchMember
		}
		if aerr := authorise(ctx, tx, accountID, actor, memberAction(current, role)); aerr != nil {
			return aerr
		}
		if current == role {
			return nil
		}
		if current == RoleOwner && owners == 1 {
			return ErrLastOwner
		}
		if _, xerr := tx.Exec(ctx, `UPDATE innsegl_auth.memberships SET until = clock_timestamp()
			WHERE account_id = $1 AND user_id = $2 AND until IS NULL`, accountID, userID); xerr != nil {
			return fmt.Errorf("accounts: ending the membership: %w", xerr)
		}
		if _, xerr := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.memberships (user_id, account_id, role) VALUES ($1, $2, $3)`,
			userID, accountID, role); xerr != nil {
			return fmt.Errorf("accounts: beginning the membership: %w", xerr)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "membership.role_changed",
			Subject: userID, Detail: map[string]any{"from": current, "to": role}})
	})
}

// RemoveMember ends a live membership and, in the same transaction, revokes
// every session of the person (they sign in again and see what their other
// memberships allow) and suspends the active installations they created in
// this account. Suspension is not revocation: an admin may reactivate a
// machine the organisation keeps.
func (s *Store) RemoveMember(ctx context.Context, accountID, userID, actor string) (api.OrgRemoval, error) {
	var out api.OrgRemoval
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		roles, owners, err := liveMembersTx(ctx, tx, accountID)
		if err != nil {
			return err
		}
		current, ok := roles[userID]
		if !ok {
			return errNoSuchMember
		}
		if aerr := authorise(ctx, tx, accountID, actor, memberAction(current)); aerr != nil {
			return aerr
		}
		if current == RoleOwner && owners == 1 {
			return ErrLastOwner
		}
		if _, xerr := tx.Exec(ctx, `UPDATE innsegl_auth.memberships SET until = clock_timestamp()
			WHERE account_id = $1 AND user_id = $2 AND until IS NULL`, accountID, userID); xerr != nil {
			return fmt.Errorf("accounts: ending the membership: %w", xerr)
		}
		if aerr := appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "membership.removed",
			Subject: userID, Detail: map[string]any{"role": current}}); aerr != nil {
			return aerr
		}
		out.Suspended, err = suspendCreatedByTx(ctx, tx, accountID, userID, actor)
		if err != nil {
			return err
		}
		out.SessionsRevoked, err = revokeSessionsTx(ctx, tx, accountID, userID, actor)
		return err
	})
	if err != nil {
		return api.OrgRemoval{}, err
	}
	return out, nil
}

func suspendCreatedByTx(ctx context.Context, tx pgx.Tx, accountID, userID, actor string) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE innsegl_auth.installations SET status = 'suspended'
		WHERE account_id = $1 AND created_by = $2 AND status = 'active'
		RETURNING installation_id`, accountID, userID)
	if err != nil {
		return nil, fmt.Errorf("accounts: suspending the member's installations: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("accounts: suspending the member's installations: %w", err)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if aerr := appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "installation.suspended",
			Subject: id, Detail: map[string]any{"from": StatusActive, "reason": "member removed"}}); aerr != nil {
			return nil, aerr
		}
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}

func revokeSessionsTx(ctx context.Context, tx pgx.Tx, accountID, userID, actor string) (int, error) {
	tag, err := tx.Exec(ctx, `UPDATE innsegl_auth.sessions SET revoked_at = clock_timestamp()
		WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return 0, fmt.Errorf("accounts: revoking the member's sessions: %w", err)
	}
	n := int(tag.RowsAffected())
	if n == 0 {
		return 0, nil
	}
	return n, appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "sessions.revoked",
		Subject: userID, Detail: map[string]any{"count": n}})
}

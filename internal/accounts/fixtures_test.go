// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Fixture helpers. Nothing in the binary calls these: enrolment goes through
// the *Tx internals, and the dashboard's account setup is the operator path.
// The tests use them to build a known starting state.

// ErrAlreadyMember: the user already holds a live membership.
var ErrAlreadyMember = errors.New("accounts: the user is already a member of this account")

// AddMember gives a user a live membership. A second live membership for the
// same pair is ErrAlreadyMember.
func (s *Store) AddMember(ctx context.Context, accountID, userID, role, actor string) error {
	switch role {
	case RoleOwner, RoleAdmin, RoleMember:
	default:
		return fmt.Errorf("%w: role %q is not owner, admin or member", ErrInvalid, role)
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO innsegl_auth.memberships (user_id, account_id, role) VALUES ($1, $2, $3)`,
			userID, accountID, role); err != nil {
			if pgCode(err) == "23505" {
				return ErrAlreadyMember
			}
			return fmt.Errorf("accounts: adding the member: %w", err)
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "membership.added",
			Subject: userID, Detail: map[string]any{"role": role}})
	})
}

// EndRepoGrant ends the account's live grant on a repository. No live grant
// is ErrNotFound.
func (s *Store) EndRepoGrant(ctx context.Context, accountID, repo, actor string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE innsegl_auth.repo_grants SET until = clock_timestamp()
			  WHERE account_id = $1 AND repo = $2 AND until IS NULL`, accountID, repo)
		if err != nil {
			return fmt.Errorf("accounts: ending the grant: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "repo_grant.ended",
			Subject: repo})
	})
}

// ConsumeEnrolmentToken spends a token exactly once. Every failure (malformed,
// unknown, wrong secret, expired, already used) is ErrTokenInvalid.
//
// The secret's hash is compared in constant time, and the spend is one
// UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING, so two
// concurrent consumers cannot both win.
func (s *Store) ConsumeEnrolmentToken(ctx context.Context, token string) (Enrolment, error) {
	tokenID, stored, err := s.lookupToken(ctx, token)
	if err != nil {
		return Enrolment{}, err
	}
	var en Enrolment
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var cerr error
		en, cerr = consumeTokenTx(ctx, tx, tokenID, stored)
		return cerr
	})
	if err != nil {
		return Enrolment{}, err
	}
	return en, nil
}

// CreateInstallation inserts an active installation with a fresh 32-hex id.
func (s *Store) CreateInstallation(ctx context.Context, p InstallationParams) (Installation, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" || len(name) > 256 {
		return Installation{}, fmt.Errorf("%w: an installation needs a name of 1 to 256 bytes", ErrInvalid)
	}
	repos, err := normaliseRepos(p.Repos)
	if err != nil {
		return Installation{}, err
	}
	kind, err := normaliseKind(p.Kind)
	if err != nil {
		return Installation{}, err
	}
	id, err := newID(16)
	if err != nil {
		return Installation{}, err
	}
	var out Installation
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var ierr error
		out, ierr = insertInstallationTx(ctx, tx, id, p.AccountID, p.CreatedBy, name, kind, repos, p.TokenID)
		return ierr
	})
	if err != nil {
		return Installation{}, err
	}
	return out, nil
}

// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/api"
)

// The account page's reads and its two writes (RM-333, #511). Store
// implements api.Organisations with these; the API cannot import this
// package, which imports it.

// Memberships answers a user's live memberships, oldest first.
func (s *Store) Memberships(ctx context.Context, userID string) ([]api.OrgMembership, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.account_id, a.name, a.operator, m.role
		  FROM innsegl_auth.memberships m
		  JOIN innsegl_auth.accounts a USING (account_id)
		 WHERE m.user_id = $1 AND m.until IS NULL
		 ORDER BY m.since, a.account_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("accounts: listing memberships: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.OrgMembership, error) {
		var m api.OrgMembership
		err := row.Scan(&m.AccountID, &m.Name, &m.Operator, &m.Role)
		return m, err
	})
}

// Machines answers every installation of the named accounts, oldest first.
func (s *Store) Machines(ctx context.Context, accountIDs []string) ([]api.OrgMachine, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+installationColumns+` FROM innsegl_auth.installations
		  WHERE account_id = ANY($1) ORDER BY created_at, installation_id`, nonNil(accountIDs))
	if err != nil {
		return nil, fmt.Errorf("accounts: listing machines: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.OrgMachine, error) {
		i, err := scanInstallation(row)
		return api.OrgMachine{
			ID: i.ID, AccountID: i.AccountID, Name: i.Name, Kind: i.Kind, Repos: i.Repos,
			Status: i.Status, CreatedAt: i.CreatedAt, LastRenewedAt: i.LastRenewedAt, RevokedAt: i.RevokedAt,
		}, err
	})
}

// RepoGrants answers the named accounts' live repository grants, by
// repository.
func (s *Store) RepoGrants(ctx context.Context, accountIDs []string) ([]api.OrgRepoGrant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT account_id, repo, since FROM innsegl_auth.repo_grants
		 WHERE account_id = ANY($1) AND until IS NULL
		 ORDER BY repo`, nonNil(accountIDs))
	if err != nil {
		return nil, fmt.Errorf("accounts: listing repository grants: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (api.OrgRepoGrant, error) {
		var g api.OrgRepoGrant
		err := row.Scan(&g.AccountID, &g.Repo, &g.Since)
		return g, err
	})
}

// RevokeMachine revokes an installation for good: SetInstallationStatus to
// revoked, with the store's errors named as the API names them.
func (s *Store) RevokeMachine(ctx context.Context, machineID, actor string) error {
	err := s.SetInstallationStatus(ctx, machineID, StatusRevoked, actor)
	switch {
	case errors.Is(err, ErrNotFound):
		return fmt.Errorf("%w: %s", api.ErrMachineNotFound, machineID)
	case errors.Is(err, ErrRevoked):
		return fmt.Errorf("%w: %s", api.ErrMachineRevoked, machineID)
	}
	return err
}

// MintEnrolmentToken is CreateEnrolmentToken for the account page. An empty
// kind is a workstation and an empty repos list is every repository ("*").
func (s *Store) MintEnrolmentToken(ctx context.Context, accountID, actor, kind string, repos []string) (string, time.Time, error) {
	if len(repos) == 0 {
		repos = []string{AllRepos}
	}
	tok, meta, err := s.CreateEnrolmentToken(ctx, TokenParams{
		AccountID: accountID, CreatedBy: actor, Repos: repos, Kind: kind,
	})
	if errors.Is(err, ErrInvalid) {
		return "", time.Time{}, fmt.Errorf("%w: %w", api.ErrOrgInvalid, err)
	}
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, meta.ExpiresAt, nil
}

// nonNil keeps a nil list from reaching ANY($1) as NULL.
func nonNil(ids []string) []string {
	if ids == nil {
		return []string{}
	}
	return ids
}

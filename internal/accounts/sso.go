// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/api"
)

// An organisation's identity-provider connection (#485, E30): at most one
// per organisation (migration 0019), set and removed by its owner
// (api.PrivilegeManageSSO). Store implements api.SSOConnections with these.
//
// The audit trail records that the connection changed, with its id. It
// never records the sign-in name (the trail outlives an erasure), the issuer,
// the client id or the secret.

// signInNamePattern is migration 0019's CHECK, asked first so a refusal is
// ErrInvalid rather than a constraint violation.
var signInNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

const ssoColumns = `c.connection_id, c.account_id, a.name, c.sign_in_name, c.issuer, c.client_id,
	c.client_secret, c.updated_at`

func scanSSO(row pgx.Row) (api.SSOConnection, error) {
	var c api.SSOConnection
	err := row.Scan(&c.ID, &c.AccountID, &c.AccountName, &c.SignInName, &c.Issuer, &c.ClientID,
		&c.ClientSecret, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return api.SSOConnection{}, api.ErrSSONotConfigured
	}
	if err != nil {
		return api.SSOConnection{}, fmt.Errorf("accounts: reading the organisation's sign-in: %w", err)
	}
	return c, nil
}

func (s *Store) ssoWhere(ctx context.Context, q Querier, where string, arg any) (api.SSOConnection, error) {
	return scanSSO(q.QueryRow(ctx, `SELECT `+ssoColumns+`
		FROM innsegl_auth.sso_connections c JOIN innsegl_auth.accounts a USING (account_id)
		WHERE `+where, arg))
}

// SSOConnection answers the organisation's connection.
func (s *Store) SSOConnection(ctx context.Context, accountID string) (api.SSOConnection, error) {
	return s.ssoWhere(ctx, s.pool, `c.account_id = $1`, accountID)
}

// SSOConnectionByName answers the connection a sign-in name names.
func (s *Store) SSOConnectionByName(ctx context.Context, signInName string) (api.SSOConnection, error) {
	return s.ssoWhere(ctx, s.pool, `c.sign_in_name = $1`, strings.ToLower(strings.TrimSpace(signInName)))
}

// SSOConnectionByID answers one connection.
func (s *Store) SSOConnectionByID(ctx context.Context, connectionID string) (api.SSOConnection, error) {
	return s.ssoWhere(ctx, s.pool, `c.connection_id = $1`, connectionID)
}

// validSSO refuses what migration 0019 would, and an issuer that is not a
// plain https URL.
func validSSO(p api.SSOConnectionParams) error {
	if !signInNamePattern.MatchString(p.SignInName) {
		return fmt.Errorf("%w: %w: the sign-in name is 2 to 63 lowercase letters, digits and hyphens",
			api.ErrOrgInvalid, ErrInvalid)
	}
	u, err := url.Parse(p.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		len(p.Issuer) > 2048 {
		return fmt.Errorf("%w: %w: the issuer is an https URL with no user, query or fragment",
			api.ErrOrgInvalid, ErrInvalid)
	}
	if p.ClientID == "" || len(p.ClientID) > 512 || len(p.ClientSecret) > 2048 {
		return fmt.Errorf("%w: %w: the client id is 1 to 512 bytes, the secret at most 2048",
			api.ErrOrgInvalid, ErrInvalid)
	}
	return nil
}

// SetSSOConnection creates or replaces the organisation's connection. A new
// issuer or client id revokes the sessions the old one opened, in the same
// transaction.
func (s *Store) SetSSOConnection(ctx context.Context, accountID string, p api.SSOConnectionParams, actor string) (api.SSOConnection, error) {
	p.SignInName = strings.ToLower(strings.TrimSpace(p.SignInName))
	p.Issuer = strings.TrimSpace(p.Issuer)
	p.ClientID = strings.TrimSpace(p.ClientID)
	if err := validSSO(p); err != nil {
		return api.SSOConnection{}, err
	}
	var out api.SSOConnection
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := authorise(ctx, tx, accountID, actor, api.PrivilegeManageSSO); err != nil {
			return err
		}
		old, err := s.ssoWhere(ctx, tx, `c.account_id = $1 FOR UPDATE OF c`, accountID)
		exists := err == nil
		if err != nil && !errors.Is(err, api.ErrSSONotConfigured) {
			return err
		}
		if p.KeepSecret && p.ClientSecret == "" {
			p.ClientSecret = old.ClientSecret
		}
		id := old.ID
		if !exists {
			if id, err = newID(16); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `
			INSERT INTO innsegl_auth.sso_connections
			    (connection_id, account_id, sign_in_name, issuer, client_id, client_secret, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (account_id) DO UPDATE SET sign_in_name = EXCLUDED.sign_in_name,
			    issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
			    client_secret = EXCLUDED.client_secret, updated_at = clock_timestamp()`,
			id, accountID, p.SignInName, p.Issuer, p.ClientID, p.ClientSecret, nullable(actor)); err != nil {
			if pgCode(err) == "23505" {
				return api.ErrSSONameTaken
			}
			return fmt.Errorf("accounts: saving the organisation's sign-in: %w", err)
		}
		if aerr := appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "sso.configured",
			Subject: id, Detail: map[string]any{"created": !exists}}); aerr != nil {
			return aerr
		}
		if exists && (old.Issuer != p.Issuer || old.ClientID != p.ClientID) {
			if _, rerr := revokeSSOSessionsTx(ctx, tx, accountID, id, actor); rerr != nil {
				return rerr
			}
		}
		out, err = s.ssoWhere(ctx, tx, `c.connection_id = $1`, id)
		return err
	})
	if err != nil {
		return api.SSOConnection{}, err
	}
	return out, nil
}

// RemoveSSOConnection removes the organisation's connection, revoking every
// session it opened first: the foreign key would only clear the reference.
func (s *Store) RemoveSSOConnection(ctx context.Context, accountID, actor string) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if err := authorise(ctx, tx, accountID, actor, api.PrivilegeManageSSO); err != nil {
			return err
		}
		c, err := s.ssoWhere(ctx, tx, `c.account_id = $1 FOR UPDATE OF c`, accountID)
		if err != nil {
			return err
		}
		if aerr := appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "sso.removed",
			Subject: c.ID}); aerr != nil {
			return aerr
		}
		if n, err = revokeSSOSessionsTx(ctx, tx, accountID, c.ID, actor); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM innsegl_auth.sso_connections WHERE connection_id = $1`, c.ID); err != nil {
			return fmt.Errorf("accounts: removing the organisation's sign-in: %w", err)
		}
		return nil
	})
	return n, err
}

// revokeSSOSessionsTx revokes every live session the connection opened.
func revokeSSOSessionsTx(ctx context.Context, tx pgx.Tx, accountID, connectionID, actor string) (int, error) {
	tag, err := tx.Exec(ctx, `UPDATE innsegl_auth.sessions SET revoked_at = clock_timestamp()
		WHERE sso_connection_id = $1 AND revoked_at IS NULL`, connectionID)
	if err != nil {
		return 0, fmt.Errorf("accounts: revoking the sign-in's sessions: %w", err)
	}
	n := int(tag.RowsAffected())
	if n == 0 {
		return 0, nil
	}
	return n, appendAudit(ctx, tx, AuditEntry{Actor: actor, AccountID: accountID, Action: "sessions.revoked",
		Subject: connectionID, Detail: map[string]any{"count": n, "reason": "organisation sign-in changed"}})
}

// JoinThroughSSO answers the user's live membership of the connection's
// organisation, making them a member when they have never held one. A
// person with only ended memberships there was removed (a role change ends
// one row and begins another, so it always leaves one live): the
// organisation's sign-in does not bring them back.
func (s *Store) JoinThroughSSO(ctx context.Context, connectionID, userID string) (api.OrgMembership, bool, error) {
	var (
		out    api.OrgMembership
		joined bool
	)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		c, err := s.ssoWhere(ctx, tx, `c.connection_id = $1`, connectionID)
		if err != nil {
			return err
		}
		var live, ended int
		if err = tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE until IS NULL), count(*) FILTER (WHERE until IS NOT NULL)
			FROM innsegl_auth.memberships WHERE account_id = $1 AND user_id = $2`,
			c.AccountID, userID).Scan(&live, &ended); err != nil {
			return fmt.Errorf("accounts: reading the membership: %w", err)
		}
		switch {
		case live == 0 && ended > 0:
			return api.ErrRemovedMember
		case live == 0:
			if err = insertMemberTx(ctx, tx, c.AccountID, userID, RoleMember, userID,
				map[string]any{"via": "organisation sign-in", "connection": c.ID}); err != nil {
				return err
			}
			joined = true
		}
		role, err := roleOf(ctx, tx, c.AccountID, userID)
		if err != nil {
			return err
		}
		var operator bool
		if err = tx.QueryRow(ctx, `SELECT operator FROM innsegl_auth.accounts WHERE account_id = $1`,
			c.AccountID).Scan(&operator); err != nil {
			return fmt.Errorf("accounts: reading the organisation: %w", err)
		}
		out = api.OrgMembership{AccountID: c.AccountID, Name: c.AccountName, Operator: operator, Role: role}
		return nil
	})
	if err != nil {
		return api.OrgMembership{}, false, err
	}
	return out, joined, nil
}

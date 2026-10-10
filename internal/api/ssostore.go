// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// An identity provider's identities and the sessions they open (#485,
// migration 0019). An identity is the provider's (issuer, subject) pair,
// joined to an existing user; nothing else the provider says is stored.

// Errors the identity store answers.
var (
	// ErrIdentityNotFound: no user holds that (issuer, subject).
	ErrIdentityNotFound = errors.New("api: that identity is not linked to any account")
	// ErrIdentityLinkedElsewhere: another user holds that (issuer, subject).
	ErrIdentityLinkedElsewhere = errors.New("api: that identity is linked to another account")
)

// CreateSSOSession is CreateSession for a sign-in through an organisation's
// connection: no passkey, and the connection named, so removing or changing
// the connection can revoke it.
func (a *AuthStore) CreateSSOSession(ctx context.Context, userID, connectionID string, lifetime time.Duration) (token string, expiresAt time.Time, err error) {
	raw, err := newRandomID(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().UTC().Add(lifetime)
	if _, err = a.pool.Exec(ctx,
		`INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, expires_at, sso_connection_id)
		 VALUES ($1, $2, $3, $4)`,
		hashToken(raw), userID, expiresAt, connectionID); err != nil {
		return "", time.Time{}, fmt.Errorf("api: creating a session for user %s: %w", userID, err)
	}
	return raw, expiresAt, nil
}

// LinkOIDCIdentity joins (issuer, subject) to userID, recording the
// connection it came through. Linking it again to the same user changes
// nothing; to another user is ErrIdentityLinkedElsewhere.
func (a *AuthStore) LinkOIDCIdentity(ctx context.Context, issuer, subject, userID, connectionID string) error {
	var holder string
	err := a.pool.QueryRow(ctx, `
		WITH ins AS (
		    INSERT INTO innsegl_auth.oidc_identities (issuer, subject, user_id, connection_id)
		    VALUES ($1, $2, $3, $4)
		    ON CONFLICT (issuer, subject) DO NOTHING
		    RETURNING user_id)
		SELECT user_id FROM ins
		UNION ALL
		SELECT user_id FROM innsegl_auth.oidc_identities WHERE issuer = $1 AND subject = $2
		LIMIT 1`, issuer, subject, userID, connectionID).Scan(&holder)
	if err != nil {
		return fmt.Errorf("api: linking an identity: %w", err)
	}
	if holder != userID {
		return ErrIdentityLinkedElsewhere
	}
	return nil
}

// UserByOIDCIdentity answers the user (issuer, subject) is linked to, and
// stamps the identity's last use.
func (a *AuthStore) UserByOIDCIdentity(ctx context.Context, issuer, subject string) (string, error) {
	var userID string
	err := a.pool.QueryRow(ctx, `UPDATE innsegl_auth.oidc_identities SET last_used_at = clock_timestamp()
		WHERE issuer = $1 AND subject = $2 RETURNING user_id`, issuer, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrIdentityNotFound
	}
	if err != nil {
		return "", fmt.Errorf("api: looking up an identity: %w", err)
	}
	return userID, nil
}

// OIDCIdentityRow is one linked identity as the account page lists it: the
// organisation whose sign-in linked it, never the issuer or subject.
type OIDCIdentityRow struct {
	ID           int64
	Organisation string // empty when that organisation's sign-in has since gone
	SignInName   string
	LinkedAt     time.Time
	LastUsedAt   *time.Time
}

// OIDCIdentities lists a user's linked identities, oldest first.
func (a *AuthStore) OIDCIdentities(ctx context.Context, userID string) ([]OIDCIdentityRow, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT i.identity_id, coalesce(acc.name, ''), coalesce(c.sign_in_name, ''), i.created_at, i.last_used_at
		  FROM innsegl_auth.oidc_identities i
		  LEFT JOIN innsegl_auth.sso_connections c ON c.connection_id = i.connection_id
		  LEFT JOIN innsegl_auth.accounts acc ON acc.account_id = c.account_id
		 WHERE i.user_id = $1
		 ORDER BY i.created_at, i.identity_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("api: listing identities for user %s: %w", userID, err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (OIDCIdentityRow, error) {
		var r OIDCIdentityRow
		err := row.Scan(&r.ID, &r.Organisation, &r.SignInName, &r.LinkedAt, &r.LastUsedAt)
		return r, err
	})
}

// UnlinkOIDCIdentity removes one of the user's identities. Another user's,
// or none, is ErrIdentityNotFound. It stops the next sign-in; a session
// already open ends as any other does (expiry, signing out, or the account
// page's "sign out other sessions").
func (a *AuthStore) UnlinkOIDCIdentity(ctx context.Context, userID string, id int64) error {
	tag, err := a.pool.Exec(ctx, `DELETE FROM innsegl_auth.oidc_identities WHERE identity_id = $1 AND user_id = $2`,
		id, userID)
	if err != nil {
		return fmt.Errorf("api: unlinking an identity: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

// unlinkOIDCIdentityBySubject removes a link this server made a moment ago,
// when the organisation then refused the person: the link is undone so a
// refused join leaves nothing behind.
func (a *AuthStore) unlinkOIDCIdentityBySubject(ctx context.Context, userID, issuer, subject string) error {
	_, err := a.pool.Exec(ctx, `DELETE FROM innsegl_auth.oidc_identities
		WHERE issuer = $1 AND subject = $2 AND user_id = $3`, issuer, subject, userID)
	if err != nil {
		return fmt.Errorf("api: undoing a link: %w", err)
	}
	return nil
}

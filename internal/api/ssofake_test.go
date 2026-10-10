// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// fakeOrgs' organisation sign-in (#485). The connection is held here and
// ALSO written to the real database (as AcceptInvitationAsNewUser writes its
// user there), because a session opened through it names it by foreign key.
// internal/accounts runs the real spine's half (AUTH-008, AUTH-011).

type fakeSSO struct {
	conns      map[string]SSOConnection // by account
	joins      []string                 // connectionID|userID JoinThroughSSO was asked
	joinErr    error                    // answered by JoinThroughSSO when set
	setErr     error                    // answered by SetSSOConnection when set
	removed    []string                 // accountID|actor
	removedErr error
}

func (f *fakeOrgs) sso() *fakeSSO {
	if f.ssoState == nil {
		f.ssoState = &fakeSSO{conns: map[string]SSOConnection{}}
	}
	return f.ssoState
}

func (f *fakeOrgs) SSOConnection(_ context.Context, accountID string) (SSOConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.sso().conns[accountID]
	if !ok {
		return SSOConnection{}, ErrSSONotConfigured
	}
	return c, nil
}

func (f *fakeOrgs) SSOConnectionByName(_ context.Context, name string) (SSOConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.sso().conns {
		if c.SignInName == strings.ToLower(strings.TrimSpace(name)) {
			return c, nil
		}
	}
	return SSOConnection{}, ErrSSONotConfigured
}

func (f *fakeOrgs) SSOConnectionByID(_ context.Context, id string) (SSOConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.sso().conns {
		if c.ID == id {
			return c, nil
		}
	}
	return SSOConnection{}, ErrSSONotConfigured
}

func (f *fakeOrgs) SetSSOConnection(ctx context.Context, accountID string, p SSOConnectionParams, actor string) (SSOConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sso().setErr != nil {
		return SSOConnection{}, f.sso().setErr
	}
	old, exists := f.sso().conns[accountID]
	id := old.ID
	if !exists {
		id = strings.Repeat(accountID[:1], 31) + "5"
	}
	if p.KeepSecret && p.ClientSecret == "" {
		p.ClientSecret = old.ClientSecret
	}
	name := ""
	for _, m := range f.memberships[actor] {
		if m.AccountID == accountID {
			name = m.Name
		}
	}
	c := SSOConnection{ID: id, AccountID: accountID, AccountName: name, SignInName: p.SignInName, Issuer: p.Issuer,
		ClientID: p.ClientID, ClientSecret: p.ClientSecret, UpdatedAt: time.Now().UTC()}
	if err := f.persistSSO(ctx, c); err != nil {
		return SSOConnection{}, err
	}
	f.sso().conns[accountID] = c
	return c, nil
}

// persistSSO writes the account and connection rows a session's foreign key
// needs.
func (f *fakeOrgs) persistSSO(ctx context.Context, c SSOConnection) error {
	conn, err := pgx.Connect(ctx, f.ownerDSN)
	if err != nil {
		return err
	}
	defer func() { discardError(conn.Close(ctx)) }()
	_, err = conn.Exec(ctx, `
		INSERT INTO innsegl_auth.accounts (account_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING;`, c.AccountID, c.AccountName)
	if err != nil {
		return err
	}
	_, err = conn.Exec(ctx, `
		INSERT INTO innsegl_auth.sso_connections (connection_id, account_id, sign_in_name, issuer, client_id, client_secret)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (account_id) DO UPDATE SET sign_in_name = EXCLUDED.sign_in_name, issuer = EXCLUDED.issuer,
		    client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret`,
		c.ID, c.AccountID, c.SignInName, c.Issuer, c.ClientID, c.ClientSecret)
	return err
}

func (f *fakeOrgs) RemoveSSOConnection(_ context.Context, accountID, actor string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sso().removedErr != nil {
		return 0, f.sso().removedErr
	}
	if _, ok := f.sso().conns[accountID]; !ok {
		return 0, ErrSSONotConfigured
	}
	delete(f.sso().conns, accountID)
	f.sso().removed = append(f.sso().removed, accountID+"|"+actor)
	return 1, nil
}

func (f *fakeOrgs) JoinThroughSSO(_ context.Context, connectionID, userID string) (OrgMembership, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sso().joins = append(f.sso().joins, connectionID+"|"+userID)
	if f.sso().joinErr != nil {
		return OrgMembership{}, false, f.sso().joinErr
	}
	for _, c := range f.sso().conns {
		if c.ID != connectionID {
			continue
		}
		for _, m := range f.memberships[userID] {
			if m.AccountID == c.AccountID {
				return m, false, nil
			}
		}
		m := OrgMembership{AccountID: c.AccountID, Name: c.AccountName, Role: roleMember}
		f.memberships[userID] = append(f.memberships[userID], m)
		return m, true, nil
	}
	return OrgMembership{}, false, ErrSSONotConfigured
}

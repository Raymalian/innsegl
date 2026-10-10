// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/api"
)

// An organisation's identity-provider connection (#485, E30), against a real
// Postgres. The sign-in flow itself is internal/api's (AUTH-009, AUTH-010);
// these are the spine's rules: who may set it, what it records, and who an
// organisation's sign-in may let in.

var acmeSSO = api.SSOConnectionParams{
	SignInName: "acme", Issuer: "https://idp.example.test", ClientID: "innsegl", ClientSecret: "top-secret",
}

func seedSSOSession(t *testing.T, e *env, user, hash, connectionID string) {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, expires_at, sso_connection_id)
		VALUES ($1, $2, now() + interval '1 day', $3)`, hash, user, connectionID); err != nil {
		t.Fatal(err)
	}
}

// AUTH-008 (spine): only an owner sets or removes the connection; the audit
// trail records that it changed and never the issuer, client or secret; a
// sign-in name belongs to one organisation; changing the issuer or client,
// or removing the connection, revokes every session it opened.
func TestAUTH008OnlyTheOwnerSetsTheConnectionAndItsSessionsEndWithIt(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)

	for _, actor := range []string{"u-admin", "u-member"} {
		if _, err := s.SetSSOConnection(ctx, a.ID, acmeSSO, actor); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s set the connection: %v, want ErrForbidden", actor, err)
		}
	}
	if _, err := s.SSOConnection(ctx, a.ID); !errors.Is(err, api.ErrSSONotConfigured) {
		t.Fatalf("no connection yet: %v, want ErrSSONotConfigured", err)
	}
	for _, bad := range []api.SSOConnectionParams{
		{SignInName: "A", Issuer: acmeSSO.Issuer, ClientID: "c"},
		{SignInName: "acme", Issuer: "http://idp.example.test", ClientID: "c"},
		{SignInName: "acme", Issuer: acmeSSO.Issuer},
	} {
		if _, err := s.SetSSOConnection(ctx, a.ID, bad, "u-1"); !errors.Is(err, api.ErrOrgInvalid) {
			t.Errorf("%+v: %v, want ErrOrgInvalid", bad, err)
		}
	}

	c, err := s.SetSSOConnection(ctx, a.ID, acmeSSO, "u-1")
	if err != nil {
		t.Fatalf("the owner set the connection: %v", err)
	}
	if len(c.ID) != 32 || c.AccountID != a.ID || c.SignInName != "acme" || c.ClientSecret != "top-secret" ||
		c.AccountName != "Acme" {
		t.Fatalf("connection = %+v", c)
	}
	byName, err := s.SSOConnectionByName(ctx, "acme")
	if err != nil || byName.ID != c.ID {
		t.Fatalf("by name: %+v %v", byName, err)
	}
	if _, err = s.SSOConnectionByName(ctx, "nobody"); !errors.Is(err, api.ErrSSONotConfigured) {
		t.Fatalf("an unknown name: %v", err)
	}

	recordPseudonymous(t, e)
	other, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Other", Owner: "u-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetSSOConnection(ctx, other.ID, acmeSSO, "u-admin"); !errors.Is(err, api.ErrSSONameTaken) {
		t.Fatalf("a second organisation took the sign-in name: %v, want ErrSSONameTaken", err)
	}

	// Editing with the secret left blank keeps it; the id stays.
	keep := acmeSSO
	keep.ClientSecret, keep.KeepSecret = "", true
	seedSSOSession(t, e, "u-member", strings.Repeat("a", 64), c.ID)
	again, err := s.SetSSOConnection(ctx, a.ID, keep, "u-1")
	if err != nil || again.ID != c.ID || again.ClientSecret != "top-secret" {
		t.Fatalf("edit keeping the secret: %+v %v", again, err)
	}
	if n := liveSessions(t, e, "u-member"); n != 1 {
		t.Fatalf("an edit that kept the issuer and client revoked %d sessions", 1-n)
	}
	moved := acmeSSO
	moved.Issuer = "https://idp2.example.test"
	if _, err = s.SetSSOConnection(ctx, a.ID, moved, "u-1"); err != nil {
		t.Fatal(err)
	}
	if n := liveSessions(t, e, "u-member"); n != 0 {
		t.Fatalf("a new issuer left %d sessions of the old one live", n)
	}

	seedSSOSession(t, e, "u-member", strings.Repeat("b", 64), c.ID)
	seedSession(t, e, "u-member", strings.Repeat("c", 64))
	if _, err = s.RemoveSSOConnection(ctx, a.ID, "u-admin"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin removed the connection: %v", err)
	}
	n, err := s.RemoveSSOConnection(ctx, a.ID, "u-1")
	if err != nil || n != 1 {
		t.Fatalf("remove: %d %v, want the one session it opened revoked", n, err)
	}
	if live := liveSessions(t, e, "u-member"); live != 1 {
		t.Fatalf("the passkey session was revoked too, or the SSO one survived: %d live", live)
	}
	if _, err = s.RemoveSSOConnection(ctx, a.ID, "u-1"); !errors.Is(err, api.ErrSSONotConfigured) {
		t.Fatalf("removing twice: %v", err)
	}

	got := strings.Join(auditActions(t, e, a.ID), ",")
	if !strings.HasSuffix(got, "sso.configured,sso.configured,sso.configured,sessions.revoked,sso.removed,sessions.revoked") {
		t.Fatalf("audit = %s", got)
	}
	cn, cctx := ownerConn(t, e.ownerDSN)
	var dump string
	if err = cn.QueryRow(cctx, `SELECT string_agg(row_to_json(x)::text, '') FROM innsegl_auth.audit x`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"idp.example.test", "idp2.example.test", "top-secret", `"innsegl"`} {
		if strings.Contains(dump, leak) {
			t.Errorf("the audit trail holds %q", leak)
		}
	}
}

// AUTH-011 (spine): an organisation's sign-in lets an existing person in as
// a member, once; it never brings back someone the organisation removed,
// and an invitation does.
func TestAUTH011JoiningThroughTheSignInNeverReturnsARemovedMember(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)
	seedUser(t, e, "u-new")
	c, err := s.SetSSOConnection(ctx, a.ID, acmeSSO, "u-1")
	if err != nil {
		t.Fatal(err)
	}

	m, joined, err := s.JoinThroughSSO(ctx, c.ID, "u-new")
	if err != nil || !joined || m.AccountID != a.ID || m.Role != RoleMember {
		t.Fatalf("first join: %+v %v %v", m, joined, err)
	}
	m, joined, err = s.JoinThroughSSO(ctx, c.ID, "u-new")
	if err != nil || joined || m.Role != RoleMember {
		t.Fatalf("second join: %+v %v %v, want the live membership unchanged", m, joined, err)
	}
	m, joined, err = s.JoinThroughSSO(ctx, c.ID, "u-admin")
	if err != nil || joined || m.Role != RoleAdmin {
		t.Fatalf("an admin signing in: %+v %v %v, want their role kept", m, joined, err)
	}
	if err = s.SetRole(ctx, a.ID, "u-new", RoleAdmin, "u-1"); err != nil {
		t.Fatal(err)
	}
	if _, joined, err = s.JoinThroughSSO(ctx, c.ID, "u-new"); err != nil || joined {
		t.Fatalf("after a role change: joined=%v %v", joined, err)
	}

	seedSSOSession(t, e, "u-new", strings.Repeat("e", 64), c.ID)
	r, err := s.RemoveMember(ctx, a.ID, "u-new", "u-1")
	if err != nil || r.SessionsRevoked != 1 {
		t.Fatalf("removal: %+v %v, want the SSO session revoked", r, err)
	}
	if _, _, err = s.JoinThroughSSO(ctx, c.ID, "u-new"); !errors.Is(err, api.ErrRemovedMember) {
		t.Fatalf("a removed member signed back in: %v, want ErrRemovedMember", err)
	}
	if _, _, err = s.JoinThroughSSO(ctx, strings.Repeat("0", 32), "u-new"); !errors.Is(err, api.ErrSSONotConfigured) {
		t.Fatalf("an unknown connection: %v", err)
	}

	code, _, err := s.CreateInvitation(ctx, a.ID, RoleMember, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcceptInvitation(ctx, code, "u-new"); err != nil {
		t.Fatal(err)
	}
	if _, joined, err = s.JoinThroughSSO(ctx, c.ID, "u-new"); err != nil || joined {
		t.Fatalf("re-invited: joined=%v %v, want the invitation's membership", joined, err)
	}

	got := auditActions(t, e, a.ID)
	var added []string
	for _, action := range got {
		if action == "membership.added" {
			added = append(added, action)
		}
	}
	// owner, admin, member at setup; u-new by sign-in; u-new by invitation.
	if len(added) != 5 {
		t.Errorf("membership.added rows = %d in %v", len(added), got)
	}
}

// AUTH-011 (migration): 0019 is additive. Existing users, passkeys and
// sessions keep every value, a session from before it names no connection,
// and every earlier ceremony kind is still accepted beside the new ones.
func TestAUTH011TheMigrationKeepsEveryExistingSignIn(t *testing.T) {
	e, l := premigration(t, "0019")
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx, `
		INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('u-old', 'Old Person');
		INSERT INTO innsegl_auth.passkeys (credential_id, user_id, credential, attestation_format)
		     VALUES ('cred-old', 'u-old', '{}', 'none');
		INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, passkey_id, expires_at)
		     VALUES (repeat('a', 64), 'u-old', 'cred-old', now() + interval '1 day')`); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var s string
		if err := c.QueryRow(ctx, `SELECT
			(SELECT string_agg(u::text, '|') FROM innsegl_auth.users u) ||
			(SELECT string_agg(p::text, '|') FROM innsegl_auth.passkeys p) ||
			(SELECT string_agg(row(s.session_id_hash, s.user_id, s.passkey_id, s.created_at, s.expires_at,
			     s.revoked_at)::text, '|') FROM innsegl_auth.sessions s)`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot()
	if err := l.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("existing sign-in rows changed:\nbefore %s\nafter  %s", before, after)
	}
	var unlinked bool
	if err := c.QueryRow(ctx, `SELECT sso_connection_id IS NULL FROM innsegl_auth.sessions`).Scan(&unlinked); err != nil || !unlinked {
		t.Fatalf("an existing session names a connection: %v %v", unlinked, err)
	}
	for _, kind := range []string{"login", "remove_member", "resume_installation", "sso", "configure_sso", "remove_sso"} {
		if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.webauthn_ceremonies (ceremony_id, kind, session_data, expires_at)
			VALUES ($1, $2, '{}', now() + interval '1 minute')`, "cer-"+kind, kind); err != nil {
			t.Errorf("ceremony kind %s refused: %v", kind, err)
		}
	}
}

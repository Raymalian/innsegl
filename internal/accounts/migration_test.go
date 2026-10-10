// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const spineVersion = "0010"

func ownerConn(t *testing.T, dsn string) (*pgx.Conn, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, ctx
}

// ACC-001: the migration is additive. Existing users, passkeys and sessions
// are untouched; every existing user owns exactly one account; the first
// account is the operator's.
func TestACC001MigrationIsAdditiveAndGivesEveryUserAnAccount(t *testing.T) {
	e, l := premigration(t, spineVersion)
	c, ctx := ownerConn(t, e.ownerDSN)

	for i, id := range []string{"u-first", "u-second", "u-third"} {
		if _, err := c.Exec(ctx,
			`INSERT INTO innsegl_auth.users (user_id, display_name, created_at) VALUES ($1, $2, $3)`,
			id, "Person "+id, time.Date(2026, 9, 1+i, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.passkeys (credential_id, user_id, credential, attestation_format)
		VALUES ('cred-1', 'u-first', '{}', 'none')`); err != nil {
		t.Fatalf("passkey: %v", err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, expires_at)
		VALUES (repeat('a', 64), 'u-first', now() + interval '1 day')`); err != nil {
		t.Fatalf("session: %v", err)
	}

	snapshot := func() string {
		var s string
		q := `SELECT (SELECT coalesce(string_agg(u::text, '|' ORDER BY user_id), '') FROM innsegl_auth.users u) ||
			(SELECT coalesce(string_agg(p::text, '|' ORDER BY credential_id), '') FROM innsegl_auth.passkeys p) ||
			(SELECT coalesce(string_agg(s::text, '|' ORDER BY session_id_hash), '') FROM innsegl_auth.sessions s)`
		if err := c.QueryRow(ctx, q).Scan(&s); err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		return s
	}
	before := snapshot()
	if err := l.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("existing users/passkeys/sessions changed:\nbefore %s\nafter  %s", before, after)
	}

	rows, err := c.Query(ctx, `SELECT u.user_id, a.operator, m.role, a.account_id,
			(SELECT count(*) FROM innsegl_auth.memberships WHERE user_id = u.user_id),
			(SELECT count(*) FROM innsegl_auth.audit WHERE account_id = a.account_id AND action = 'account.created')
		FROM innsegl_auth.users u
		JOIN innsegl_auth.memberships m ON m.user_id = u.user_id AND m.until IS NULL
		JOIN innsegl_auth.accounts a ON a.account_id = m.account_id
		ORDER BY u.created_at`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	ids := map[string]bool{}
	for rows.Next() {
		var user, role, account string
		var operator bool
		var memberships, audits int
		if err := rows.Scan(&user, &operator, &role, &account, &memberships, &audits); err != nil {
			t.Fatal(err)
		}
		if role != "owner" || memberships != 1 || audits != 1 {
			t.Errorf("%s: role %q, %d memberships, %d audit rows; want owner, 1, 1", user, role, memberships, audits)
		}
		if len(account) != 32 || strings.Trim(account, "0123456789abcdef") != "" {
			t.Errorf("%s: account id %q is not 32 lowercase hex", user, account)
		}
		ids[account] = true
		got = append(got, user+":"+map[bool]string{true: "operator", false: "plain"}[operator])
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := "u-first:operator,u-second:plain,u-third:plain"
	if strings.Join(got, ",") != want {
		t.Fatalf("accounts = %v, want %s", got, want)
	}
	if len(ids) != 3 {
		t.Fatalf("accounts are not distinct: %v", ids)
	}
}

// ACC-005: migration 0017 is additive. An invitation and a ceremony written
// before it are untouched and still read; the operator's CLI may then invite
// with no inviter, and an accepted invitation names who accepted it.
func TestACC005Migration0017KeepsWhatWasThere(t *testing.T) {
	e, l := premigration(t, "0017")
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx, `
		INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('u-old', 'Old');
		INSERT INTO innsegl_auth.accounts (account_id, name) VALUES ('acct-old', 'Old Org');
		INSERT INTO innsegl_auth.invitations (account_id, role, code_hash, created_by, expires_at)
		     VALUES ('acct-old', 'member', repeat('c', 64), 'u-old', now() + interval '1 day');
		INSERT INTO innsegl_auth.webauthn_ceremonies (ceremony_id, kind, session_data, expires_at)
		     VALUES ('cer-old', 'revoke_installation', '{}', now() + interval '1 minute')`); err != nil {
		t.Fatalf("seed before 0017: %v", err)
	}
	snapshot := func() string {
		var s string
		if err := c.QueryRow(ctx, `SELECT
			(SELECT string_agg(concat_ws('|', invitation_id, account_id, role, code_hash, created_by, expires_at, used_at), ',')
			   FROM innsegl_auth.invitations) ||
			(SELECT string_agg(concat_ws('|', ceremony_id, kind, session_data), ',') FROM innsegl_auth.webauthn_ceremonies)`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot()
	if err := l.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("0017 changed existing rows:\n%s\n%s", before, after)
	}
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.invitations (account_id, role, code_hash, expires_at)
		VALUES ('acct-old', 'admin', repeat('d', 64), now() + interval '1 day')`); err != nil {
		t.Errorf("an invitation with no inviter: %v", err)
	}
	if _, err := c.Exec(ctx, `UPDATE innsegl_auth.invitations SET used_at = now() WHERE code_hash = repeat('c', 64)`); err == nil {
		t.Errorf("an accepted invitation that names nobody was admitted")
	}
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.webauthn_ceremonies (ceremony_id, kind, session_data, expires_at)
		VALUES ('cer-new', 'register_invited', '{}', now() + interval '1 minute')`); err != nil {
		t.Errorf("the new ceremony kind: %v", err)
	}
}

// ACC-001: a deployment with no users gets no account.
func TestACC001EmptyDeploymentGetsNoAccounts(t *testing.T) {
	e, _ := migrated(t)
	c, ctx := ownerConn(t, e.ownerDSN)
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.accounts`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("accounts = %d, err %v; want 0", n, err)
	}
}

// LED-045: client_id keeps gateway_run_mapping insert-only, and the migration
// leaves the ledger's event count and last hash alone.
func TestLED045ClientIDKeepsTheMappingInsertOnlyAndLeavesTheLedgerAlone(t *testing.T) {
	e, l := premigration(t, spineVersion)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for n := 1; n <= 3; n++ {
		if _, err := l.Append(ctx, eventBody(n)); err != nil {
			t.Fatalf("Append %d: %v", n, err)
		}
	}
	countBefore, err := l.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := l.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := ownerConn(t, e.ownerDSN)
	if _, err = c.Exec(ctx, `INSERT INTO innsegl.gateway_run_mapping (run_id, session_id, agent_id)
		VALUES ('run-1', 's-1', 'a-1')`); err != nil {
		t.Fatalf("insert mapping: %v", err)
	}

	if err = l.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	countAfter, err := l.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	headAfter, err := l.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if countAfter != countBefore || headAfter != headBefore || countBefore != 3 {
		t.Fatalf("ledger changed: count %d -> %d, head %+v -> %+v", countBefore, countAfter, headBefore, headAfter)
	}

	var clientID *string
	if err := c.QueryRow(ctx, `SELECT client_id FROM innsegl.gateway_run_mapping`).Scan(&clientID); err != nil || clientID != nil {
		t.Fatalf("pre-existing row client_id = %v, err %v; want NULL", clientID, err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO innsegl.gateway_run_mapping (run_id, session_id, agent_id, client_id)
		VALUES ('run-2', 's-1', 'a-1', 'abc')`); err != nil {
		t.Fatalf("insert with client_id: %v", err)
	}
	for _, stmt := range []string{
		`UPDATE innsegl.gateway_run_mapping SET client_id = 'x'`,
		`DELETE FROM innsegl.gateway_run_mapping`,
		`TRUNCATE innsegl.gateway_run_mapping`,
	} {
		_, err := c.Exec(ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "insert-only") {
			t.Errorf("%s: err = %v; want the insert-only refusal", stmt, err)
		}
	}
}

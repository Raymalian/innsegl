// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/erasure"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
)

// RM-303 (#482): every account change is audited; erasing an organisation
// removes its account data and its repositories' names and leaves the chain
// byte-identical. Real Postgres.

// ACC-009: each change appends exactly the audit rows it names, in the same
// transaction; the trail reads back newest first; and no role can rewrite it.
func TestACC009EveryChangeIsOneAuditRowAndTheTrailIsAppendOnly(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)

	count := func() int { return len(auditActions(t, e, a.ID)) }
	steps := []struct {
		name string
		do   func() error
		rows int
	}{
		{"invite", func() error { _, _, err := s.CreateInvitation(ctx, a.ID, RoleMember, "u-1"); return err }, 1},
		{"role change", func() error { return s.SetRole(ctx, a.ID, "u-member", RoleAdmin, "u-1") }, 1},
		{"role unchanged", func() error { return s.SetRole(ctx, a.ID, "u-member", RoleAdmin, "u-1") }, 0},
		{"refused change", func() error {
			if err := s.SetRole(ctx, a.ID, "u-1", RoleMember, "u-member"); !errors.Is(err, ErrForbidden) {
				return fmt.Errorf("want ErrForbidden, got %w", err)
			}
			return nil
		}, 0},
		{"grant", func() error { return s.GrantRepo(ctx, a.ID, "github.com/acme/app", "u-1") }, 1},
		{"remove (no sessions, no machines)", func() error {
			_, err := s.RemoveMember(ctx, a.ID, "u-member", "u-1")
			return err
		}, 1},
	}
	for _, st := range steps {
		before := count()
		if err := st.do(); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		if got := count() - before; got != st.rows {
			t.Errorf("%s wrote %d audit rows, want %d", st.name, got, st.rows)
		}
	}

	log, err := s.AuditLog(ctx, a.ID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 3 || log[0].Action != "membership.removed" || log[0].Actor != "u-1" ||
		log[0].Subject != "u-member" || log[0].At.IsZero() || log[1].Action != "repo_grant.created" {
		t.Fatalf("AuditLog = %+v", log)
	}
	all, err := s.AuditLog(ctx, "", 0)
	if err != nil || len(all) < count() {
		t.Fatalf("every account's trail: %d rows, %v", len(all), err)
	}

	for _, dsn := range []string{e.writer, e.ownerDSN} {
		c, cctx := ownerConn(t, dsn)
		for _, q := range []string{
			`UPDATE innsegl_auth.audit SET subject = 'x'`,
			`DELETE FROM innsegl_auth.audit`,
			`TRUNCATE innsegl_auth.audit`,
		} {
			if _, xerr := c.Exec(cctx, q); xerr == nil {
				t.Errorf("%q succeeded", q)
			}
		}
	}
}

// mayErase is the role table's answer, as the CLI passes it.
func mayErase(role string) bool { return api.RoleMay(role, api.PrivilegeEraseOrganisation) }

const eraseKey = "abababababababababababababababababababababababababababababababab"

// erasureFixture is two organisations on a pseudonymous chain: Beta, which
// will be erased, with a member, a machine, an invitation, a token and two
// repositories (one of them ended and since taken by Acme), and Acme, which
// keeps its own.
type erasureFixture struct {
	e        *env
	s        *Store
	acme     Account
	beta     Account
	ledger   *ledger.Store
	repos    *identity.Repositories
	betaRepo string
	handed   string
	acmeRepo string
}

func newErasureFixture(t *testing.T) *erasureFixture {
	t.Helper()
	e, s, acme := setup(t)
	ctx := tctx(t)
	recordPseudonymous(t, e)
	f := &erasureFixture{e: e, s: s, acme: acme,
		betaRepo: "github.com/beta/secret-plan", handed: "github.com/beta/handed-over",
		acmeRepo: "github.com/acme/app"}

	beta, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Beta Corp"})
	if err != nil {
		t.Fatal(err)
	}
	f.beta = beta
	for _, u := range []string{"u-beta-owner", "u-beta-member"} {
		seedUser(t, e, u)
	}
	if err = s.AddMember(ctx, beta.ID, "u-beta-owner", RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	if err = s.AddMember(ctx, beta.ID, "u-beta-member", RoleMember, "u-beta-owner"); err != nil {
		t.Fatal(err)
	}
	// u-1 belongs to both: erasing Beta must leave their Acme membership.
	if err = s.AddMember(ctx, beta.ID, "u-1", RoleAdmin, "u-beta-owner"); err != nil {
		t.Fatal(err)
	}
	seedSession(t, e, "u-beta-member", strings.Repeat("e", 64))
	for _, g := range []struct{ acct, repo string }{
		{beta.ID, f.betaRepo}, {beta.ID, f.handed}, {acme.ID, f.acmeRepo},
	} {
		if err = s.GrantRepo(ctx, g.acct, g.repo, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.EndRepoGrant(ctx, beta.ID, f.handed, ""); err != nil {
		t.Fatal(err)
	}
	if err = s.GrantRepo(ctx, acme.ID, f.handed, ""); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateInstallation(ctx, InstallationParams{AccountID: beta.ID, CreatedBy: "u-beta-member",
		Name: "beta laptop", Kind: KindWorkstation, Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.CreateEnrolmentToken(ctx, TokenParams{AccountID: beta.ID, CreatedBy: "u-beta-owner"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.CreateInvitation(ctx, beta.ID, RoleMember, "u-beta-owner"); err != nil {
		t.Fatal(err)
	}

	l, err := ledger.Open(ctx, e.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	f.ledger = l
	f.repos, err = identity.NewRepositories(identity.ModePseudonymous, eraseKey)
	if err != nil {
		t.Fatal(err)
	}
	l.UseRepositories(f.repos)
	for i, r := range []string{f.betaRepo, f.handed, f.acmeRepo, f.betaRepo} {
		b := eventBody(100 + i)
		b[event.FieldEventType] = event.EventTypeRunRegistered
		b[event.FieldRunID] = fmt.Sprintf("run-erase-%d", i)
		b[event.FieldSpiffeID] = "spiffe://innsegl.dev/agent/fix-ci/jira-118/" + fmt.Sprintf("run-erase-%d", i)
		b[event.FieldAgentType] = "fix-ci"
		b[event.FieldTaskRef] = "jira-118"
		b[event.FieldRepo] = r
		b[event.FieldBranch] = "main"
		delete(b, "tool_name")
		if _, aerr := l.Append(ctx, b); aerr != nil {
			t.Fatalf("append %d: %v", i, aerr)
		}
	}
	return f
}

// ownerPool connects as the database owner, the role erasure runs as.
func (f *erasureFixture) ownerPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(tctx(t), f.e.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func (f *erasureFixture) chain(t *testing.T) ([]byte, ledger.Head) {
	t.Helper()
	ctx := tctx(t)
	n, err := f.ledger.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, cctx := ownerConn(t, f.e.ownerDSN)
	var rows []byte
	if err = c.QueryRow(cctx, `SELECT string_agg(canonical::text, E'\n' ORDER BY chain_position)
		FROM innsegl.events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	records, err := f.ledger.Events(ctx, 1, n)
	if err != nil {
		t.Fatal(err)
	}
	head, err := ledger.Verify(records)
	if err != nil {
		t.Fatal(err)
	}
	return rows, head
}

func (f *erasureFixture) rowsFor(t *testing.T, accountID string) map[string]int {
	t.Helper()
	c, ctx := ownerConn(t, f.e.ownerDSN)
	out := map[string]int{}
	for _, table := range []string{"accounts", "memberships", "installations", "enrolment_tokens",
		"repo_grants", "invitations"} {
		var n int
		if err := c.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.`+table+` WHERE account_id = $1`,
			accountID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

func (f *erasureFixture) aliases(t *testing.T) map[string]string {
	t.Helper()
	c, ctx := ownerConn(t, f.e.ownerDSN)
	rows, err := c.Query(ctx, `SELECT value, literal FROM innsegl.pseudonyms WHERE kind = 'repo'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var v, l string
		if err := rows.Scan(&v, &l); err != nil {
			t.Fatal(err)
		}
		out[l] = v
	}
	return out
}

// ACC-010: erasing an organisation deletes its account rows and the aliases
// of the repositories only it held, revokes its members' sessions, and
// changes no byte of the chain. A repository another organisation now holds
// keeps its name; the other organisation keeps everything.
func TestACC010ErasingAnOrganisationLeavesTheChainByteIdentical(t *testing.T) {
	f := newErasureFixture(t)
	ctx := tctx(t)
	rowsBefore, headBefore := f.chain(t)
	acmeBefore := f.rowsFor(t, f.acme.ID)
	if got := f.aliases(t); got[f.betaRepo] == "" || got[f.acmeRepo] == "" || got[f.handed] == "" {
		t.Fatalf("aliases before = %v", got)
	}

	res, err := erasure.Organisation(ctx, f.ownerPool(t), f.beta.ID, "u-beta-owner", mayErase)
	if err != nil {
		t.Fatalf("erasure.Organisation: %v", err)
	}
	if !slices.Equal(res.Repositories, []string{f.betaRepo}) || !slices.Equal(res.Kept, []string{f.handed}) {
		t.Errorf("erased repositories %v kept %v, want [%s] and [%s]", res.Repositories, res.Kept, f.betaRepo, f.handed)
	}
	if res.Members != 3 || res.Installations != 1 || res.SessionsRevoked != 1 || len(res.Pseudonyms) == 0 {
		t.Errorf("result = %+v", res)
	}

	for table, n := range f.rowsFor(t, f.beta.ID) {
		if n != 0 {
			t.Errorf("%d rows of %s remain for the erased organisation", n, table)
		}
	}
	if got := f.rowsFor(t, f.acme.ID); fmt.Sprint(got) != fmt.Sprint(acmeBefore) {
		t.Errorf("Acme's rows changed: %v -> %v", acmeBefore, got)
	}
	al := f.aliases(t)
	if _, ok := al[f.betaRepo]; ok {
		t.Errorf("the erased organisation's repository still resolves")
	}
	if al[f.acmeRepo] == "" || al[f.handed] == "" {
		t.Errorf("another organisation's repository lost its name: %v", al)
	}
	if n := liveSessions(t, f.e, "u-beta-member"); n != 0 {
		t.Errorf("an erased organisation's member keeps %d sessions", n)
	}
	ms, err := f.s.Memberships(ctx, "u-1")
	if err != nil || len(ms) != 1 || ms[0].AccountID != f.acme.ID {
		t.Errorf("u-1's memberships after erasure = %+v %v, want only Acme", ms, err)
	}

	rowsAfter, headAfter := f.chain(t)
	if !bytes.Equal(rowsBefore, rowsAfter) || headAfter != headBefore {
		t.Fatalf("the chain changed under erasure: head %v -> %v", headBefore, headAfter)
	}

	c, cctx := ownerConn(t, f.e.ownerDSN)
	var detail string
	if err = c.QueryRow(cctx, `SELECT detail::text FROM innsegl_auth.audit
		WHERE action = 'account.erased' AND account_id = $1`, f.beta.ID).Scan(&detail); err != nil {
		t.Fatalf("no account.erased row: %v", err)
	}
	for _, leak := range []string{"secret-plan", "beta/", "Beta Corp"} {
		if strings.Contains(detail, leak) {
			t.Errorf("the erasure's audit row names %q: %s", leak, detail)
		}
	}
}

// ACC-015: the audit trail holds no name — no organisation or machine name
// and no repository literal — so erasing an organisation leaves nothing
// readable about it in any accounts table, while its audit rows stay.
func TestACC015AfterErasureNoAccountsTableNamesTheOrganisation(t *testing.T) {
	f := newErasureFixture(t)
	ctx := tctx(t)
	c, cctx := ownerConn(t, f.e.ownerDSN)
	// A passkey confirmation still pending for the organisation holds its
	// request, repositories included, as a mint's does.
	if _, err := c.Exec(cctx, `INSERT INTO innsegl_auth.webauthn_ceremonies
		(ceremony_id, kind, session_data, pending_user_id, expires_at)
		VALUES ('cer-beta', 'mint_enrolment_token', $1, 'u-beta-owner', now() + interval '5 minutes')`,
		`{"request":{"organisation_id":"`+f.beta.ID+`","repos":["`+f.betaRepo+`"]}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := erasure.Organisation(ctx, f.ownerPool(t), f.beta.ID, "", mayErase); err != nil {
		t.Fatal(err)
	}

	var auditRows int
	if err := c.QueryRow(cctx, `SELECT count(*) FROM innsegl_auth.audit WHERE account_id = $1`, f.beta.ID).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows < 5 {
		t.Fatalf("the erased organisation has %d audit rows; the trail is append-only and keeps them", auditRows)
	}
	rows, err := c.Query(cctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'innsegl_auth' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	for _, table := range tables {
		var dump string
		if err := c.QueryRow(cctx, `SELECT coalesce(string_agg(row_to_json(x)::text, E'\n'), '') FROM innsegl_auth.`+table+` x`).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		for what, name := range map[string]string{"organisation name": "Beta Corp", "repository": f.betaRepo,
			"machine name": "beta laptop"} {
			if strings.Contains(dump, name) {
				t.Errorf("innsegl_auth.%s still holds the erased organisation's %s", table, what)
			}
		}
	}
}

// ACC-011: who may erase, and what is never erased.
func TestACC011ErasureIsTheOwnersAndNeverTheOperators(t *testing.T) {
	f := newErasureFixture(t)
	ctx := tctx(t)
	pool := f.ownerPool(t)

	if _, err := erasure.Organisation(ctx, pool, f.beta.ID, "u-1", mayErase); !errors.Is(err, erasure.ErrNotOwner) {
		t.Errorf("an admin erases: %v, want ErrNotOwner", err)
	}
	if _, err := erasure.Organisation(ctx, pool, f.beta.ID, "u-stranger", mayErase); !errors.Is(err, erasure.ErrNotOwner) {
		t.Errorf("a stranger erases: %v, want ErrNotOwner", err)
	}
	if got := f.rowsFor(t, f.beta.ID); got["accounts"] != 1 || got["memberships"] != 3 {
		t.Fatalf("a refused erasure removed rows: %v", got)
	}

	seedUser(t, f.e, "u-op")
	if _, err := f.s.FoundOperator(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := f.s.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var op string
	for _, a := range list {
		if a.Operator {
			op = a.ID
		}
	}
	if _, err := erasure.Organisation(ctx, pool, op, "", mayErase); !errors.Is(err, erasure.ErrOperatorOrganisation) {
		t.Errorf("erasing the deployment's own organisation: %v, want ErrOperatorOrganisation", err)
	}

	if _, err := erasure.Organisation(ctx, pool, f.beta.ID, "", mayErase); err != nil {
		t.Fatalf("the operator's CLI erases: %v", err)
	}
	if _, err := erasure.Organisation(ctx, pool, f.beta.ID, "", mayErase); !errors.Is(err, erasure.ErrNoSuchOrganisation) {
		t.Errorf("erasing twice: %v, want ErrNoSuchOrganisation", err)
	}
	// The auth-writer role every service holds cannot delete an alias, so
	// it cannot erase.
	if _, err := erasure.Organisation(ctx, f.s.pool, f.acme.ID, "", mayErase); err == nil {
		t.Errorf("the auth-writer role erased an organisation")
	}
}

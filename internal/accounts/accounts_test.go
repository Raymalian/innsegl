// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func tctx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// seedUser inserts a user as the owner role does at enrolment.
func seedUser(t *testing.T, e *env, id string) {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ($1, $1)`, id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func auditActions(t *testing.T, e *env, account string) []string {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	rows, err := c.Query(ctx, `SELECT action FROM innsegl_auth.audit WHERE account_id = $1 ORDER BY id`, account)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func setup(t *testing.T) (*env, *Store, Account) {
	t.Helper()
	e, s := migrated(t)
	seedUser(t, e, "u-1")
	a, err := s.CreateAccount(tctx(t), CreateAccountParams{Name: "Acme"})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := s.AddMember(tctx(t), a.ID, "u-1", RoleOwner, ""); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	return e, s, a
}

func TestAccountsCreateAndMembership(t *testing.T) {
	e, s, a := setup(t)
	if len(a.ID) != 32 || a.Operator || a.Name != "Acme" {
		t.Fatalf("account = %+v", a)
	}
	if err := s.AddMember(tctx(t), a.ID, "u-1", RoleAdmin, ""); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("second live membership: %v, want ErrAlreadyMember", err)
	}
	if err := s.AddMember(tctx(t), a.ID, "u-1", "boss", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad role: %v, want ErrInvalid", err)
	}
	if _, err := s.CreateAccount(tctx(t), CreateAccountParams{Name: " "}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty name: %v, want ErrInvalid", err)
	}
	got := strings.Join(auditActions(t, e, a.ID), ",")
	if got != "account.created,membership.added" {
		t.Fatalf("audit = %s", got)
	}
}

// ACC-002: single use, expiry, hash only at rest.
func TestACC002EnrolmentTokenIsSingleUse(t *testing.T) {
	e, s, a := setup(t)
	tok, meta, err := s.CreateEnrolmentToken(tctx(t), TokenParams{
		AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"github.com/acme/app"}, Kind: KindService})
	if err != nil {
		t.Fatalf("CreateEnrolmentToken: %v", err)
	}
	if !strings.HasPrefix(tok, "ie_"+meta.TokenID+"_") || time.Until(meta.ExpiresAt) > 15*time.Minute {
		t.Fatalf("token %q meta %+v", tok, meta)
	}
	en, err := s.ConsumeEnrolmentToken(tctx(t), tok)
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if en.AccountID != a.ID || en.CreatedBy != "u-1" || en.Kind != KindService ||
		len(en.Repos) != 1 || en.Repos[0] != "github.com/acme/app" {
		t.Fatalf("enrolment = %+v", en)
	}
	if _, err := s.ConsumeEnrolmentToken(tctx(t), tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("second consume: %v, want ErrTokenInvalid", err)
	}
	got := strings.Join(auditActions(t, e, a.ID), ",")
	if !strings.HasSuffix(got, "enrolment_token.created,enrolment_token.consumed") {
		t.Fatalf("audit = %s", got)
	}
}

func TestACC002ConcurrentConsumeAdmitsExactlyOne(t *testing.T) {
	_, s, a := setup(t)
	tok, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{
		AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := s.ConsumeEnrolmentToken(context.Background(), tok); results <- err }()
	}
	ok := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d consumers succeeded, want exactly 1", ok)
	}
}

func TestACC002ExpiredAndForgedTokensAreRefused(t *testing.T) {
	e, s, a := setup(t)
	tok, meta, err := s.CreateEnrolmentToken(tctx(t), TokenParams{
		AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err = c.Exec(ctx, `UPDATE innsegl_auth.enrolment_tokens SET expires_at = now() - interval '1 second'
		WHERE token_id = $1`, meta.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConsumeEnrolmentToken(tctx(t), tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired consume: %v, want ErrTokenInvalid", err)
	}

	fresh, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(fresh, "_")
	forged := parts[0] + "_" + parts[1] + "_" + strings.Repeat("0", len(parts[2]))
	for _, bad := range []string{"", "ie_", "nonsense", forged, "ie_nosuchid_" + parts[2], fresh + "x"} {
		if _, err := s.ConsumeEnrolmentToken(tctx(t), bad); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("consume(%q): %v, want ErrTokenInvalid", bad, err)
		}
	}
	// The forgery did not burn the real token.
	if _, err := s.ConsumeEnrolmentToken(tctx(t), fresh); err != nil {
		t.Fatalf("real token after forgeries: %v", err)
	}
}

func TestACC002OnlyAHashIsAtRest(t *testing.T) {
	e, s, a := setup(t)
	tok, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Split(tok, "_")[2]
	c, ctx := ownerConn(t, e.ownerDSN)
	var row string
	if err := c.QueryRow(ctx, `SELECT t::text FROM innsegl_auth.enrolment_tokens t`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	var audit string
	if err := c.QueryRow(ctx, `SELECT coalesce(string_agg(x::text, ' '), '') FROM innsegl_auth.audit x`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for i := 0; i+12 <= len(secret); i++ {
		w := secret[i : i+12]
		if strings.Contains(row, w) || strings.Contains(audit, w) {
			t.Fatalf("a 12-character window of the secret (%s) is stored", w)
		}
	}
}

func TestAccountsTokenRepoValidation(t *testing.T) {
	_, s, a := setup(t)
	for _, repos := range [][]string{nil, {}, {"*", "github.com/a/b"}, {"notarepo"}, {"github.com/a/b", ""}} {
		_, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: repos})
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("repos %v: %v, want ErrInvalid", repos, err)
		}
	}
	if _, _, err := s.CreateEnrolmentToken(tctx(t), TokenParams{
		AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"*"}, Kind: "toaster"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad kind: %v, want ErrInvalid", err)
	}
}

func TestAccountsInstallationLifecycle(t *testing.T) {
	e, s, a := setup(t)
	tok, meta, err := s.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1", Repos: []string{"github.com/acme/app"}})
	if err != nil {
		t.Fatal(err)
	}
	en, err := s.ConsumeEnrolmentToken(tctx(t), tok)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := s.CreateInstallation(tctx(t), InstallationParams{
		AccountID: en.AccountID, CreatedBy: en.CreatedBy, Name: "laptop", Kind: en.Kind, Repos: en.Repos, TokenID: meta.TokenID})
	if err != nil {
		t.Fatalf("CreateInstallation: %v", err)
	}
	if len(inst.ID) != 32 || inst.Status != StatusActive || inst.Kind != KindWorkstation {
		t.Fatalf("installation = %+v", inst)
	}
	c, ctx := ownerConn(t, e.ownerDSN)
	var linked *string
	if err = c.QueryRow(ctx, `SELECT installation_id FROM innsegl_auth.enrolment_tokens WHERE token_id = $1`,
		meta.TokenID).Scan(&linked); err != nil || linked == nil || *linked != inst.ID {
		t.Fatalf("token.installation_id = %v, err %v; want %s", linked, err, inst.ID)
	}

	got, err := s.GetInstallation(tctx(t), inst.ID)
	if err != nil || got.AccountID != a.ID || got.Status != StatusActive || got.Repos[0] != "github.com/acme/app" {
		t.Fatalf("GetInstallation = %+v, %v", got, err)
	}
	if _, err = s.GetInstallation(tctx(t), strings.Repeat("0", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing installation: %v", err)
	}
	list, err := s.ListInstallations(tctx(t), a.ID)
	if err != nil || len(list) != 1 || list[0].ID != inst.ID {
		t.Fatalf("ListInstallations = %+v, %v", list, err)
	}

	if err = s.SetInstallationStatus(tctx(t), inst.ID, StatusSuspended, "u-1"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetInstallationStatus(tctx(t), inst.ID, StatusActive, "u-1"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetInstallationStatus(tctx(t), inst.ID, StatusRevoked, "u-1"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetInstallation(tctx(t), inst.ID)
	if err != nil || got.Status != StatusRevoked || got.RevokedAt == nil {
		t.Fatalf("after revoke: %+v", got)
	}
	if err := s.SetInstallationStatus(tctx(t), inst.ID, StatusActive, "u-1"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("un-revoke: %v, want ErrRevoked", err)
	}
	if err := s.SetInstallationStatus(tctx(t), inst.ID, "gone", "u-1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad status: %v", err)
	}
	if err := s.SetInstallationStatus(tctx(t), strings.Repeat("1", 32), StatusRevoked, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// Every write left a row.
	want := "account.created,membership.added,enrolment_token.created,enrolment_token.consumed," +
		"installation.created,installation.suspended,installation.active,installation.revoked"
	if g := strings.Join(auditActions(t, e, a.ID), ","); g != want {
		t.Fatalf("audit:\n got %s\nwant %s", g, want)
	}
}

// ACC-003: scope is the installation's repos intersected with the account's
// live grants.
func TestACC003Scope(t *testing.T) {
	e, s, a := setup(t)
	ctx := tctx(t)
	mk := func(repos ...string) Installation {
		i, err := s.CreateInstallation(ctx, InstallationParams{
			AccountID: a.ID, CreatedBy: "u-1", Name: "m", Kind: KindWorkstation, Repos: repos})
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	const r1, r2, r3 = "github.com/acme/one", "github.com/acme/two", "github.com/acme/three"
	listed := mk(r1, r3)
	star := mk("*")
	if err := s.GrantRepo(ctx, a.ID, r1, "u-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantRepo(ctx, a.ID, r2, "u-1"); err != nil {
		t.Fatal(err)
	}

	check := func(i Installation, repo string, want bool) {
		t.Helper()
		got, err := s.InScope(ctx, i.ID, repo)
		if err != nil || got != want {
			t.Errorf("InScope(%s, %s) = %v, %v; want %v", i.ID[:6], repo, got, err, want)
		}
	}
	check(listed, r1, true)  // listed and granted
	check(listed, r2, false) // granted, not listed
	check(listed, r3, false) // listed, not granted
	check(star, r1, true)
	check(star, r2, true)
	check(star, r3, false) // not granted
	check(star, "*", false)

	// Ending the grant withdraws admission at once.
	if err := s.EndRepoGrant(ctx, a.ID, r1, "u-1"); err != nil {
		t.Fatal(err)
	}
	check(listed, r1, false)
	check(star, r1, false)
	if err := s.EndRepoGrant(ctx, a.ID, r1, "u-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ending twice: %v, want ErrNotFound", err)
	}
	// ...and it can be granted again.
	if err := s.GrantRepo(ctx, a.ID, r1, "u-1"); err != nil {
		t.Fatal(err)
	}
	check(listed, r1, true)

	// A suspended or revoked installation admits nothing.
	if err := s.SetInstallationStatus(ctx, listed.ID, StatusSuspended, ""); err != nil {
		t.Fatal(err)
	}
	check(listed, r1, false)

	// Another account's grant never admits.
	other, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GrantRepo(ctx, other.ID, r3, ""); err != nil {
		t.Fatal(err)
	}
	check(star, r3, false)

	// An unknown installation is out of scope, not an error.
	if ok, err := s.InScope(ctx, strings.Repeat("9", 32), r1); err != nil || ok {
		t.Fatalf("unknown installation: %v, %v", ok, err)
	}
	if !strings.Contains(strings.Join(auditActions(t, e, a.ID), ","), "repo_grant.ended") {
		t.Fatal("ending a grant left no audit row")
	}
}

// ACC-003: one live holder per repo, enforced by the database.
func TestACC003OneLiveHolderPerRepoIsEnforcedByTheDatabase(t *testing.T) {
	e, s, a := setup(t)
	ctx := tctx(t)
	other, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	const repo = "github.com/acme/one"
	if err = s.GrantRepo(ctx, a.ID, repo, ""); err != nil {
		t.Fatal(err)
	}
	if err = s.GrantRepo(ctx, other.ID, repo, ""); !errors.Is(err, ErrRepoHeld) {
		t.Fatalf("second holder: %v, want ErrRepoHeld", err)
	}
	if err = s.GrantRepo(ctx, a.ID, repo, ""); err != nil {
		t.Fatalf("regranting to the holder should be a no-op: %v", err)
	}
	// Bypass the Go check: the index itself refuses.
	c, cctx := ownerConn(t, e.ownerDSN)
	_, err = c.Exec(cctx, `INSERT INTO innsegl_auth.repo_grants (account_id, repo) VALUES ($1, $2)`, other.ID, repo)
	if err == nil || !strings.Contains(err.Error(), "repo_grants_one_live_holder") {
		t.Fatalf("direct insert: %v; want the unique index to refuse", err)
	}
	// Once ended, another account may hold it.
	if err := s.EndRepoGrant(ctx, a.ID, repo, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantRepo(ctx, other.ID, repo, ""); err != nil {
		t.Fatalf("grant after end: %v", err)
	}
}

func TestAccountsAuditIsAppendOnlyForTheWriter(t *testing.T) {
	e, s, a := setup(t)
	c, ctx := ownerConn(t, e.writer)
	for _, stmt := range []string{
		`UPDATE innsegl_auth.audit SET action = 'x'`,
		`DELETE FROM innsegl_auth.audit`,
		`TRUNCATE innsegl_auth.audit`,
	} {
		if _, err := c.Exec(ctx, stmt); err == nil {
			t.Errorf("%s was admitted", stmt)
		}
	}
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.audit WHERE account_id = $1`, a.ID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("writer cannot read audit: %d, %v", n, err)
	}
	if err := s.Audit(tctx(t), AuditEntry{Actor: "u-1", AccountID: a.ID, Action: "custom.thing", Subject: "s",
		Detail: map[string]any{"k": "v"}}); err != nil {
		t.Fatalf("Audit: %v", err)
	}
}

func TestAccountsOpenRefusesALedgerWriter(t *testing.T) {
	e, _ := migrated(t)
	if _, err := Open(tctx(t), e.ownerDSN); err == nil {
		t.Fatal("Open accepted the owner credential, which can write the ledger")
	}
}

func TestAccountsStoreErrorPaths(t *testing.T) {
	_, s, a := setup(t)
	ctx := tctx(t)
	if err := s.AddMember(ctx, "nope", "u-1", RoleMember, ""); err == nil {
		t.Error("AddMember to a missing account succeeded")
	}
	if _, _, err := s.CreateEnrolmentToken(ctx, TokenParams{AccountID: "nope", CreatedBy: "u-1", Repos: []string{"*"}}); err == nil {
		t.Error("token for a missing account succeeded")
	}
	if _, err := s.CreateInstallation(ctx, InstallationParams{AccountID: a.ID, CreatedBy: "u-1", Name: "", Kind: KindService,
		Repos: []string{"*"}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("nameless installation: %v", err)
	}
	if err := s.GrantRepo(ctx, a.ID, "*", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("granting '*': %v", err)
	}
	if err := s.GrantRepo(ctx, "nope", "github.com/a/b", ""); err == nil {
		t.Error("grant to a missing account succeeded")
	}
	if _, err := s.ListInstallations(ctx, "nope"); err != nil {
		t.Errorf("listing an unknown account: %v", err)
	}
	s.Close()
	if _, err := s.GetInstallation(ctx, strings.Repeat("a", 32)); err == nil {
		t.Error("closed store answered")
	}
}

// ListAccounts answers every organisation with its owners and live repository
// grants, so an operator on the core can find the ids `enrol-token` needs.
func TestListAccountsNamesOwnersAndGrants(t *testing.T) {
	_, s, a := setup(t)
	ctx := tctx(t)
	if err := s.GrantRepo(ctx, a.ID, "github.com/acme/one", "u-1"); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *AccountSummary
	for i := range list {
		if list[i].ID == a.ID {
			got = &list[i]
		}
	}
	if got == nil {
		t.Fatalf("ListAccounts = %+v, missing %s", list, a.ID)
	}
	if got.Name != a.Name || len(got.Repos) != 1 || got.Repos[0] != "github.com/acme/one" {
		t.Errorf("summary = %+v", got)
	}
	if len(got.Owners) == 0 {
		t.Errorf("summary names no owner: %+v", got)
	}
}

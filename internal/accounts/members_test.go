// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/api"
)

// RM-301 (#480): owners, admins and members. Scope checks on the account
// surface only (plan, Authorization E1). These run against a real Postgres.

// orgWithPeople is an account with an owner (u-1), an admin and a member.
func orgWithPeople(t *testing.T) (*env, *Store, Account) {
	t.Helper()
	e, s, a := setup(t)
	for id, role := range map[string]string{"u-admin": RoleAdmin, "u-member": RoleMember} {
		seedUser(t, e, id)
		if err := s.AddMember(tctx(t), a.ID, id, role, "u-1"); err != nil {
			t.Fatalf("AddMember %s: %v", id, err)
		}
	}
	return e, s, a
}

func liveSessions(t *testing.T, e *env, user string) int {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	var n int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM innsegl_auth.sessions
		WHERE user_id = $1 AND revoked_at IS NULL`, user).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func seedSession(t *testing.T, e *env, user, hash string) {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl_auth.sessions (session_id_hash, user_id, expires_at)
		VALUES ($1, $2, now() + interval '1 day')`, hash, user); err != nil {
		t.Fatal(err)
	}
}

// ACC-004: the role matrix, asked of the store the CLI and the API share.
// Owner: everything, including the owner role and erasure. Admin: members
// (never an owner), machines. Member: read, and their own machines. A user
// outside the account may do nothing in it.
func TestACC004TheRoleMatrixIsTheOneTable(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)
	seedUser(t, e, "u-stranger")

	cases := []struct {
		user, action string
		want         bool
	}{
		{"u-1", api.PrivilegeManageMembers, true},
		{"u-1", api.PrivilegeManageOwners, true},
		{"u-1", api.PrivilegeEraseOrganisation, true},
		{"u-1", api.PrivilegeConnectMachine, true},
		{"u-admin", api.PrivilegeManageMembers, true},
		{"u-admin", api.PrivilegeManageOwners, false},
		{"u-admin", api.PrivilegeEraseOrganisation, false},
		{"u-admin", api.PrivilegeRevokeMachine, true},
		{"u-member", api.PrivilegeReadLedger, true},
		{"u-member", api.PrivilegeConnectMachine, true},
		{"u-member", api.PrivilegeRevokeMachine, false},
		{"u-member", api.PrivilegeManageMembers, false},
		{"u-member", api.PrivilegeEraseOrganisation, false},
		{"u-stranger", api.PrivilegeReadLedger, false},
	}
	for _, tc := range cases {
		err := s.Authorise(ctx, a.ID, tc.user, tc.action)
		if tc.want && err != nil {
			t.Errorf("%s may %s: refused: %v", tc.user, tc.action, err)
		}
		if !tc.want && !errors.Is(err, ErrForbidden) {
			t.Errorf("%s may not %s: err = %v, want ErrForbidden", tc.user, tc.action, err)
		}
	}
	if err := s.Authorise(ctx, a.ID, "", api.PrivilegeEraseOrganisation); err != nil {
		t.Errorf("the operator's CLI (no actor) is refused: %v", err)
	}
}

// ACC-005: add, change and list members; the owner role is the owner's to
// give or take; the last owner stays; every change is one audit row.
func TestACC005MembersAreAddedChangedAndListed(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)

	if err := s.AddMember(ctx, a.ID, "u-member", RoleMember, "u-1"); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("adding a live member again: %v, want ErrAlreadyMember", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-member", RoleAdmin, "u-admin"); err != nil {
		t.Fatalf("an admin makes a member an admin: %v", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-member", RoleOwner, "u-admin"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin makes someone an owner: %v, want ErrForbidden", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-1", RoleMember, "u-admin"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin demotes the owner: %v, want ErrForbidden", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-1", RoleAdmin, "u-1"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("the last owner demotes themself: %v, want ErrLastOwner", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-member", "superuser", "u-1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a fourth role: %v, want ErrInvalid", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-stranger", RoleMember, "u-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a role for a non-member: %v, want ErrNotFound", err)
	}
	if err := s.SetRole(ctx, a.ID, "u-member", RoleAdmin, "u-1"); err != nil {
		t.Fatalf("setting the role it already holds: %v", err)
	}

	got, err := s.Members(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	roles := map[string]string{}
	for _, m := range got {
		roles[m.UserID] = m.Role
		if m.DisplayName == "" || m.Since.IsZero() {
			t.Errorf("member %+v lacks a name or a since", m)
		}
	}
	if len(got) != 3 || roles["u-1"] != RoleOwner || roles["u-admin"] != RoleAdmin || roles["u-member"] != RoleAdmin {
		t.Fatalf("Members = %+v", got)
	}

	// History is kept: the old row ended, a new one began.
	c, cctx := ownerConn(t, e.ownerDSN)
	var rows int
	if err := c.QueryRow(cctx, `SELECT count(*) FROM innsegl_auth.memberships
		WHERE account_id = $1 AND user_id = 'u-member'`, a.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("u-member has %d membership rows, want 2 (the ended one kept)", rows)
	}
	audit := auditActions(t, e, a.ID)
	if n := strings.Count(strings.Join(audit, ","), "membership.role_changed"); n != 1 {
		t.Errorf("audit = %v, want exactly one membership.role_changed (a no-op writes none)", audit)
	}
}

// ACC-006: removing a member ends the membership, revokes every session of
// theirs, and suspends the active installations they created in that
// organisation — not anyone else's, and not theirs in another organisation.
func TestACC006RemovalRevokesSessionsAndSuspendsTheirInstallations(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)
	recordPseudonymous(t, e)
	other, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddMember(ctx, other.ID, "u-member", RoleMember, ""); err != nil {
		t.Fatal(err)
	}

	mk := func(account, by, name string) Installation {
		t.Helper()
		i, ierr := s.CreateInstallation(ctx, InstallationParams{AccountID: account, CreatedBy: by,
			Name: name, Kind: KindWorkstation, Repos: []string{"*"}})
		if ierr != nil {
			t.Fatal(ierr)
		}
		return i
	}
	theirs := mk(a.ID, "u-member", "member laptop")
	revoked := mk(a.ID, "u-member", "old laptop")
	if err = s.SetInstallationStatus(ctx, revoked.ID, StatusRevoked, "u-1"); err != nil {
		t.Fatal(err)
	}
	ownersMachine := mk(a.ID, "u-1", "owner laptop")
	elsewhere := mk(other.ID, "u-member", "member laptop at Other")
	seedSession(t, e, "u-member", strings.Repeat("b", 64))
	seedSession(t, e, "u-member", strings.Repeat("c", 64))
	seedSession(t, e, "u-1", strings.Repeat("d", 64))

	if _, err = s.RemoveMember(ctx, a.ID, "u-member", "u-member"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a member removes themself without the privilege: %v, want ErrForbidden", err)
	}
	if _, err = s.RemoveMember(ctx, a.ID, "u-1", "u-admin"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin removes the owner: %v, want ErrForbidden", err)
	}
	if _, err = s.RemoveMember(ctx, a.ID, "u-1", "u-1"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("the last owner removes themself: %v, want ErrLastOwner", err)
	}

	r, err := s.RemoveMember(ctx, a.ID, "u-member", "u-admin")
	if err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if r.SessionsRevoked != 2 || !slices.Equal(r.Suspended, []string{theirs.ID}) {
		t.Fatalf("removal = %+v, want 2 sessions and only %s suspended", r, theirs.ID)
	}
	if n := liveSessions(t, e, "u-member"); n != 0 {
		t.Errorf("u-member keeps %d live sessions", n)
	}
	if n := liveSessions(t, e, "u-1"); n != 1 {
		t.Errorf("the owner's session was touched: %d live", n)
	}
	for id, want := range map[string]string{theirs.ID: StatusSuspended, revoked.ID: StatusRevoked,
		ownersMachine.ID: StatusActive, elsewhere.ID: StatusActive} {
		got, gerr := s.GetInstallation(ctx, id)
		if gerr != nil || got.Status != want {
			t.Errorf("installation %s: %s %v, want %s", id, got.Status, gerr, want)
		}
	}
	ms, err := s.Memberships(ctx, "u-member")
	if err != nil || len(ms) != 1 || ms[0].AccountID != other.ID {
		t.Errorf("u-member's memberships after removal: %+v %v, want only Other", ms, err)
	}
	if _, err = s.RemoveMember(ctx, a.ID, "u-member", "u-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing again: %v, want ErrNotFound", err)
	}
	got := strings.Join(auditActions(t, e, a.ID), ",")
	if !strings.HasSuffix(got, "membership.removed,installation.suspended,sessions.revoked") {
		t.Errorf("audit = %s", got)
	}
}

// ACC-007 (E1): nothing refuses an agent action because of a role. A
// member's installation is in scope exactly as an owner's is, before and
// after any role change; only removal, which suspends it, takes it out.
func TestACC007NoRoleRefusesAnAgentAction(t *testing.T) {
	_, s, a := orgWithPeople(t)
	ctx := tctx(t)
	const repo = "github.com/acme/app"
	if err := s.GrantRepo(ctx, a.ID, repo, "u-1"); err != nil {
		t.Fatal(err)
	}
	mine, err := s.CreateInstallation(ctx, InstallationParams{AccountID: a.ID, CreatedBy: "u-member",
		Name: "member laptop", Kind: KindWorkstation, Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	check := func(when string, want bool) {
		t.Helper()
		in, ierr := s.InScope(ctx, mine.ID, repo)
		if ierr != nil || in != want {
			t.Errorf("%s: InScope = %v %v, want %v", when, in, ierr, want)
		}
		claimed, cerr := s.ClaimRepo(ctx, mine.ID, repo)
		if cerr != nil || claimed != want {
			t.Errorf("%s: ClaimRepo = %v %v, want %v", when, claimed, cerr, want)
		}
	}
	check("as a member", true)
	for _, role := range []string{RoleAdmin, RoleOwner, RoleMember} {
		if err := s.SetRole(ctx, a.ID, "u-member", role, "u-1"); err != nil {
			t.Fatal(err)
		}
		check("as "+role, true)
	}
	if _, err := s.RemoveMember(ctx, a.ID, "u-member", "u-1"); err != nil {
		t.Fatal(err)
	}
	check("after removal", false)
}

// ACC-005: a new organisation made with an owner has that owner from the
// same transaction; an unknown user makes no organisation.
func TestACC005ANewOrganisationHasItsOwnerFromTheStart(t *testing.T) {
	e, s, _ := setup(t)
	ctx := tctx(t)
	recordPseudonymous(t, e)
	seedUser(t, e, "u-beta")
	b, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Beta", Owner: "u-beta"})
	if err != nil {
		t.Fatalf("CreateAccount with an owner: %v", err)
	}
	ms, err := s.Members(ctx, b.ID)
	if err != nil || len(ms) != 1 || ms[0].UserID != "u-beta" || ms[0].Role != RoleOwner {
		t.Fatalf("members = %+v %v", ms, err)
	}
	if got := strings.Join(auditActions(t, e, b.ID), ","); got != "account.created,membership.added" {
		t.Errorf("audit = %s", got)
	}
	before, err := s.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateAccount(ctx, CreateAccountParams{Name: "Gamma", Owner: "nobody"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown owner: %v, want ErrInvalid", err)
	}
	after, err := s.ListAccounts(ctx)
	if err != nil || len(after) != len(before) {
		t.Fatalf("a refused creation left an organisation: %d -> %d (%v)", len(before), len(after), err)
	}
}

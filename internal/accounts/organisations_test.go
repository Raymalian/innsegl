// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/api"
)

// RM-333 (#511): the account page reads the spine through api.Organisations,
// which Store implements. These run against a real Postgres.

var _ api.Organisations = (*Store)(nil)

func TestRM333MembershipsAreTheUsersLiveOnesWithRoles(t *testing.T) {
	e, s, a := setup(t)
	ctx := tctx(t)
	recordPseudonymous(t, e) // a second account needs the switch (ACC-008)
	b, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Beta"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddMember(ctx, b.ID, "u-1", RoleMember, ""); err != nil {
		t.Fatal(err)
	}
	gone, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Gone"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddMember(ctx, gone.ID, "u-1", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	c, cctx := ownerConn(t, e.ownerDSN)
	if _, err = c.Exec(cctx, `UPDATE innsegl_auth.memberships SET until = now() WHERE account_id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}

	got, err := s.Memberships(ctx, "u-1")
	if err != nil {
		t.Fatalf("Memberships: %v", err)
	}
	if len(got) != 2 || got[0].AccountID != a.ID || got[0].Role != RoleOwner || got[0].Name != "Acme" ||
		got[1].AccountID != b.ID || got[1].Role != RoleMember {
		t.Fatalf("Memberships = %+v", got)
	}
	none, err := s.Memberships(ctx, "nobody")
	if err != nil || len(none) != 0 {
		t.Fatalf("a user with no membership: %+v, %v", none, err)
	}
}

func TestRM333MachinesAndGrantsAreThoseOfTheNamedOrganisations(t *testing.T) {
	e, s, a := setup(t)
	ctx := tctx(t)
	recordPseudonymous(t, e) // a second account needs the switch (ACC-008)
	other, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := s.CreateInstallation(ctx, InstallationParams{AccountID: a.ID, CreatedBy: "u-1",
		Name: "laptop", Kind: KindWorkstation, Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateInstallation(ctx, InstallationParams{AccountID: other.ID, CreatedBy: "u-1",
		Name: "theirs", Kind: KindService, Repos: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	if err = s.GrantRepo(ctx, a.ID, "github.com/acme/app", "u-1"); err != nil {
		t.Fatal(err)
	}
	if err = s.GrantRepo(ctx, other.ID, "github.com/other/app", "u-1"); err != nil {
		t.Fatal(err)
	}

	machines, err := s.Machines(ctx, []string{a.ID})
	if err != nil {
		t.Fatalf("Machines: %v", err)
	}
	if len(machines) != 1 || machines[0].ID != mine.ID || machines[0].Name != "laptop" ||
		machines[0].Status != StatusActive || machines[0].AccountID != a.ID || machines[0].CreatedAt.IsZero() {
		t.Fatalf("Machines = %+v", machines)
	}
	grants, err := s.RepoGrants(ctx, []string{a.ID})
	if err != nil {
		t.Fatalf("RepoGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].Repo != "github.com/acme/app" || grants[0].AccountID != a.ID || grants[0].Since.IsZero() {
		t.Fatalf("RepoGrants = %+v", grants)
	}
	if m, err := s.Machines(ctx, nil); err != nil || len(m) != 0 {
		t.Fatalf("Machines(nil) = %+v, %v", m, err)
	}
	if g, err := s.RepoGrants(ctx, nil); err != nil || len(g) != 0 {
		t.Fatalf("RepoGrants(nil) = %+v, %v", g, err)
	}
}

func TestRM333RevokeMachineIsFinalAndNamedErrors(t *testing.T) {
	e, s, a := setup(t)
	ctx := tctx(t)
	inst, err := s.CreateInstallation(ctx, InstallationParams{AccountID: a.ID, CreatedBy: "u-1",
		Name: "laptop", Kind: KindWorkstation, Repos: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeMachine(ctx, inst.ID, "u-1"); err != nil {
		t.Fatalf("RevokeMachine: %v", err)
	}
	got, err := s.GetInstallation(ctx, inst.ID)
	if err != nil || got.Status != StatusRevoked || got.RevokedAt == nil {
		t.Fatalf("after revoke: %+v", got)
	}
	if err = s.RevokeMachine(ctx, inst.ID, "u-1"); !errors.Is(err, api.ErrMachineRevoked) {
		t.Fatalf("second revoke: %v, want api.ErrMachineRevoked", err)
	}
	if err = s.RevokeMachine(ctx, strings.Repeat("0", 32), "u-1"); !errors.Is(err, api.ErrMachineNotFound) {
		t.Fatalf("unknown machine: %v, want api.ErrMachineNotFound", err)
	}
	actions := strings.Join(auditActions(t, e, a.ID), ",")
	if !strings.HasSuffix(actions, "installation.revoked") {
		t.Fatalf("audit = %s", actions)
	}
}

func TestRM333MintEnrolmentTokenAnswersAConsumableToken(t *testing.T) {
	_, s, a := setup(t)
	ctx := tctx(t)
	tok, expires, err := s.MintEnrolmentToken(ctx, a.ID, "u-1", "", nil)
	if err != nil {
		t.Fatalf("MintEnrolmentToken: %v", err)
	}
	if !strings.HasPrefix(tok, "ie_") || expires.IsZero() {
		t.Fatalf("token %q expires %v", tok, expires)
	}
	en, err := s.ConsumeEnrolmentToken(ctx, tok)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if en.AccountID != a.ID || en.Kind != KindWorkstation || len(en.Repos) != 1 || en.Repos[0] != AllRepos {
		t.Fatalf("enrolment = %+v", en)
	}
	if _, _, err = s.MintEnrolmentToken(ctx, a.ID, "u-1", "toaster", nil); !errors.Is(err, api.ErrOrgInvalid) {
		t.Fatalf("bad kind: %v, want api.ErrOrgInvalid", err)
	}
	if _, _, err = s.MintEnrolmentToken(ctx, a.ID, "u-1", KindService, []string{"not a repo"}); !errors.Is(err, api.ErrOrgInvalid) {
		t.Fatalf("bad repos: %v, want api.ErrOrgInvalid", err)
	}
}

func TestRM333OrganisationReadsFailOnAClosedStore(t *testing.T) {
	_, s, a := setup(t)
	ctx := tctx(t)
	s.Close()
	if _, err := s.Memberships(ctx, "u-1"); err == nil {
		t.Error("Memberships answered on a closed store")
	}
	if _, err := s.Machines(ctx, []string{a.ID}); err == nil {
		t.Error("Machines answered on a closed store")
	}
	if _, err := s.RepoGrants(ctx, []string{a.ID}); err == nil {
		t.Error("RepoGrants answered on a closed store")
	}
	if err := s.RevokeMachine(ctx, strings.Repeat("0", 32), "u-1"); err == nil ||
		errors.Is(err, api.ErrMachineNotFound) {
		t.Errorf("RevokeMachine on a closed store: %v", err)
	}
	if _, _, err := s.MintEnrolmentToken(ctx, a.ID, "u-1", "", nil); err == nil || errors.Is(err, api.ErrOrgInvalid) {
		t.Errorf("MintEnrolmentToken on a closed store: %v", err)
	}
}

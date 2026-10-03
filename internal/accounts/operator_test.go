// SPDX-License-Identifier: Apache-2.0

package accounts

import "testing"

// A fresh install had users and no organisation: nothing created the
// deployment's own, so the first user's account page showed none, and no
// machine could be connected from it. FoundOperator creates it, once, with
// the deployment's first user as owner.
func TestFoundOperatorMakesTheFirstUserOwner(t *testing.T) {
	e, s := migrated(t)
	ctx := tctx(t)

	if created, err := s.FoundOperator(ctx); err != nil || created {
		t.Fatalf("FoundOperator with no users = %v, %v; want false, nil", created, err)
	}

	seedUser(t, e, "u-1")
	seedUser(t, e, "u-2")
	created, err := s.FoundOperator(ctx)
	if err != nil || !created {
		t.Fatalf("FoundOperator = %v, %v; want true, nil", created, err)
	}
	m, err := s.Memberships(ctx, "u-1")
	if err != nil || len(m) != 1 || !m[0].Operator || m[0].Role != RoleOwner || m[0].Name != "u-1" {
		t.Fatalf("u-1 memberships = %+v, %v; want owner of the operator organisation", m, err)
	}
	if m2, err := s.Memberships(ctx, "u-2"); err != nil || len(m2) != 0 {
		t.Fatalf("u-2 memberships = %+v, %v; only the first user is made owner", m2, err)
	}

	if again, err := s.FoundOperator(ctx); err != nil || again {
		t.Fatalf("second FoundOperator = %v, %v; want false, nil", again, err)
	}
	if got := auditActions(t, e, m[0].AccountID); len(got) != 2 {
		t.Fatalf("audit = %v; want the creation and the membership, once", got)
	}
}

// A deployment whose operator organisation already exists is left alone.
func TestFoundOperatorLeavesAnExistingOneAlone(t *testing.T) {
	e, s := migrated(t)
	ctx := tctx(t)
	seedUser(t, e, "u-1")
	if _, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Ops", Operator: true}); err != nil {
		t.Fatal(err)
	}
	if created, err := s.FoundOperator(ctx); err != nil || created {
		t.Fatalf("FoundOperator = %v, %v; want false, nil", created, err)
	}
	if m, err := s.Memberships(ctx, "u-1"); err != nil || len(m) != 0 {
		t.Fatalf("u-1 was added to an organisation that existed: %+v, %v", m, err)
	}
}

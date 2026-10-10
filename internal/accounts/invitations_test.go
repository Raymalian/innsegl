// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// RM-302 (#481): invitations by single-use link. No email is asked for or
// stored. These run against a real Postgres.

// AUTH-006: an invitation is a secret shown once, single use, bounded in
// time and withdrawable; only its hash is stored, and nothing in the
// accounts schema can hold an email address for it.
func TestAUTH006AnInvitationIsASingleUseSecretAndStoresNoEmail(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)

	if _, _, err := s.CreateInvitation(ctx, a.ID, RoleMember, "u-member"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a member invites: %v, want ErrForbidden", err)
	}
	if _, _, err := s.CreateInvitation(ctx, a.ID, RoleOwner, "u-admin"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an admin invites an owner: %v, want ErrForbidden", err)
	}
	if _, _, err := s.CreateInvitation(ctx, a.ID, "guest", "u-1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a fourth role: %v, want ErrInvalid", err)
	}
	code, inv, err := s.CreateInvitation(ctx, a.ID, RoleMember, "u-admin")
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if !strings.HasPrefix(code, "iv_") || len(code) < 40 {
		t.Fatalf("code %q is not an iv_ secret", code)
	}
	if d := time.Until(inv.ExpiresAt); d <= 0 || d > InvitationTTL {
		t.Fatalf("expires in %v, want within %v", d, InvitationTTL)
	}

	peek, err := s.PeekInvitation(ctx, code)
	if err != nil || peek.AccountID != a.ID || peek.AccountName != "Acme" || peek.Role != RoleMember {
		t.Fatalf("PeekInvitation = %+v %v", peek, err)
	}

	c, cctx := ownerConn(t, e.ownerDSN)
	var stored string
	if err = c.QueryRow(cctx, `SELECT code_hash FROM innsegl_auth.invitations WHERE invitation_id = $1`,
		inv.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(code, stored) || stored == "" {
		t.Fatalf("the stored hash %q is the code, or empty", stored)
	}
	var emailColumns int
	if err = c.QueryRow(cctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'innsegl_auth' AND table_name IN ('invitations', 'users', 'memberships')
		  AND column_name ILIKE '%mail%'`).Scan(&emailColumns); err != nil {
		t.Fatal(err)
	}
	if emailColumns != 0 {
		t.Fatalf("%d columns could hold an email for a person", emailColumns)
	}

	seedUser(t, e, "u-new")
	if _, err = s.AcceptInvitation(ctx, code, "u-new"); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	seedUser(t, e, "u-late")
	if _, err = s.AcceptInvitation(ctx, code, "u-late"); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("second accept: %v, want ErrInvitationInvalid", err)
	}
	if _, err = s.PeekInvitation(ctx, code); !errors.Is(err, ErrInvitationInvalid) {
		t.Fatalf("peek after use: %v, want ErrInvitationInvalid", err)
	}
	for _, bad := range []string{"", "iv_", "iv_nope", "ie_x_y", code + "0"} {
		if _, err = s.PeekInvitation(ctx, bad); !errors.Is(err, ErrInvitationInvalid) {
			t.Errorf("peek %q: %v, want ErrInvitationInvalid", bad, err)
		}
	}

	t.Run("expired", func(t *testing.T) {
		old, oinv, oerr := s.CreateInvitation(ctx, a.ID, RoleMember, "u-1")
		if oerr != nil {
			t.Fatal(oerr)
		}
		if _, xerr := c.Exec(cctx, `UPDATE innsegl_auth.invitations SET expires_at = now() - interval '1 second'
			WHERE invitation_id = $1`, oinv.ID); xerr != nil {
			t.Fatal(xerr)
		}
		if _, aerr := s.AcceptInvitation(ctx, old, "u-late"); !errors.Is(aerr, ErrInvitationInvalid) {
			t.Fatalf("accepting an expired invitation: %v, want ErrInvitationInvalid", aerr)
		}
	})
	t.Run("withdrawn", func(t *testing.T) {
		w, winv, werr := s.CreateInvitation(ctx, a.ID, RoleAdmin, "u-1")
		if werr != nil {
			t.Fatal(werr)
		}
		if rerr := s.RevokeInvitation(ctx, a.ID, winv.ID, "u-member"); !errors.Is(rerr, ErrForbidden) {
			t.Fatalf("a member withdraws: %v, want ErrForbidden", rerr)
		}
		if rerr := s.RevokeInvitation(ctx, a.ID, winv.ID, "u-admin"); rerr != nil {
			t.Fatalf("RevokeInvitation: %v", rerr)
		}
		if _, aerr := s.AcceptInvitation(ctx, w, "u-late"); !errors.Is(aerr, ErrInvitationInvalid) {
			t.Fatalf("accepting a withdrawn invitation: %v, want ErrInvitationInvalid", aerr)
		}
		if rerr := s.RevokeInvitation(ctx, a.ID, winv.ID, "u-1"); !errors.Is(rerr, ErrNotFound) {
			t.Fatalf("withdrawing twice: %v, want ErrNotFound", rerr)
		}
		list, lerr := s.Invitations(ctx, a.ID)
		if lerr != nil {
			t.Fatal(lerr)
		}
		states := map[int64]string{}
		for _, i := range list {
			states[i.ID] = i.State
		}
		if states[inv.ID] != InvitationAccepted || states[winv.ID] != InvitationWithdrawn {
			t.Fatalf("Invitations states = %v", states)
		}
	})

	got := strings.Join(auditActions(t, e, a.ID), ",")
	for _, want := range []string{"invitation.created", "invitation.accepted", "invitation.withdrawn"} {
		if !strings.Contains(got, want) {
			t.Errorf("audit %s lacks %s", got, want)
		}
	}
	if strings.Contains(got, code) {
		t.Errorf("the audit trail holds the code")
	}
}

// AUTH-007: accepting gives the invited role, to an existing user or to a
// new one created in the same transaction; an existing member is refused
// without spending the link; two concurrent accepts admit exactly one.
func TestAUTH007AcceptingGivesTheInvitedRoleOnce(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)

	code, _, err := s.CreateInvitation(ctx, a.ID, RoleAdmin, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AcceptInvitation(ctx, code, "u-member"); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("an existing member accepts: %v, want ErrAlreadyMember", err)
	}
	if _, err = s.PeekInvitation(ctx, code); err != nil {
		t.Fatalf("the refused accept spent the link: %v", err)
	}

	created := false
	m, err := s.AcceptInvitationAsNewUser(ctx, code, func(q Querier) (string, error) {
		created = true
		_, xerr := q.Exec(ctx, `INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('u-fresh', 'Fresh Person')`)
		return "u-fresh", xerr
	})
	if err != nil || !created {
		t.Fatalf("AcceptInvitationAsNewUser: %v (created %v)", err, created)
	}
	if m.AccountID != a.ID || m.Role != RoleAdmin || m.Name != "Acme" {
		t.Fatalf("membership = %+v", m)
	}

	// A new user whose creation fails leaves no user and no spent link.
	code2, _, err := s.CreateInvitation(ctx, a.ID, RoleMember, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("passkey insert failed")
	if _, err = s.AcceptInvitationAsNewUser(ctx, code2, func(q Querier) (string, error) {
		if _, xerr := q.Exec(ctx, `INSERT INTO innsegl_auth.users (user_id, display_name) VALUES ('u-ghost', 'Ghost')`); xerr != nil {
			return "", xerr
		}
		return "", boom
	}); !errors.Is(err, boom) {
		t.Fatalf("a failing creation: %v, want it returned", err)
	}
	c, cctx := ownerConn(t, e.ownerDSN)
	var ghosts int
	if err = c.QueryRow(cctx, `SELECT count(*) FROM innsegl_auth.users WHERE user_id = 'u-ghost'`).Scan(&ghosts); err != nil {
		t.Fatal(err)
	}
	if ghosts != 0 {
		t.Fatalf("a failed acceptance left the user behind")
	}
	if _, err = s.PeekInvitation(ctx, code2); err != nil {
		t.Fatalf("a failed acceptance spent the link: %v", err)
	}

	// Concurrent accepts of one link: exactly one membership.
	for _, id := range []string{"u-r1", "u-r2", "u-r3", "u-r4"} {
		seedUser(t, e, id)
	}
	var wg sync.WaitGroup
	wins := make(chan string, 4)
	for _, id := range []string{"u-r1", "u-r2", "u-r3", "u-r4"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, aerr := s.AcceptInvitation(ctx, code2, id); aerr == nil {
				wins <- id
			}
		}(id)
	}
	wg.Wait()
	close(wins)
	if n := len(wins); n != 1 {
		t.Fatalf("%d concurrent accepts won, want 1", n)
	}
}

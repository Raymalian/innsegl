// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
)

// `innsegl accounts` verbs for members, roles, invitations and the audit
// trail (#480, #481, #482): flags, output and exit statuses against the
// stub. The writes themselves are internal/accounts' ACC-004..011 and
// AUTH-006/007 against a real Postgres.

type orgCalls struct {
	setRoles    [][4]string // account, user, role, actor
	removed     [][3]string // account, user, actor
	invites     [][3]string // account, role, actor
	withdrawn   []string
	members     []api.OrgMember
	invitations []api.OrgInvitation
	audit       []accounts.AuditRecord
	auditFor    []string
	removal     api.OrgRemoval
}

func (s *stubAccountsStore) org() *orgCalls {
	if s.orgState == nil {
		s.orgState = &orgCalls{}
	}
	return s.orgState
}

func (s *stubAccountsStore) Members(_ context.Context, _ string) ([]api.OrgMember, error) {
	return s.org().members, s.err
}

func (s *stubAccountsStore) SetRole(_ context.Context, account, user, role, actor string) error {
	s.org().setRoles = append(s.org().setRoles, [4]string{account, user, role, actor})
	return s.err
}

func (s *stubAccountsStore) RemoveMember(_ context.Context, account, user, actor string) (api.OrgRemoval, error) {
	s.org().removed = append(s.org().removed, [3]string{account, user, actor})
	return s.org().removal, s.err
}

func (s *stubAccountsStore) CreateInvitation(_ context.Context, account, role, actor string) (string, api.OrgInvitation, error) {
	s.org().invites = append(s.org().invites, [3]string{account, role, actor})
	return "iv_" + strings.Repeat("7", 64), api.OrgInvitation{ID: 9, Role: role,
		ExpiresAt: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}, s.err
}

func (s *stubAccountsStore) Invitations(_ context.Context, _ string) ([]api.OrgInvitation, error) {
	return s.org().invitations, s.err
}

func (s *stubAccountsStore) RevokeInvitation(_ context.Context, account string, id int64, actor string) error {
	s.org().withdrawn = append(s.org().withdrawn, account+"|"+actor+"|"+strings.Repeat("x", int(id)))
	return s.err
}

func (s *stubAccountsStore) AuditLog(_ context.Context, account string, _ int) ([]accounts.AuditRecord, error) {
	s.org().auditFor = append(s.org().auditFor, account)
	return s.org().audit, s.err
}

// ACC-005 at the command line: members, set-role and a new account's owner.
func TestACC005AccountsCLIMembersAndRoles(t *testing.T) {
	s := &stubAccountsStore{}
	s.org().members = []api.OrgMember{{UserID: "u-1", DisplayName: "Owner Person", Role: "owner",
		Since: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}}
	code, out, stderr := runAccounts(s, "members", "-dsn", "x", "--account", "acct-1")
	if code != exitOK || !strings.HasPrefix(out, "USER") || !strings.Contains(out, "u-1") ||
		!strings.Contains(out, "Owner Person") || !strings.Contains(out, "owner") {
		t.Fatalf("members: exit %d out %q err %q", code, out, stderr)
	}
	if code, _, _ := runAccounts(s, "members", "-dsn", "x"); code != exitUsage {
		t.Errorf("members without --account: exit %d", code)
	}

	if code, _, stderr := runAccounts(s, "set-role", "-dsn", "x", "--account", "acct-1", "--by", "u-1",
		"u-2", "admin"); code != exitOK {
		t.Fatalf("set-role: exit %d: %s", code, stderr)
	}
	if got := s.org().setRoles; len(got) != 1 || got[0] != [4]string{"acct-1", "u-2", "admin", "u-1"} {
		t.Fatalf("set-role called %v", got)
	}
	if code, _, _ := runAccounts(s, "set-role", "-dsn", "x", "--account", "acct-1", "u-2"); code != exitUsage {
		t.Errorf("set-role without a role: exit %d", code)
	}

	if code, out, stderr := runAccounts(s, "new", "-dsn", "x", "--name", "Beta", "--owner", "u-9"); code != exitOK ||
		strings.TrimSpace(out) != "acct-1" {
		t.Fatalf("new --owner: exit %d out %q: %s", code, out, stderr)
	}
	if p := s.createAccount[len(s.createAccount)-1]; p.Owner != "u-9" || p.Name != "Beta" {
		t.Errorf("new --owner passed %+v", p)
	}

	s.err = api.ErrOrgForbidden
	if code, _, stderr := runAccounts(s, "set-role", "-dsn", "x", "--account", "acct-1", "--by", "u-3",
		"u-2", "owner"); code == exitOK || !strings.Contains(stderr, "role") {
		t.Errorf("a forbidden change: exit %d: %s", code, stderr)
	}
}

// ACC-006 at the command line: removal reports what it revoked and
// suspended.
func TestACC006AccountsCLIRemoveMemberReportsSessionsAndMachines(t *testing.T) {
	s := &stubAccountsStore{}
	s.org().removal = api.OrgRemoval{SessionsRevoked: 2, Suspended: []string{"inst-a", "inst-b"}}
	code, _, stderr := runAccounts(s, "remove-member", "-dsn", "x", "--account", "acct-1", "u-2")
	if code != exitOK {
		t.Fatalf("remove-member: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"u-2", "2 sessions", "inst-a", "inst-b"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("remove-member does not report %q: %s", want, stderr)
		}
	}
	if got := s.org().removed; len(got) != 1 || got[0] != [3]string{"acct-1", "u-2", ""} {
		t.Errorf("removed %v", got)
	}
	if code, _, _ := runAccounts(s, "remove-member", "-dsn", "x", "--account", "acct-1"); code != exitUsage {
		t.Errorf("no user: exit %d", code)
	}
}

// AUTH-006 at the command line: the link goes to stdout and nowhere else,
// carries the code in its fragment (never sent to a server), and names no
// email.
func TestAUTH006AccountsCLIInviteGivesALinkOnStdoutOnly(t *testing.T) {
	s := &stubAccountsStore{}
	code, out, stderr := runAccounts(s, "invite", "-dsn", "x", "--account", "acct-1", "--role", "member",
		"--origin", "https://core.example.test:8443")
	if code != exitOK {
		t.Fatalf("invite: exit %d: %s", code, stderr)
	}
	want := "https://core.example.test:8443/invite#iv_" + strings.Repeat("7", 64)
	if strings.TrimSpace(out) != want {
		t.Fatalf("stdout %q, want %q", out, want)
	}
	if strings.Contains(stderr, "iv_") || !strings.Contains(stderr, "2026-10-13T09:00:00Z") {
		t.Errorf("stderr must name the expiry and never the code: %s", stderr)
	}
	if got := s.org().invites; len(got) != 1 || got[0] != [3]string{"acct-1", "member", ""} {
		t.Errorf("invites %v", got)
	}
	for _, args := range [][]string{
		{"invite", "-dsn", "x", "--role", "member", "--origin", "https://c"},
		{"invite", "-dsn", "x", "--account", "a", "--origin", "https://c"},
		{"invite", "-dsn", "x", "--account", "a", "--role", "member", "--origin", ""},
		{"invite", "-dsn", "x", "--account", "a", "--role", "member", "--origin", "ftp://c"},
	} {
		if got, _, _ := runAccounts(s, args...); got != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, got)
		}
	}

	s.org().invitations = []api.OrgInvitation{{ID: 9, Role: "member", State: "pending",
		ExpiresAt: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}}
	code, out, _ = runAccounts(s, "invitations", "-dsn", "x", "--account", "acct-1")
	if code != exitOK || !strings.HasPrefix(out, "ID") || !strings.Contains(out, "pending") {
		t.Fatalf("invitations: %d %q", code, out)
	}
	if code, _, stderr := runAccounts(s, "withdraw-invitation", "-dsn", "x", "--account", "acct-1", "3"); code != exitOK {
		t.Fatalf("withdraw-invitation: exit %d: %s", code, stderr)
	}
	if got := s.org().withdrawn; len(got) != 1 || got[0] != "acct-1||xxx" {
		t.Errorf("withdrawn %v", got)
	}
	if code, _, _ := runAccounts(s, "withdraw-invitation", "-dsn", "x", "--account", "acct-1", "three"); code != exitUsage {
		t.Errorf("a non-numeric id: exit %d", code)
	}
}

// ACC-009 at the command line: the trail, newest first, one line a row.
func TestACC009AccountsCLIAuditListsTheTrail(t *testing.T) {
	s := &stubAccountsStore{}
	s.org().audit = []accounts.AuditRecord{{ID: 7, At: time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC),
		Actor: "u-1", AccountID: "acct-1", Action: "membership.removed", Subject: "u-2",
		Detail: map[string]any{"role": "member"}}}
	code, out, stderr := runAccounts(s, "audit", "-dsn", "x", "--account", "acct-1")
	if code != exitOK {
		t.Fatalf("audit: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"AT", "2026-10-10T08:00:00Z", "u-1", "membership.removed", "u-2", `"role":"member"`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit output lacks %q:\n%s", want, out)
		}
	}
	if code, _, _ = runAccounts(s, "audit", "-dsn", "x"); code != exitOK || s.org().auditFor[1] != "" {
		t.Errorf("audit of every account: exit %d, asked %v", code, s.org().auditFor)
	}
	s.err = errors.New("boom")
	if code, _, _ = runAccounts(s, "audit", "-dsn", "x"); code == exitOK {
		t.Errorf("a failing read: exit 0")
	}
}

// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
)

// `innsegl accounts`: flag handling and exit statuses against a stub, in
// adminenrolcode_test.go's shape. The real writes against a real Postgres are
// internal/accounts' own ACC-001..003.

type stubAccountsStore struct {
	createAccount  []accounts.CreateAccountParams
	tokens         []accounts.TokenParams
	listed         []string
	statuses       [][3]string
	grants         [][2]string
	installations  []accounts.Installation
	err            error
	token          string
	tokenExpiresAt time.Time
}

func (s *stubAccountsStore) CreateAccount(_ context.Context, p accounts.CreateAccountParams) (accounts.Account, error) {
	s.createAccount = append(s.createAccount, p)
	return accounts.Account{ID: "acct-1", Name: p.Name}, s.err
}

func (s *stubAccountsStore) CreateEnrolmentToken(_ context.Context, p accounts.TokenParams) (string, accounts.TokenMeta, error) {
	s.tokens = append(s.tokens, p)
	return s.token, accounts.TokenMeta{TokenID: "tid", ExpiresAt: s.tokenExpiresAt}, s.err
}

func (s *stubAccountsStore) ListInstallations(_ context.Context, account string) ([]accounts.Installation, error) {
	s.listed = append(s.listed, account)
	return s.installations, s.err
}

func (s *stubAccountsStore) SetInstallationStatus(_ context.Context, id, status, actor string) error {
	s.statuses = append(s.statuses, [3]string{id, status, actor})
	return s.err
}

func (s *stubAccountsStore) GrantRepo(_ context.Context, account, repo, actor string) error {
	s.grants = append(s.grants, [2]string{account, repo})
	return s.err
}

func stubAccountsDeps(s *stubAccountsStore, openErr error, closed *bool) accountsCLIDeps {
	return accountsCLIDeps{open: func(context.Context, string) (accountsStore, func(), error) {
		if openErr != nil {
			return nil, nil, openErr
		}
		return s, func() {
			if closed != nil {
				*closed = true
			}
		}, nil
	}}
}

func runAccounts(s *stubAccountsStore, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runAccountsCommand(args, &out, &errb, stubAccountsDeps(s, nil, nil))
	return code, out.String(), errb.String()
}

func TestAccountsCLINoVerbIsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := accountsCommand(nil, &out, &errb); code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if code := accountsCommand([]string{"bogus"}, &out, &errb); code != exitUsage {
		t.Fatalf("unknown verb: exit %d, want %d", code, exitUsage)
	}
	out.Reset()
	if code := accountsCommand([]string{"help"}, &out, &errb); code != exitOK || !strings.Contains(out.String(), "enrol-token") {
		t.Fatalf("help: exit %d, out %q", code, out.String())
	}
}

func TestAccountsCLIRequiresADSN(t *testing.T) {
	t.Setenv(envAuthWriterDSN, "")
	for _, args := range [][]string{
		{"new", "--name", "Acme"},
		{"enrol-token", "--account", "a", "--by", "u", "--repos", "*"},
		{"installations", "--account", "a"},
		{"revoke-installation", "abc"},
		{"grant-repo", "--account", "a", "github.com/a/b"},
	} {
		code, _, stderr := runAccounts(&stubAccountsStore{}, args...)
		if code != exitUsage || !strings.Contains(stderr, "-dsn") {
			t.Errorf("%v: exit %d, stderr %q; want usage naming -dsn", args, code, stderr)
		}
	}
}

func TestAccountsCLINewPrintsTheAccountID(t *testing.T) {
	s := &stubAccountsStore{}
	code, stdout, stderr := runAccounts(s, "new", "-dsn", "postgres://x", "--name", "Acme Ltd")
	if code != exitOK || strings.TrimSpace(stdout) != "acct-1" {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if len(s.createAccount) != 1 || s.createAccount[0].Name != "Acme Ltd" || s.createAccount[0].Operator {
		t.Fatalf("CreateAccount = %+v", s.createAccount)
	}
	if code, _, _ := runAccounts(s, "new", "-dsn", "postgres://x"); code != exitUsage {
		t.Errorf("new without --name: exit %d, want usage", code)
	}
}

func TestAccountsCLIEnrolTokenPrintsTheTokenOnlyOnStdout(t *testing.T) {
	s := &stubAccountsStore{token: "ie_tid_secretsecret", tokenExpiresAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	code, stdout, stderr := runAccounts(s, "enrol-token", "-dsn", "postgres://x",
		"--account", "acct-1", "--by", "u-1", "--repos", "github.com/a/b, github.com/a/c", "--kind", "service")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.TrimSpace(stdout) != "ie_tid_secretsecret" {
		t.Fatalf("stdout = %q", stdout)
	}
	if strings.Contains(stderr, "secretsecret") || !strings.Contains(stderr, "2026-10-01T12:00:00Z") {
		t.Errorf("stderr = %q; want the expiry and never the secret", stderr)
	}
	p := s.tokens[0]
	if p.AccountID != "acct-1" || p.CreatedBy != "u-1" || p.Kind != "service" ||
		strings.Join(p.Repos, "|") != "github.com/a/b|github.com/a/c" {
		t.Fatalf("params = %+v", p)
	}
}

func TestAccountsCLIEnrolTokenRejectsMissingFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--by", "u", "--repos", "*"},
		{"--account", "a", "--repos", "*"},
		{"--account", "a", "--by", "u"},
		{"--account", "a", "--by", "u", "--repos", "*", "--kind", "toaster"},
	} {
		code, _, _ := runAccounts(&stubAccountsStore{}, append([]string{"enrol-token", "-dsn", "x"}, args...)...)
		if code != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}

func TestAccountsCLIInstallationsListsOnePerLine(t *testing.T) {
	s := &stubAccountsStore{installations: []accounts.Installation{
		{ID: "i1", Status: "active", Kind: "workstation", Name: "laptop", Repos: []string{"*"}},
		{ID: "i2", Status: "revoked", Kind: "service", Name: "ci", Repos: []string{"github.com/a/b", "github.com/a/c"}},
	}}
	code, stdout, stderr := runAccounts(s, "installations", "-dsn", "x", "--account", "acct-1")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "i1\tactive\tworkstation\tlaptop\t*") ||
		!strings.HasSuffix(lines[1], "github.com/a/b,github.com/a/c") {
		t.Fatalf("stdout = %q", stdout)
	}
	if s.listed[0] != "acct-1" {
		t.Fatalf("listed %v", s.listed)
	}
}

func TestAccountsCLIRevokeInstallationTakesAPositionalID(t *testing.T) {
	s := &stubAccountsStore{}
	for _, args := range [][]string{
		{"revoke-installation", "-dsn", "x", "abc123"},
		{"revoke-installation", "abc123", "-dsn", "x"},
	} {
		if code, _, stderr := runAccounts(s, args...); code != exitOK {
			t.Fatalf("%v: exit %d: %s", args, code, stderr)
		}
	}
	if len(s.statuses) != 2 || s.statuses[0] != [3]string{"abc123", "revoked", ""} {
		t.Fatalf("statuses = %v", s.statuses)
	}
	if code, _, _ := runAccounts(s, "revoke-installation", "-dsn", "x"); code != exitUsage {
		t.Errorf("no id: exit %d, want usage", code)
	}
	if code, _, _ := runAccounts(s, "revoke-installation", "-dsn", "x", "a", "b"); code != exitUsage {
		t.Errorf("two ids: exit %d, want usage", code)
	}
}

func TestAccountsCLIGrantRepo(t *testing.T) {
	s := &stubAccountsStore{}
	code, _, stderr := runAccounts(s, "grant-repo", "-dsn", "x", "--account", "acct-1", "github.com/a/b")
	if code != exitOK || s.grants[0] != [2]string{"acct-1", "github.com/a/b"} {
		t.Fatalf("exit %d, grants %v, stderr %s", code, s.grants, stderr)
	}
	for _, args := range [][]string{
		{"grant-repo", "-dsn", "x", "github.com/a/b"},
		{"grant-repo", "-dsn", "x", "--account", "acct-1"},
	} {
		if code, _, _ := runAccounts(s, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
}

func TestAccountsCLIReportsStoreFailures(t *testing.T) {
	boom := errors.New("boom")
	for _, args := range [][]string{
		{"new", "--name", "A"},
		{"enrol-token", "--account", "a", "--by", "u", "--repos", "*"},
		{"installations", "--account", "a"},
		{"revoke-installation", "abc"},
		{"grant-repo", "--account", "a", "github.com/a/b"},
	} {
		code, _, stderr := runAccounts(&stubAccountsStore{err: boom}, append([]string{args[0], "-dsn", "x"}, args[1:]...)...)
		if code != exitCredentialUnusable || !strings.Contains(stderr, "boom") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	var out, errb bytes.Buffer
	var closed bool
	code := runAccountsCommand([]string{"new", "-dsn", "x", "--name", "A"}, &out, &errb,
		stubAccountsDeps(&stubAccountsStore{}, nil, &closed))
	if code != exitOK || !closed {
		t.Errorf("exit %d, closed %v; want the store closed", code, closed)
	}
	code = runAccountsCommand([]string{"new", "-dsn", "x", "--name", "A"}, &out, &errb,
		stubAccountsDeps(nil, errors.New("refused"), nil))
	if code != exitCredentialUnusable {
		t.Errorf("open failure: exit %d", code)
	}
}

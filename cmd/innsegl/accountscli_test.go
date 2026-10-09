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
	createAccount []accounts.CreateAccountParams
	tokens        []accounts.TokenParams
	listed        []string
	statuses      [][3]string
	grants        [][2]string
	installations []accounts.Installation
	// installationsBy, when set, answers ListInstallations per account.
	installationsBy map[string][]accounts.Installation
	accounts        []accounts.AccountSummary
	err             error
	token           string
	tokenExpiresAt  time.Time
	recoveryFor     []string
	recoveryCodes   []string
	authorResets    [][2]string
}

func (s *stubAccountsStore) RecoveryCodes(_ context.Context, userID string) ([]string, error) {
	s.recoveryFor = append(s.recoveryFor, userID)
	return s.recoveryCodes, s.err
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
	if s.installationsBy != nil {
		return s.installationsBy[account], s.err
	}
	return s.installations, s.err
}

func (s *stubAccountsStore) SetInstallationStatus(_ context.Context, id, status, actor string) error {
	s.statuses = append(s.statuses, [3]string{id, status, actor})
	return s.err
}

func (s *stubAccountsStore) OperatorAuthor(_ context.Context, id string) (string, string, bool, error) {
	if id == "i1" {
		return "alpha", "12345+alpha@users.noreply.github.com", true, nil
	}
	return "", "", false, nil
}

func (s *stubAccountsStore) ResetOperatorAuthor(_ context.Context, id, actor string) error {
	s.authorResets = append(s.authorResets, [2]string{id, actor})
	return s.err
}

// GH-008's reset: the one way a pinned operator author changes, run on the
// core host (#545).
func TestGH008AccountsCLIAuthorResetTakesAPositionalID(t *testing.T) {
	s := &stubAccountsStore{}
	if code, _, stderr := runAccounts(s, "author-reset", "-dsn", "x", "abc123"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(s.authorResets) != 1 || s.authorResets[0] != [2]string{"abc123", ""} {
		t.Fatalf("resets = %v", s.authorResets)
	}
	if code, _, _ := runAccounts(s, "author-reset", "-dsn", "x"); code != exitUsage {
		t.Errorf("no id: exit %d, want usage", code)
	}
	s.err = accounts.ErrNotFound
	if code, _, _ := runAccounts(s, "author-reset", "-dsn", "x", "nope"); code == exitOK {
		t.Error("an unknown installation: exit 0")
	}
}

func (s *stubAccountsStore) ListAccounts(context.Context) ([]accounts.AccountSummary, error) {
	return s.accounts, s.err
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

// --repos defaults to "*": every repository the organisation holds or will
// hold (ADR-0063, amended 2026-10-02). An explicit list still narrows.
func TestAccountsCLIEnrolTokenReposDefaultToEverything(t *testing.T) {
	s := &stubAccountsStore{token: "ie_tid_secretsecret"}
	if code, _, stderr := runAccounts(s, "enrol-token", "-dsn", "postgres://x", "--account", "a", "--by", "u"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if p := s.tokens[0]; len(p.Repos) != 1 || p.Repos[0] != accounts.AllRepos {
		t.Fatalf("repos = %v, want [*]", p.Repos)
	}
}

func TestAccountsCLIEnrolTokenRejectsMissingFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--by", "u", "--repos", "*"},
		{"--account", "a", "--repos", "*"},
		{"--account", "a", "--by", "u", "--repos", " "},
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
	if len(lines) != 3 {
		t.Fatalf("stdout = %q, want a header and two rows", stdout)
	}
	if got := strings.Fields(lines[1]); len(got) < 6 ||
		strings.Join(got[:6], " ") != "acct-1 i1 active workstation laptop *" {
		t.Fatalf("first row = %q", lines[1])
	}
	if !strings.HasSuffix(strings.TrimSpace(lines[2]), "github.com/a/b,github.com/a/c  -") {
		t.Fatalf("second row = %q", lines[2])
	}
	// GH-008: the pinned operator author is the last column, "-" for none.
	if !strings.HasSuffix(strings.TrimSpace(lines[1]), "alpha <12345+alpha@users.noreply.github.com>") {
		t.Fatalf("the pinned operator author is not listed: %q", lines[1])
	}
	if len(s.listed) != 1 || s.listed[0] != "acct-1" {
		t.Fatalf("listed %v", s.listed)
	}
}

// GH-012 (PROPOSED for doc 07) — the core's listings read on their own: a
// header line names the columns, and `installations` with no --account
// lists every account's machines (#545).
func TestGH012AccountsListingsHaveHeadersAndInstallationsCoverEveryAccount(t *testing.T) {
	s := &stubAccountsStore{
		accounts: []accounts.AccountSummary{
			{ID: "acct-1", Name: "Acme", Owners: []string{"u-1"}},
			{ID: "acct-2", Name: "Beta", Operator: true, Owners: []string{"u-2"}},
		},
		installationsBy: map[string][]accounts.Installation{
			"acct-1": {{ID: "i1", Status: "active", Kind: "workstation", Name: "laptop", Repos: []string{"*"}}},
			"acct-2": {{ID: "i9", Status: "active", Kind: "service", Name: "ci", Repos: []string{"*"}}},
		},
	}
	code, out, errOut := runAccounts(s, "list", "-dsn", "x")
	if code != exitOK {
		t.Fatalf("list: exit %d: %s", code, errOut)
	}
	if h := strings.Fields(strings.SplitN(out, "\n", 2)[0]); strings.Join(h, " ") != "ID NAME OPERATOR OWNERS REPOS" {
		t.Fatalf("list header = %q", h)
	}

	code, out, errOut = runAccounts(s, "installations", "-dsn", "x")
	if code != exitOK {
		t.Fatalf("installations with no --account: exit %d: %s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if h := strings.Fields(lines[0]); strings.Join(h, " ") != "ACCOUNT ID STATUS KIND NAME REPOS OPERATOR-AUTHOR" {
		t.Fatalf("installations header = %q", h)
	}
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "acct-1") || !strings.HasPrefix(lines[2], "acct-2") ||
		!strings.Contains(lines[2], "i9") {
		t.Fatalf("installations of every account:\n%s", out)
	}

	s.listed = nil
	if code, out, _ = runAccounts(s, "installations", "-dsn", "x", "--account", "acct-2"); code != exitOK ||
		strings.Contains(out, "i1") || !strings.Contains(out, "i9") {
		t.Fatalf("--account still filters: exit %d\n%s", code, out)
	}
}

// GH-012 — a verb with no credential says where the credential is: in the
// innsegl-api container (deploy/compose/innsegl.yml).
func TestGH012AMissingDSNNamesTheContainerThatHoldsIt(t *testing.T) {
	t.Setenv(envAuthWriterDSN, "")
	code, _, stderr := runAccounts(&stubAccountsStore{}, "author-reset", "abc")
	if code != exitUsage || !strings.Contains(stderr, "docker exec innsegl-api innsegl accounts author-reset") {
		t.Fatalf("exit %d, stderr %q; want the docker exec form", code, stderr)
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

// `innsegl accounts list` prints each organisation's id, name, owners and
// granted repositories: what an operator on the core needs for enrol-token.
func TestAccountsCLIListPrintsIDsOwnersAndRepos(t *testing.T) {
	s := &stubAccountsStore{accounts: []accounts.AccountSummary{{
		ID: "acct-1", Name: "Acme", Operator: true, Owners: []string{"u-1"}, Repos: []string{"github.com/acme/app"},
	}}}
	code, out, errOut := runAccounts(s, "list", "-dsn", "postgres://x")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"acct-1", "Acme", "operator", "u-1", "github.com/acme/app"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q lacks %q", out, want)
		}
	}
}

// An owner who never saw their recovery codes, or lost every passkey, gets
// back in through the operator: `recovery-codes --user ID` replaces the
// user's codes and prints the new ones on STDOUT only, once. A code signs in
// once and leads to the account page, where a passkey is added. The account,
// its installations and the history recorded under it stay as they were.
func TestAccountsCLIRecoveryCodesPrintsNewCodesOnStdoutOnly(t *testing.T) {
	s := &stubAccountsStore{recoveryCodes: []string{"aaaa-bbbb-cccc", "dddd-eeee-ffff"}}
	code, stdout, stderr := runAccounts(s, "recovery-codes", "-dsn", "postgres://x", "--user", "u-1")
	if code != exitOK {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if stdout != "aaaa-bbbb-cccc\ndddd-eeee-ffff\n" {
		t.Fatalf("stdout %q, want one code per line", stdout)
	}
	if strings.Contains(stderr, "aaaa") || !strings.Contains(stderr, "voided") {
		t.Errorf("stderr %q: it must say the old codes are void and never repeat a code", stderr)
	}
	if len(s.recoveryFor) != 1 || s.recoveryFor[0] != "u-1" {
		t.Fatalf("RecoveryCodes called for %v", s.recoveryFor)
	}
	if code, _, _ := runAccounts(s, "recovery-codes", "-dsn", "postgres://x"); code != exitUsage {
		t.Errorf("without --user: exit %d, want usage", code)
	}
	s.err = errors.New("no such user")
	if code, _, _ := runAccounts(s, "recovery-codes", "-dsn", "postgres://x", "--user", "nobody"); code == exitOK {
		t.Error("an unknown user was accepted")
	}
}

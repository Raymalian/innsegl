// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
)

// `innsegl accounts` — the operator's core CLI over the accounts spine (#456):
// organisations, enrolment tokens, installations and repository grants.
//
// Like `admin-credential enrol-code`, it holds the auth-writer credential
// ($INNSEGL_API_AUTH_DSN) and nothing that can write the ledger; opening the
// store refuses a credential that can. A secret (the enrolment token) goes to
// STDOUT and to nowhere else.

// accountsStore is what this command needs of internal/accounts.Store — an
// interface so flag handling and exit statuses are testable without Postgres.
type accountsStore interface {
	CreateAccount(ctx context.Context, p accounts.CreateAccountParams) (accounts.Account, error)
	CreateEnrolmentToken(ctx context.Context, p accounts.TokenParams) (string, accounts.TokenMeta, error)
	ListInstallations(ctx context.Context, accountID string) ([]accounts.Installation, error)
	SetInstallationStatus(ctx context.Context, id, status, actor string) error
	// OperatorAuthor and ResetOperatorAuthor read and clear an installation's
	// pinned operator author; its machine's next report pins again (#545).
	OperatorAuthor(ctx context.Context, id string) (name, email string, ok bool, err error)
	ResetOperatorAuthor(ctx context.Context, id, actor string) error
	GrantRepo(ctx context.Context, accountID, repo, actor string) error
	ListAccounts(ctx context.Context) ([]accounts.AccountSummary, error)
	// RecoveryCodes replaces an existing user's recovery codes and returns
	// the new ones, shown once.
	RecoveryCodes(ctx context.Context, userID string) ([]string, error)
}

// cliAccountsStore is accounts.Store plus the one auth operation the
// accounts spine does not hold: recovery codes live with the passkeys
// (internal/api), and minting them there keeps one implementation of the
// code format and its hash.
type cliAccountsStore struct {
	*accounts.Store
	auth *api.AuthStore
}

func (c cliAccountsStore) RecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if _, err := c.auth.UserByID(ctx, userID); err != nil {
		return nil, fmt.Errorf("user %s: %w", userID, err)
	}
	return c.auth.MintRecoveryCodes(ctx, userID)
}

// accountsCLIDeps are the seams this command's tests replace.
type accountsCLIDeps struct {
	open func(ctx context.Context, dsn string) (accountsStore, func(), error)
}

func (d accountsCLIDeps) opener() func(context.Context, string) (accountsStore, func(), error) {
	if d.open != nil {
		return d.open
	}
	return func(ctx context.Context, dsn string) (accountsStore, func(), error) {
		s, err := accounts.Open(ctx, dsn)
		if err != nil {
			return nil, nil, err
		}
		a, err := api.OpenAuthStore(ctx, dsn)
		if err != nil {
			s.Close()
			return nil, nil, err
		}
		return cliAccountsStore{Store: s, auth: a}, func() { a.Close(); s.Close() }, nil
	}
}

func accountsCommand(args []string, stdout, stderr io.Writer) int {
	return runAccountsCommand(args, stdout, stderr, accountsCLIDeps{})
}

func accountsUsage(w io.Writer) {
	fprintf(w, "innsegl accounts - organisations, enrolment tokens, installations and repository grants\n\n")
	fprintf(w, "Usage:\n  innsegl accounts <verb> [flags]\n\nVerbs:\n")
	fprintf(w, "  list                                                      every account: id, name, owners, repositories\n")
	fprintf(w, "  new                  --name NAME                          create an account; prints its id\n")
	fprintf(w, "  enrol-token          --account ID --by USER --repos a,b|* [--kind workstation|service]\n")
	fprintf(w, "                                                            mint a 15-minute single-use token, on stdout\n")
	fprintf(w, "  installations        --account ID                         list an account's installations, last column its pinned operator author\n")
	fprintf(w, "  revoke-installation  ID                                   revoke one installation, for good\n")
	fprintf(w, "  author-reset         ID                                   clear one installation's pinned operator author\n")
	fprintf(w, "  grant-repo           --account ID REPO                    give an account a repository\n")
	fprintf(w, "  recovery-codes       --user ID                            replace a user's recovery codes; the new ones on stdout\n\n")
	fprintf(w, "Every verb takes -dsn (default $%s), the auth-writer connection string.\n", envAuthWriterDSN)
}

func runAccountsCommand(args []string, stdout, stderr io.Writer, deps accountsCLIDeps) int {
	if len(args) == 0 {
		accountsUsage(stderr)
		return exitUsage
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "help", "-h", "--help":
		accountsUsage(stdout)
		return exitOK
	case "new", "enrol-token", "installations", "revoke-installation", "grant-repo", "list", "recovery-codes",
		"author-reset":
		return accountsVerb(verb, rest, stdout, stderr, deps)
	default:
		fprintf(stderr, "innsegl accounts: unknown verb %q\n\n", verb)
		accountsUsage(stderr)
		return exitUsage
	}
}

// accountsVerb parses one verb's flags, opens the store and runs it.
func accountsVerb(verb string, args []string, stdout, stderr io.Writer, deps accountsCLIDeps) int {
	name := "innsegl accounts " + verb
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dsn := fs.String("dsn", os.Getenv(envAuthWriterDSN),
		"the auth-writer connection string ($"+envAuthWriterDSN+")")
	var acctName, account, by, repos, kind, user *string
	switch verb {
	case "new":
		acctName = fs.String("name", "", "the organisation's name")
	case "enrol-token":
		account = fs.String("account", "", "the account the installation will belong to")
		by = fs.String("by", "", "the user id minting the token")
		repos = fs.String("repos", accounts.AllRepos, "comma-separated host/org/name entries, or * (the default) for every repository the account holds or will hold")
		kind = fs.String("kind", accounts.KindWorkstation, "workstation or service")
	case "installations", "grant-repo":
		account = fs.String("account", "", "the account id")
	case "recovery-codes":
		user = fs.String("user", "", "the user id (owners= in `accounts list`)")
	}
	fs.Usage = func() {
		fprintf(stderr, "%s\n\nFlags:\n", name)
		fs.PrintDefaults()
	}

	// Flags may come before or after the one positional argument.
	var positional []string
	rest := args
	for {
		redactCredentialDefaults(fs)
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return exitOK
			}
			return exitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	usage := func(msg string) int {
		fprintf(stderr, "%s: %s\n", name, msg)
		return exitUsage
	}
	wantPositional := 0
	if verb == "revoke-installation" || verb == "grant-repo" || verb == "author-reset" {
		wantPositional = 1
	}
	if len(positional) != wantPositional {
		return usage("expected " + map[int]string{0: "no positional arguments", 1: "exactly one positional argument"}[wantPositional])
	}
	if *dsn == "" {
		return usage("-dsn (or $" + envAuthWriterDSN + ") is required")
	}
	switch verb {
	case "new":
		if strings.TrimSpace(*acctName) == "" {
			return usage("--name is required")
		}
	case "enrol-token":
		if *account == "" || *by == "" || strings.TrimSpace(*repos) == "" {
			return usage("--account and --by are required, and --repos may not be blank")
		}
		if *kind != accounts.KindWorkstation && *kind != accounts.KindService {
			return usage("--kind must be workstation or service")
		}
	case "installations", "grant-repo":
		if *account == "" {
			return usage("--account is required")
		}
	case "recovery-codes":
		if *user == "" {
			return usage("--user is required")
		}
	}

	ctx := context.Background()
	store, closeAll, err := deps.opener()(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "%s: %v\n", name, err)
		return exitCredentialUnusable
	}
	if closeAll != nil {
		defer closeAll()
	}
	fail := func(err error) int {
		fprintf(stderr, "%s: %v\n", name, err)
		return exitCredentialUnusable
	}

	switch verb {
	case "list":
		list, err := store.ListAccounts(ctx)
		if err != nil {
			return fail(err)
		}
		for _, a := range list {
			flagText := ""
			if a.Operator {
				flagText = "\toperator"
			}
			fprintf(stdout, "%s\t%s%s\towners=%s\trepos=%s\n", a.ID, a.Name, flagText,
				strings.Join(a.Owners, ","), strings.Join(a.Repos, ","))
		}
	case "new":
		a, err := store.CreateAccount(ctx, accounts.CreateAccountParams{Name: *acctName})
		if err != nil {
			return fail(err)
		}
		fprintf(stdout, "%s\n", a.ID)
	case "enrol-token":
		var list []string
		for _, r := range strings.Split(*repos, ",") {
			if r = strings.TrimSpace(r); r != "" {
				list = append(list, r)
			}
		}
		token, meta, err := store.CreateEnrolmentToken(ctx, accounts.TokenParams{
			AccountID: *account, CreatedBy: *by, Repos: list, Kind: *kind})
		if err != nil {
			return fail(err)
		}
		// STDOUT and nothing else: the diagnostic names the expiry, never the
		// token.
		fprintf(stdout, "%s\n", token)
		fprintf(stderr, "%s: issued, single use, valid until %s\n", name, meta.ExpiresAt.UTC().Format(time.RFC3339))
	case "installations":
		list, err := store.ListInstallations(ctx, *account)
		if err != nil {
			return fail(err)
		}
		for _, i := range list {
			// The last column is the installation's pinned operator author
			// (#545), "-" when none is pinned.
			author := "-"
			if n, e, ok, aerr := store.OperatorAuthor(ctx, i.ID); aerr != nil {
				return fail(aerr)
			} else if ok {
				author = n + " <" + e + ">"
			}
			fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", i.ID, i.Status, i.Kind, i.Name, strings.Join(i.Repos, ","), author)
		}
	case "revoke-installation":
		if err := store.SetInstallationStatus(ctx, positional[0], accounts.StatusRevoked, ""); err != nil {
			return fail(err)
		}
		fprintf(stderr, "%s: %s revoked\n", name, positional[0])
	case "author-reset":
		if err := store.ResetOperatorAuthor(ctx, positional[0], ""); err != nil {
			return fail(err)
		}
		fprintf(stderr, "%s: %s has no operator author pinned; its machine's next "+
			"`innsegl author repo <path> operator` pins one\n", name, positional[0])
	case "grant-repo":
		if err := store.GrantRepo(ctx, *account, positional[0], ""); err != nil {
			return fail(err)
		}
		fprintf(stderr, "%s: %s granted to %s\n", name, positional[0], *account)
	case "recovery-codes":
		codes, err := store.RecoveryCodes(ctx, *user)
		if err != nil {
			return fail(err)
		}
		// STDOUT and nothing else, once: the codes are stored only as
		// hashes, so this is the one time they can be read.
		for _, c := range codes {
			fprintf(stdout, "%s\n", c)
		}
		fprintf(stderr, "%s: %d new codes for %s; every earlier code is voided. Each signs in once, "+
			"to the account page, where a passkey is added. Save them now: they cannot be shown again.\n",
			name, len(codes), *user)
	}
	return exitOK
}

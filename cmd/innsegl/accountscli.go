// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
)

// `innsegl accounts` — the operator's core CLI over the accounts spine (#456):
// organisations, members and roles (#480), invitations (#481), the audit
// trail (#482), enrolment tokens, installations and repository grants.
//
// Like `admin-credential enrol-code`, it holds the auth-writer credential
// ($INNSEGL_API_AUTH_DSN) and nothing that can write the ledger; opening the
// store refuses a credential that can. A secret (an enrolment token, an
// invitation link, recovery codes) goes to STDOUT and to nowhere else.
//
// Without --by a change is the operator's, the deployment's admin path, and
// is audited with no actor. With --by USER it is that user's, and their role
// in the organisation is checked exactly as the dashboard checks it.

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

	Members(ctx context.Context, accountID string) ([]api.OrgMember, error)
	SetRole(ctx context.Context, accountID, userID, role, actor string) error
	RemoveMember(ctx context.Context, accountID, userID, actor string) (api.OrgRemoval, error)
	CreateInvitation(ctx context.Context, accountID, role, actor string) (string, api.OrgInvitation, error)
	Invitations(ctx context.Context, accountID string) ([]api.OrgInvitation, error)
	RevokeInvitation(ctx context.Context, accountID string, invitationID int64, actor string) error
	AuditLog(ctx context.Context, accountID string, limit int) ([]accounts.AuditRecord, error)
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
	fprintf(w, "innsegl accounts - organisations, members, invitations, enrolment tokens, installations and repository grants\n\n")
	fprintf(w, "Usage:\n  innsegl accounts <verb> [flags]\n\nVerbs:\n")
	fprintf(w, "  list                                                      every account: id, name, owners, repositories\n")
	fprintf(w, "  new                  --name NAME [--owner USER]           create an account; prints its id\n")
	fprintf(w, "  members              --account ID                         an account's members and their roles\n")
	fprintf(w, "  set-role             --account ID [--by USER] USER ROLE   give a member the role owner, admin or member\n")
	fprintf(w, "  remove-member        --account ID [--by USER] USER        end a membership; revokes the person's sessions\n")
	fprintf(w, "                                                            and suspends the installations they created there\n")
	fprintf(w, "  invite               --account ID --role ROLE [--by USER] [--origin URL]\n")
	fprintf(w, "                                                            a single-use invitation link, on stdout\n")
	fprintf(w, "  invitations          --account ID                         an account's invitations and their state\n")
	fprintf(w, "  withdraw-invitation  --account ID [--by USER] ID          withdraw a pending invitation\n")
	fprintf(w, "  audit                [--account ID] [--limit N]           the audit trail, newest first\n")
	fprintf(w, "  enrol-token          --account ID --by USER --repos a,b|* [--kind workstation|service]\n")
	fprintf(w, "                                                            mint a 15-minute single-use token, on stdout\n")
	fprintf(w, "  installations        [--account ID]                       every account's installations, or one account's; last column the pinned operator author\n")
	fprintf(w, "  revoke-installation  ID                                   revoke one installation, for good\n")
	fprintf(w, "  author-reset         ID                                   clear one installation's pinned operator author\n")
	fprintf(w, "  grant-repo           --account ID REPO                    give an account a repository\n")
	fprintf(w, "  recovery-codes       --user ID                            replace a user's recovery codes; the new ones on stdout\n\n")
	fprintf(w, "Every verb takes -dsn (default $%s), the auth-writer connection string.\n", envAuthWriterDSN)
	fprintf(w, "Without --by a change is the operator's; with --by USER, that user's role is checked.\n")
	fprintf(w, "On a compose core that is set in the innsegl-api container: docker exec innsegl-api innsegl accounts <verb> ...\n")
	fprintf(w, "Erasing an organisation is `innsegl erase-organisation`, as the database owner.\n")
}

var accountsVerbs = map[string]int{ // verb -> positional arguments it takes
	"list": 0, "new": 0, "members": 0, "set-role": 2, "remove-member": 1, "invite": 0, "invitations": 0,
	"withdraw-invitation": 1, "audit": 0, "enrol-token": 0, "installations": 0, "revoke-installation": 1,
	"author-reset": 1, "grant-repo": 1, "recovery-codes": 0,
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
	}
	if _, ok := accountsVerbs[verb]; !ok {
		fprintf(stderr, "innsegl accounts: unknown verb %q\n\n", verb)
		accountsUsage(stderr)
		return exitUsage
	}
	return accountsVerb(verb, rest, stdout, stderr, deps)
}

// accountsFlags are every flag a verb may declare; nil when it does not.
type accountsFlags struct {
	dsn, name, owner, account, by, repos, kind, user, role, origin *string
	limit                                                         *int
}

func declareAccountsFlags(verb string, fs *flag.FlagSet) accountsFlags {
	var f accountsFlags
	f.dsn = fs.String("dsn", os.Getenv(envAuthWriterDSN),
		"the auth-writer connection string ($"+envAuthWriterDSN+")")
	byFlag := func() { f.by = fs.String("by", "", "the user making the change; their role is checked (default: the operator)") }
	accountFlag := func(usage string) { f.account = fs.String("account", "", usage) }
	switch verb {
	case "new":
		f.name = fs.String("name", "", "the organisation's name")
		f.owner = fs.String("owner", "", "a user id to make its first owner")
	case "enrol-token":
		accountFlag("the account the installation will belong to")
		f.by = fs.String("by", "", "the user id minting the token")
		f.repos = fs.String("repos", accounts.AllRepos, "comma-separated host/org/name entries, or * (the default) for every repository the account holds or will hold")
		f.kind = fs.String("kind", accounts.KindWorkstation, "workstation or service")
	case "installations", "grant-repo", "members", "invitations":
		accountFlag("the account id")
	case "set-role", "remove-member", "withdraw-invitation":
		accountFlag("the account id")
		byFlag()
	case "invite":
		accountFlag("the account the person is invited to")
		f.role = fs.String("role", "", "owner, admin or member")
		f.origin = fs.String("origin", os.Getenv(envAPIRPOrigin),
			"the dashboard's origin the link opens ($"+envAPIRPOrigin+")")
		byFlag()
	case "audit":
		accountFlag("one account's trail (default: every account's)")
		f.limit = fs.Int("limit", 200, "at most this many rows; 0 for all")
	case "recovery-codes":
		f.user = fs.String("user", "", "the user id (the OWNERS column of `accounts list`)")
	}
	return f
}

// validateAccountsVerb answers a usage message, or "" when the flags and
// positional arguments are enough to open the store.
func validateAccountsVerb(verb string, f accountsFlags, positional []string) string {
	switch verb {
	case "new":
		if strings.TrimSpace(*f.name) == "" {
			return "--name is required"
		}
	case "enrol-token":
		if *f.account == "" || *f.by == "" || strings.TrimSpace(*f.repos) == "" {
			return "--account and --by are required, and --repos may not be blank"
		}
		if *f.kind != accounts.KindWorkstation && *f.kind != accounts.KindService {
			return "--kind must be workstation or service"
		}
	case "grant-repo", "members", "invitations", "set-role", "remove-member", "withdraw-invitation":
		if *f.account == "" {
			return "--account is required"
		}
	case "invite":
		if *f.account == "" || *f.role == "" {
			return "--account and --role are required"
		}
		u, err := url.Parse(*f.origin)
		if *f.origin == "" || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "--origin (or $" + envAPIRPOrigin + ") must be the dashboard's http(s) origin; the link opens there"
		}
	case "recovery-codes":
		if *f.user == "" {
			return "--user is required"
		}
	}
	if verb == "withdraw-invitation" {
		if _, err := strconv.ParseInt(positional[0], 10, 64); err != nil {
			return "the invitation id is a number (the ID column of `accounts invitations`)"
		}
	}
	return ""
}

// accountsVerb parses one verb's flags, opens the store and runs it.
func accountsVerb(verb string, args []string, stdout, stderr io.Writer, deps accountsCLIDeps) int {
	name := "innsegl accounts " + verb
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := declareAccountsFlags(verb, fs)
	fs.Usage = func() {
		fprintf(stderr, "%s\n\nFlags:\n", name)
		fs.PrintDefaults()
	}

	// Flags may come before or after the positional arguments.
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
	if want := accountsVerbs[verb]; len(positional) != want {
		return usage(map[int]string{0: "expected no positional arguments", 1: "expected exactly one positional argument",
			2: "expected exactly two positional arguments"}[want])
	}
	if *f.dsn == "" {
		// The credential lives in one container on a compose core
		// (deploy/compose/innsegl.yml): say where, in the form to paste.
		return usage("-dsn (or $" + envAuthWriterDSN + ") is required. On the core host it is set in the " +
			"innsegl-api container; run it there: docker exec innsegl-api innsegl accounts " +
			strings.Join(append([]string{verb}, args...), " "))
	}
	if msg := validateAccountsVerb(verb, f, positional); msg != "" {
		return usage(msg)
	}

	ctx := context.Background()
	store, closeAll, err := deps.opener()(ctx, *f.dsn)
	if err != nil {
		fprintf(stderr, "%s: %v\n", name, err)
		return exitCredentialUnusable
	}
	if closeAll != nil {
		defer closeAll()
	}
	if err := runAccountsVerb(ctx, verb, f, positional, store, stdout, stderr); err != nil {
		fprintf(stderr, "%s: %v\n", name, err)
		return exitCredentialUnusable
	}
	return exitOK
}

// runAccountsVerb runs a parsed, validated verb against an open store.
func runAccountsVerb(ctx context.Context, verb string, f accountsFlags, positional []string,
	store accountsStore, stdout, stderr io.Writer,
) error {
	name := "innsegl accounts " + verb
	switch verb {
	case "list":
		list, err := store.ListAccounts(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fprintf(tw, "ID\tNAME\tOPERATOR\tOWNERS\tREPOS\n")
		for _, a := range list {
			fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, map[bool]string{true: "operator", false: "-"}[a.Operator],
				dashIfEmpty(strings.Join(a.Owners, ",")), dashIfEmpty(strings.Join(a.Repos, ",")))
		}
		return tw.Flush()
	case "new":
		a, err := store.CreateAccount(ctx, accounts.CreateAccountParams{Name: *f.name, Owner: *f.owner})
		if err != nil {
			return err
		}
		fprintf(stdout, "%s\n", a.ID)
	case "members":
		ms, err := store.Members(ctx, *f.account)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fprintf(tw, "USER\tNAME\tROLE\tSINCE\n")
		for _, m := range ms {
			fprintf(tw, "%s\t%s\t%s\t%s\n", m.UserID, m.DisplayName, m.Role, m.Since.UTC().Format(time.RFC3339))
		}
		return tw.Flush()
	case "set-role":
		if err := store.SetRole(ctx, *f.account, positional[0], positional[1], *f.by); err != nil {
			return err
		}
		fprintf(stderr, "%s: %s is %s of %s\n", name, positional[0], positional[1], *f.account)
	case "remove-member":
		r, err := store.RemoveMember(ctx, *f.account, positional[0], *f.by)
		if err != nil {
			return err
		}
		fprintf(stderr, "%s: %s removed from %s; %d sessions revoked; installations suspended: %s\n",
			name, positional[0], *f.account, r.SessionsRevoked, dashIfEmpty(strings.Join(r.Suspended, ",")))
	case "invite":
		code, inv, err := store.CreateInvitation(ctx, *f.account, *f.role, *f.by)
		if err != nil {
			return err
		}
		// The code rides in the fragment, which a browser never sends to a
		// server: no proxy or access log sees it. STDOUT and nowhere else.
		fprintf(stdout, "%s/invite#%s\n", strings.TrimRight(*f.origin, "/"), code)
		fprintf(stderr, "%s: invitation %d to %s as %s, single use, valid until %s\n", name, inv.ID,
			*f.account, inv.Role, inv.ExpiresAt.UTC().Format(time.RFC3339))
	case "invitations":
		list, err := store.Invitations(ctx, *f.account)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fprintf(tw, "ID\tROLE\tSTATE\tCREATED-BY\tACCEPTED-BY\tEXPIRES\n")
		for _, i := range list {
			fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", i.ID, i.Role, i.State, dashIfEmpty(i.CreatedBy),
				dashIfEmpty(i.AcceptedBy), i.ExpiresAt.UTC().Format(time.RFC3339))
		}
		return tw.Flush()
	case "withdraw-invitation":
		id, _ := strconv.ParseInt(positional[0], 10, 64) // validated
		if err := store.RevokeInvitation(ctx, *f.account, id, *f.by); err != nil {
			return err
		}
		fprintf(stderr, "%s: invitation %d withdrawn\n", name, id)
	case "audit":
		rows, err := store.AuditLog(ctx, *f.account, *f.limit)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fprintf(tw, "AT\tACCOUNT\tACTOR\tACTION\tSUBJECT\tDETAIL\n")
		for _, r := range rows {
			detail, jerr := json.Marshal(r.Detail)
			if jerr != nil {
				return jerr
			}
			fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.At.UTC().Format(time.RFC3339), dashIfEmpty(r.AccountID),
				dashIfEmpty(r.Actor), r.Action, dashIfEmpty(r.Subject), detail)
		}
		return tw.Flush()
	case "enrol-token":
		var list []string
		for _, r := range strings.Split(*f.repos, ",") {
			if r = strings.TrimSpace(r); r != "" {
				list = append(list, r)
			}
		}
		token, meta, err := store.CreateEnrolmentToken(ctx, accounts.TokenParams{
			AccountID: *f.account, CreatedBy: *f.by, Repos: list, Kind: *f.kind})
		if err != nil {
			return err
		}
		// STDOUT and nothing else: the diagnostic names the expiry, never the
		// token.
		fprintf(stdout, "%s\n", token)
		fprintf(stderr, "%s: issued, single use, valid until %s\n", name, meta.ExpiresAt.UTC().Format(time.RFC3339))
	case "installations":
		return listInstallations(ctx, store, *f.account, stdout)
	case "revoke-installation":
		if err := store.SetInstallationStatus(ctx, positional[0], accounts.StatusRevoked, ""); err != nil {
			return err
		}
		fprintf(stderr, "%s: %s revoked\n", name, positional[0])
	case "author-reset":
		if err := store.ResetOperatorAuthor(ctx, positional[0], ""); err != nil {
			return err
		}
		fprintf(stderr, "%s: %s has no operator author pinned; its machine's next "+
			"`innsegl author repo <path> operator` pins one\n", name, positional[0])
	case "grant-repo":
		if err := store.GrantRepo(ctx, *f.account, positional[0], ""); err != nil {
			return err
		}
		fprintf(stderr, "%s: %s granted to %s\n", name, positional[0], *f.account)
	case "recovery-codes":
		codes, err := store.RecoveryCodes(ctx, *f.user)
		if err != nil {
			return err
		}
		// STDOUT and nothing else, once: the codes are stored only as
		// hashes, so this is the one time they can be read.
		for _, c := range codes {
			fprintf(stdout, "%s\n", c)
		}
		fprintf(stderr, "%s: %d new codes for %s; every earlier code is voided. Each signs in once, "+
			"to the account page, where a passkey is added. Save them now: they cannot be shown again.\n",
			name, len(codes), *f.user)
	}
	return nil
}

// listInstallations prints one account's installations, or every account's
// when account is empty (GH-012).
func listInstallations(ctx context.Context, store accountsStore, account string, stdout io.Writer) error {
	ids := []string{account}
	if account == "" {
		all, err := store.ListAccounts(ctx)
		if err != nil {
			return err
		}
		ids = ids[:0]
		for _, a := range all {
			ids = append(ids, a.ID)
		}
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fprintf(tw, "ACCOUNT\tID\tSTATUS\tKIND\tNAME\tREPOS\tOPERATOR-AUTHOR\n")
	for _, acct := range ids {
		list, err := store.ListInstallations(ctx, acct)
		if err != nil {
			return err
		}
		for _, i := range list {
			// The last column is the installation's pinned operator author
			// (#545), "-" when none is pinned.
			author := "-"
			if n, e, ok, aerr := store.OperatorAuthor(ctx, i.ID); aerr != nil {
				return aerr
			} else if ok {
				author = n + " <" + e + ">"
			}
			fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", acct, i.ID, i.Status, i.Kind, i.Name,
				dashIfEmpty(strings.Join(i.Repos, ",")), author)
		}
	}
	return tw.Flush()
}

// dashIfEmpty keeps a listing's columns aligned when a value is empty.
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

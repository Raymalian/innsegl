// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/erasure"
	"innsegl.dev/innsegl/internal/mirror"
)

// mayErase is the role table's answer to who may erase an organisation: its
// owners (api.RoleMay).
func mayErase(role string) bool { return api.RoleMay(role, api.PrivilegeEraseOrganisation) }

// `innsegl erase-organisation` (#482, ADR-0080 decision 3).
//
// In one transaction it deletes the aliases of every repository only this
// organisation held, revokes its members' sessions and deletes its account
// rows; then it removes those repositories' mirrors. The chain, the sealed
// segments and the anchors are untouched. The audit trail keeps its rows and
// gains one naming the organisation's id and counts.
//
// It runs as the database OWNER, as erase-repository does: no service role
// may delete an alias.

func eraseOrganisationCommand(args []string, stdout, stderr io.Writer) int {
	return runEraseOrganisation(context.Background(), args, stdout, stderr)
}

func runEraseOrganisation(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl erase-organisation", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"the ledger database as its OWNER; no service role can delete an alias ($"+envLedgerDSN+")")
		account   = fs.String("account", "", "the organisation's id (the ID column of `innsegl accounts list`)")
		by        = fs.String("by", "", "the owner who asked; refused unless they are a live owner (default: the operator)")
		mirrorDir = fs.String("mirror-dir", os.Getenv(mirror.EnvDir),
			"the core's repository mirror; each erased repository's mirror is removed ($"+mirror.EnvDir+")")
	)
	fs.Usage = func() {
		fprintf(stderr, "innsegl erase-organisation - erase an organisation and its repositories' names (#482)\n\n")
		fprintf(stderr, "Usage:\n  innsegl erase-organisation -account ID [flags]\n\n")
		fprintf(stderr, "Deletes the organisation's members, installations, tokens, invitations and\n")
		fprintf(stderr, "repository grants, revokes its members' sessions, and erases the names\n")
		fprintf(stderr, "and mirrors of repositories no other organisation holds. No event changes.\n\n")
		fprintf(stderr, "Flags:\n")
		fs.PrintDefaults()
	}
	redactCredentialDefaults(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	switch {
	case fs.NArg() > 0:
		fprintf(stderr, "innsegl erase-organisation: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	case *account == "":
		fprintf(stderr, "innsegl erase-organisation: -account is required\n")
		return exitUsage
	case *dsn == "":
		fprintf(stderr, "innsegl erase-organisation: -dsn (or $%s) is required\n", envLedgerDSN)
		return exitUsage
	}

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "innsegl erase-organisation: connect to the ledger: %v\n", err)
		return exitReapInconclusive
	}
	defer func() { _ = conn.Close(ctx) }()

	res, err := erasure.Organisation(ctx, conn, *account, *by, mayErase)
	if err != nil {
		fprintf(stderr, "innsegl erase-organisation: %v\n", err)
		return exitReapInconclusive
	}
	fprintf(stdout, "innsegl erase-organisation: erased %s: %d members, %d installations, %d invitations, "+
		"%d enrolment tokens, %d repository grants; %d sessions revoked\n", *account, res.Members,
		res.Installations, res.Invitations, res.Tokens, res.Grants, res.SessionsRevoked)
	fprintf(stdout, "  names erased: %d repositories (%d aliases); kept, held by another organisation: %d\n",
		len(res.Repositories), len(res.Pseudonyms), len(res.Kept))

	if len(res.Repositories) == 0 {
		return exitOK
	}
	if *mirrorDir == "" {
		fprintf(stdout, "  no mirror directory configured; no mirror removed\n")
		return exitOK
	}
	m, err := mirror.Open(*mirrorDir)
	if err != nil {
		fprintf(stderr, "innsegl erase-organisation: the organisation is erased, and the mirror could not be "+
			"opened: %v. Remove each erased repository's mirror by hand: a mirror keeps the name in its path\n", err)
		return exitReapIncomplete
	}
	failed := false
	for _, repo := range res.Repositories {
		removed, rerr := m.Remove(repo)
		switch {
		case rerr != nil:
			failed = true
			fprintf(stderr, "innsegl erase-organisation: the mirror of %s was not removed: %v\n", repo, rerr)
		case removed:
			fprintf(stdout, "  removed the mirror of %s\n", repo)
		default:
			fprintf(stdout, "  no mirror of %s is held\n", repo)
		}
	}
	if failed {
		return exitReapIncomplete
	}
	return exitOK
}

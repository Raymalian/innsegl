// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/erasure"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mirror"
)

// `innsegl erase-repository` (ADR-0080 decision 3, operator decision 6).
//
// It deletes a repository's aliases, under every key id, and its branches',
// and the repository's mirror on the core. The chain, the sealed segments and
// the anchors are untouched: the events keep their pseudonyms, and nothing
// can turn those back into the name. Events recorded before the deployment
// switched to pseudonymous keep the literal name forever (E7); erasure cannot
// reach them.
//
// It runs as the database OWNER: the append role every service holds may
// insert an alias and never delete one.

func eraseRepositoryCommand(args []string, stdout, stderr io.Writer) int {
	return runEraseRepository(context.Background(), args, stdout, stderr)
}

func runEraseRepository(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl erase-repository", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		dsn = fs.String("dsn", os.Getenv(envLedgerDSN),
			"the ledger database as its OWNER; the append role cannot delete an alias ($"+envLedgerDSN+")")
		repo      = fs.String("repo", "", "the repository to erase, as host/org/name")
		mirrorDir = fs.String("mirror-dir", os.Getenv(mirror.EnvDir),
			"the core's repository mirror; the repository's mirror is removed with its name ($"+mirror.EnvDir+")")
		actor = fs.String("actor", os.Getenv("USER"), "who asked, for the audit record")
	)
	fs.Usage = func() {
		fprintf(stderr, "innsegl erase-repository - erase a repository's name from this deployment (ADR-0080)\n\n")
		fprintf(stderr, "Usage:\n  innsegl erase-repository -repo host/org/name [flags]\n\n")
		fprintf(stderr, "Deletes the aliases that resolve the repository's and its branches'\n")
		fprintf(stderr, "pseudonyms, and its mirror. No event changes. Events recorded before\n")
		fprintf(stderr, "the switch to pseudonymous keep the literal name forever.\n\n")
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
		fprintf(stderr, "innsegl erase-repository: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	case *repo == "":
		fprintf(stderr, "innsegl erase-repository: -repo is required\n")
		return exitUsage
	case event.ValidateRepo(*repo) != nil:
		fprintf(stderr, "innsegl erase-repository: -repo %q: %v\n", *repo, event.ValidateRepo(*repo))
		return exitUsage
	case *dsn == "":
		fprintf(stderr, "innsegl erase-repository: -dsn (or $%s) is required\n", envLedgerDSN)
		return exitUsage
	}

	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		fprintf(stderr, "innsegl erase-repository: connect to the ledger: %v\n", err)
		return exitReapInconclusive
	}
	defer func() { _ = conn.Close(ctx) }()

	erased, err := erasure.Repository(ctx, conn, *repo, *actor)
	if err != nil {
		fprintf(stderr, "innsegl erase-repository: %v\n", err)
		return exitReapInconclusive
	}
	if len(erased) == 0 {
		fprintf(stdout, "innsegl erase-repository: no alias of %s is held; nothing to erase in the ledger\n", *repo)
	} else {
		fprintf(stdout, "innsegl erase-repository: erased %d aliases of %s and its branches\n", len(erased), *repo)
	}

	if *mirrorDir == "" {
		fprintf(stdout, "  no mirror directory configured; no mirror removed\n")
		return exitOK
	}
	m, err := mirror.Open(*mirrorDir)
	if err != nil {
		fprintf(stderr, "innsegl erase-repository: the aliases are erased, and the mirror could not be "+
			"opened: %v. Remove %s's mirror by hand: a mirror keeps the name in its path\n", err, *repo)
		return exitReapIncomplete
	}
	removed, err := m.Remove(*repo)
	if err != nil {
		fprintf(stderr, "innsegl erase-repository: the aliases are erased, and the mirror was not "+
			"removed: %v\n", err)
		return exitReapIncomplete
	}
	if removed {
		fprintf(stdout, "  removed the mirror of %s\n", *repo)
	} else {
		fprintf(stdout, "  no mirror of %s is held\n", *repo)
	}
	return exitOK
}

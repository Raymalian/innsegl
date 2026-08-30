// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"innsegl.dev/innsegl/internal/verify"
)

// `innsegl verify` — the command that proves I5.
//
//	I5: Verification never trusts this system. Every attribution claim must be
//	checkable against Fulcio/Rekor by a third party with no access to our
//	database.
//
// So this command has NO database flag, NO ledger DSN and no way to be given
// one. That is not an omission to be filled in later: the ledger is the thing
// a verifier must not need, and a flag for it would be an invitation to depend
// on it. What it takes is a repository, a revision, and the two URLs a
// stranger would be handed — Fulcio's and Rekor's. VER-001 runs this binary
// inside a container with no route to a running Postgres and requires all
// three checks to pass anyway.
//
// The exit status is the verdict, so a script can gate on it without parsing
// prose, and the four states doc 06 §4.1 and VER-006 require are four
// different numbers. Collapsing "could not check" into "failed" would be doc
// 06 anti-pattern 2 wearing a shell's clothing.

// Exit statuses for `innsegl verify`, continuing cli.go's contract. The canary
// owns 3 and 4 and the reaper 5 and 6, in their own commands; these are this
// command's, and they are chosen so that ANY non-zero status means "do not
// treat this commit as attributed".
const (
	// exitVerifyFailed: the checks ran and the attribution does not hold.
	exitVerifyFailed = 3
	// exitVerifyUnavailable: a check could not run — Fulcio or Rekor could not
	// be reached. NEVER conflated with failure (doc 06 P2).
	exitVerifyUnavailable = 4
	// exitVerifyUnattributed: the commit makes no attribution claim. Not a
	// failure; a commit nobody claimed (E7).
	exitVerifyUnattributed = 5
	// exitVerifyUnusable: the request could not be acted on at all — no such
	// repository, no such commit, a configuration that cannot verify.
	exitVerifyUnusable = 6
)

// Flags fall back to the environment so a CI job can be configured once.
// envFulcioURL and envRekorURL are serve.go's, reused rather than respelled:
// two names for one endpoint is a deployment that can set the wrong one.
const envIssuer = "INNSEGL_OIDC_ISSUER"

// verifyTimeout bounds the whole verification. Two HTTP round trips and a few
// git reads; a verifier that has not answered in a minute should say so.
const verifyTimeout = 90 * time.Second

func verifyCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("innsegl verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", ".", "path to the git repository holding the commit")
	fulcio := fs.String("fulcio-url", os.Getenv(envFulcioURL),
		"the certificate authority's base URL ($"+envFulcioURL+")")
	rekor := fs.String("rekor-url", os.Getenv(envRekorURL),
		"the transparency log's base URL ($"+envRekorURL+")")
	issuer := fs.String("issuer", os.Getenv(envIssuer),
		"the OIDC issuer the certificate must name; empty means report it and do not "+
			"constrain it ($"+envIssuer+")")
	asJSON := fs.Bool("json", false, "write the report as JSON")
	fs.Usage = func() {
		fprintf(stderr, "Usage:\n  innsegl verify <commit> [flags]\n\n"+
			"Performs the three checks of a commit's attribution using git, Fulcio and\n"+
			"Rekor only. It never reads this system's ledger, and there is no flag with\n"+
			"which to point it at one.\n\nFlags:\n")
		fs.PrintDefaults()
		fprintf(stderr, "\nExit status:\n"+
			"  0  verified\n"+
			"  %d  failed — the checks ran and the attribution does not hold\n"+
			"  %d  verification unavailable — a check could not run\n"+
			"  %d  unattributed — the commit makes no attribution claim\n"+
			"  %d  unusable — no such commit, or a configuration that cannot verify\n",
			exitVerifyFailed, exitVerifyUnavailable, exitVerifyUnattributed, exitVerifyUnusable)
	}
	// Parsed in a loop so that `innsegl verify <sha> --repo x` works as well as
	// `innsegl verify --repo x <sha>`. Go's flag package stops at the first
	// non-flag argument, and a verifier that silently ignored the flags after
	// the commit SHA would be a verifier configured by accident.
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if len(positional) != 1 {
		fprintf(stderr, "innsegl verify: exactly one commit is required, got %d\n\n",
			len(positional))
		fs.Usage()
		return exitUsage
	}

	v, verr := verify.New(verify.Config{
		FulcioURL: *fulcio,
		RekorURL:  *rekor,
		Issuer:    *issuer,
	})
	if verr != nil {
		fprintf(stderr, "innsegl verify: %v\n", verr)
		return exitVerifyUnusable
	}

	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()
	report, err := v.Verify(ctx, *repo, positional[0])
	if err != nil {
		fprintf(stderr, "innsegl verify: %v\n", err)
		return exitVerifyUnusable
	}

	if *asJSON {
		out, jerr := verify.RenderJSON(report)
		if jerr != nil {
			fprintf(stderr, "innsegl verify: %v\n", jerr)
			return exitVerifyUnusable
		}
		fprintf(stdout, "%s", out)
	} else {
		fprintf(stdout, "%s", verify.Render(report))
	}
	return verdictExit(report.Verdict)
}

// verdictExit maps the four states onto four statuses. An unknown verdict is
// not treated as success: a verifier that exits zero on a state it does not
// recognise is a verifier that can be made to pass by adding a state.
func verdictExit(v verify.Verdict) int {
	switch v {
	case verify.VerdictVerified:
		return exitOK
	case verify.VerdictFailed:
		return exitVerifyFailed
	case verify.VerdictUnavailable:
		return exitVerifyUnavailable
	case verify.VerdictUnattributed:
		return exitVerifyUnattributed
	default:
		return exitVerifyUnusable
	}
}

// parseInterspersed parses flags that may appear before, after or between
// positional arguments, and returns the positional ones in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
}

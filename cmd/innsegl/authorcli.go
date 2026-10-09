// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"innsegl.dev/innsegl/internal/client"
)

// `innsegl author` — which repositories author agent commits as the operator
// (ENF-010, internal/client/authors.go). Run by the operator on their own
// machine; the hook only reads what it writes.

const authorUsage = `usage:
  innsegl author                                    list the setting, and the pair the core holds for this machine
  innsegl author repo <path> operator|agent          one repository's mode
  innsegl author operator 'Name <address>'           optional: a typed identity instead

Agent commits are authored as the unlinked agent address unless a repository is
set to operator. In operator mode they are authored as that repository's own
git user.email, which must be a GitHub noreply address, with its login as the
name; user.name is never used. I6 allows the operator as author; the agent
stays in the trailers and the signature.

Setting operator mode reports the identity (the typed one if set, else the
repository's) to the core, which pins it for this machine on first use, and
prints one result line. Exit status:
  0   pinned on the core now, or already pinned (the same pair)
  2   usage: not a git repository, or a malformed command
  29  refused: the core holds a different pair for this machine; reset it on
      the core host, then run this again
  30  the core could not be reached, did not answer, or is older than this
      client; or the client service, which the call goes through, is down
  31  not pinned: the identity is not a GitHub noreply address named by its
      own login, which is all the core pins
`

// Exit statuses of `innsegl author repo <path> operator` (ENF-014).
const (
	// exitAuthorRefused: the core holds a different pair for this machine.
	exitAuthorRefused = 29
	// exitAuthorUnreachable: the core was not reached, or did not answer.
	exitAuthorUnreachable = 30
	// exitAuthorNotPinnable: the identity is not one the core pins.
	exitAuthorNotPinnable = 31
)

// The reset an operator runs on a compose core (deploy/compose/innsegl.yml's
// container_name for the accounts credential's holder).
const authorResetCommand = "docker exec innsegl-api innsegl accounts author-reset "

// reportOperatorAuthor tells the core this machine's operator author;
// readOperatorAuthorPin reads what it holds. Variables so a test can stand
// in for the core.
var (
	reportOperatorAuthor  = client.ReportOperatorAuthor
	readOperatorAuthorPin = client.PinnedOperatorAuthor
)

func authorCommand(args []string, stdout, stderr io.Writer) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fprintf(stderr, "innsegl author: %v\n", err)
		return exitUsage
	}
	return runAuthor(context.Background(), args, stdout, stderr, home)
}

func runAuthor(ctx context.Context, args []string, stdout, stderr io.Writer, home string) int {
	paths := client.ClientPaths(home)
	authors, err := client.ReadAuthors(paths)
	if err != nil {
		fprintf(stderr, "innsegl author: %v\n", err)
		return exitUsage
	}
	if len(args) == 0 {
		listAuthors(stdout, authors)
		listCorePin(ctx, stdout, paths)
		return exitOK
	}
	result := exitOK
	switch args[0] {
	case "-h", "--help", "help":
		fprintf(stdout, "%s", authorUsage)
		return exitOK
	case "operator":
		if len(args) != 2 {
			fprintf(stderr, "%s", authorUsage)
			return exitUsage
		}
		authors, err = authors.SetOperator(args[1])
	case "repo":
		if len(args) != 3 {
			fprintf(stderr, "%s", authorUsage)
			return exitUsage
		}
		commonDir, gerr := gitCommonDir(ctx, args[1])
		if gerr != nil {
			fprintf(stderr, "innsegl author: %s is not a git repository: %v\n", args[1], gerr)
			return exitUsage
		}
		if args[2] == client.AuthorOperator {
			var set bool
			result, set = pinOperatorAuthor(ctx, paths, authors, args[1], stdout, stderr)
			if !set {
				return result
			}
		}
		authors, err = authors.SetRepo(commonDir, args[2])
	default:
		fprintf(stderr, "%s", authorUsage)
		return exitUsage
	}
	if err != nil {
		fprintf(stderr, "innsegl author: %v\n", err)
		return exitUsage
	}
	if err := client.WriteAuthors(paths, authors); err != nil {
		fprintf(stderr, "innsegl author: %v\n", err)
		return exitUsage
	}
	listAuthors(stdout, authors)
	return result
}

// pinOperatorAuthor reports the effective operator identity to the core and
// prints exactly one result line (ENF-014). The identity is the typed
// override when one is set, else the repository's noreply pair. It answers
// the exit status, and whether the repository may be set to operator mode:
// only once the core holds the pair, since a commit authored as a pair the
// core has not pinned would be refused at signing — or, for a typed override
// the core cannot pin, because that override is the manual path, admitted
// only by the core's own configuration.
func pinOperatorAuthor(ctx context.Context, paths client.Paths, authors client.Authors, repo string,
	stdout, stderr io.Writer,
) (code int, set bool) {
	name, email, override := authors.TypedOperator()
	if override {
		if err := client.CheckPinnable(name, email); err != nil {
			fprintf(stderr, "innsegl author: not pinned: the typed operator identity %s <%s> is not one the core "+
				"pins (%v). The repository is set to operator mode; its commits are signed only if the core's "+
				"INNSEGL_SIGN_AUTHOR_OPERATORS lists this pair.\n", name, email, err)
			return exitAuthorNotPinnable, true
		}
	} else {
		var err error
		name, email, err = client.NoreplyIdentity(ctx, repo)
		if err != nil {
			fprintf(stderr, "innsegl author: not pinned: %v; the repository stays in agent mode. Set it, then "+
				"run this again: git -C %s config user.email <id>+<login>@users.noreply.github.com\n", err, repo)
			return exitAuthorNotPinnable, false
		}
	}
	pair := name + " <" + email + ">"
	outcome, err := reportOperatorAuthor(ctx, paths, name, email)
	switch {
	case err == nil && outcome == client.PinHeld:
		fprintf(stdout, "innsegl author: already pinned on the core for this machine (same pair): %s\n", pair)
		return exitOK, true
	case err == nil:
		fprintf(stdout, "innsegl author: pinned on the core for this machine: %s\n", pair)
		return exitOK, true
	case errors.Is(err, client.ErrOperatorAuthorPinned):
		fprintf(stderr, "innsegl author: refused: the core holds a different pair for this machine, so the "+
			"repository stays in agent mode. To pin %s instead, run on the core host: %s%s, then run this again\n",
			pair, authorResetCommand, installationOrPlaceholder(paths))
		return exitAuthorRefused, false
	case versionSkewOrService(err):
		// ENF-016: not the core being unreachable; the message says which part.
		fprintf(stderr, "innsegl author: %v; the repository stays in agent mode. Then run this again\n", err)
		return exitAuthorUnreachable, false
	default:
		fprintf(stderr, "innsegl author: core unreachable: %v; the repository stays in agent mode. "+
			"Check `innsegl status`, then run this again\n", err)
		return exitAuthorUnreachable, false
	}
}

// versionSkewOrService is an error that is not the core being unreachable:
// a core older than this client, or the local client service down or older
// than this command. Its own message names the part and the fix (ENF-016).
func versionSkewOrService(err error) bool {
	return errors.Is(err, client.ErrCoreOlder) || errors.Is(err, client.ErrClientServiceDown) ||
		errors.Is(err, client.ErrClientServiceOld)
}

// installationOrPlaceholder is this machine's installation id, or a
// placeholder when core.json cannot be read.
func installationOrPlaceholder(paths client.Paths) string {
	if cfg, err := client.ReadCoreConfig(paths); err == nil {
		return cfg.InstallationID
	}
	return "<installation-id>"
}

// listCorePin prints the pair the core holds for this machine (ENF-015). A
// core that cannot be asked is shown on that line; the local listing above
// stands either way.
func listCorePin(ctx context.Context, stdout io.Writer, paths client.Paths) {
	name, email, ok, err := readOperatorAuthorPin(ctx, paths)
	switch {
	case versionSkewOrService(err):
		fprintf(stdout, "pinned on the core for this machine: unknown (%v)\n", err)
	case err != nil:
		fprintf(stdout, "pinned on the core for this machine: unknown (core unreachable: %v)\n", err)
	case ok:
		fprintf(stdout, "pinned on the core for this machine: %s <%s>\n", name, email)
	default:
		fprintf(stdout, "pinned on the core for this machine: none\n")
	}
}

func listAuthors(stdout io.Writer, a client.Authors) {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	operator := a.Operator
	if operator == "" {
		operator = "each repository's own noreply user.email"
	}
	fprintf(tw, "operator identity\t%s\n", operator)
	repos := make([]string, 0, len(a.Repos))
	for r := range a.Repos {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	for _, r := range repos {
		fprintf(tw, "%s\t%s\n", r, a.Repos[r])
	}
	fprintf(tw, "every other repository\t%s\n", client.AuthorAgent)
	_ = tw.Flush()
}

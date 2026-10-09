// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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
  innsegl author                                    list the setting
  innsegl author repo <path> operator|agent          one repository's mode
  innsegl author operator 'Name <address>'           optional: a typed identity instead

Agent commits are authored as the unlinked agent address unless a repository is
set to operator. In operator mode they are authored as that repository's own
git user.email, which must be a GitHub noreply address, with its login as the
name; user.name is never used. I6 allows the operator as author; the agent
stays in the trailers and the signature. Setting operator mode reports the
address to the core, which pins it for this machine on first use.
`

// reportOperatorAuthor tells the core this machine's operator author.
// A variable so a test can stand in for the core.
var reportOperatorAuthor = client.ReportOperatorAuthor

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
		return listAuthors(stdout, authors)
	}
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
		if args[2] == client.AuthorOperator && authors.Operator == "" {
			if code := pinOperatorAuthor(ctx, paths, args[1], stderr); code != exitOK {
				return code
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
	return listAuthors(stdout, authors)
}

// pinOperatorAuthor reads the repository's noreply address and reports it to
// the core, which pins it for this machine on first use. Operator mode is set
// only once the core holds it: a commit authored as an address the core has
// not pinned would be refused at signing.
func pinOperatorAuthor(ctx context.Context, paths client.Paths, repo string, stderr io.Writer) int {
	name, email, err := client.NoreplyIdentity(ctx, repo)
	if err != nil {
		fprintf(stderr, "innsegl author: %v. Set it in that repository: "+
			"git config user.email <id>+<login>@users.noreply.github.com\n", err)
		return exitUsage
	}
	if err := reportOperatorAuthor(ctx, paths, name, email); err != nil {
		fprintf(stderr, "innsegl author: the core did not pin this machine's operator author, "+
			"so the repository stays in agent mode: %v\n", err)
		return exitConnectFailed
	}
	return exitOK
}

func listAuthors(stdout io.Writer, a client.Authors) int {
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
	return exitOK
}

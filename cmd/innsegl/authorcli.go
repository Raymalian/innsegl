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
  innsegl author operator 'Name <address>'           the operator identity, once
  innsegl author repo <path> operator|agent          one repository's mode

Agent commits are authored as the unlinked agent address unless a repository is
set to operator. In operator mode they are authored as the operator identity,
which I6 allows; the agent stays in the trailers and the signature. The core
signs such a commit only when its own configuration pins the same pair
(INNSEGL_SIGN_AUTHOR_OPERATORS). Use a GitHub noreply address.
`

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

func listAuthors(stdout io.Writer, a client.Authors) int {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	operator := a.Operator
	if operator == "" {
		operator = "(not set)"
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

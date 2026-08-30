// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"innsegl.dev/innsegl/internal/version"
)

// Process exit codes. These are part of the CLI contract: scripts and the
// compose smoke test distinguish "the command refused" from "you asked for
// something that does not exist".
const (
	exitOK             = 0 // the command completed
	exitNotImplemented = 1 // the command exists but has no behaviour yet
	exitUsage          = 2 // the command line was not understood
)

// command is one subcommand of the single innsegl binary.
type command struct {
	// summary is the one-line description shown in the usage block.
	summary string
	// exec runs the subcommand with the arguments that follow its name.
	exec func(args []string, stdout, stderr io.Writer) int
}

// commands is the dispatch table. The reference deployment runs the MCP
// server, the reconciler, the sealer and the reaper from this one binary,
// selected by subcommand, and hands third parties the same binary for
// `innsegl verify`. Adding or renaming an entry changes an operator-visible
// surface, so the set is asserted by test.
var commands = map[string]command{
	"serve": {
		summary: "run the innsegl MCP server",
		exec:    serveCommand,
	},
	// The reconciler is IP §6.5's required background component: it expires
	// dangling signing intents and repairs the records a crash between Phase B
	// and Phase C lost. doc 05 §2 runs it single-active, from this binary.
	"reconcile": {
		summary: "reconcile signing intents against the transparency log",
		exec:    reconcileCommand,
	},
	"seal": {
		summary: "seal ledger segments and anchor them in the transparency log",
		exec:    notImplemented("seal"),
	},
	// The reaper is the seventh body: IP §6.7 requires orphaned entries to be
	// expired and recorded, and doc 05 §2 runs that single-active on a
	// schedule — which needs something an operator can schedule.
	"reap": {
		summary: "delete identity entries orphaned past their TTL",
		exec:    reapCommand,
	},
	"verify": {
		summary: "verify a commit's attribution without access to the ledger",
		exec:    verifyCommand,
	},
	// The canary is the sixth: doc 05 §2 requires the SEG-005 deletion check
	// to run "as a scheduled job in production, not only at deploy", and a
	// subcommand whose exit status is the verdict serves both callers.
	"canary": {
		summary: "prove the object store refuses to delete a sealed segment (SEG-005)",
		exec:    canaryCommand,
	},
}

// run dispatches args (os.Args[1:]) and returns the process exit code. It
// takes its writers so the whole command line is testable in-process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	case "version", "--version", "-v":
		fprintf(stdout, "%s\n", version.String())
		return exitOK
	}

	cmd, ok := commands[args[0]]
	if !ok {
		fprintf(stderr, "innsegl: unknown subcommand %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}

	return cmd.exec(args[1:], stdout, stderr)
}

// notImplemented builds the placeholder body for a subcommand that is wired
// up but not yet built. It fails loudly rather than exiting zero: a caller
// must never be able to mistake "nothing happened" for success.
func notImplemented(name string) func(args []string, stdout, stderr io.Writer) int {
	return func(_ []string, _, stderr io.Writer) int {
		fprintf(stderr, "innsegl %s: not implemented\n", name)
		return exitNotImplemented
	}
}

// usage writes the help block to w. Subcommands are listed in a stable order
// so the output can be diffed.
func usage(w io.Writer) {
	var b strings.Builder

	b.WriteString("innsegl - verifiable identity and attribution for AI agents\n\n")
	b.WriteString("Usage:\n  innsegl <subcommand> [arguments]\n\nSubcommands:\n")

	names := make([]string, 0, len(commands))
	width := 0
	for name := range commands {
		names = append(names, name)
		if len(name) > width {
			width = len(name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, name, commands[name].summary)
	}

	b.WriteString("\nOther:\n")
	fmt.Fprintf(&b, "  %-*s  print this help\n", width, "help")
	fmt.Fprintf(&b, "  %-*s  print the build version\n", width, "version")

	fprintf(w, "%s", b.String())
}

// fprintf writes to w and discards the result. Diagnostics that cannot be
// written are not worth a second failure path; nothing in this package makes
// a decision based on the outcome.
func fprintf(w io.Writer, format string, a ...any) {
	_, _ = fmt.Fprintf(w, format, a...)
}

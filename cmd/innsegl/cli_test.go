// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// documentedSubcommands is the subcommand surface fixed by the deployment
// topology (doc 05 §1): the MCP server, the reconciler, the sealer, the
// orphan-entry reaper and the third-party verify CLI all ship as one binary.
var documentedSubcommands = []string{"reap", "reconcile", "seal", "serve", "verify"}

func TestSubcommandSetIsExactlyTheDocumentedFive(t *testing.T) {
	got := make([]string, 0, len(commands))
	for name := range commands {
		got = append(got, name)
	}
	sort.Strings(got)

	if strings.Join(got, ",") != strings.Join(documentedSubcommands, ",") {
		t.Fatalf("subcommand set changed: got %v, want %v", got, documentedSubcommands)
	}
}

func TestRunDispatchesEverySubcommand(t *testing.T) {
	for _, name := range documentedSubcommands {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run([]string{name}, &stdout, &stderr)

			if code == exitOK {
				t.Errorf("run(%q) = %d, want a non-zero exit while unimplemented", name, code)
			}
			if code != exitNotImplemented {
				t.Errorf("run(%q) = %d, want %d (exitNotImplemented)", name, code, exitNotImplemented)
			}
			if !strings.Contains(stderr.String(), "innsegl "+name+": not implemented") {
				t.Errorf("run(%q) stderr = %q, want it to name the subcommand and say \"not implemented\"", name, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("run(%q) wrote %q to stdout, want diagnostics on stderr only", name, stdout.String())
			}
		})
	}
}

func TestRunRoutesOnFirstArgumentOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"verify", "0f1e2d3c", "--json"}, &stdout, &stderr)

	if code != exitNotImplemented {
		t.Errorf("run with trailing arguments = %d, want %d", code, exitNotImplemented)
	}
	if !strings.Contains(stderr.String(), "innsegl verify: not implemented") {
		t.Errorf("stderr = %q, want the verify stub to have been reached", stderr.String())
	}
}

func TestRunRejectsUnknownSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"frobnicate"}, &stdout, &stderr)

	if code != exitUsage {
		t.Errorf("run(\"frobnicate\") = %d, want %d (exitUsage)", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), `unknown subcommand "frobnicate"`) {
		t.Errorf("stderr = %q, want it to quote the rejected subcommand", stderr.String())
	}
	for _, name := range documentedSubcommands {
		if !strings.Contains(stderr.String(), name) {
			t.Errorf("stderr = %q, want usage listing %q", stderr.String(), name)
		}
	}
}

func TestRunWithoutArgumentsPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(nil, &stdout, &stderr)

	if code != exitUsage {
		t.Errorf("run(nil) = %d, want %d (exitUsage)", code, exitUsage)
	}
	for _, name := range documentedSubcommands {
		if !strings.Contains(stderr.String(), name) {
			t.Errorf("stderr = %q, want usage listing %q", stderr.String(), name)
		}
	}
}

func TestRunHelpSucceedsAndListsEverySubcommand(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run([]string{arg}, &stdout, &stderr)

			if code != exitOK {
				t.Errorf("run(%q) = %d, want %d (exitOK)", arg, code, exitOK)
			}
			for _, name := range documentedSubcommands {
				if !strings.Contains(stdout.String(), name) {
					t.Errorf("run(%q) stdout = %q, want usage listing %q", arg, stdout.String(), name)
				}
			}
			if stderr.Len() != 0 {
				t.Errorf("run(%q) wrote %q to stderr, want requested help on stdout", arg, stderr.String())
			}
		})
	}
}

func TestRunVersionSucceedsAndPrintsTheVersionString(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run([]string{arg}, &stdout, &stderr)

			if code != exitOK {
				t.Errorf("run(%q) = %d, want %d (exitOK)", arg, code, exitOK)
			}
			if !strings.Contains(stdout.String(), "innsegl") {
				t.Errorf("run(%q) stdout = %q, want the binary name", arg, stdout.String())
			}
		})
	}
}

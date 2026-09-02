// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// documentedSubcommands is the subcommand surface fixed by the deployment
// topology: the MCP server, the reconciler, the sealer, the orphan-entry
// reaper and the third-party verify CLI all ship as one binary (doc 05 §1),
// and the WORM deletion canary joins them because doc 05 §2 requires SEG-005
// to run "as a scheduled job in production, not only at deploy" — which needs
// something an operator can schedule.
//
// `api` is doc 05 §1's `innsegl-dashboard` row, backend half. RM-076 (#109)
// shipped the UI half alone because nothing in the module constructed an
// api.Server, so every query-API view rendered its own load-failure state
// permanently (RM-083, #121).
var documentedSubcommands = []string{
	"api", "canary", "reap", "reconcile", "seal", "serve", "verify",
}

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

// TestRunDispatchesEverySubcommandToABody. RM-078 (#112) removed the last
// stub: `innsegl seal` printed "not implemented" and exited 1 while
// internal/segment held a tested sealer, an anchorer and a WORM writer that
// nothing in cmd/ called, so a deployment accumulated no cold tier at all.
// This is the gate that keeps every documented subcommand attached to a body.
//
// -h is the probe because it reaches each subcommand's own flag set without
// reading the environment: a stub has no flag set to print.
func TestRunDispatchesEverySubcommandToABody(t *testing.T) {
	for _, name := range documentedSubcommands {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run([]string{name, "-h"}, &stdout, &stderr)

			if code != exitOK {
				t.Errorf("run(%q -h) = %d, want %d", name, code, exitOK)
			}
			if code == exitNotImplemented {
				t.Errorf("run(%q) = %d (exitNotImplemented); the subcommand is a stub", name, code)
			}
			if strings.Contains(stderr.String()+stdout.String(), "not implemented") {
				t.Errorf("run(%q) still reports \"not implemented\"", name)
			}
			if !strings.Contains(stderr.String()+stdout.String(), "innsegl "+name) {
				t.Errorf("run(%q -h) printed no usage naming the subcommand: %q",
					name, stderr.String()+stdout.String())
			}
		})
	}
}

func TestRunRoutesOnFirstArgumentOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer

	// Every subcommand now has a body, so routing is asserted through one that
	// refuses its own arguments: `seal` with a trailing argument reaches the
	// sealer and is refused there, which is only reachable if run dispatched
	// on the first argument alone.
	code := run([]string{"seal", "-once", "extra"}, &stdout, &stderr)

	if code != exitUsage {
		t.Errorf("run with trailing arguments = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "innsegl seal:") {
		t.Errorf("stderr = %q, want the seal subcommand to have been reached", stderr.String())
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

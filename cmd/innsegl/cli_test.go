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
//
// `migrate-schema` is doc 08 §3(c): a MAJOR schema release must append a
// migration attestation to the ledger marking the cutover position. That is
// the one of §3's four requirements that lives in a DEPLOYMENT's chain rather
// than in this repository, so no test here can produce it and an operator has
// to run something. Like `reap`, it runs from a trusted host holding the
// ledger DSN.
//
// `retire` is RM-154 (#257): the ONLY way an operator's positive knowledge
// that a run is over reaches the ledger without an MCP client. It is unlike
// its neighbours in what it holds — no ledger DSN, no SPIRE admin credential,
// only the address of the identity-lifecycle listener — because the retirement
// is `retire_agent`'s and this is a client of it.
// `gateway` is not an entry: it is ADR-0060's companion of the one
// `innsegl` process, run only as `serve -also gateway` (ADR-0071).
// `hook`, `git-hook` and `sign` are the host half of ADR-0059's commit path
// (E17): what the harness and git run, each a client of the core. `link`
// (RM-245, #390) installs the prepare-commit-msg hook `git-hook` and `sign`
// depend on into a repository, the piece `init`'s own opt-in pre-push hook
// does not cover. `connect` and `client` (RM-285, #461, ADR-0063) belong to an
// enrolled client machine: enrolment, and the service that holds its key.
var documentedSubcommands = []string{
	"accounts", "admin-credential", "api", "canary", "client", "connect", "git-hook", "hook", "init", "link", "migrate-schema",
	"reap", "reconcile", "retire", "seal", "serve", "sign", "status", "trust-backup", "verify",
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

// The commit path's host commands name their own sub-step; anything else is
// a usage error, never a silent success git or the harness would read as
// consent.
func TestCommitPathHostCommandsRefuseAnUnknownStep(t *testing.T) {
	for _, args := range [][]string{{"hook"}, {"hook", "post-tool-use"}, {"git-hook"}, {"git-hook", "commit-msg"}} {
		var stdout, stderr strings.Builder
		if code := run(args, &stdout, &stderr); code != exitUsage {
			t.Errorf("run(%q) = %d, want %d", args, code, exitUsage)
		}
		if stdout.Len() != 0 {
			t.Errorf("run(%q) wrote to stdout: %q", args, stdout.String())
		}
	}
}

// TestRunDispatchesGitsSigningProgramInvocationDirectlyToSign is RM-245's
// decision 2: git invokes `gpg.x509.program` directly as
// `<program> --status-fd=<N> -bsau <key>` (ADR-0059 decision 3) — no "sign"
// subcommand name anywhere in argv, because a deployment points git's
// gpg.x509.program at this binary itself, with no wrapper script. `run`
// recognises that shape (args[0] starting with "--status-fd") and dispatches
// it exactly as it would `sign <the same args>`: no subcommand name ever
// starts with "-", so this is unambiguous with the dispatch table.
func TestRunDispatchesGitsSigningProgramInvocationDirectlyToSign(t *testing.T) {
	cases := [][]string{
		{"--status-fd=2", "-bsau", "key"},
		{"--status-fd", "2", "-bsau", "key"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var wantStdout, wantStderr bytes.Buffer
			wantCode := run(append([]string{"sign"}, args...), &wantStdout, &wantStderr)

			var gotStdout, gotStderr bytes.Buffer
			gotCode := run(args, &gotStdout, &gotStderr)

			if gotCode != wantCode {
				t.Errorf("run(%v) = %d, want %d (same as `sign %v`)", args, gotCode, wantCode, args)
			}
			if gotStdout.String() != wantStdout.String() {
				t.Errorf("run(%v) stdout = %q, want %q", args, gotStdout.String(), wantStdout.String())
			}
			if gotStderr.String() != wantStderr.String() {
				t.Errorf("run(%v) stderr = %q, want %q", args, gotStderr.String(), wantStderr.String())
			}
		})
	}
}

// TestRunDispatchesVerifyModeDirectlyToSign is the --verify half of decision
// 2: `git verify-commit` invokes the same gpg.x509.program with --verify, and
// this binary points that at gitsign rather than trying to handle it, exactly
// as `innsegl sign --verify` already does (sign_test.go's
// TestRunSignRefusesVerifyMode).
func TestRunDispatchesVerifyModeDirectlyToSign(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--status-fd=1", "--verify"}, &stdout, &stderr)
	if code == exitOK {
		t.Fatalf("run with --verify = %d, want non-zero (this program never verifies)", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "gitsign") {
		t.Errorf("stderr = %q, want it to name gitsign as the verifier", stderr.String())
	}
}

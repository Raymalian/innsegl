// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"slices"
	"testing"
)

// CLI-011 and CLI-012 (proposed for doc 07; doc 07 is not modified here).
//
// Four of doc 05 §1's services are one binary run four ways: `innsegl:local`
// as serve, api, seal and reconcile. They are four containers because the
// compose file starts them four times, not because they need to be separate
// processes — measured with `docker inspect`, which reports the same image and
// different commands.
//
// `-also` lets one process run the others. It is opt-in: unset changes nothing
// and every deployment that does not ask for it keeps four containers.
//
// # What these tests protect
//
// A name this flag does not understand must FAIL, not be skipped. The failure
// mode otherwise is a deployment that asked for `-also sealer` (the container's
// name) instead of `-also seal` (the subcommand's), started cleanly, and
// silently never sealed a segment — the ledger would grow and nothing would
// anchor, which nothing else in the system reports as an error because from
// every other component's point of view the sealer simply has not run yet.
//
// That is the whole reason this is validated at parse time rather than at use.

func TestCLI011ServeAlsoAcceptsTheThreeCompanionCommands(t *testing.T) {
	for _, want := range [][]string{
		{"api"},
		{"seal"},
		{"reconcile"},
		{"seal", "reconcile"},
		{"api", "seal", "reconcile"},
		{"reap"},
		{"seal", "reconcile", "reap"},
	} {
		got, err := parseAlso(joinComma(want))
		if err != nil {
			t.Errorf("parseAlso(%q): %v", joinComma(want), err)
			continue
		}
		if !slices.Equal(got, want) {
			t.Errorf("parseAlso(%q) = %v, want %v", joinComma(want), got, want)
		}
	}
}

func TestCLI012ServeAlsoRefusesANameItDoesNotUnderstand(t *testing.T) {
	// "sealer" and "reconciler" are the CONTAINER names in doc 05 §1, and are
	// the two most likely things an operator types. Neither is a subcommand.
	for _, bad := range []string{"sealer", "reconciler", "dashboard", "serve", "verify", "nonsense"} {
		if _, err := parseAlso(bad); err == nil {
			t.Errorf("parseAlso(%q) was accepted; an unrecognised name must fail at parse "+
				"time, or a deployment starts cleanly and silently never runs it", bad)
		}
	}
	if _, err := parseAlso("api,,seal"); err == nil {
		t.Error("parseAlso accepted an empty element; a trailing or doubled comma is a typo, not a request")
	}
}

func TestCLI013ServeAlsoEmptyMeansNone(t *testing.T) {
	got, err := parseAlso("")
	if err != nil {
		t.Fatalf("parseAlso(\"\"): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("parseAlso(\"\") = %v, want none — unset must change nothing", got)
	}
}

// TestCLI013ServeRejectsABadAlsoBeforeStartingAnything. The flag is validated
// during parsing, so a bad value is exit 2 with nothing opened — not a server
// that came up and then failed.
func TestCLI013ServeRejectsABadAlsoBeforeStartingAnything(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := serveCommand([]string{"-also", "sealer"}, &out, &errBuf)
	if code != exitUsage {
		t.Errorf("serve -also sealer exited %d, want %d (usage)", code, exitUsage)
	}
	if out.Len() != 0 {
		t.Errorf("serve printed an address on stdout for a request it refused: %q", out.String())
	}
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

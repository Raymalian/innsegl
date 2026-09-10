// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// OPS-006 (proposed for doc 07; doc 07 is not modified here) — RM-122, #194.
//
// ADR-0047 decision 4 is written and off by default. A pass nothing can turn on
// is a pass that does not exist, and this is the wiring that decides whether a
// deployment keeps lookup-by-SHA working after a merge.
//
// # Measured on 2026-09-10, which is why this is not hypothetical
//
// PR #200 merged by rebase — the only strategy `main` permits, since
// required_linear_history forbids a merge commit and squash is disabled. All
// fifteen commits were rewritten, every gitsign signature destroyed, every
// Agent-* trailer intact. That is the state this pass exists to record, and
// nothing recorded it, because nothing was configured to.
func TestOPS006TheRebasePassIsOffUntilABranchIsNamed(t *testing.T) {
	t.Run("the flags are documented in the help", func(t *testing.T) {
		var stdout, stderr strings.Builder
		if code := run([]string{"reconcile", "-h"}, &stdout, &stderr); code != exitOK {
			t.Fatalf("reconcile -h = %d", code)
		}
		help := stderr.String() + stdout.String()
		for _, want := range []string{"rebase-branch", "rebase-repos"} {
			if !strings.Contains(help, want) {
				t.Errorf("the help does not mention -%s, so an operator cannot find "+
					"the control that keeps lookup-by-SHA working after a merge", want)
			}
		}
	})

	t.Run("a repo list with no branch is refused, not silently ignored", func(t *testing.T) {
		// Half a configuration is the shape that looks enabled and does
		// nothing. The reconciler refuses a RebaseConfig with no branch for
		// the same reason; this refuses it at the command line, where the
		// operator can still see which flag was wrong.
		var stdout, stderr strings.Builder
		code := run([]string{"reconcile", "-rebase-repos", "github.com/acme/api"}, &stdout, &stderr)
		if code != exitUsage {
			t.Errorf("run = %d, want %d for a repo list with no branch to walk", code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "rebase-branch") {
			t.Errorf("said %q, which does not name the missing flag", stderr.String())
		}
	})

	t.Run("a branch with no repos is refused too", func(t *testing.T) {
		var stdout, stderr strings.Builder
		code := run([]string{"reconcile", "-rebase-branch", "main"}, &stdout, &stderr)
		if code != exitUsage {
			t.Errorf("run = %d, want %d for a branch with no repository to walk it in",
				code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "rebase-repos") {
			t.Errorf("said %q, which does not name the missing flag", stderr.String())
		}
	})
}

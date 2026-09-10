// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/reconciler"
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

// TestOPS007TheCycleReportsWhatTheRebasePassDid.
//
// The reconciler's own comment about drift says it plainly: "a control a
// deployment cannot see the state of is a control it does not have." The
// rebase pass shipped with exactly that defect — on 2026-09-10 it recorded
// five superseding events on a live chain and the cycle report said nothing,
// so the only way to know it had worked was to query Postgres by hand.
//
// OFF must be as visible as ON. A deployment that has not configured the pass
// is a deployment where lookup by SHA stops working after the next merge, and
// silence reads exactly like "there was nothing to record".
func TestOPS007TheCycleReportsWhatTheRebasePassDid(t *testing.T) {
	t.Run("off says off", func(t *testing.T) {
		out := renderReconcileResult(reconciler.Result{})
		if !strings.Contains(out, "rebase") {
			t.Errorf("the report says nothing about the rebase pass:\n%s\n"+
				"A deployment cannot tell a pass that is off from one that found "+
				"nothing, and the difference is whether the next merge is "+
				"recoverable", out)
		}
	})

	t.Run("on reports what it recorded", func(t *testing.T) {
		out := renderReconcileResult(reconciler.Result{
			Rebase: reconciler.RebaseReport{
				Enabled: true, Recorded: 5, AlreadyRecorded: 2, Unmatched: 1,
			},
		})
		for _, want := range []string{"5", "2", "1"} {
			if !strings.Contains(out, want) {
				t.Errorf("the report omits a count (%s):\n%s", want, out)
			}
		}
	})

	t.Run("a repository it could not read is named", func(t *testing.T) {
		// The one outcome that must never be quiet: an unreadable repository
		// looks identical to a branch with no rewrites.
		out := renderReconcileResult(reconciler.Result{
			Rebase: reconciler.RebaseReport{
				Enabled: true, Unreadable: []string{"github.com/acme/api"},
			},
		})
		if !strings.Contains(out, "github.com/acme/api") {
			t.Errorf("the report does not name the repository it could not read:\n%s", out)
		}
	})
}

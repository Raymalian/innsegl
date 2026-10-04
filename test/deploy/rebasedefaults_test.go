// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The reconciler refuses a rebase repository list without a branch, and a
// branch without one (cmd/innsegl reconcile.go, ADR-0047); it runs inside
// the core, so a mismatched pair crash-loops the core on every host
// (measured 2026-10-04: the branch defaulted empty, the repositories did
// not). The Makefile's defaults are set together or not at all.
func TestTheRebaseDefaultsAreSetTogether(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	value := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + ` \?=(.*)$`).FindSubmatch(mk)
		if m == nil {
			t.Fatalf("the Makefile sets no default for %s", name)
		}
		return strings.TrimSpace(string(m[1]))
	}
	branch, repos := value("INNSEGL_REBASE_BRANCH"), value("INNSEGL_REBASE_REPOS")
	if (branch == "") != (repos == "") {
		t.Fatalf("INNSEGL_REBASE_BRANCH=%q and INNSEGL_REBASE_REPOS=%q: the reconciler refuses one "+
			"without the other and the core will not start", branch, repos)
	}
}

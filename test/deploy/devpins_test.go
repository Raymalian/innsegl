// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// OPS-196 (PROPOSED for doc 07, #592) — a hint that tells a developer how to
// install gobco or golangci-lint names the version CI runs, never @latest: a
// newer tool than CI's reports what CI does not, or misses what CI catches.

var (
	ciGobcoPin    = regexp.MustCompile(`go install github\.com/rillig/gobco@(v[0-9.]+)`)
	ciLintPin     = regexp.MustCompile(`(?m)^\s+version: (v2\.[0-9.]+)\s*$`)
	gobcoHint     = regexp.MustCompile(`github\.com/rillig/gobco@(\S+?)['"\s\\]`)
	lintHint      = regexp.MustCompile(`golangci-lint[^\n]*?@(\S+?)['"\s\\]`)
	lintMentioned = regexp.MustCompile(`golangci-lint run`)
)

func TestOPS196InstallHintsNameTheCIPins(t *testing.T) {
	root := deploytest.RepoRoot(t)
	ci := deploytest.ReadFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	gobco := ciGobcoPin.FindStringSubmatch(ci)
	lint := ciLintPin.FindStringSubmatch(ci)
	if gobco == nil || lint == nil {
		t.Fatal("ci.yml no longer pins gobco and golangci-lint where this test reads them")
	}

	var files []string
	for _, glob := range []string{"scripts/*.sh", "Makefile", "CONTRIBUTING.md", "reference/*.md"} {
		m, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		rel, err := filepath.Rel(root, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range gobcoHint.FindAllStringSubmatch(text, -1) {
			if h[1] != gobco[1] {
				t.Errorf("%s: gobco hint names @%s; CI runs %s", rel, h[1], gobco[1])
			}
		}
		for _, h := range lintHint.FindAllStringSubmatch(text, -1) {
			if h[1] != lint[1] {
				t.Errorf("%s: golangci-lint hint names @%s; CI runs %s", rel, h[1], lint[1])
			}
		}
		// Where a developer is told to run golangci-lint, the version is named.
		if lintMentioned.MatchString(text) && !strings.Contains(text, lint[1]) {
			t.Errorf("%s tells a developer to run golangci-lint without naming CI's version %s", rel, lint[1])
		}
	}
}

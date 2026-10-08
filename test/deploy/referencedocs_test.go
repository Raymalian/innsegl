// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// DOC-001 (PROPOSED for doc 07) — reference/ is the record of every part.
// Every `innsegl` subcommand in cmd/innsegl's command table and every
// Makefile target with a `##` help line must be named, in backticks, on
// some reference/*.md page. A new subcommand or target with no page fails
// here, naming it, so the reference cannot fall behind the code silently.

// commandTableEntry is one key of the `commands` map literal in cli.go.
var commandTableEntry = regexp.MustCompile(`^\t"([a-z0-9-]+)":\s*\{`)

// makeHelpLine is a Makefile help line: `## target: what it does`.
var makeHelpLine = regexp.MustCompile(`^## ([A-Za-z0-9_.-]+):`)

// codeSpan is one inline code span in Markdown.
var codeSpan = regexp.MustCompile("`([^`\n]+)`")

// cliSubcommands reads the dispatch table in cmd/innsegl/cli.go.
func cliSubcommands(t *testing.T, root string) []string {
	t.Helper()
	src := readFile(t, filepath.Join(root, "cmd", "innsegl", "cli.go"))
	start := strings.Index(src, "var commands = map[string]command{")
	if start < 0 {
		t.Fatal("cmd/innsegl/cli.go has no `var commands = map[string]command{` table")
	}
	body := src[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	var names []string
	for _, line := range strings.Split(body, "\n") {
		if m := commandTableEntry.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	if len(names) < 10 {
		t.Fatalf("read %d subcommands from cli.go's table; the parser no longer matches it", len(names))
	}
	return names
}

// makeTargets reads every target that has a `##` help line.
func makeTargets(t *testing.T, root string) []string {
	t.Helper()
	var names []string
	for _, line := range strings.Split(readFile(t, filepath.Join(root, "Makefile")), "\n") {
		if m := makeHelpLine.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	if len(names) < 10 {
		t.Fatalf("read %d help-line targets from the Makefile; the parser no longer matches it", len(names))
	}
	return names
}

// referenceSpans returns every inline code span on every reference page.
func referenceSpans(t *testing.T, root string) []string {
	t.Helper()
	pages, err := filepath.Glob(filepath.Join(root, "reference", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	var spans []string
	for _, p := range pages {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range codeSpan.FindAllStringSubmatch(string(body), -1) {
			spans = append(spans, m[1])
		}
	}
	return spans
}

// mentioned reports whether some span runs `<prefix> <name>` as words.
func mentioned(spans []string, prefix, name string) bool {
	re := regexp.MustCompile(`(^|\s)` + regexp.QuoteMeta(prefix+" "+name) + `(\s|$)`)
	for _, s := range spans {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func TestDOC001EveryCommandAndTargetHasAReferencePage(t *testing.T) {
	root := repoRoot(t)
	spans := referenceSpans(t, root)

	var missing []string
	for _, c := range cliSubcommands(t, root) {
		if !mentioned(spans, "innsegl", c) {
			missing = append(missing, "`innsegl "+c+"`")
		}
	}
	for _, target := range makeTargets(t, root) {
		if !mentioned(spans, "make", target) {
			missing = append(missing, "`make "+target+"`")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("no reference/*.md page names these in backticks (%d):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

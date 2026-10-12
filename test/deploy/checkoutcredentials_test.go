// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// GH-013 (proposed for doc 07) — no CI checkout leaves the job token in
// .git/config. Every actions/checkout step sets `persist-credentials: false`,
// unless the step genuinely pushes; such a step carries an inline
// `# persist-credentials-allowed: <reason>` comment inside the step.
//
// Dependency update checks (.github/dependabot.yml) cover the four ecosystems
// the repo ships, weekly.

var (
	checkoutUses = regexp.MustCompile(`^\s*(?:-\s+)?uses:\s*actions/checkout@`)
	persistFalse = regexp.MustCompile(`^\s*persist-credentials:\s*false\s*(#.*)?$`)
)

func indentOf(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

// checkoutViolations returns "file:line" for each checkout step in text that
// neither sets persist-credentials: false nor carries an allow comment.
func checkoutViolations(name, text string) []string {
	lines := strings.Split(text, "\n")
	var bad []string
	for i, l := range lines {
		if !checkoutUses.MatchString(l) {
			continue
		}
		// Find the step's "- " line, then read until the next step or a
		// dedent below the step's keys.
		start := i
		for start > 0 && !strings.HasPrefix(strings.TrimLeft(lines[start], " "), "- ") {
			start--
		}
		dash := indentOf(lines[start])
		ok := false
		for j := start; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if j > start && t != "" && !strings.HasPrefix(t, "#") && indentOf(lines[j]) <= dash {
				break
			}
			if persistFalse.MatchString(lines[j]) || strings.Contains(lines[j], "persist-credentials-allowed:") {
				ok = true
				break
			}
		}
		if !ok {
			bad = append(bad, name+":"+strconv.Itoa(i+1))
		}
	}
	return bad
}

func TestGH013EveryCheckoutDropsItsCredentials(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found (err=%v)", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range checkoutViolations(filepath.Base(f), string(b)) {
			t.Errorf("%s: actions/checkout without `persist-credentials: false` (or a `# persist-credentials-allowed: <why>` comment)", v)
		}
	}
}

func TestGH013TheCheckoutGateCatchesAMissingSetting(t *testing.T) {
	bare := "    steps:\n      - name: Check out\n        uses: actions/checkout@abc # v1\n      - run: true\n"
	if got := checkoutViolations("x.yml", bare); len(got) != 1 {
		t.Errorf("bare checkout: got %v, want one violation", got)
	}
	other := "      - uses: actions/checkout@abc\n        with:\n          fetch-depth: 0\n      - run: echo persist-credentials: false\n"
	if got := checkoutViolations("x.yml", other); len(got) != 1 {
		t.Errorf("checkout with only fetch-depth: got %v, want one violation", got)
	}
	good := "      - uses: actions/checkout@abc\n        with:\n          persist-credentials: false\n"
	allowed := "      - uses: actions/checkout@abc\n        # persist-credentials-allowed: pushes the tag\n"
	for _, s := range []string{good, allowed} {
		if got := checkoutViolations("x.yml", s); len(got) != 0 {
			t.Errorf("got %v, want none for %q", got, s)
		}
	}
}

func TestGH013DependabotCoversEveryEcosystemWeekly(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, ".github", "dependabot.yml"))
	if err != nil {
		t.Fatalf("dependabot config missing: %v", err)
	}
	text := string(b)
	for _, eco := range []string{"gomod", "npm", "github-actions", "docker"} {
		if !strings.Contains(text, "package-ecosystem: "+eco) {
			t.Errorf("dependabot.yml has no %s ecosystem", eco)
		}
	}
	if n := strings.Count(text, "interval: weekly"); n < 4 {
		t.Errorf("dependabot.yml has %d weekly schedules, want 4", n)
	}
	if !strings.Contains(text, `directory: "/web"`) {
		t.Errorf("dependabot.yml npm entry does not point at /web")
	}
}

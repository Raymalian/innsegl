// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-162 (PROPOSED) — the image build copies every source folder the
// binaries it builds compile from.
//
// MEASURED on a live core: a new top-level package (reference/, which embeds
// the reference pages) built and tested everywhere outside Docker, and the
// image build failed with "no required module provides package
// innsegl.dev/innsegl/reference": the Dockerfile copies cmd, internal and
// migrations by name, and nothing told it about a fourth folder.
// ---------------------------------------------------------------------------

func TestOPS162TheImageBuildCopiesEverySourceFolderItCompiles(t *testing.T) {
	root := repoRoot(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go is not on PATH: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}",
		"./cmd/innsegl", "./cmd/ca-bootstrap")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const module = "innsegl.dev/innsegl/"
	need := map[string]bool{}
	for _, p := range strings.Fields(string(out)) {
		if rest, ok := strings.CutPrefix(p, module); ok {
			need[strings.SplitN(rest, "/", 2)[0]] = true
		}
	}
	df := readFile(t, filepath.Join(root, "Dockerfile"))
	ignore := readFile(t, filepath.Join(root, ".dockerignore"))
	for dir := range need {
		if !regexp.MustCompile(`(?m)^COPY ` + regexp.QuoteMeta(dir) + ` \./` + regexp.QuoteMeta(dir) + `$`).MatchString(df) {
			t.Errorf("the binaries compile from %s/, and the Dockerfile's build stage does not COPY %s ./%s", dir, dir, dir)
		}
		if regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(dir) + `/?$`).MatchString(ignore) {
			t.Errorf(".dockerignore excludes %s/, which the binaries compile from", dir)
		}
	}
}

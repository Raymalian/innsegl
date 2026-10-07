// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// test/failure mints a new transparency-log tree and test/smoke ends its
// teardown in `docker compose down -v`. Both are correct on a throwaway CI
// runner and destructive on any machine that holds a deployment. A guard that
// decides at run time can misjudge a host (measured 2026-10-07: the stack
// stopped but its volumes present read as "no deployment"). A build tag cannot:
// without `-tags destructive` these packages do not compile, so no script,
// agent or bare `go test ./...` can reach them unless someone asks for it.
var destructivePackages = []string{"test/failure", "test/smoke"}

func TestDestructivePackagesBuildOnlyWithAnExplicitTag(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range destructivePackages {
		files, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no Go files found (%v)", dir, err)
		}
		for _, f := range files {
			body, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "\n//go:build destructive\n") {
				t.Errorf("%s has no `//go:build destructive` line: without it a plain `go test ./...` "+
					"compiles and runs a package that destroys a deployment", strings.TrimPrefix(f, root+"/"))
			}
		}
	}
}

// CI is the one place these packages are meant to run, so CI must ask for
// them by name, and lint must still see them.
func TestCIAsksForTheDestructivePackagesByTag(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ci, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"go vet -tags destructive ./...",
		"INNSEGL_TEST_FLAGS: -tags=destructive",
		"go test ${PKGS} -race -tags destructive",
	} {
		if !strings.Contains(string(ci), want) {
			t.Errorf("ci.yml does not contain %q: CI would silently stop running or vetting the destructive packages", want)
		}
	}
	lint, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lint), "build-tags:") || !strings.Contains(string(lint), "- destructive") {
		t.Error(".golangci.yml does not lint with the destructive build tag: those files would go unlinted")
	}
}

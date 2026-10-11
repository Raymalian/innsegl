// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"os/exec"
	"strings"
	"testing"
)

// ShippedFiles is every tracked file an adopter runs: the compose stack and
// its scripts, the image build, the operator entry points and the runbooks.
// Test harnesses are excluded; see the case that calls this for why.
func ShippedFiles(t *testing.T, root string) []string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(),
		"git", "-C", root, "ls-files", "deploy", "runbooks", "Dockerfile", "Makefile").Output()
	if err != nil {
		t.Fatalf("listing the shipped files: %v", err)
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f != "" {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatal("no shipped files were listed; the guard would pass vacuously")
	}
	return files
}

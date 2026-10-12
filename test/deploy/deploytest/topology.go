// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// ServiceLine matches a top-level service key in a compose file: exactly two
// spaces of indent, a name, a colon, end of line. The shipped files are hand
// written with that convention and every comment in them is a `#` line, so a
// regexp is enough and buys the package no YAML dependency.
var ServiceLine = regexp.MustCompile(`^ {2}([a-z][a-z0-9_-]*):\s*$`)

// ComposeServices returns the service names a compose file declares.
func ComposeServices(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is part of the reference deployment and must exist: %v", path, err)
	}

	var out []string
	inServices := false
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case strings.HasPrefix(line, "services:"):
			inServices = true
			continue
		case line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#"):
			inServices = false
		}
		if !inServices {
			continue
		}
		if m := ServiceLine.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func ReadFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	return string(body)
}

// RepoRoot finds the module root from the test's working directory.
func RepoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(),
		"git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}

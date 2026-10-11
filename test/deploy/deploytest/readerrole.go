// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"strings"
	"testing"
)

// ComposeServiceBlock returns one service's lines from a compose file, from its
// two-space key to the next one. The shipped files are hand written with that
// convention (topology_test.go's serviceLine relies on it too), which buys this
// package no YAML dependency.
func ComposeServiceBlock(t *testing.T, body, service string) string {
	t.Helper()
	lines := strings.Split(body, "\n")
	start := -1
	for i, line := range lines {
		if line == "  "+service+":" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no `%s:` service key in the compose file", service)
	}
	for i := start + 1; i < len(lines); i++ {
		if m := ServiceLine.FindStringSubmatch(lines[i]); m != nil {
			return strings.Join(lines[start:i], "\n")
		}
		if lines[i] != "" && !strings.HasPrefix(lines[i], " ") &&
			!strings.HasPrefix(lines[i], "#") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

func Contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

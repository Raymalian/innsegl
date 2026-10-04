// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The three stacks run on one host and publish on loopback unless
// INNSEGL_BIND moves them, so two services with the same default host port
// cannot both start. Measured 2026-10-04: spire-oidc and the dashboard's
// HTTPS both defaulted to 8443, and on a loopback install the second one
// failed with "port is already allocated".
func TestNoTwoServicesShareADefaultHostPort(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "deploy", "compose", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no compose files: %v", err)
	}
	published := regexp.MustCompile(`(?m)^\s*- "[^"]*\$\{([A-Z_]+):-([0-9]+)\}:[0-9]+"`)
	seen := map[string]string{}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range published.FindAllStringSubmatch(string(body), -1) {
			name, port := m[1], m[2]
			where := filepath.Base(f) + " " + name
			if prev, ok := seen[port]; ok && prev != where {
				t.Errorf("host port %s is the default of both %s and %s", port, prev, where)
			}
			seen[port] = where
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no published host ports; the pattern no longer matches the compose files")
	}
}

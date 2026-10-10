// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OPS-181 (#473): the ACME DNS credential is read by the core at start, so
// storing a new one restarts the core then, through the compose-up path that
// hashes the credential's volume. Measured on the dev stack: with the token
// stored and only `make update` left to pick it up, the update answered
// "already up to date" (nothing in the checkout changed) and the core kept
// the old credential.
func TestOPS181StoringTheACMECredentialRecreatesTheCore(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "\ninnsegl-acme-credential:")
	if start < 0 {
		t.Fatal("the Makefile has no innsegl-acme-credential target")
	}
	recipe := text[start+1:]
	if end := strings.Index(recipe, "\n\n"); end > 0 {
		recipe = recipe[:end]
	}
	if !strings.Contains(recipe, "innsegl-here-services") {
		t.Fatalf("innsegl-acme-credential stores the credential and leaves the core running on the old one:\n%s", recipe)
	}
	if strings.Contains(recipe, "docker compose") && strings.Contains(recipe, " up") {
		t.Fatal("innsegl-acme-credential runs a bare compose up; it must go through compose-up")
	}
}

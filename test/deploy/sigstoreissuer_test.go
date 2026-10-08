// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-156 (PROPOSED for doc 07's TC-OPS) — every recipe has the JWT issuer
// (#533).
//
// MEASURED: sigstore.yml requires INNSEGL_SPIRE_JWT_ISSUER for interpolation
// (`:?`), for any compose verb. The custody recipes ran compose without it,
// so `make ca-custody-up` failed on a live core, and the store and its network
// were never created. Passing it at each call site is what failed: the next
// call site forgets. The Makefile exports it, and this runs a real recipe in
// an environment without it to show it arrives anyway.
// ---------------------------------------------------------------------------

func TestOPS156EveryRecipeHasTheIssuer(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	probe := filepath.Join(t.TempDir(), "probe.mk")
	if err := os.WriteFile(probe, []byte("ops156-probe:\n\t@printf '%s\\n' \"$$INNSEGL_SPIRE_JWT_ISSUER\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "make", "-s", "--no-print-directory",
		"-f", "Makefile", "-f", probe, "ops156-probe")
	cmd.Dir = repoRoot(t)
	var env []string
	for _, kv := range stackEnv(t.TempDir(), "") {
		if !strings.HasPrefix(kv, "INNSEGL_SPIRE_JWT_ISSUER=") {
			env = append(env, kv)
		}
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make ops156-probe: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got == "" {
		t.Fatal("a recipe run without INNSEGL_SPIRE_JWT_ISSUER in the environment does not have it; " +
			"compose over sigstore.yml fails there")
	}
}

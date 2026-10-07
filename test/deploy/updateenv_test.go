// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-135 (PROPOSED for doc 07's TC-OPS) — `make update` sees a settings
// change, not only a code change (#533).
//
// MEASURED: turning the trust-key backup on is two lines in
// deploy/compose/.env and `make update`. The update recorded only the commit
// it deployed, found the checkout unchanged, printed "already up to date" and
// started nothing; the backup service never ran. What `make update` records
// must name the settings it deployed with as well.
// ---------------------------------------------------------------------------

// deployedState matches what the update recipe writes into its marker.
var deployedState = regexp.MustCompile(`echo '([^']*)' > '\.innsegl/deployed-commit'`)

func updateMarker(t *testing.T, envFile string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "make", "-n", "--no-print-directory", "update",
		"COMPOSE_ENV_FILE="+envFile)
	cmd.Dir = repoRoot(t)
	cmd.Env = stackEnv(t.TempDir(), "")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n update: %v\n%s", err, out)
	}
	m := deployedState.FindSubmatch(out)
	if m == nil {
		t.Fatalf("make -n update writes no deployed marker this test can read:\n%s", out)
	}
	return string(m[1])
}

func TestOPS135UpdateRecordsTheSettingsItDeployedWith(t *testing.T) {
	env := filepath.Join(t.TempDir(), ".env")
	write := func(s string) {
		if err := os.WriteFile(env, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("INNSEGL_TLS=1\n")
	before := updateMarker(t, env)
	if again := updateMarker(t, env); again != before {
		t.Fatalf("the same settings gave two markers: %q then %q", before, again)
	}

	write("INNSEGL_TLS=1\nCOMPOSE_PROFILES=trust-backup\n")
	if after := updateMarker(t, env); after == before {
		t.Fatalf("a changed .env left the marker at %q, so make update would call it up to date", after)
	}

	if err := os.Remove(env); err != nil {
		t.Fatal(err)
	}
	if none := updateMarker(t, env); none == before {
		t.Fatalf("no .env gave the same marker as one with settings: %q", none)
	}
}

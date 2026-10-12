// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"os/exec"
	"regexp"
	"testing"
)

// deployedState matches what the update recipe writes into its marker.
var deployedState = regexp.MustCompile(`echo '([^']*)' > '\.innsegl/deployed-commit'`)

func UpdateMarker(t *testing.T, envFile string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), "make", "-n", "--no-print-directory", "update",
		"COMPOSE_ENV_FILE="+envFile)
	cmd.Dir = RepoRoot(t)
	cmd.Env = StackEnv(t.TempDir(), "")
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

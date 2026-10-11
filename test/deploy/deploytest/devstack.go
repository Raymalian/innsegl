// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// StackEnv is the environment a test runs make or a script under: this
// process's, minus everything that chooses a stack or a bind, plus HOME and
// the mode the test asks for ("" leaves INNSEGL_STACK unset).
func StackEnv(home, mode string, extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "HOME", k == "INNSEGL_BIND", k == "MAKEFLAGS", k == "MFLAGS",
			strings.HasPrefix(k, "INNSEGL_STACK"),
			strings.HasPrefix(k, "INNSEGL_TRUST_"),
			k == "INNSEGL_GATEWAY_CA_HOST_DIR", k == "INNSEGL_LOG_DIR",
			k == "INNSEGL_BACKUP_HOST_DIR":
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+home,
		// No docker is asked which containers run: a test never depends on
		// what this machine happens to have up.
		"INNSEGL_STACK_DOCKER=true",
		"INNSEGL_REKOR_PORT=23000")
	if mode != "" {
		env = append(env, "INNSEGL_STACK="+mode)
	}
	return append(env, extra...)
}

// MakeDryRun is what `make -n` would run for the targets, in a mode.
func MakeDryRun(t *testing.T, mode string, targets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	args := append([]string{"-n", "--no-print-directory"}, targets...)
	cmd := exec.CommandContext(t.Context(), "make", args...)
	cmd.Dir = RepoRoot(t)
	cmd.Env = StackEnv(t.TempDir(), mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %v (INNSEGL_STACK=%s): %v\n%s", targets, mode, err, out)
	}
	return string(out)
}

func Itoa(n int64) string { return strconv.FormatInt(n, 10) }

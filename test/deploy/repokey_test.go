// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/identity"
)

// OPS-175 (ADR-0080 decision 2): the shipped identity one-shot also generates
// the repository key, per deployment, once, and the compose file hands the
// core its path and a literal default. The key is never a constant in a
// shipped file.
func TestOPS175TheStackGeneratesItsOwnRepositoryKey(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, identityInitScript)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl is not on PATH, so the shipped generator cannot be run here: %v", err)
	}

	generate := func(t *testing.T, dir string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "sh", script)
		cmd.Env = append(os.Environ(),
			identitySecretEnv+"="+filepath.Join(dir, "secret"),
			"INNSEGL_REPO_KEY_FILE="+filepath.Join(dir, "repo-key"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", identityInitScript, err, out)
		}
		body, err := os.ReadFile(filepath.Join(dir, "repo-key"))
		if err != nil {
			t.Fatalf("%s exited 0 and wrote no repository key: %v", identityInitScript, err)
		}
		return strings.TrimSpace(string(body))
	}

	alpha, beta := t.TempDir(), t.TempDir()
	first := generate(t, alpha)
	r, err := identity.NewRepositories(identity.ModePseudonymous, first)
	if err != nil {
		t.Fatalf("the generated key is not one NewRepositories accepts: %v", err)
	}
	secret, err := os.ReadFile(filepath.Join(alpha, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(secret)) == first {
		t.Error("the repository key is the identity secret; ADR-0080 decision 2 makes it its own")
	}
	if again := generate(t, alpha); again != first {
		t.Error("a second run replaced the repository key; every pseudonym would change on a restart")
	}
	if other := generate(t, beta); other == first {
		t.Error("two deployments generated the same repository key")
	}
	t.Logf("key id %s", r.KeyID())

	compose, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "innsegl.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"INNSEGL_REPO_MODE: ${INNSEGL_REPO_MODE:-literal}",
		"INNSEGL_REPO_KEY_FILE: *repo-key-file",
	} {
		if !strings.Contains(string(compose), want) {
			t.Errorf("innsegl.yml does not carry %q", want)
		}
	}
}

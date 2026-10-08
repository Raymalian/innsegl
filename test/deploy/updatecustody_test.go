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
// OPS-161 (PROPOSED) — `make update` is not "up to date" while a service it
// keeps is not running (#533).
//
// MEASURED on a live core: after `make ca-custody-reset` removed the store's
// containers, `make update` found the same commit and .env and a running core,
// printed "already up to date", and left the CA key store and its custodian
// down. With custody on, those two are part of what update keeps running.
// ---------------------------------------------------------------------------

// fakeDocker answers `ps` with the stack's base services and `inspect` as
// running for every container named in running.
func fakeDocker(t *testing.T, running ...string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"  ps) printf 'innsegl-spire-server\\ninnsegl-sigstore-rekor\\n' ;;\n" +
		"  inspect) for c in " + strings.Join(running, " ") + "; do [ \"$c\" = \"$4\" ] && { echo 'running restarting=false'; exit 0; }; done; exit 1 ;;\n" +
		"esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runUpdate(t *testing.T, env, deployed, dockerDir string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "make", "-s", "--no-print-directory", "update",
		"COMPOSE_ENV_FILE="+env, "DEPLOYED_FILE="+deployed, "MAKE=true")
	cmd.Dir = repoRoot(t)
	base := stackEnv(t.TempDir(), "live")
	var e []string
	for _, kv := range base {
		if strings.HasPrefix(kv, "PATH=") {
			kv = "PATH=" + dockerDir + string(os.PathListSeparator) + strings.TrimPrefix(kv, "PATH=")
		}
		e = append(e, kv)
	}
	cmd.Env = e
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make update: %v\n%s", err, out)
	}
	return string(out)
}

func TestOPS161UpdateIsNotUpToDateWhileTheCustodianIsDown(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	dir := t.TempDir()
	env := filepath.Join(dir, ".env")
	if err := os.WriteFile(env, []byte("INNSEGL_CA_CUSTODY=on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deployed := filepath.Join(dir, "deployed")
	if err := os.WriteFile(deployed, []byte(updateMarker(t, env)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	all := fakeDocker(t, "innsegl-mcp", "innsegl-ca-store", "innsegl-ca-custodian")
	if out := runUpdate(t, env, deployed, all); !strings.Contains(out, "already up to date") {
		t.Fatalf("control: everything running and the same state should be up to date:\n%s", out)
	}
	down := fakeDocker(t, "innsegl-mcp", "innsegl-ca-store")
	if out := runUpdate(t, env, deployed, down); strings.Contains(out, "already up to date") {
		t.Fatalf("the custodian is down and update called it up to date:\n%s", out)
	}
}

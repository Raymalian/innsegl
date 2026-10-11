// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// OPS-129 for CA key custody (#585). A dev stack runs custody under its own
// names: every container, network and trust volume of the custody overlays
// and of the ca-custody Make targets is innsegl-dev-*, so a dev custodian can
// never open, unlock or empty a live store. A live core keeps every name it
// had, byte for byte: renaming a live store's volume would orphan the CA key.
// ---------------------------------------------------------------------------

// The custody overlays' live names, as they are on a running core. #585 adds
// the CA's network and the token keeper; nothing that existed is renamed.
var (
	liveCustodyContainers = []string{"innsegl-ca-bootstrap", "innsegl-ca-custodian", "innsegl-ca-export",
		"innsegl-ca-import", "innsegl-ca-store", "innsegl-ca-token-keeper"}
	// innsegl-sigstore_default is the import profile's export one-shot's,
	// which names no network.
	liveCustodyNetworks = []string{"innsegl-ca-sign", "innsegl-ca-store", "innsegl-ca-unlock", "innsegl-sigstore_default"}
	liveCustodyVolumes  = []string{"innsegl-ca-token", "innsegl-sigstore_innsegl-ca-import-scratch",
		"innsegl-sigstore_sigstore-fulcio-kms", "innsegl-trust-ca-custody", "innsegl-trust-ca-store"}
	liveCoreCustodyNetworks = []string{"innsegl-ca-unlock"}
	liveCoreCustodyVolumes  = []string{"innsegl-trust-ca-custody"}
)

// added is what b names that a does not.
func added(a, b []string) []string {
	var out []string
	for _, n := range b {
		if !slices.Contains(a, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// makeDryRunCustody is `make -n targets` in a mode, with custody on in the
// compose .env.
func makeDryRunCustody(t *testing.T, mode string, targets ...string) string {
	t.Helper()
	if _, err := exec.LookPath("make"); err != nil {
		t.Skipf("make is not on PATH: %v", err)
	}
	on := filepath.Join(t.TempDir(), "on.env")
	if err := os.WriteFile(on, []byte("INNSEGL_CA_CUSTODY=on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-n", "--no-print-directory"}, targets...)
	args = append(args, "COMPOSE_ENV_FILE="+on, "FROM=/x", "CONFIRM=restore")
	cmd := exec.CommandContext(t.Context(), "make", args...)
	cmd.Dir = repoRoot(t)
	cmd.Env = stackEnv(t.TempDir(), mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %v (INNSEGL_STACK=%s): %v\n%s", targets, mode, err, out)
	}
	return string(out)
}

var custodyTargets = []string{"ca-custody-up", "ca-custody-volumes", "ca-custody-ready", "ca-custody-stage",
	"ca-custody-switch", "ca-custody-restore", "innsegl-ca-custody-init", "update"}

// OPS-129 (#585) — a live core's custody is exactly what it was: the same
// compose files, containers, networks and trust volumes.
func TestOPS129CustodyKeepsEveryLiveName(t *testing.T) {
	if markerSays(t, repoRoot(t)) == "dev" {
		t.Skip("this checkout is marked dev; the live case runs in an unmarked one")
	}
	out := makeDryRunCustody(t, "live", custodyTargets...)
	for _, want := range []string{
		"-f deploy/compose/sigstore.yml -f deploy/compose/sigstore.keycustody.yml up -d innsegl-ca-store innsegl-ca-custodian",
		"-f deploy/compose/innsegl.yml -f deploy/compose/innsegl.custody.yml up -d",
		"for v in innsegl-trust-ca-store innsegl-trust-ca-custody; do",
		"docker run --rm -v innsegl-trust-ca-custody:/d ",
		"docker exec innsegl-ca-custodian innsegl ca-custodian ready",
		"docker volume rm innsegl-trust-ca-store",
		"INNSEGL_CA_STORE_CONTAINER='innsegl-ca-store' scripts/ca-custody.sh init",
		"for c in innsegl-core innsegl-ca-store innsegl-ca-custodian; do",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a live custody target no longer runs %q:\n%s", want, out)
		}
	}
	for _, never := range []string{"deploy/compose/dev/", devPrefix} {
		if strings.Contains(out, never) {
			t.Errorf("a live custody target names %q, which only a dev stack may:\n%s", never, out)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping the compose half: %v", err)
	}
	env := trustEnv(t, t.TempDir(), "")
	baseC, baseN, baseV := composeAllProfiles(ctx, t, env, "deploy/compose/sigstore.yml").names()
	sig := composeAllProfiles(ctx, t, env, "deploy/compose/sigstore.yml", "deploy/compose/sigstore.keycustody.yml")
	if sig.Name != "innsegl-sigstore" {
		t.Errorf("live custody runs in project %q; want innsegl-sigstore", sig.Name)
	}
	c, n, v := sig.names()
	for _, cmp := range []struct {
		kind      string
		got, want []string
	}{
		{"containers", added(baseC, c), liveCustodyContainers},
		{"networks", added(baseN, n), liveCustodyNetworks},
		{"volumes", added(baseV, v), liveCustodyVolumes},
	} {
		if !reflect.DeepEqual(cmp.got, cmp.want) {
			t.Errorf("live custody %s are %v; want exactly %v", cmp.kind, cmp.got, cmp.want)
		}
	}
	_, coreN, coreV := composeAllProfiles(ctx, t, env, "deploy/compose/innsegl.yml").names()
	core := composeAllProfiles(ctx, t, env, "deploy/compose/innsegl.yml", "deploy/compose/innsegl.custody.yml")
	_, n, v = core.names()
	if got := added(coreN, n); !reflect.DeepEqual(got, liveCoreCustodyNetworks) {
		t.Errorf("the live core's custody networks are %v; want %v", got, liveCoreCustodyNetworks)
	}
	if got := added(coreV, v); !reflect.DeepEqual(got, liveCoreCustodyVolumes) {
		t.Errorf("the live core's custody volumes are %v; want %v", got, liveCoreCustodyVolumes)
	}
}

// OPS-129 (#585) — a dev stack's custody is innsegl-dev-* throughout, and
// names no live container, network or volume.
func TestOPS129DevCustodyHasItsOwnNames(t *testing.T) {
	out := makeDryRunCustody(t, "dev", custodyTargets...)
	for _, want := range []string{
		"-f deploy/compose/sigstore.yml -f deploy/compose/dev/sigstore.yml -f deploy/compose/sigstore.keycustody.yml " +
			"-f deploy/compose/dev/sigstore.keycustody.yml up -d innsegl-ca-store innsegl-ca-custodian",
		"-f deploy/compose/innsegl.custody.yml -f deploy/compose/dev/innsegl.custody.yml up -d",
		"for v in innsegl-dev-trust-ca-store innsegl-dev-trust-ca-custody; do",
		"docker exec innsegl-dev-ca-custodian innsegl ca-custodian ready",
		"docker volume rm innsegl-dev-trust-ca-store",
		"INNSEGL_CA_STORE_CONTAINER='innsegl-dev-ca-store' scripts/ca-custody.sh init",
		"for c in innsegl-dev-core innsegl-dev-ca-store innsegl-dev-ca-custodian; do",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("a dev custody target does not run %q:\n%s", want, out)
		}
	}
	// Compose SERVICE names (`up -d innsegl-ca-store`) are the same in both;
	// what must not appear is a live container or volume addressed directly.
	for _, live := range []string{"exec innsegl-ca-", "CONTAINER='innsegl-ca-", "innsegl-trust-ca-",
		"in innsegl-core", " innsegl-ca-custodian;", "innsegl-ca-token"} {
		if strings.Contains(out, live) {
			t.Errorf("a dev custody target addresses a live name (%q):\n%s", live, out)
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping the compose half: %v", err)
	}
	home := t.TempDir()
	stdout, stderr, code := stackMode(t, repoRoot(t), stackEnv(home, "dev"), "env")
	if code != 0 {
		t.Fatalf("stack-mode.sh env in dev: exit %d: %s", code, stderr)
	}
	env := trustEnv(t, home, devTrustPrefix)
	for k, v := range envLines(stdout) {
		env = append(env, k+"="+v)
	}
	liveEnv := trustEnv(t, home, "")
	for _, files := range [][2]string{
		{"sigstore.yml", "sigstore.keycustody.yml"},
		{"innsegl.yml", "innsegl.custody.yml"},
	} {
		live := composeAllProfiles(ctx, t, liveEnv, "deploy/compose/"+files[0], "deploy/compose/"+files[1])
		dev := composeAllProfiles(ctx, t, env, "deploy/compose/"+files[0], "deploy/compose/dev/"+files[0],
			"deploy/compose/"+files[1], "deploy/compose/dev/"+files[1])
		lc, ln, lv := live.names()
		liveNames := append(append(append(append([]string{live.Name}, lc...), ln...), lv...), liveTrustVolumes...)
		dc, dn, dv := dev.names()
		if len(dc) != len(lc) || len(dn) != len(ln) || len(dv) != len(lv) {
			t.Errorf("%s: the dev overlays changed what runs: %d/%d/%d containers/networks/volumes, live has %d/%d/%d",
				files[1], len(dc), len(dn), len(dv), len(lc), len(ln), len(lv))
		}
		for kind, list := range map[string][]string{"container": dc, "network": dn, "volume": dv} {
			for _, name := range list {
				if !strings.HasPrefix(name, devPrefix+"-") {
					t.Errorf("%s: dev %s %q is not %s-*", files[1], kind, name, devPrefix)
				}
				if slices.Contains(liveNames, name) {
					t.Errorf("%s: dev %s %q is a live name", files[1], kind, name)
				}
			}
		}
	}
}

// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// OPS-190 and OPS-191 (PROPOSED for doc 07's TC-OPS) — `make update` proves
// signing works once the services are up (#587, RM-343).
//
// An update can leave the stack running but unable to sign: the services are
// healthy, the CA cannot reach its key. scripts/update-signing.sh runs the
// core's one-shot `innsegl signing-probe` (exit 0 ok, 35 failing, 36 could
// not be set up) with `docker exec` into <prefix>-core.
//
//	OPS-190: after the services are up, a failing probe exits non-zero with
//	  the reason and one repair line; a passing one exits 0; exit 36 is
//	  reported as a set-up fault, not as a signing failure; a stack with no
//	  Fulcio configured skips with a line.
//	OPS-191: a probe that already failed BEFORE the update is reported first,
//	  and the failure after it says the update did not cause it.
//
// The fake core is a plain container named <prefix>-core whose `innsegl` prints
// /out and exits with /rc, so the test needs no image of ours.
// ---------------------------------------------------------------------------

func fakeCore(t *testing.T, prefix string, fulcio bool) {
	t.Helper()
	fakeCoreNamed(t, prefix+"-core", fulcio)
}

// fakeCoreNamed starts the fake core under any container name.
func fakeCoreNamed(t *testing.T, name string, fulcio bool) {
	t.Helper()
	script := `printf '#!/bin/sh\ncat /out\nexit $(cat /rc)\n' > /usr/local/bin/innsegl; ` +
		`chmod +x /usr/local/bin/innsegl; echo 0 > /rc; echo 'signing: ok - the CA issued a certificate at T' > /out; exec sleep 3600`
	args := []string{"run", "-d", "--name", name, "--network", "none"}
	if fulcio {
		args = append(args, "-e", "INNSEGL_FULCIO_URL=http://fulcio.invalid")
	}
	args = append(args, opsInputsImage, "sh", "-c", script)
	if out, err := exec.CommandContext(t.Context(), "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("starting the fake core: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if err := exec.CommandContext(context.Background(), "docker", "rm", "-f", name).Run(); err != nil {
			t.Logf("removing the fake core %s: %v", name, err)
		}
	})
	for i := 0; i < 50; i++ {
		if exec.CommandContext(t.Context(), "docker", "exec", name, "test", "-f", "/out").Run() == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the fake core never got its probe command")
}

func setProbe(t *testing.T, prefix string, rc int, out string) {
	t.Helper()
	cmd := fmt.Sprintf("echo %d > /rc; cat > /out", rc)
	c := exec.CommandContext(t.Context(), "docker", "exec", "-i", prefix+"-core", "sh", "-c", cmd)
	c.Stdin = strings.NewReader(out + "\n")
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("setting the probe result: %v\n%s", err, b)
	}
}

func runSigning(t *testing.T, prefix, mode string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), filepath.Join(repoRoot(t), "scripts", "update-signing.sh"), mode)
	cmd.Env = append(os.Environ(), append([]string{"INNSEGL_STACK_PREFIX=" + prefix}, env...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode()
	}
	t.Fatalf("running update-signing.sh: %v", err)
	return "", -1
}

func requireDocker(t *testing.T, id string) {
	t.Helper()
	if err := dockertest.Usable(t.Context()); err != nil {
		skip, failure := dockertest.StartupOutcome(err)
		if failure != "" {
			t.Fatal(failure)
		}
		t.Skipf("skipping %s: %s", id, skip)
	}
}

func TestOPS190UpdateFailsWhenSigningIsBrokenAfterTheServicesAreUp(t *testing.T) {
	requireDocker(t, "OPS-190")
	prefix := uniqueName(t, "ops190")
	fakeCore(t, prefix, true)

	out, rc := runSigning(t, prefix, "after")
	if rc != 0 || !strings.Contains(out, "signing: ok") {
		t.Fatalf("healthy signing: want exit 0 and 'signing: ok', got %d:\n%s", rc, out)
	}

	setProbe(t, prefix, 35, "signing: FAILING - Fulcio answered HTTP 500: the CA key is unreadable")
	out, rc = runSigning(t, prefix, "after")
	if rc == 0 {
		t.Fatalf("signing is broken and the update exited 0 - the rehearsal's failure:\n%s", out)
	}
	if !strings.Contains(out, "the CA key is unreadable") {
		t.Errorf("the reason is missing:\n%s", out)
	}
	// #588: the repair is `innsegl doctor` on the operator machine, which
	// runs the unlock itself when that is the repair.
	if !strings.Contains(out, "runbooks/ca-custody.md") || !strings.Contains(out, "innsegl doctor") ||
		strings.Contains(out, "ca-custody unlock") {
		t.Errorf("without custody the repair names doctor and the runbook, not unlock:\n%s", out)
	}

	out, rc = runSigning(t, prefix, "after", "INNSEGL_CA_CUSTODY=on")
	if rc == 0 || !strings.Contains(out, "innsegl doctor") {
		t.Errorf("with custody the repair is `innsegl doctor` (exit %d):\n%s", rc, out)
	}

	setProbe(t, prefix, 36, "signing: could not be set up - no SPIRE credential")
	out, rc = runSigning(t, prefix, "after")
	if rc == 0 || !strings.Contains(out, "could not be set up") || strings.Contains(out, "signing: FAILING") {
		t.Errorf("exit 36 is reported as a set-up fault, distinct from a failure (exit %d):\n%s", rc, out)
	}
}

func TestOPS190SkipsAStackWithNoFulcio(t *testing.T) {
	requireDocker(t, "OPS-190")
	prefix := uniqueName(t, "ops190n")
	fakeCore(t, prefix, false)
	setProbe(t, prefix, 35, "signing: FAILING - would fail if it ran")
	out, rc := runSigning(t, prefix, "after")
	if rc != 0 || !strings.Contains(out, "signing: not configured") {
		t.Fatalf("no Fulcio: want exit 0 and a skip line, got %d:\n%s", rc, out)
	}
}

func TestOPS191ReportsASigningFailureThatPredatesTheUpdate(t *testing.T) {
	requireDocker(t, "OPS-191")
	prefix := uniqueName(t, "ops191")
	fakeCore(t, prefix, true)
	setProbe(t, prefix, 35, "signing: FAILING - the store is sealed")

	out, rc := runSigning(t, prefix, "before")
	if rc != 35 {
		t.Errorf("before the update the probe's own exit code is returned, got %d:\n%s", rc, out)
	}
	if !strings.Contains(out, "was already failing before the update") || !strings.Contains(out, "the store is sealed") {
		t.Errorf("the pre-update failure is not stated first:\n%s", out)
	}

	out, rc = runSigning(t, prefix, "after", "INNSEGL_SIGNING_BEFORE=35")
	if rc == 0 || !strings.Contains(out, "not caused by this update") {
		t.Errorf("the failure after the update must say it predates it (exit %d):\n%s", rc, out)
	}

	setProbe(t, prefix, 0, "signing: ok - the CA issued a certificate at T")
	out, rc = runSigning(t, prefix, "before")
	if rc != 0 || strings.Contains(out, "already failing") {
		t.Errorf("a healthy stack before the update says nothing alarming (exit %d):\n%s", rc, out)
	}
}

// OPS-191: the first update onto this code finds a core built before the
// probe existed. Its `innsegl` answers `signing-probe` with usage and exit 2.
// MEASURED in the in-place rehearsal of #591: `before` read that as a signing
// outage, printed "was already failing before the update" over the whole
// usage text, and named a repair, on a core that signed. A core with no
// probe is not checked before the update; it is not a failure.
func TestOPS191ACoreBuiltBeforeTheProbeIsNotAFailure(t *testing.T) {
	requireDocker(t, "OPS-191")
	prefix := uniqueName(t, "ops191o")
	fakeCore(t, prefix, true)
	setProbe(t, prefix, 2, "innsegl: unknown subcommand \"signing-probe\"\n\nUsage:\n  innsegl <subcommand> [arguments]")

	out, rc := runSigning(t, prefix, "before")
	if rc != 0 {
		t.Errorf("a core with no probe: want exit 0 before the update, got %d:\n%s", rc, out)
	}
	if strings.Contains(out, "already failing") || strings.Contains(out, "repair:") || strings.Contains(out, "Usage:") {
		t.Errorf("a core with no probe is reported as a signing outage:\n%s", out)
	}
	if !strings.Contains(out, "signing: not checked before the update") {
		t.Errorf("want one line saying it was not checked:\n%s", out)
	}
}

// OPS-197 (RM-346, #594): the update onto the rename finds the core running
// under its old name (the prefix, then -mcp). `before` probes that one, so a CA
// that already could not sign is still reported before the update; `after`
// never does, because by then the old container must have been replaced.
func TestOPS197BeforeProbesACoreStillUnderItsOldName(t *testing.T) {
	requireDocker(t, "OPS-197")
	prefix := uniqueName(t, "ops197")
	fakeCoreNamed(t, prefix+"-mcp", true)

	out, rc := runSigning(t, prefix, "before")
	if rc != 0 || !strings.Contains(out, "signing: ok") {
		t.Errorf("before: want the old-named core probed (exit 0, 'signing: ok'), got %d:\n%s", rc, out)
	}
	out, rc = runSigning(t, prefix, "after")
	if rc == 0 || !strings.Contains(out, prefix+"-core is not running") {
		t.Errorf("after: an old-named core must not stand in for the new one (exit %d):\n%s", rc, out)
	}
}

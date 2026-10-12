// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"strings"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// OPS-233 (proposed for doc 07; doc 07 is not modified here) — RM-372, #624.
//
// `make innsegl-demo` ran `compose run demo-agent` with no --build, and the
// demo agent's script is copied into its image. A machine that had built the
// image once kept running that copy: a fix to the script did not reach it.
// Measured 2026-10-12: the local innsegl-demo-agent:local was five days old.
// The script itself is exercised against the tools by test/contract OPS-230.
// ---------------------------------------------------------------------------

func TestOPS233TheDemoRunsTheScriptFromThisCheckout(t *testing.T) {
	out := strings.ReplaceAll(deploytest.MakeDryRun(t, "dev", "innsegl-demo"), "\\\n", " ")
	var run string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " run ") && strings.Contains(line, "demo-agent") {
			run = line
		}
	}
	if run == "" {
		t.Fatalf("make -n innsegl-demo runs no demo-agent:\n%s", out)
	}
	if !strings.Contains(run, "--build") {
		t.Errorf("the demo's compose run does not build the demo image from this checkout:\n%s", run)
	}
}

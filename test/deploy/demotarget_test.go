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
//
// And the core it runs against must be one `make start` would run. #604 had
// `compose run` recreate the core with -lifecycle-on-agent-listener as a
// dependency, under this target's environment, which lacks what
// innsegl-here-services passes (INNSEGL_MCP_ALSO among it). Measured on a dev
// custody stack 2026-10-12: that core never listened, stayed unhealthy, and
// the demo stopped at "dependency failed to start". So the flag goes through
// innsegl-here-services, and the demo runs with --no-deps against that core.
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
	if !strings.Contains(run, "--no-deps") {
		t.Errorf("the demo's compose run brings the core up again under its own environment:\n%s", run)
	}
	flagged := strings.Index(out, "INNSEGL_MCP_LIFECYCLE_ON_AGENT_LISTENER=true make innsegl-here-services")
	if flagged < 0 || flagged > strings.Index(out, "--profile demo run") {
		t.Errorf("make innsegl-demo does not bring the core up with the flag through "+
			"innsegl-here-services before the demo runs:\n%s", out)
	}
}

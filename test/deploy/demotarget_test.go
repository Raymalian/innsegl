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
// `make innsegl-demo` ran `compose run demo-agent`, and `compose run` brings
// the service's dependencies up first: innsegl-core, under THIS target's
// environment. That environment has no INNSEGL_MCP_ADMIN_LISTEN, which `make
// start` sets, so the core's definition differed and compose recreated it
// with every tool on one listener: the demo changed the deployment it
// demonstrated. It also never rebuilt the demo's image, so a change to the
// script did not reach a machine that already had one.
//
// What must hold, in both stack modes:
//   - the demo runs with --no-deps, against the core `make start` left;
//   - it builds its own image from this checkout (--build);
//   - it hands the script the identity lifecycle's listener and a credential
//     minted for the demo's repository, from the core's own key volume.
// The script is exercised against the tools by test/contract OPS-230.
// ---------------------------------------------------------------------------

func TestOPS233TheDemoRunsAgainstTheCoreAsItIs(t *testing.T) {
	for _, mode := range []string{"live", "dev"} {
		t.Run(mode, func(t *testing.T) {
			out := strings.ReplaceAll(deploytest.MakeDryRun(t, mode, "innsegl-demo"), "\\\n", " ")
			var run string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, " run ") && strings.Contains(line, "demo-agent") {
					run = line
				}
			}
			if run == "" {
				t.Fatalf("make -n innsegl-demo runs no demo-agent:\n%s", out)
			}
			for _, want := range []string{"--no-deps", "--build", "--profile demo"} {
				if !strings.Contains(run, want) {
					t.Errorf("the demo's compose run has no %s:\n%s", want, run)
				}
			}
			prefix := "innsegl"
			if mode == "dev" {
				prefix = "innsegl-dev"
			}
			for _, want := range []string{
				"INNSEGL_MCP_ADMIN_URL",
				"-e INNSEGL_MCP_ADMIN_CREDENTIAL",
				"admin-credential mint -key /k/signing.key -repo 'github.com/innsegl-demo/scratch'",
				"-v " + prefix + "-core_innsegl-admin-key:/k:ro",
				"--network none",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("make innsegl-demo does not run %q:\n%s", want, out)
				}
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"strings"
	"testing"
	"time"
)

// RM-211 (#339). One-process mode is built into the compose file, not a flag.
//
// The reconciler's SPIRE pass runs only with the MCP's admin identity, so only
// when the reconciler runs inside the MCP (ADR-0056). That arrangement was an
// overlay file and a Makefile flag, and a redeploy that forgot the flag
// brought the separate containers back and turned the pass off without a
// word. So a PLAIN `docker compose up` of the shipped files has to be the
// one-process arrangement, and the separate containers have to be something a
// deployment asks for by name: the `separate` profile.
func TestRM211OneProcessIsBuiltIn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping RM-211: %v", err)
	}
	t.Setenv("INNSEGL_PROJECTS", "/srv/host-projects")
	t.Setenv("INNSEGL_MCP_ALSO", "")

	for _, files := range [][]string{
		{"deploy/compose/innsegl.yml"},
		{"deploy/compose/innsegl.yml", "deploy/compose/innsegl.workrepo.yml"},
	} {
		plain := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, files...)

		also, _ := plain.env("innsegl-mcp", "INNSEGL_MCP_ALSO")
		have := map[string]bool{}
		for _, name := range strings.Split(also, ",") {
			have[strings.TrimSpace(name)] = true
		}
		for _, want := range []string{"seal", "reconcile", "reap"} {
			if !have[want] {
				t.Errorf("%v with no profile: innsegl-mcp's INNSEGL_MCP_ALSO = %q, which does not run %s",
					files, also, want)
			}
		}
		for _, folded := range []string{"innsegl-sealer", "innsegl-reconciler"} {
			if _, ok := plain.Services[folded]; ok {
				t.Errorf("%v with no profile starts %s; it runs inside the MCP unless --profile separate asks for it",
					files, folded)
			}
		}

		// The multi-replica topology (doc 05 §2) still has both, by name.
		separate := interpolateComposeProfiles(ctx, t, "innsegl-segments", []string{"separate"}, files...)
		for _, folded := range []string{"innsegl-sealer", "innsegl-reconciler"} {
			if _, ok := separate.Services[folded]; !ok {
				t.Errorf("%v with --profile separate does not declare %s", files, folded)
			}
		}
	}

	// And the loop list is still the operator's to set: the separate
	// topology runs the MCP with the reaper alone.
	t.Setenv("INNSEGL_MCP_ALSO", "reap")
	cfg := interpolateComposeProfiles(ctx, t, "innsegl-segments", []string{"separate"}, "deploy/compose/innsegl.yml")
	if also, _ := cfg.env("innsegl-mcp", "INNSEGL_MCP_ALSO"); also != "reap" {
		t.Errorf("INNSEGL_MCP_ALSO=reap is not honoured: innsegl-mcp gets %q", also)
	}
}

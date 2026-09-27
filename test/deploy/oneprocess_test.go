// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// RM-207 (#333). One-process mode must not lose what the folded services had.
//
// innsegl.oneprocess.yml runs the sealer and the reconciler inside the MCP.
// It was written before the reconciler gained its rebase and writes passes,
// and never gained their settings or their mount: measured on 2026-09-27, the
// MCP in one-process mode lacked INNSEGL_REBASE_BRANCH, INNSEGL_REBASE_REPOS,
// INNSEGL_WRITES_LOG_DIR, INNSEGL_WRITES_REPOS and /harness-log, so switching
// to it would have silently turned both passes off. Every setting and every
// mount a folded service is given must reach the process that now runs it.
func TestRM207OneProcessKeepsWhatTheFoldedServicesHad(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping RM-207: %v", err)
	}
	t.Setenv("INNSEGL_PROJECTS", "/srv/host-projects")
	t.Setenv("INNSEGL_REBASE_BRANCH", "main")
	t.Setenv("INNSEGL_REBASE_REPOS", "example.test/org/name")
	t.Setenv("INNSEGL_WRITES_REPOS", "example.test/org/name")
	files := []string{"deploy/compose/innsegl.yml", "deploy/compose/innsegl.workrepo.yml"}
	separate := interpolateCompose(ctx, t, "innsegl-segments", files...)
	one := interpolateCompose(ctx, t, "innsegl-segments",
		append(files, "deploy/compose/innsegl.oneprocess.yml")...)

	mcp := one.service(t, "innsegl-mcp")
	targets := map[string]bool{}
	for _, v := range mcp.Volumes {
		targets[v.Target] = true
	}
	for _, folded := range []string{"innsegl-sealer", "innsegl-reconciler"} {
		svc := separate.service(t, folded)
		var missing []string
		for key := range svc.Environment {
			if _, ok := mcp.Environment[key]; !ok {
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("in one-process mode the MCP lacks %s's settings: %s", folded, strings.Join(missing, ", "))
		}
		for _, v := range svc.Volumes {
			if !targets[v.Target] {
				t.Errorf("in one-process mode the MCP lacks %s's mount at %s", folded, v.Target)
			}
		}
	}
	if also, _ := one.env("innsegl-mcp", "INNSEGL_MCP_ALSO"); !strings.Contains(also, "reconcile") {
		t.Errorf("INNSEGL_MCP_ALSO = %q; one-process mode must run the reconciler", also)
	}
	// The reason for this mode's use here: the reconciler's SPIRE pass runs
	// only with an admin identity, and the MCP's is the only one there is.
	if addr, _ := one.env("innsegl-mcp", "INNSEGL_SPIRE_ADDRESS"); addr == "" {
		t.Error("in one-process mode the MCP has no INNSEGL_SPIRE_ADDRESS, so the reconciler's SPIRE pass stays off")
	}
}

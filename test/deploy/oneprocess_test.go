// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// RM-207 (#333), RM-211 (#339). One-process mode must not lose what the folded
// services had.
//
// A plain `up` runs the sealer and the reconciler inside the MCP; the
// `separate` profile runs them as their own containers. The first version of
// this arrangement was an overlay written before the reconciler gained its
// rebase and writes passes, and it never gained their settings or their
// mount: measured on 2026-09-27, the MCP lacked INNSEGL_REBASE_BRANCH,
// INNSEGL_REBASE_REPOS, INNSEGL_WRITES_LOG_DIR, INNSEGL_WRITES_REPOS and
// /harness-log, so both passes would have been off in silence. Every setting,
// every mount and every network a folded service is given must reach the
// process that runs it by default, with the same value.
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
	t.Setenv("INNSEGL_MCP_ALSO", "")
	files := []string{"deploy/compose/innsegl.yml", "deploy/compose/innsegl.workrepo.yml"}
	separate := interpolateComposeProfiles(ctx, t, "innsegl-segments", []string{"separate"}, files...)
	plain := interpolateComposeProfiles(ctx, t, "innsegl-segments", nil, files...)

	mcp := plain.service(t, "innsegl-mcp")
	targets := map[string]bool{}
	for _, v := range mcp.Volumes {
		targets[v.Target] = true
	}
	for _, folded := range []string{"innsegl-sealer", "innsegl-reconciler"} {
		svc := separate.service(t, folded)
		var missing, differ []string
		for key, want := range svc.Environment {
			got, ok := mcp.Environment[key]
			switch {
			case !ok:
				missing = append(missing, key)
			case (got == nil) != (want == nil) || (got != nil && *got != *want):
				differ = append(differ, key)
			}
		}
		sort.Strings(missing)
		sort.Strings(differ)
		if len(missing) > 0 {
			t.Errorf("by default the MCP lacks %s's settings: %s", folded, strings.Join(missing, ", "))
		}
		if len(differ) > 0 {
			t.Errorf("by default the MCP has %s's settings with other values: %s", folded, strings.Join(differ, ", "))
		}
		for _, v := range svc.Volumes {
			if !targets[v.Target] {
				t.Errorf("by default the MCP lacks %s's mount at %s", folded, v.Target)
			}
		}
		for _, n := range svc.networkNames() {
			if _, ok := mcp.Networks[n]; !ok {
				t.Errorf("by default the MCP is not on %s's network %s", folded, n)
			}
		}
	}
	// The reason this is the default: the reconciler's SPIRE pass runs only
	// with an admin identity, and the MCP's is the only one there is.
	if addr, _ := plain.env("innsegl-mcp", "INNSEGL_SPIRE_ADDRESS"); addr == "" {
		t.Error("the MCP has no INNSEGL_SPIRE_ADDRESS, so the reconciler's SPIRE pass stays off")
	}
}

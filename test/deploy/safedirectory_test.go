// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"
)

// RM-197 (#318). Every service that runs git over the projects mount trusts
// exactly the two places it sees that folder, and nothing wider.
//
// The container binds the host projects folder twice: at /projects, and at its
// host path, so a linked worktree's `.git` file resolves. Through the second
// mount Docker Desktop can report the gitdir as uid 0, and git refuses the
// repository as "dubious ownership". sign_commit builds its own environment
// and was fixed in #308; describe_workspace, the proof API and the
// reconciler's git calls inherit the container's, and went on refusing a
// fresh worktree. Measured live: describe_workspace answered "is not a git
// working tree: exit status 128" for a worktree git could read.
func TestRM197ProjectReadersTrustOnlyTheProjectMounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := composeUsable(ctx); err != nil {
		t.Skipf("skipping RM-197: %v", err)
	}
	const projects = "/srv/host-projects"
	t.Setenv("INNSEGL_PROJECTS", projects)
	cfg := interpolateCompose(ctx, t, "innsegl-segments",
		"deploy/compose/innsegl.yml", "deploy/compose/innsegl.workrepo.yml")

	want := []string{"/projects/*", projects + "/*"}
	for _, service := range []string{"innsegl-mcp", "innsegl-api", "innsegl-reconciler"} {
		t.Run(service, func(t *testing.T) {
			raw, ok := cfg.env(service, "GIT_CONFIG_COUNT")
			n, err := strconv.Atoi(raw)
			if !ok || err != nil {
				t.Fatalf("GIT_CONFIG_COUNT is %q (set: %v); git in this service trusts no mount", raw, ok)
			}
			var got []string
			for i := range n {
				k, _ := cfg.env(service, "GIT_CONFIG_KEY_"+strconv.Itoa(i))
				v, _ := cfg.env(service, "GIT_CONFIG_VALUE_"+strconv.Itoa(i))
				if k != "safe.directory" {
					t.Errorf("GIT_CONFIG_KEY_%d is %q, want safe.directory and nothing else", i, k)
				}
				got = append(got, v)
			}
			if !slices.Equal(got, want) {
				t.Errorf("safe.directory entries are %q, want %q", got, want)
			}
			if slices.Contains(got, "*") {
				t.Errorf("safe.directory trusts every directory: %q", got)
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// signCommitSafeDirectories reads the safe.directory entries the built git
// environment carries, and fails the test on any GIT_CONFIG_* entry that is
// not one.
func signCommitSafeDirectories(t *testing.T, env []string) []string {
	t.Helper()
	vars := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	count, err := strconv.Atoi(vars["GIT_CONFIG_COUNT"])
	if err != nil {
		t.Fatalf("GIT_CONFIG_COUNT is %q: %v", vars["GIT_CONFIG_COUNT"], err)
	}
	var dirs []string
	for i := range count {
		n := strconv.Itoa(i)
		if key := vars["GIT_CONFIG_KEY_"+n]; key != "safe.directory" {
			t.Errorf("GIT_CONFIG_KEY_%d is %q, want safe.directory and nothing else", i, key)
		}
		dirs = append(dirs, vars["GIT_CONFIG_VALUE_"+n])
	}
	return dirs
}

// RM-188 (#308): the container binds the host projects folder twice, at
// /projects and at INNSEGL_HOST_PROJECTS, and a linked worktree's .git file
// reaches its gitdir through the second. There Docker Desktop can report the
// files as uid 0, and git refuses a repository it believes root owns. The
// built environment trusts those two mount roots and nothing wider.
func TestRM188SignerTrustsOnlyTheProjectMounts(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		want []string
	}{
		{"both mounts", "/srv/host-projects", []string{"/projects/*", "/srv/host-projects/*"}},
		{"a trailing slash is not doubled", "/srv/host-projects/", []string{"/projects/*", "/srv/host-projects/*"}},
		{"no host mount configured", "", []string{"/projects/*"}},
		{"a relative host mount is not trusted", "Applications", []string{"/projects/*"}},
		{"the filesystem root is not trusted", "/", []string{"/projects/*"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvHostProjects, tc.host)

			got := signCommitSafeDirectories(t, signCommitGitEnv("/projects/repo"))
			if !slices.Equal(got, tc.want) {
				t.Errorf("safe.directory entries are %q, want %q", got, tc.want)
			}
			if slices.Contains(got, "*") {
				t.Errorf("safe.directory trusts every directory: %q", got)
			}
		})
	}
}

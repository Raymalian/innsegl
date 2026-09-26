// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// RM-188 (#308): the commit itself is made by git in the signer's own
// isolated config, so it meets the same "dubious ownership" refusal as the
// MCP's reads when a linked worktree's gitdir is reached through the host
// projects mount. The signer trusts exactly the roots it is configured with,
// each as a subtree, and never every directory.
func TestRM188SignerCommitTrustsOnlyItsConfiguredRoots(t *testing.T) {
	for _, tc := range []struct {
		name  string
		roots []string
		want  []string
	}{
		{"both mounts", []string{"/projects", "/srv/host-projects/"},
			[]string{"safe.directory=/projects/*", "safe.directory=/srv/host-projects/*"}},
		{"none configured", nil, nil},
		{"a relative root is not trusted", []string{"/projects", "Applications"},
			[]string{"safe.directory=/projects/*"}},
		{"the filesystem root is not trusted", []string{"/", ""}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Signer{cfg: Config{TrustedRoots: tc.roots}}
			got := gitConfigEntries(s.baseEnv(&trustFiles{}))
			if !slices.Equal(got, tc.want) {
				t.Errorf("git config entries are %q, want %q", got, tc.want)
			}
		})
	}
}

// gitConfigEntries reads GIT_CONFIG_COUNT/KEY_n/VALUE_n back as key=value.
func gitConfigEntries(env []string) []string {
	vars := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	var out []string
	for i := 0; ; i++ {
		n := strconv.Itoa(i)
		k, ok := vars["GIT_CONFIG_KEY_"+n]
		if !ok {
			return out
		}
		out = append(out, k+"="+vars["GIT_CONFIG_VALUE_"+n])
	}
}

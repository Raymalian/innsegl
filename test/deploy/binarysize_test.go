// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// OPS-180: the core's binary fits under the size the SPIRE agent hashes a
// workload's binary up to. Over it, the agent's unix attestor refuses to
// attest the core, the core gets no identity and never comes up. Measured
// on a dev-stack update rehearsal (#473): an ACME library's all-providers
// import took the binary from 42 MB to 100 MB, and innsegl-mcp hung at
// start waiting for an SVID while the agent logged "exceeds size limit".
// Built the way the Dockerfile builds it, for the platform the image
// targets.
func TestOPS180TheCoreBinaryFitsTheAttestorsSizeLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	root := repoRoot(t)
	conf, err := os.ReadFile(filepath.Join(root, "deploy", "compose", "spire", "agent.conf"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`workload_size_limit\s*=\s*(\d+)`).FindSubmatch(conf)
	if m == nil {
		t.Fatal("agent.conf sets no workload_size_limit")
	}
	limit, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			out := filepath.Join(t.TempDir(), "innsegl")
			cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", out, "./cmd/innsegl")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
			if b, berr := cmd.CombinedOutput(); berr != nil {
				t.Fatalf("go build: %v\n%s", berr, b)
			}
			info, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			// Room for a release's growth: a binary within 10% of the limit
			// is one dependency away from an outage.
			if margin := limit - limit/10; info.Size() > margin {
				t.Fatalf("the linux/%s binary is %d bytes; the attestor hashes up to %d, and 90%% of that is %d",
					arch, info.Size(), limit, margin)
			}
		})
	}
}

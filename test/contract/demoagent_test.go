// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// OPS-230 (proposed for doc 07; doc 07 is not modified here) — RM-372, #624.
//
// THE SHIPPED DEMO AGENT, RUN AGAINST THE SHIPPED TOOLS. `make innsegl-demo`
// runs deploy/compose/innsegl/demo-agent.sh, a curl-and-jq MCP client, and
// nothing ran it in a test. #341 made a run id alone insufficient: the tools
// that act for a run require the run_token register_agent hands back, and a
// deployment derives the token secret by default. The script was never
// updated, so get_credential answered RUN_NOT_FOUND straight after a
// successful register_agent, and nobody found out until an operator ran it.
//
// Here the script itself runs, unmodified, against mcp.New over HTTP with the
// shipped tool configurations and run tokens on, serving every tool on one
// listener: what the dev core serves for `make innsegl-demo` (ADR-0083,
// -lifecycle-on-agent-listener).
//
// SPIRE and the signer are this package's fakes (see harness_test.go): the
// claim is that the demo speaks the protocol the tools serve, not that a real
// Fulcio signs. test/smoke's OPS-004 makes that claim, with its own client.
// ---------------------------------------------------------------------------

// demoRepo is the shipped demo's own default repository.
const demoRepo = "github.com/innsegl-demo/scratch"

func TestOPS230TheShippedDemoAgentCompletesAgainstTheShippedTools(t *testing.T) {
	for _, tool := range []string{"sh", "curl", "jq", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("the demo agent needs %s, which is not on PATH: %v", tool, err)
		}
	}
	script := demoScript(t)

	s := newStackOnWith(t, freshDSN(t, requirePG(t)), true)
	srv := httptest.NewServer(s.server.Handler())
	t.Cleanup(srv.Close)
	runDemo(t, script, s, srv.URL)
}

// demoScript is the path of the script `make innsegl-demo` builds into its
// image.
func demoScript(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	path := filepath.Join(filepath.Dir(here), "..", "..", "deploy", "compose", "innsegl", "demo-agent.sh")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the shipped demo agent is not at %s: %v", path, err)
	}
	return path
}

// runDemo runs the demo script against url and requires it to finish the
// happy path.
func runDemo(t *testing.T, script string, s *stack, url string) {
	t.Helper()
	ctx := testCtx(t, 3*time.Minute)
	cmd := exec.CommandContext(ctx, "sh", script)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"INNSEGL_MCP_URL=" + url,
		"INNSEGL_WORKSPACE=" + s.scRoot,
		"INNSEGL_DEMO_REPO=" + demoRepo,
		// The task the stack's fixtures use, so sign_commit's task_ref check
		// is the shipped one and not a special case.
		"INNSEGL_DEMO_AGENT_TYPE=" + testAgentType,
		"INNSEGL_DEMO_TASK_REF=" + testTaskID,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped demo agent failed: %v\n%s", err, out)
	}
	for _, want := range []string{"registered spiffe://", "holds a JWT-SVID", "signed commit ",
		"get_credential after retirement is refused", "done."} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the demo agent exited 0 without %q:\n%s", want, out)
		}
	}
	if n := s.scSigner.callCount(); n != 1 {
		t.Errorf("the signer was asked %d times; the demo signs exactly one commit", n)
	}
}

// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/mcp"
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
// shipped tool configurations and run tokens on, in the two shapes a core
// serves:
//
//   - one listener with every tool (INNSEGL_MCP_ADMIN_LISTEN unset);
//   - the split `make start` turns on: get_credential and sign_commit on the
//     agent listener, register_agent and retire_agent on the identity
//     lifecycle listener behind a repository-scoped admin credential (#264).
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

	t.Run("one listener", func(t *testing.T) {
		s := newStackOnWith(t, freshDSN(t, requirePG(t)), true)
		all := httptest.NewServer(s.server.Handler())
		t.Cleanup(all.Close)
		runDemo(t, script, s, all.URL, "", "")
	})

	t.Run("agent and identity lifecycle listeners", func(t *testing.T) {
		s := newStackOnWith(t, freshDSN(t, requirePG(t)), true)
		jwks, credential := demoAdminCredential(t, demoRepo)
		verifier, err := mcp.NewAdminCredentialVerifier(mcp.AdminCredentialConfig{KeySetFile: jwks})
		if err != nil {
			t.Fatalf("NewAdminCredentialVerifier: %v", err)
		}
		agentSrv, err := mcp.New(mcp.Config{Version: "v0.0.0-contract", Tools: mcp.AgentTools()})
		if err != nil {
			t.Fatalf("mcp.New (agent): %v", err)
		}
		adminSrv, err := mcp.New(mcp.Config{Version: "v0.0.0-contract", Tools: mcp.AdminTools(),
			AdminCredential: verifier})
		if err != nil {
			t.Fatalf("mcp.New (identity lifecycle): %v", err)
		}
		agent := httptest.NewServer(agentSrv.Handler())
		t.Cleanup(agent.Close)
		admin := httptest.NewServer(adminSrv.Handler())
		t.Cleanup(admin.Close)
		runDemo(t, script, s, agent.URL, admin.URL, credential)
	})
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

// runDemo runs the demo script against agentURL (and adminURL, when the
// identity lifecycle is split off) and requires it to finish the happy path.
func runDemo(t *testing.T, script string, s *stack, agentURL, adminURL, credential string) {
	t.Helper()
	ctx := testCtx(t, 3*time.Minute)
	cmd := exec.CommandContext(ctx, "sh", script)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"INNSEGL_MCP_URL=" + agentURL,
		"INNSEGL_WORKSPACE=" + s.scRoot,
		"INNSEGL_DEMO_REPO=" + demoRepo,
		// The task the stack's fixtures use, so sign_commit's task_ref check
		// is the shipped one and not a special case.
		"INNSEGL_DEMO_AGENT_TYPE=" + testAgentType,
		"INNSEGL_DEMO_TASK_REF=" + testTaskID,
	}
	if adminURL != "" {
		cmd.Env = append(cmd.Env,
			"INNSEGL_MCP_ADMIN_URL="+adminURL,
			"INNSEGL_MCP_ADMIN_CREDENTIAL="+credential)
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

// demoAdminCredential writes a one-key JWK set and mints a credential for repo
// under it, the format `innsegl admin-credential mint` writes (ES256 over
// mcp.AdminCredentialSigningInput, the two coordinates fixed-width).
func demoAdminCredential(t *testing.T, repo string) (jwksPath, credential string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := mcp.AdminCredentialJWKOf(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(mcp.AdminCredentialJWKSet{Keys: []mcp.AdminCredentialJWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	jwksPath = filepath.Join(t.TempDir(), "jwks.json")
	if werr := os.WriteFile(jwksPath, body, 0o600); werr != nil {
		t.Fatal(werr)
	}

	nonce := make([]byte, 16)
	if _, rerr := rand.Read(nonce); rerr != nil {
		t.Fatal(rerr)
	}
	now := time.Now().UTC()
	input, err := mcp.AdminCredentialSigningInput(jwk.KID, mcp.AdminCredentialClaims{
		Issuer:    mcp.AdminCredentialIssuer,
		Audience:  mcp.AdminCredentialAudience,
		Repo:      repo,
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		Expiry:    now.Add(10 * time.Minute).Unix(),
		TokenID:   hex.EncodeToString(nonce),
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(input))
	r, sig, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	sig.FillBytes(raw[32:])
	return jwksPath, input + "." + base64.RawURLEncoding.EncodeToString(raw)
}

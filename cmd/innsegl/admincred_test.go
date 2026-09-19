// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/mcp"
)

// #264's issuing side, and the start-up refusal that makes the check
// unskippable.
//
// MCP-090's third limb — "missing verification material with the listener
// enabled refuses to start" — lives here, because it is a CONFIGURATION
// decision and this is the file that reads one. The other two limbs (unknown
// key id, rotation with overlap) are in internal/mcp/admincred_test.go, beside
// the verifier that makes them. See that file for why these ids and not the
// ones #264 names.

// runAdminCredential runs the subcommand and returns its status and streams.
func runAdminCredential(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"admin-credential"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// ---------------------------------------------------------------------------
// MCP-090 — the start-up refusal.
// ---------------------------------------------------------------------------

// TestMCP090ServeRefusesToStartWithAnAdminListenerAndNoVerificationMaterial.
//
// A deployment that believes it is authenticated and is not is worse than one
// that knows it is open. The shipped compose file said so itself — "Do NOT turn
// this on until something is arranged to do the registering" — above a setting
// that was on, with six identity-lifecycle tools behind it and no check at all.
func TestMCP090ServeRefusesToStartWithAnAdminListenerAndNoVerificationMaterial(t *testing.T) {
	base := serveOptions{
		dsn: "postgres://x", spireAddress: "h:1", trustDomain: "innsegl.dev",
		parentID: "spiffe://innsegl.dev/spire/agent/x", fulcioURL: "http://f", rekorURL: "http://r",
		listen: "127.0.0.1:0", healthListen: "127.0.0.1:0",
		identityMode: string(identity.ModePseudonymous), identitySecret: testIdentitySecret,
	}
	if problem := base.validate(); problem != "" {
		t.Fatalf("the complete configuration was refused: %s", problem)
	}

	open := base
	open.adminListen = "0.0.0.0:8090"
	problem := open.validate()
	if problem == "" {
		t.Fatal("a deployment serving the identity lifecycle with nothing to authenticate a " +
			"caller was accepted; any process that can reach that listener could then mint a run")
	}
	for _, want := range []string{"-admin-jwks", envMCPAdminJWKSFile, "-admin-listen"} {
		if !strings.Contains(problem, want) {
			t.Errorf("the refusal %q does not name %q", problem, want)
		}
	}

	// The other direction is refused too: material with no listener reads as a
	// control that is on and is not.
	stray := base
	stray.adminJWKS = "/run/innsegl/admin/jwks.json"
	if stray.validate() == "" {
		t.Error("a key set with no identity-lifecycle listener was accepted; the file would " +
			"be read and never used, which reads as a control that is on")
	}

	// Both together are the configuration that works.
	whole := base
	whole.adminListen, whole.adminJWKS = "0.0.0.0:8090", "/run/innsegl/admin/jwks.json"
	if problem := whole.validate(); problem != "" {
		t.Errorf("the split listener with its key set was refused: %s", problem)
	}

	// SINGLE-LISTENER MODE REQUIRES NOTHING. That is every deployment before
	// #264 and every one that has not opted in.
	if problem := base.validate(); problem != "" {
		t.Errorf("single-listener mode was refused: %s", problem)
	}
}

// ---------------------------------------------------------------------------
// keygen, mint, verify.
// ---------------------------------------------------------------------------

// TestAdminCredentialRoundTripsThroughTheShippedVerifier. The mint command and
// the server share ONE definition of what gets signed; this is what proves the
// two halves have not drifted.
func TestAdminCredentialRoundTripsThroughTheShippedVerifier(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.key")
	jwksPath := filepath.Join(dir, "jwks.json")

	code, kid, stderr := runAdminCredential(t, "keygen", "-key", keyPath, "-jwks", jwksPath)
	if code != exitOK {
		t.Fatalf("keygen = %d: %s", code, stderr)
	}
	if strings.TrimSpace(kid) == "" {
		t.Fatal("keygen printed no key id")
	}

	// The private half is 0600 and the key set is not private at all.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat %s: %v", keyPath, err)
	}
	if perm := info.Mode().Perm(); perm != adminCredentialKeyMode {
		t.Errorf("the signing key is mode %o, want %o", perm, adminCredentialKeyMode)
	}

	code, token, stderr := runAdminCredential(t, "mint",
		"-key", keyPath, "-repo", "github.com/acme/widgets")
	if code != exitOK {
		t.Fatalf("mint = %d: %s", code, stderr)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		t.Fatal("mint printed no credential")
	}
	// The credential goes to stdout and NOWHERE else. A value echoed onto a
	// second stream is a value in a second log.
	if strings.Contains(stderr, token) {
		t.Error("mint echoed the credential onto stderr")
	}

	verifier, err := mcp.NewAdminCredentialVerifier(mcp.AdminCredentialConfig{KeySetFile: jwksPath})
	if err != nil {
		t.Fatalf("the shipped verifier refused the key set keygen wrote: %v", err)
	}
	scope, ok := verifier.Verify(token)
	if !ok {
		explained, err := verifier.Explain(token)
		t.Fatalf("the shipped verifier refused a freshly minted credential: %v (%+v)",
			err, explained)
	}
	if scope.Repo != "github.com/acme/widgets" {
		t.Errorf("the credential authorises %q, want github.com/acme/widgets", scope.Repo)
	}

	// And the operator-facing verb agrees with the server.
	code, out, _ := runAdminCredential(t, "verify", "-jwks", jwksPath, "-token", token)
	if code != exitOK {
		t.Fatalf("verify = %d for a credential the server admits", code)
	}
	if strings.TrimSpace(out) != "github.com/acme/widgets" {
		t.Errorf("verify printed %q", out)
	}
}

// TestAdminCredentialKeygenRotatesByOverlap. A rotation that REPLACED the key
// set would refuse every credential already in flight, so the public half is
// added beside what is there and the outgoing entry is removed by hand.
func TestAdminCredentialKeygenRotatesByOverlap(t *testing.T) {
	dir := t.TempDir()
	jwksPath := filepath.Join(dir, "jwks.json")
	outgoing := filepath.Join(dir, "outgoing.key")
	incoming := filepath.Join(dir, "incoming.key")

	if code, _, stderr := runAdminCredential(t, "keygen", "-key", outgoing, "-jwks", jwksPath); code != exitOK {
		t.Fatalf("keygen (outgoing) = %d: %s", code, stderr)
	}
	mintCode, before, mintErr := runAdminCredential(t, "mint",
		"-key", outgoing, "-repo", "github.com/acme/widgets")
	if mintCode != exitOK {
		t.Fatalf("mint under the outgoing key = %d: %s", mintCode, mintErr)
	}

	if code, _, stderr := runAdminCredential(t, "keygen", "-key", incoming, "-jwks", jwksPath); code != exitOK {
		t.Fatalf("keygen (incoming) = %d: %s", code, stderr)
	}
	mintCode, after, mintErr := runAdminCredential(t, "mint",
		"-key", incoming, "-repo", "github.com/acme/widgets")
	if mintCode != exitOK {
		t.Fatalf("mint under the incoming key = %d: %s", mintCode, mintErr)
	}

	var set mcp.AdminCredentialJWKSet
	body, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatalf("reading %s: %v", jwksPath, err)
	}
	if parseErr := json.Unmarshal(body, &set); parseErr != nil {
		t.Fatalf("the key set is not JSON: %v", parseErr)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("the key set holds %d keys after a rotation, want 2 — an overlap is what "+
			"keeps credentials already in flight working", len(set.Keys))
	}

	verifier, err := mcp.NewAdminCredentialVerifier(mcp.AdminCredentialConfig{KeySetFile: jwksPath})
	if err != nil {
		t.Fatalf("NewAdminCredentialVerifier: %v", err)
	}
	for name, token := range map[string]string{"outgoing": before, "incoming": after} {
		if _, ok := verifier.Verify(strings.TrimSpace(token)); !ok {
			t.Errorf("the %s key's credential is refused during the overlap", name)
		}
	}
}

// TestAdminCredentialKeygenLeavesAnExistingKeyAlone. Replacing a signing key
// silently strands every credential minted under it.
func TestAdminCredentialKeygenLeavesAnExistingKeyAlone(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.key")
	jwksPath := filepath.Join(dir, "jwks.json")
	if code, _, stderr := runAdminCredential(t, "keygen", "-key", keyPath, "-jwks", jwksPath); code != exitOK {
		t.Fatalf("keygen = %d: %s", code, stderr)
	}
	original, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading %s: %v", keyPath, err)
	}

	code, _, stderr := runAdminCredential(t, "keygen", "-key", keyPath, "-jwks", jwksPath)
	if code != exitCredentialUnusable {
		t.Errorf("a second keygen over an existing key = %d, want %d", code, exitCredentialUnusable)
	}
	if !strings.Contains(stderr, "-force") {
		t.Errorf("the refusal does not say how to mean it: %q", stderr)
	}
	replaced, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading %s: %v", keyPath, err)
	}
	if !bytes.Equal(original, replaced) {
		t.Error("the existing signing key was overwritten")
	}
}

// TestAdminCredentialMintRefusesATTLBeyondTheBound. There is no revocation
// list — a list is a dependency on the issuer being reachable, which this
// design deliberately does not have — so the TTL is the whole of the bound.
func TestAdminCredentialMintRefusesATTLBeyondTheBound(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "admin.key")
	if code, _, stderr := runAdminCredential(t, "keygen",
		"-key", keyPath, "-jwks", filepath.Join(dir, "jwks.json")); code != exitOK {
		t.Fatalf("keygen = %d: %s", code, stderr)
	}
	code, _, _ := runAdminCredential(t, "mint",
		"-key", keyPath, "-repo", "github.com/acme/widgets", "-ttl", "24h")
	if code != exitUsage {
		t.Errorf("mint -ttl 24h = %d, want %d", code, exitUsage)
	}
}

// TestAdminCredentialVerifySaysWhatTheServerNeverWill. The listener answers
// every failure with one byte-identical refusal, because a distinguishable
// "wrong audience" is an oracle. An operator debugging their own token on
// their own machine has no such constraint, and this is where they are told.
func TestAdminCredentialVerifySaysWhatTheServerNeverWill(t *testing.T) {
	dir := t.TempDir()
	jwksPath := filepath.Join(dir, "jwks.json")
	if code, _, stderr := runAdminCredential(t, "keygen",
		"-key", filepath.Join(dir, "admin.key"), "-jwks", jwksPath); code != exitOK {
		t.Fatalf("keygen = %d: %s", code, stderr)
	}

	code, _, stderr := runAdminCredential(t, "verify", "-jwks", jwksPath, "-token", "not-a-token")
	if code != exitCredentialRefused {
		t.Errorf("verify of a malformed credential = %d, want %d", code, exitCredentialRefused)
	}
	if !strings.Contains(stderr, "REFUSED") || !strings.Contains(stderr, "segments") {
		t.Errorf("verify did not say what was wrong: %q", stderr)
	}
}

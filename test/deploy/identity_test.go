// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/identity"
)

// ---------------------------------------------------------------------------
// OPS-011 and OPS-012 (PROPOSED for doc 07's TC-OPS) — the reference
// deployment generates ITS OWN pseudonymisation secret, and no two deployments
// share one.
//
// RM-084 (#124). #119 made the deployment secret mandatory — `serve` defaults
// to `-identity-mode pseudonymous` and `identity.New` refuses that mode
// without at least identity.MinSecretBytes — and `deploy/compose/innsegl.yml`
// set neither `INNSEGL_IDENTITY_MODE` nor `INNSEGL_IDENTITY_SECRET`. So the
// shipped stack crashlooped on a clean `docker compose up`, and the refusal
// that was working exactly as designed read as a broken product.
//
// THE OBVIOUS FIX IS THE ONE THIS FILE EXISTS TO PREVENT. A constant in
// innsegl.yml would start the container, and it would give every deployment on
// earth the same pseudonyms: `a7f3c91b` would mean one particular task
// reference EVERYWHERE, and anyone who learned one mapping would hold it for
// every installation. That is worse than no pseudonymisation, because it looks
// private and is not. OPS-011's third case is the guard that fails if anyone
// ever ships one.
// ---------------------------------------------------------------------------

// identityInitScript is the shipped generator, by the path innsegl.yml mounts.
const identityInitScript = "deploy/compose/innsegl/identity-init.sh"

// identitySecretEnv is what `innsegl serve` reads the secret's PATH from —
// one name, set by the one-shot that writes the file and by the service that
// reads it, so the writer and the reader cannot name different files.
const identitySecretEnv = "INNSEGL_IDENTITY_SECRET_FILE"

func TestOPS011TheStackGeneratesItsOwnIdentitySecret(t *testing.T) {
	root := repoRoot(t)
	stackPath := filepath.Join(root, "deploy", "compose", "innsegl.yml")
	stack := readFile(t, stackPath)

	t.Run("the one-shot ships and is a service", func(t *testing.T) {
		if _, err := os.Stat(filepath.Join(root, identityInitScript)); err != nil {
			t.Fatalf("%s must ship: it is what gives each deployment a secret of its "+
				"own, and without it `docker compose up` needs a manual step (#124): %v",
				identityInitScript, err)
		}
		services := composeServices(t, stackPath)
		if !containsString(services, "innsegl-identity-init") {
			t.Fatalf("deploy/compose/innsegl.yml declares no innsegl-identity-init "+
				"service; it declares %v", services)
		}
	})

	t.Run("the MCP gates on it and reads the file it wrote", func(t *testing.T) {
		mcp := composeService(t, stack, "innsegl-mcp")
		for _, want := range []struct{ needle, why string }{
			{"innsegl-identity-init",
				"the MCP must gate on the one-shot's completion: starting before the " +
					"secret exists is the crashloop #124 is about"},
			{"service_completed_successfully",
				"a one-shot is depended on by completion, not by start — the shape " +
					"innsegl-db-init and sigstore-bootstrap already use"},
			{identitySecretEnv,
				"compose cannot inject a file's contents into an environment variable, " +
					"so the MCP is told the PATH — the INNSEGL_MCP_SVID_FILE convention"},
		} {
			if !strings.Contains(mcp, want.needle) {
				t.Errorf("the innsegl-mcp service never mentions %q: %s", want.needle, want.why)
			}
		}
	})

	// The network footprint, asserted rather than remembered. #100: this
	// machine tops out at roughly twenty-nine Docker networks and the three
	// shipped stacks already hold twelve. A one-shot that generates key
	// material reaches nothing, so it joins nothing — sigstore-bootstrap's
	// reasoning, verbatim: "Nothing it does requires reaching anything, so
	// nothing can reach it either."
	t.Run("the one-shot costs no network", func(t *testing.T) {
		init := composeService(t, stack, "innsegl-identity-init")
		if !strings.Contains(init, "network_mode: none") {
			t.Errorf("innsegl-identity-init does not set `network_mode: none`. It writes "+
				"a key and talks to nobody; a network it does not need is a network "+
				"#100's ceiling pays for:\n%s", init)
		}
		if strings.Contains(init, "networks:") {
			t.Errorf("innsegl-identity-init joins a network:\n%s", init)
		}
	})

	// THE GUARD. A shipped constant would have "fixed" #124 and broken the
	// property the whole feature exists for.
	//
	// SCOPE, said plainly: everything an ADOPTER runs. Test harnesses are
	// excluded and that is deliberate rather than convenient — test/smoke and
	// cmd/innsegl carry fixture secrets for stacks they create and destroy
	// within one run, which are secrets of nothing. What may not carry a
	// constant is the artifact somebody else deploys.
	t.Run("nothing an adopter runs carries a constant secret", func(t *testing.T) {
		for _, file := range shippedFiles(t, root) {
			body, err := os.ReadFile(filepath.Join(root, file))
			if err != nil {
				t.Fatalf("reading tracked file %s: %v", file, err)
			}
			for _, line := range strings.Split(string(body), "\n") {
				value, ok := constantIdentitySecret(line)
				if !ok {
					continue
				}
				t.Errorf("%s sets the deployment secret to the constant %s:\n  %s\n\n"+
					"A constant gives EVERY deployment the same pseudonyms, so one "+
					"resolved mapping resolves them everywhere. That is worse than no "+
					"pseudonymisation, because it looks private and is not (#124). Use "+
					"%s and let innsegl-identity-init generate one per deployment.",
					file, value, strings.TrimSpace(line), identitySecretEnv)
			}
		}
	})

	t.Run("the generator draws from a CSPRNG", func(t *testing.T) {
		script := readFile(t, filepath.Join(root, identityInitScript))
		if !strings.Contains(script, "openssl rand") {
			t.Errorf("%s does not call `openssl rand`. The secret keys an HMAC whose "+
				"32-bit output is published, so its own entropy is what protects every "+
				"pseudonym; anything a reader can predict is not a key.", identityInitScript)
		}
	})
}

// TestOPS012TheIdentitySecretIsPerDeploymentAndSurvivesARestart runs the
// SHIPPED generator — not a re-description of it — and measures the three
// properties #124's acceptance names.
//
// It needs no Docker and no network. The script is POSIX `sh` over `openssl`,
// so running it against a temporary directory exercises exactly the bytes the
// one-shot container runs, at the cost of neither a container nor one of
// #100's twenty-nine networks.
func TestOPS012TheIdentitySecretIsPerDeploymentAndSurvivesARestart(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, identityInitScript)

	// #101's rule: an ABSENT dependency is a skip, a dependency that is
	// PRESENT AND BROKE is a failure, and they never share a variable. Only
	// this lookup can produce a skip; every generator failure below is fatal.
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl is not on PATH, so the shipped generator cannot be run here: %v", err)
	}

	// generate runs the shipped script against one deployment's directory and
	// returns what it left behind.
	generate := func(t *testing.T, dir string) string {
		t.Helper()
		path := filepath.Join(dir, "secret")
		cmd := exec.CommandContext(t.Context(), "sh", script)
		cmd.Env = append(os.Environ(), identitySecretEnv+"="+path)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", identityInitScript, err, out)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s exited 0 and wrote no secret at %s: %v", identityInitScript, path, err)
		}
		return strings.TrimSpace(string(body))
	}

	// Two deployments, each with its own directory — which is what two
	// installations with their own named volumes are.
	alpha, beta := t.TempDir(), t.TempDir()

	first := generate(t, alpha)
	if len(first) < identity.MinSecretBytes {
		t.Fatalf("the generated secret is %d bytes; identity.New refuses anything under %d",
			len(first), identity.MinSecretBytes)
	}

	t.Run("a restart leaves the secret alone", func(t *testing.T) {
		again := generate(t, alpha)
		if again != first {
			t.Fatalf("the second run replaced the secret. Every pseudonym this " +
				"deployment ever minted would change on a `docker compose up`, and " +
				"one run's replayed register_agent would derive a SECOND SPIFFE ID " +
				"for a run id SPIRE already holds an entry for.")
		}
	})

	t.Run("a second deployment gets a different secret", func(t *testing.T) {
		other := generate(t, beta)
		if other == first {
			t.Fatalf("two deployments generated the same secret, so every deployment " +
				"shares one pseudonym space (#124)")
		}
	})

	// The property all of the above exists to produce, measured through the
	// package that produces it rather than inferred from the bytes.
	t.Run("the same task reference pseudonymises differently in each deployment", func(t *testing.T) {
		const taskRef = "jira-118"

		alphaP := newPseudonymiser(t, first)
		betaP := newPseudonymiser(t, generate(t, beta))
		restartedP := newPseudonymiser(t, generate(t, alpha))

		alphaTask := pseudonym(t, alphaP, taskRef)
		betaTask := pseudonym(t, betaP, taskRef)
		restartedTask := pseudonym(t, restartedP, taskRef)

		if alphaTask == betaTask {
			t.Errorf("%q pseudonymises to %q in BOTH deployments. The pseudonym is "+
				"deployment-scoped precisely so that resolving one mapping does not "+
				"resolve it everywhere.", taskRef, alphaTask)
		}
		if alphaTask != restartedTask {
			t.Errorf("%q pseudonymises to %q before a restart and %q after it. A run "+
				"registered yesterday and retired today must carry one identity.",
				taskRef, alphaTask, restartedTask)
		}
		t.Logf("%q -> %s (deployment A), %s (deployment B), %s (A restarted)",
			taskRef, alphaTask, betaTask, restartedTask)
	})
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func newPseudonymiser(t *testing.T, secret string) *identity.Pseudonymiser {
	t.Helper()
	p, err := identity.New(identity.ModePseudonymous, secret)
	if err != nil {
		t.Fatalf("the generated secret is not one identity.New accepts: %v", err)
	}
	return p
}

func pseudonym(t *testing.T, p *identity.Pseudonymiser, taskRef string) string {
	t.Helper()
	got, err := p.TaskID(taskRef)
	if err != nil {
		t.Fatalf("TaskID(%q): %v", taskRef, err)
	}
	return got
}

// identitySecretAssignment matches an assignment to the deployment secret in
// any of the shapes a deployment writes one: compose YAML, an env file, a
// shell export, a Dockerfile ENV. The optional `_FILE` group is what
// distinguishes "here is the secret" from "here is where the secret lives".
var identitySecretAssignment = regexp.MustCompile(`INNSEGL_IDENTITY_SECRET(_FILE)?\s*[:=]\s*(\S*)`)

// identitySecretFlag matches the flag form, which a compose `command:` could
// use instead of the environment — in either of compose's two spellings, the
// shell string and the JSON array, so the quotes and comma between a flag and
// its value are skipped.
//
// The value is held to something that could actually BE a secret — eight or
// more characters from a key alphabet. Without that, prose naming the two
// flags together ("`-identity-secret / -identity-secret-file`") reads as an
// assignment of `/`, and a guard that cries wolf on documentation is a guard
// somebody deletes.
var identitySecretFlag = regexp.MustCompile(
	`-identity-secret(-file)?["']?[\s=,]*["']?([A-Za-z0-9][A-Za-z0-9+/=_.~-]{7,})`)

// constantIdentitySecret reports whether one line hands the deployment secret
// a value that is baked into the file, and what that value is.
//
// A value that begins with `$` is not baked in: `${INNSEGL_IDENTITY_SECRET}`
// is compose interpolation, `$(openssl rand -hex 32)` is generation, and
// `$INNSEGL_IDENTITY_SECRET` is a shell reference. Everything else — a bare
// string, a quoted string, a YAML anchor alias — is a constant somebody
// shipped.
func constantIdentitySecret(line string) (string, bool) {
	for _, m := range [][]string{
		identitySecretAssignment.FindStringSubmatch(line),
		identitySecretFlag.FindStringSubmatch(line),
	} {
		if m == nil || m[1] != "" {
			continue
		}
		value := strings.Trim(m[2], `"'`)
		if value == "" || strings.HasPrefix(value, "$") {
			continue
		}
		return value, true
	}
	return "", false
}

// shippedFiles is every tracked file an adopter runs: the compose stack and
// its scripts, the image build, the operator entry points and the runbooks.
// Test harnesses are excluded; see the case that calls this for why.
func shippedFiles(t *testing.T, root string) []string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(),
		"git", "-C", root, "ls-files", "deploy", "runbooks", "Dockerfile", "Makefile").Output()
	if err != nil {
		t.Fatalf("listing the shipped files: %v", err)
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f != "" {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatal("no shipped files were listed; the guard would pass vacuously")
	}
	return files
}

// composeService returns the block of a compose file belonging to one service:
// its key line and every line indented beneath it.
func composeService(t *testing.T, stack, name string) string {
	t.Helper()
	var block []string
	inBlock := false
	for _, line := range strings.Split(stack, "\n") {
		if m := serviceLine.FindStringSubmatch(line); m != nil {
			inBlock = m[1] == name
			if inBlock {
				block = append(block, line)
			}
			continue
		}
		if inBlock {
			block = append(block, line)
		}
	}
	if len(block) == 0 {
		t.Fatalf("deploy/compose/innsegl.yml declares no %s service", name)
	}
	return strings.Join(block, "\n")
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

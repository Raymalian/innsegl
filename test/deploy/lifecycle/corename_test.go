// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// ---------------------------------------------------------------------------
// OPS-197 (PROPOSED for doc 07's TC-OPS) — the core container is
// `innsegl-core` (RM-346, #594).
//
// The core runs `innsegl serve`: the MCP server, the gateway, and by default
// the sealer, reconciler and reaper (ADR-0056). Its service and container
// were called after one of those jobs. They are now `innsegl-core`, and
// `innsegl-dev-core` on a dev stack.
//
// The old name stays as a DNS alias on the clients' network for one release,
// so a client that reaches the core by it keeps working through the switch.
// That alias, and the one fallback in scripts/update-signing.sh that probes a
// core still running under the old name before the update replaces it, are
// the only places the old container name may remain.
//
// What does NOT change: the `innsegl serve` command, the MCP tool names, the
// SPIFFE ID and its selectors (no selector names the container), the volume
// names, the network names (`innsegl-mcp-clients` stays) and the compose
// project name.
// ---------------------------------------------------------------------------

// coreOldNameAlias is the DNS name kept for one release.
const coreOldNameAlias = "innsegl-mcp"

// oldCoreName matches the old container name in each form a file wrote it:
// the live name, the dev name, and a name built from a stack prefix. A
// following hyphen or word character makes it another name (the network
// innsegl-mcp-clients, a test harness's innsegl-mcptest-<pid>), so those
// are not matches.
var oldCoreName = regexp.MustCompile(
	`(innsegl|innsegl-dev|<prefix>|PREFIX\)|PREFIX\}|innsegl\}|prefix *\+ *")-mcp([^-\w]|$)`)

// oldCoreNameAllowed lists, per file, the trimmed lines that may name the old
// container. Each is the documented alias or the pre-switch fallback.
var oldCoreNameAllowed = map[string][]string{
	"deploy/compose/innsegl.yml": {
		"- innsegl-mcp",
	},
	"reference/stack-and-make.md": {
		"innsegl-mcp     old name; DNS alias only, removed in the next release",
	},
	"scripts/update-signing.sh": {
		`old="${INNSEGL_STACK_PREFIX:-innsegl}-mcp"`,
	},
	// The fallback's own test runs a fake core under the old name.
	"test/deploy/lifecycle/updatesigning_test.go": {
		`fakeCoreNamed(t, prefix+"-mcp", true)`,
	},
}

func TestOPS197NoOldCoreContainerNameRemains(t *testing.T) {
	root := deploytest.RepoRoot(t)
	out, err := exec.CommandContext(t.Context(), "git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("listing the tracked files: %v", err)
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	if len(files) < 100 {
		t.Fatalf("only %d tracked files were listed; the check would pass vacuously", len(files))
	}

	var hits []string
	for _, f := range files {
		// This file names the old name to forbid it. CHANGELOG.md and the
		// ADRs record what was shipped and decided, under the name it had.
		if f == "test/deploy/lifecycle/corename_test.go" || f == "CHANGELOG.md" || strings.HasPrefix(f, "docs/") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue // a tracked file removed in the working tree
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !oldCoreName.MatchString(line) {
				continue
			}
			if slices.Contains(oldCoreNameAllowed[f], strings.TrimSpace(line)) {
				continue
			}
			hits = append(hits, f+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
		}
	}
	if len(hits) > 0 {
		t.Errorf("%d line(s) still name the old core container; it is innsegl-core (RM-346):\n%s",
			len(hits), strings.Join(hits, "\n"))
	}
}

// coreRendered reads the core's service, container name and per-network
// aliases from the interpolated compose files.
type coreRendered struct {
	Name     string `json:"name"`
	Services map[string]struct {
		ContainerName string `json:"container_name"`
		Networks      map[string]*struct {
			Aliases []string `json:"aliases"`
		} `json:"networks"`
	} `json:"services"`
}

func renderCore(t *testing.T, files ...string) coreRendered {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is not on PATH: %v", err)
	}
	root := deploytest.RepoRoot(t)
	args := []string{"compose", "--profile", "*"}
	for _, f := range files {
		args = append(args, "-f", filepath.Join(root, f))
	}
	args = append(args, "config", "--format", "json")
	cmd := exec.CommandContext(t.Context(), "docker", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080",
		"INNSEGL_SPIRE_PARENT_ID=unset")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose %v config: %v\n%s", files, err, stderr.String())
	}
	var doc coreRendered
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestOPS197CoreServiceAndContainerAreInnseglCore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		files     []string
		project   string
		container string
	}{
		{"live", []string{deploytest.CoreBase}, "innsegl-core", "innsegl-core"},
		{"live, custody", []string{deploytest.CoreBase, deploytest.CoreCustody}, "innsegl-core", "innsegl-core"},
		{"dev", []string{deploytest.CoreBase, "deploy/compose/dev/innsegl.yml"}, "innsegl-dev-core", "innsegl-dev-core"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := renderCore(t, tc.files...)
			// The project name is not renamed: the volumes are named after it.
			if doc.Name != tc.project {
				t.Errorf("compose project = %q, want %q; the volumes are named after it", doc.Name, tc.project)
			}
			if _, ok := doc.Services["innsegl-mcp"]; ok {
				t.Error("the service innsegl-mcp is still declared; it is innsegl-core")
			}
			core, ok := doc.Services["innsegl-core"]
			if !ok {
				t.Fatal("no innsegl-core service")
			}
			if core.ContainerName != tc.container {
				t.Errorf("container_name = %q, want %q", core.ContainerName, tc.container)
			}
			// The old DNS name, for one release, on the network clients use.
			clients, ok := core.Networks["innsegl-mcp-clients"]
			if !ok || clients == nil || !slices.Contains(clients.Aliases, coreOldNameAlias) {
				t.Errorf("innsegl-core does not carry the alias %q on innsegl-mcp-clients", coreOldNameAlias)
			}
			// No other service takes either name, so neither resolves twice.
			for name, s := range doc.Services {
				if name == "innsegl-core" {
					continue
				}
				if s.ContainerName == tc.container {
					t.Errorf("service %s also uses the container name %s", name, tc.container)
				}
				for net, n := range s.Networks {
					if n != nil && (slices.Contains(n.Aliases, coreOldNameAlias) || slices.Contains(n.Aliases, "innsegl-core")) {
						t.Errorf("service %s carries a core alias on %s", name, net)
					}
				}
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0

package gateway

// workspace_test.go — RM-231 (#376): MCPWorkspaceResolver, the contract's
// WorkspaceResolver implemented on describe_workspace's own configured path
// (internal/mcp/gateway.go's ResolveWorkspaceForGateway). GID-004
// (internal/mcp/gateway_test.go) already proves that wrapper derives repo,
// branch and task from a real git repository and refuses a path outside the
// mount or a non-repository, never guessing. This file proves only the one
// thing that lives here and nowhere else: MCPWorkspaceResolver.Resolve
// translates between mcp.GatewayWorkspace and this package's own Workspace
// without dropping or swapping a field.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"innsegl.dev/innsegl/internal/mcp"
)

func gwGitInit(t *testing.T, dir, remote string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	gwGit(t, dir, "init", "-q", "-b", "main")
	gwGit(t, dir, "config", "user.email", "gateway-test@example.com")
	gwGit(t, dir, "config", "user.name", "Gateway Test")
	gwGit(t, dir, "remote", "add", "origin", remote)
}

func gwGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestMCPWorkspaceResolverResolvesTheTreeItIsGiven(t *testing.T) {
	projects := t.TempDir()
	repo := filepath.Join(projects, "example-repo")
	gwGitInit(t, repo, "git@github.com:Example-Org/Example-Repo.git")
	if err := os.WriteFile(filepath.Join(repo, "seed"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("seeding a file: %v", err)
	}
	gwGit(t, repo, "add", "seed")
	gwGit(t, repo, "commit", "-q", "-m", "seed", "--no-gpg-sign")
	gwGit(t, repo, "checkout", "-q", "-b", "dev/rm231-workspace-resolver")

	restore, err := mcp.ConfigureDescribeWorkspace(mcp.DescribeWorkspaceConfig{
		HostProjects: projects, Projects: projects,
	})
	if err != nil {
		t.Fatalf("ConfigureDescribeWorkspace: %v", err)
	}
	t.Cleanup(restore)

	r := NewMCPWorkspaceResolver()
	ws, err := r.Resolve(t.Context(), repo)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", repo, err)
	}
	const wantRepo = "github.com/Example-Org/Example-Repo"
	if ws.Repo != wantRepo {
		t.Errorf("repo = %q, want %q", ws.Repo, wantRepo)
	}
	if ws.Branch != "dev/rm231-workspace-resolver" {
		t.Errorf("branch = %q, want %q", ws.Branch, "dev/rm231-workspace-resolver")
	}
	if ws.Task != "rm231" {
		t.Errorf("task = %q, want %q", ws.Task, "rm231")
	}
}

func TestMCPWorkspaceResolverRefusesAPathOutsideTheMountNeverGuessing(t *testing.T) {
	projects := t.TempDir()
	restore, err := mcp.ConfigureDescribeWorkspace(mcp.DescribeWorkspaceConfig{
		HostProjects: projects, Projects: projects,
	})
	if err != nil {
		t.Fatalf("ConfigureDescribeWorkspace: %v", err)
	}
	t.Cleanup(restore)

	r := NewMCPWorkspaceResolver()
	outside := filepath.Join(projects, "..", "elsewhere")
	if got, err := r.Resolve(t.Context(), outside); err == nil {
		t.Fatalf("a path outside the mount was accepted and answered %+v", got)
	}
}

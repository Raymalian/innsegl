// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// describe_workspace — RM-126 (#205), E11, IP §4:
//
//	describe_workspace(cwd) →
//	    {repo, worktree, branch, task, is_linked_worktree}.
//	Pure derivation. No writes, no identity, no privacy surface.
//
// # Why a tool and not a paragraph of documentation
//
// This is `derive_task` from the reference shim, moved. The shim is 807 lines
// across six harness events, and the derivation is the largest thing in it
// that has nothing to do with which harness is running: worktree resolution,
// the branch rule, the task grammar, the repository identifier. Every harness
// would have to reimplement all four identically, and the one that did not
// would register runs that look different in the ledger for no reason anyone
// could explain from the record. E11's rule is that anything a second harness
// would have to copy belongs here.
//
// It is also what makes the rest of the surface reachable. A shim knows one
// thing for certain — its own working directory — and every other tool wants a
// repository identifier, a branch and a task. With this, a shim reads its
// event, calls here, and passes the answer on.
//
// # The path problem, and why an unset variable is a refusal
//
// A harness reports its OWN cwd: a path on the host. This process sees the
// same tree under a bind mount at a different root and has no way to translate
// one to the other — the container knows where the mount IS, never what it
// CORRESPONDS TO. So the deployment is told, once, in EnvHostProjects.
//
// Without it there is no honest answer. The plausible guesses — assume the
// mount root, strip up to the first directory that exists — all produce a
// confident description of a repository that may not be the caller's, and the
// answer is on its way into an append-only record: a `run_registered` naming
// the wrong repository is wrong for as long as the ledger exists. So every way
// the translation can fail is a refusal with its own message, and the messages
// say what to set rather than only what was rejected.
//
// # What it deliberately does not do
//
// It never synthesises `repo` from a directory name. The identifier comes from
// the main worktree's `origin` and must satisfy doc 02 §5's three-segment
// `host/org/name` — a clone directory called `example-repo` says nothing about
// which fork or which org it came from, and a ledger row that claimed
// otherwise would be unfalsifiable.
//
// It holds no state, writes no event and mints no identity, which is why it
// needs no run id: there is nothing here an unrecorded call could do. It is on
// the admin side of #170's split all the same, because it is the tool that
// makes the other two E11 tools addressable, and handing a model the
// addressing without the recording is the gap doc 04 AB-14 names.

func init() { RegisterTool(ToolDescribeWorkspace, bindDescribeWorkspace) }

const (
	// EnvHostProjects names the host directory this deployment's projects
	// mount corresponds to. It is the ONE value this tool adds, and it is set
	// from the same INNSEGL_PROJECTS the Makefile already computes for the
	// mount itself, so the two cannot disagree.
	EnvHostProjects = "INNSEGL_HOST_PROJECTS"

	// DefaultProjectsMount is where deploy/compose/innsegl.workrepo.yml mounts
	// that directory inside the container.
	DefaultProjectsMount = "/projects"

	// describeWorkspaceThrowawayPrefix is the one branch shape that is NOT the
	// answer. A harness with worktree isolation of its own puts each subagent
	// on a throwaway branch named `worktree-agent-<id>`, which nobody works on
	// and which is deleted with the agent; recording it gave every agent its
	// own junk task where one shared task belonged. That shape, and only that
	// shape, falls back to the main worktree's branch.
	describeWorkspaceThrowawayPrefix = "worktree-agent-"

	// describeWorkspaceDetached is the honest answer for a HEAD that is on no
	// branch. doc 02 stores `branch` verbatim, so inventing a name would put a
	// branch in the ledger that does not exist.
	describeWorkspaceDetached = "detached"

	// describeWorkspaceUnnamed is the answer for a branch that folds to
	// nothing under doc 02 §5's grammar.
	describeWorkspaceUnnamed = "unnamed"

	// describeWorkspaceTaskBytes is doc 02 §5's bound on an identifier:
	// [a-z0-9][a-z0-9-]{0,62}, so 63 characters.
	describeWorkspaceTaskBytes = 63
)

// describeWorkspaceRMTask matches this project's own task identifier inside a
// branch name. A branch name is not a task id — doc 02 §5 admits no slash, so
// `dev/rm126-describe-workspace` is refused as it stands — and an RM number is
// preferred over a folded branch wherever the branch carries one.
var describeWorkspaceRMTask = regexp.MustCompile(`rm[0-9]+`)

// describeWorkspaceIn is IP §4's argument list. One argument, because one is
// all a harness can be relied on to know about itself.
type describeWorkspaceIn struct {
	// CWD is the caller's working directory AS THE CALLER SEES IT — a path on
	// the host, which this server translates onto its own mount.
	CWD string `json:"cwd"`
}

// describeWorkspaceOut is IP §4's result shape.
type describeWorkspaceOut struct {
	// Repo is doc 02 §5's `host/org/name`, read from the main worktree's
	// origin and validated. Never derived from a directory name.
	Repo string `json:"repo"`
	// Worktree is this tree expressed RELATIVE to the repository, empty when
	// it is the repository's own. That is precisely sign_commit's `worktree`
	// argument (MCP-029), so the answer can be passed straight on.
	Worktree string `json:"worktree"`
	// Branch is the branch THIS tree's commits land on, verbatim.
	Branch string `json:"branch"`
	// Task is the branch folded into doc 02 §5's identifier grammar, or the
	// RM number the branch carries.
	Task string `json:"task"`
	// IsLinkedWorktree says what an empty Worktree would otherwise leave the
	// caller to infer. It is true exactly when Worktree is not empty; it is
	// present so that no caller has to know that.
	IsLinkedWorktree bool `json:"is_linked_worktree"`
}

// DescribeWorkspaceConfig is what describe_workspace runs on: two directories
// naming the same tree, one as the host sees it and one as this process does.
type DescribeWorkspaceConfig struct {
	// HostProjects is the host directory Projects is a mount of —
	// EnvHostProjects. Empty means the tool refuses every call, which is the
	// state a deployment that has not set it is in.
	HostProjects string
	// Projects is where that directory is mounted in this process's
	// filesystem. Empty means DefaultProjectsMount.
	Projects string
}

// describeWorkspaceState holds the installed configuration, on ADR-0016 §5's
// seam: a tool registers its own binder from its own init and the binder
// receives only the *Server, so package state is where a tool's dependencies
// live.
var describeWorkspaceState struct {
	mu  sync.RWMutex
	cfg *DescribeWorkspaceConfig
}

// ConfigureDescribeWorkspace installs the two roots and returns a function
// restoring whatever was installed before.
//
// A deployment that installs nothing is not broken: describeWorkspaceConfigured
// falls back to the environment, which is where a container is configured. This
// exists so that a process CAN be told directly — and so the refusal paths are
// testable without an environment variable, which is process-wide state and
// therefore not something a test should have to own.
func ConfigureDescribeWorkspace(cfg DescribeWorkspaceConfig) (func(), error) {
	if cfg.Projects == "" {
		cfg.Projects = DefaultProjectsMount
	}
	if !filepath.IsAbs(cfg.Projects) {
		return nil, Errorf(ClassInvariantViolation, "",
			"describe_workspace configuration: the projects mount %q is relative; "+
				"it would resolve against whatever directory this process happens to be in",
			cfg.Projects)
	}
	// Empty is allowed and absent-but-relative is not: the first is a
	// deployment that has not been told, which refuses by name at call time;
	// the second is a deployment that has been told something that cannot be
	// true, and an operator should hear about that at start-up.
	if cfg.HostProjects != "" && !filepath.IsAbs(cfg.HostProjects) {
		return nil, Errorf(ClassInvariantViolation, "",
			"describe_workspace configuration: %s is %q, which is not an absolute path; "+
				"it names a directory on the operator's machine", EnvHostProjects, cfg.HostProjects)
	}

	describeWorkspaceState.mu.Lock()
	defer describeWorkspaceState.mu.Unlock()
	previous := describeWorkspaceState.cfg
	describeWorkspaceState.cfg = &cfg
	return func() {
		describeWorkspaceState.mu.Lock()
		defer describeWorkspaceState.mu.Unlock()
		describeWorkspaceState.cfg = previous
	}, nil
}

// describeWorkspaceConfigured returns the installed configuration, or the one
// the environment describes.
//
// The environment is the fallback and not the other way round because this is
// how a container is configured: compose sets EnvHostProjects beside the mount
// it is a translation of, and a value read at call time means adding it does
// not need the process rebuilt around a new flag.
func describeWorkspaceConfigured() DescribeWorkspaceConfig {
	describeWorkspaceState.mu.RLock()
	cfg := describeWorkspaceState.cfg
	describeWorkspaceState.mu.RUnlock()
	if cfg != nil {
		return *cfg
	}
	return DescribeWorkspaceConfig{
		HostProjects: os.Getenv(EnvHostProjects),
		Projects:     DefaultProjectsMount,
	}
}

func bindDescribeWorkspace(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolDescribeWorkspace),
		Description: "Describe the workspace a harness is standing in: the repository as " +
			"host/org/name, the worktree relative to it, the branch and the task. Takes the " +
			"caller's own working directory as a path on the host. Derives only; writes nothing.",
	}, describeWorkspace)
}

func describeWorkspace(ctx context.Context, _ *sdk.CallToolRequest, in describeWorkspaceIn) (describeWorkspaceOut, error) {
	cfg := describeWorkspaceConfigured()
	return cfg.describe(ctx, in.CWD)
}

// describe is the tool, once the two roots are known.
func (c DescribeWorkspaceConfig) describe(ctx context.Context, cwd string) (describeWorkspaceOut, error) {
	dir, err := c.containerPath(cwd)
	if err != nil {
		return describeWorkspaceOut{}, err
	}

	// `git worktree list` reports the MAIN worktree first from inside any
	// linked one, so this resolves to the same repository wherever the caller
	// is standing. Its failure is the worktree resolver's own message, which
	// already names the path and says what it is not.
	main, err := mainWorktreeOf(ctx, dir)
	if err != nil {
		return describeWorkspaceOut{}, Errorf(ClassInvariantViolation, "",
			"describe_workspace cannot resolve %s: %w", cwd, err)
	}

	// The tree expressed under its repository. A tree that is not under it at
	// all is REFUSED rather than answered with an empty worktree: sign_commit
	// reads an empty one as "the repository itself" (MCP-029), so an empty
	// answer here would silently send the next call to a different tree. The
	// reference shim left it empty in this case, which is the bug this does
	// not port.
	rel, err := relativeWorktree(main, dir)
	if err != nil {
		return describeWorkspaceOut{}, Errorf(ClassInvariantViolation, "",
			"describe_workspace cannot address %s under its repository: %w", cwd, err)
	}

	// The REPOSITORY's identifier, from the repository and not from this tree:
	// origin belongs to the repository, and a linked worktree has none of its
	// own. repoIDFromWorktree validates against event.ValidateRepo before it
	// returns, so a value that reaches a caller is one the ledger will accept.
	repo, err := repoIDFromWorktree(ctx, main)
	if err != nil {
		return describeWorkspaceOut{}, Errorf(ClassInvariantViolation, "",
			"describe_workspace has no repository identifier for %s: %w", cwd, err)
	}

	branch := describeWorkspaceBranch(ctx, dir, main)
	return describeWorkspaceOut{
		Repo:             repo,
		Worktree:         rel,
		Branch:           branch,
		Task:             describeWorkspaceTask(branch),
		IsLinkedWorktree: rel != "",
	}, nil
}

// containerPath translates the caller's host path onto this process's mount.
//
// Lexically, and deliberately: the host root does not exist in here, so there
// is nothing to resolve symlinks against, and a rule that consulted the
// filesystem would answer differently depending on what happened to be mounted.
// filepath.Rel over two cleaned absolute paths is the whole translation, and
// everything it cannot express is a refusal.
func (c DescribeWorkspaceConfig) containerPath(cwd string) (string, error) {
	if cwd == "" {
		return "", Errorf(ClassInvariantViolation, "",
			"describe_workspace needs the caller's own working directory; cwd was empty, "+
				"and this server's own directory is not a defensible default for it")
	}
	if !filepath.IsAbs(cwd) {
		return "", Errorf(ClassInvariantViolation, "",
			"cwd %q is relative; a harness reports an absolute path on its own machine, "+
				"and resolving a relative one here would describe whichever tree this "+
				"process happens to be standing in", cwd)
	}
	if c.HostProjects == "" {
		return "", Errorf(ClassInvariantViolation, "",
			"%s is unset: this deployment has not been told which host directory its %s "+
				"mount corresponds to, so a host path cannot be translated. Set it to the "+
				"same directory the mount is of — the deployment already computes that as "+
				"INNSEGL_PROJECTS. Nothing is guessed here: a guessed translation describes "+
				"the wrong repository and says nothing about being a guess",
			EnvHostProjects, c.Projects)
	}
	if !filepath.IsAbs(c.HostProjects) {
		return "", Errorf(ClassInvariantViolation, "",
			"%s is %q, which is not an absolute path; it names a directory on the host and "+
				"nothing can be resolved against a relative one", EnvHostProjects, c.HostProjects)
	}

	host := filepath.Clean(c.HostProjects)
	rel, err := filepath.Rel(host, filepath.Clean(cwd))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// SAY WHAT TO DO. A refusal an operator cannot act on is a dead end
		// with an explanation attached: either the tree belongs under the
		// mounted directory, or the mount is of the wrong directory, and the
		// message names both so the reader can tell which.
		return "", Errorf(ClassInvariantViolation, "",
			"cwd %q is outside %s, the host directory this deployment mounts at %s. Either "+
				"move the repository under it, or point %s and the mount at the directory "+
				"this tree is actually in",
			cwd, host, c.Projects, EnvHostProjects)
	}
	if rel == "." {
		return c.Projects, nil
	}
	return filepath.Join(c.Projects, rel), nil
}

// describeWorkspaceBranch is the branch the caller's commits land on.
//
// THE BRANCH IS THE ONE THE TREE IS ACTUALLY ON. doc 02 stores it verbatim in
// an append-only record, so it has to be the branch of the worktree the agent
// is standing in, not the trunk the repository happens to have checked out
// somewhere else. Measured by the reference shim before it was fixed: four
// subagents, each in its own worktree on its own feature branch, all recorded
// `branch: main` — the ledger said every agent was working on the trunk while
// not one of them was, and `task_ref`, folded from the branch, was wrong in
// the same four rows.
//
// The one exception is the throwaway branch a harness's own worktree isolation
// creates; see describeWorkspaceThrowawayPrefix.
func describeWorkspaceBranch(ctx context.Context, dir, main string) string {
	branch := describeWorkspaceBranchAt(ctx, dir)
	if branch == "" || strings.HasPrefix(branch, describeWorkspaceThrowawayPrefix) {
		branch = describeWorkspaceBranchAt(ctx, main)
	}
	if branch == "" || branch == "HEAD" {
		return describeWorkspaceDetached
	}
	return branch
}

// describeWorkspaceBranchAt names the branch checked out in one worktree, or
// the empty string.
//
// symbolic-ref BEFORE rev-parse, and the order is load-bearing: on an UNBORN
// branch — a repository whose first commit has not been made — rev-parse fails
// and the branch would be recorded as detached, which is not a shrug in a log
// line but a wrong value in an append-only record. symbolic-ref reads the name
// HEAD points at whether or not anything is committed there yet.
func describeWorkspaceBranchAt(ctx context.Context, dir string) string {
	if branch := describeWorkspaceLine(
		exec.CommandContext(ctx, "git", "-C", dir, "symbolic-ref", "--short", "--quiet", "HEAD"),
	); branch != "" {
		return branch
	}
	return describeWorkspaceLine(
		exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--abbrev-ref", "HEAD"),
	)
}

// describeWorkspaceLine runs one read-only git query and returns its output as
// a single trimmed line, or the empty string.
//
// A failure is not distinguished from an empty answer because the caller
// treats them the same: both mean "this tree names no branch", and the two
// fallbacks above are what decide what to do about that. The arguments are
// literal at every call site rather than assembled here, so nothing a caller
// supplies can reach git as a flag.
func describeWorkspaceLine(cmd *exec.Cmd) string {
	raw, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// describeWorkspaceTask folds a branch name into doc 02 §5's identifier
// grammar, [a-z0-9][a-z0-9-]{0,62}.
//
// A branch name is not a task id: `dev/rm126-describe-workspace` is refused
// for the slash. An RM number is this project's own task identifier and is
// preferred wherever the branch carries one — the LAST one, which is what the
// reference shim's greedy match does and is asserted against it by MCP-043.
// Otherwise the branch is folded, and a branch that folds to nothing is named
// rather than left blank.
func describeWorkspaceTask(branch string) string {
	lower := describeWorkspaceASCIILower(branch)
	if found := describeWorkspaceRMTask.FindAllString(lower, -1); len(found) > 0 {
		return found[len(found)-1]
	}
	if folded := describeWorkspaceFold(lower); folded != "" {
		return folded
	}
	return describeWorkspaceUnnamed
}

// describeWorkspaceASCIILower is `tr 'A-Z' 'a-z'`, byte for byte.
//
// Not strings.ToLower: that is Unicode-aware, so it can change a string's
// LENGTH, and this is a port whose agreement with the shell is asserted. Every
// byte outside the grammar is replaced below in any case, so nothing is lost
// by lowering only the twenty-six.
func describeWorkspaceASCIILower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// describeWorkspaceFold is the shell's four substitutions and its cut, in the
// order the shell applies them: every byte outside [a-z0-9-] becomes a hyphen,
// leading non-alphanumerics go, runs of hyphens collapse, trailing hyphens go,
// and what is left is bounded at 63 bytes. The order matters — the leading
// strip runs before the collapse — and the bound is applied last, exactly as
// `cut` is the last stage of the shell's pipeline.
func describeWorkspaceFold(lower string) string {
	var b strings.Builder
	b.Grow(len(lower))
	for i := range len(lower) {
		c := lower[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	folded := strings.TrimLeft(b.String(), "-")
	for strings.Contains(folded, "--") {
		folded = strings.ReplaceAll(folded, "--", "-")
	}
	folded = strings.TrimRight(folded, "-")
	if len(folded) > describeWorkspaceTaskBytes {
		folded = folded[:describeWorkspaceTaskBytes]
	}
	return folded
}

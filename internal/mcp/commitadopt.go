// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/signing"
)

// ADOPTION ON THE COMMIT PATH — ADR-0079.
//
// prepare-commit-msg asks the core for a commit's trailers. When the change
// it is about to commit is exactly what one dead run left, the core adds
// Agent-Adopted-Run for that run (searchAdoption). Signing then proves the
// run the payload names against the payload's own tree, with ADR-0051's
// refusals (proveCommitAdoption), and records run_adopted before the intent.
// Nobody names the dead run: only the proof can.

// AdoptionSearchWindow is how recently a dead run must have been active to be
// searched, and AdoptionSearchCap how many of the most recent are (ADR-0079
// decision 3). Work older than the window is still committable, as the
// committing run's own.
const (
	AdoptionSearchWindow = 7 * 24 * time.Hour
	AdoptionSearchCap    = 32
)

// CommitPathAdoption is what adoption needs on the commit path beyond what
// sign_commit's adopt_run needs: the candidates, and a change read from a
// commit's own tree and parent rather than from an index.
type CommitPathAdoption interface {
	SignCommitAdoption
	// DeadRuns returns the runs registered for repo that the ledger does
	// not call active and that were last active at or after since, most
	// recent first, at most limit of them.
	DeadRuns(ctx context.Context, repo string, since time.Time, limit int) ([]string, error)
	// ChangedFiles returns every path the change from parent ("" for a root
	// commit) to tree adds or modifies, with its bytes in tree. A deletion
	// is an error: a run's bodies prove bytes it left, never a path it
	// removed.
	ChangedFiles(ctx context.Context, dir, tree, parent string) (map[string][]byte, error)
	// ParentFile returns path's bytes in parent, and false when parent ("" for
	// none) holds no such path.
	ParentFile(ctx context.Context, dir, parent, path string) ([]byte, bool, error)
}

// commitAdoption answers the commit path's adoption evidence, or nil when
// this deployment has none.
func (c *signCommitService) commitAdoption() CommitPathAdoption {
	a, ok := c.adoption.(CommitPathAdoption)
	if !ok {
		return nil
	}
	return a
}

// proveAdoption is ADR-0051 decision 2 over a change: the dead run's state,
// its repository when repo is not "", every path proved from its bodies, the
// bytes equal, and nothing already spent. A refusal has recorded nothing.
func (c *signCommitService) proveAdoption(
	ctx context.Context, runID, adopted, repo string, changed map[string][]byte, base func(string) ([]byte, bool),
) (*adoptionPlan, error) {
	state, events, err := c.adoption.AdoptionEvidence(ctx, adopted)
	if err != nil {
		return nil, Errorf(ClassLedgerUnavailable, runID,
			"the ledger could not say how run %q ended or what it wrote: %v", adopted, err)
	}
	switch state {
	case "":
		return nil, Errorf(ClassRunNotFound, runID, "no run %q to adopt", adopted)
	case "retired", "lapsed", "abandoned":
	default:
		return nil, Errorf(ClassInvariantViolation, runID,
			"run %q is %s in the ledger; a run that may still be working is not dead, and its "+
				"work is not this run's to adopt (ADR-0051)", adopted, state)
	}
	if registered := registeredRepo(events); repo != "" && registered != "" && registered != repo {
		return nil, Errorf(ClassInvariantViolation, runID,
			"run %q was registered for %s, not %s; an identity's work is adopted only in the "+
				"repository it was issued for (I2, ADR-0079)", adopted, registered, repo)
	}
	if len(changed) == 0 {
		return nil, Errorf(ClassInvariantViolation, runID, "nothing is staged, so there is nothing to adopt")
	}
	names := make([]string, 0, len(changed))
	for name := range changed {
		names = append(names, name)
	}
	sort.Strings(names)

	proofs, err := rebuildLeftBytes(events, c.adoption.BodyDir(), adopted, names, base)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "run %q's work cannot be adopted: %v", adopted, err)
	}
	claim := adoptionClaim{AdoptedRunID: adopted}
	for _, name := range names {
		p := proofs[name]
		if got := strings.TrimPrefix(event.Digest(changed[name]), event.HashPrefix); got != p.SHA256 {
			return nil, Errorf(ClassInvariantViolation, runID,
				"%s is staged with bytes run %q did not leave: its last Write or Edit (%s) left "+
					"sha256 %s, and the index holds %s. Commit that change as this run's own work",
				name, adopted, p.ToolCall, p.SHA256, got)
		}
		claim.Paths = append(claim.Paths, adoptionClaimPath{Path: name, SHA256: p.SHA256, ToolCall: p.ToolCall})
	}
	if serr := c.refuseSpent(ctx, runID, adopted, claim); serr != nil {
		return nil, serr
	}
	body, err := adoptionMarshal(claim)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "the adoption claim cannot be encoded: %v", err)
	}
	return &adoptionPlan{adoptedRun: adopted, state: state, claim: body, digest: event.Digest(body)}, nil
}

// registeredRepo is the repository a run's own registration names, or "".
func registeredRepo(events []event.Fields) string {
	for _, ev := range events {
		if ev[event.FieldEventType] == event.EventTypeRunRegistered {
			return fieldString(ev, event.FieldRepo)
		}
	}
	return ""
}

// commitChange reads the change from parent to tree, and the parent's blobs
// an Edit is replayed on.
func commitChange(
	ctx context.Context, a CommitPathAdoption, dir, tree, parent string,
) (map[string][]byte, func(string) ([]byte, bool), error) {
	changed, err := a.ChangedFiles(ctx, dir, tree, parent)
	if err != nil {
		return nil, nil, err
	}
	base := func(path string) ([]byte, bool) {
		b, ok, berr := a.ParentFile(ctx, dir, parent, path)
		return b, ok && berr == nil
	}
	return changed, base, nil
}

// proveCommitAdoption is signing's proof of the run a payload's trailer names
// (ADR-0079 decision 5), against the payload's own tree and first parent.
func (c *signCommitService) proveCommitAdoption(
	ctx context.Context, runID, repo, adopted, dir, tree, parent string,
) (*adoptionPlan, error) {
	a := c.commitAdoption()
	if a == nil {
		return nil, Errorf(ClassInvariantViolation, runID,
			"adoption is not configured on this deployment: it has no body volume to prove "+
				"run %q's work against (ADR-0079)", adopted)
	}
	changed, base, err := commitChange(ctx, a, dir, tree, parent)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "the change %s cannot be read: %v", tree, err)
	}
	return c.proveAdoption(ctx, runID, adopted, repo, changed, base)
}

// searchAdoption is the trailers step's question (ADR-0079 decision 3): is
// the change from parent to tree exactly what one dead run of repo left? It
// answers that run, or "" for the committing run's own work. Only a ledger
// that cannot be read is an error.
func (c *signCommitService) searchAdoption(
	ctx context.Context, runID, repo, dir, tree, parent string, now time.Time,
) (string, error) {
	a := c.commitAdoption()
	if a == nil {
		return "", nil
	}
	changed, base, err := commitChange(ctx, a, dir, tree, parent)
	if err != nil || len(changed) == 0 {
		return "", nil
	}
	_, own, err := a.AdoptionEvidence(ctx, runID)
	if err != nil {
		return "", Errorf(ClassLedgerUnavailable, runID, "the ledger could not say what run %q wrote: %v", runID, err)
	}
	if touchesAny(own, a.BodyDir(), runID, changed) {
		return "", nil
	}
	candidates, err := a.DeadRuns(ctx, repo, now.Add(-AdoptionSearchWindow), AdoptionSearchCap)
	if err != nil {
		return "", Errorf(ClassLedgerUnavailable, runID,
			"the ledger could not say which runs of %s have ended: %v", repo, err)
	}
	var matches []string
	for _, dead := range candidates {
		if dead == runID {
			continue
		}
		if _, perr := c.proveAdoption(ctx, runID, dead, repo, changed, base); perr != nil {
			if Classify(perr).Class == ClassLedgerUnavailable {
				return "", perr
			}
			continue
		}
		matches = append(matches, dead)
	}
	if len(matches) != 1 {
		return "", nil
	}
	return matches[0], nil
}

// touchesAny reports whether runID recorded a Write or Edit to any of paths.
// A body that cannot be read counts as touching: which path it wrote cannot
// be known, and a proposal is only ever withheld by this, never made.
func touchesAny(events []event.Fields, bodyDir, runID string, paths map[string][]byte) bool {
	for _, ev := range events {
		tool := fieldString(ev, event.FieldToolName)
		if ev[event.FieldEventType] != event.EventTypeToolCall || (tool != "Write" && tool != "Edit") {
			continue
		}
		digest := fieldString(ev, event.FieldPayloadDigest)
		raw, err := os.ReadFile(filepath.Join(bodyDir, filepath.Base(runID),
			strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt))
		if err != nil {
			return true
		}
		op, err := adoptOpOf(tool, fieldString(ev, event.EventHashField), raw)
		if err != nil {
			return true
		}
		if op == nil {
			continue
		}
		for path := range paths {
			if strings.HasSuffix(op.file, "/"+path) {
				return true
			}
		}
	}
	return false
}

// AdoptionForCommit is the trailers step's adoption (ADR-0079 decisions 2 and
// 3): the dead run whose work the commit call is about to commit, or "".
// cmd/innsegl/committrailers.go calls it with the tree and parents the hook
// sent. It looks only for a plain `git commit` with a tree and at most one
// parent; anything it cannot read is no proposal, and signing would refuse
// what it could not prove anyway.
func AdoptionForCommit(ctx context.Context, call commitpath.RelayedCall, tree string, parents []string) (string, error) {
	cfg := installed(&active.signPayload)
	svc := installed(&active.commitSigner)
	if cfg == nil || svc == nil || svc.commitAdoption() == nil || tree == "" || len(parents) > 1 {
		return "", nil
	}
	var input struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(call.Input, &input) != nil || !commitpath.IsAdoptableCommit(input.Command) {
		return "", nil
	}
	run, _, err := resolveRun(ctx, svc.runs, call.RunID, runGate{})
	if err != nil || run.Repo == "" {
		return "", nil
	}
	parent := ""
	if len(parents) == 1 {
		parent = parents[0]
	}
	dir, err := commitPathDir(ctx, cfg, svc, call, run.Repo, tree, parents)
	if err != nil {
		return "", nil
	}
	return svc.searchAdoption(ctx, call.RunID, run.Repo, dir, tree, parent, cfg.now())
}

// commitPathDir is where the commit path reads a commit's objects: the core's
// mirror for a hosted client, the agent's own checkout when the call stated
// one, else the workspace sign_commit uses.
func commitPathDir(
	ctx context.Context, cfg *signPayloadState, svc *signCommitService, relayed commitpath.RelayedCall,
	repo, tree string, parents []string,
) (string, error) {
	switch {
	case relayed.Installation != "":
		return commitPathMirror(ctx, cfg.mirror, repo, tree, parents)
	case relayed.WorkingDirectory != "":
		return commitPathWorktree(ctx, relayed.WorkingDirectory, repo)
	case svc.workspace == nil:
		return "", errors.New("the call states no working directory and this core has no workspace (-workspace)")
	default:
		return svc.workspace.Worktree(ctx, repo)
	}
}

// adoptedRunOf is the run a commit message's last line adopts, or "": the
// trailer ADR-0028's render puts last when a claim adopts a run.
func adoptedRunOf(message string) string {
	lines := strings.Split(strings.TrimSuffix(message, "\n"), "\n")
	last := lines[len(lines)-1]
	prefix := signing.TrailerAgentAdoptedRun + ": "
	if !strings.HasPrefix(last, prefix) {
		return ""
	}
	return strings.TrimPrefix(last, prefix)
}

// ---- the shipped evidence -------------------------------------------------

// DeadRunLister is the ledger read behind the search. *ledger.Store
// satisfies it.
type DeadRunLister interface {
	DeadRunsForRepo(ctx context.Context, repo string, since time.Time, limit int) ([]string, error)
}

// DeadRuns is the ledger's DeadRunsForRepo; a LedgerAdoption with no
// Candidates searches nothing.
func (a LedgerAdoption) DeadRuns(ctx context.Context, repo string, since time.Time, limit int) ([]string, error) {
	if a.Candidates == nil {
		return nil, nil
	}
	return a.Candidates.DeadRunsForRepo(ctx, repo, since, limit)
}

// ChangedFiles reads the change from parent to tree out of dir's objects.
func (a LedgerAdoption) ChangedFiles(ctx context.Context, dir, tree, parent string) (map[string][]byte, error) {
	against := parent
	if against == "" {
		against = emptyTreeHash
	}
	g := GitRepos{GitPath: a.GitPath}
	removed, err := g.git(ctx, dir, "diff-tree", "-r", "--no-renames", "--name-only", "--diff-filter=D", against, tree)
	if err != nil {
		return nil, err
	}
	if removed != "" {
		return nil, fmt.Errorf("the change removes %s; adoption proves bytes a run left, never a "+
			"path it took away", strings.ReplaceAll(removed, "\n", ", "))
	}
	listed, err := g.git(ctx, dir, "diff-tree", "-r", "--no-renames", "--name-only", "-z", against, tree)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, name := range strings.Split(listed, "\x00") {
		if name == "" {
			continue
		}
		b, cerr := a.blob(ctx, dir, tree, name)
		if cerr != nil {
			return nil, fmt.Errorf("the bytes of %s cannot be read: %w", name, cerr)
		}
		out[name] = b
	}
	return out, nil
}

// ParentFile reads path's blob in parent, if parent holds one.
func (a LedgerAdoption) ParentFile(ctx context.Context, dir, parent, path string) ([]byte, bool, error) {
	if parent == "" {
		return nil, false, nil
	}
	if _, err := (GitRepos{GitPath: a.GitPath}).git(ctx, dir, "cat-file", "-e", parent+":"+path); err != nil {
		return nil, false, nil
	}
	b, err := a.blob(ctx, dir, parent, path)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// blob is path's bytes in treeish, byte for byte.
func (a LedgerAdoption) blob(ctx context.Context, dir, treeish, path string) ([]byte, error) {
	// treeish is an object id the payload or the hook named and path one git
	// itself listed; `<treeish>:<path>` is a revision, never a flag.
	//nolint:gosec // G204: gitPath is configuration and the arguments are object names
	cmd := exec.CommandContext(ctx, gitOr(a.GitPath), "-C", dir, "cat-file", "blob", treeish+":"+path)
	cmd.Env = signCommitGitEnv(dir)
	return cmd.Output()
}

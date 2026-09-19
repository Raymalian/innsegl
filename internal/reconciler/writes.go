// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: git's object id is SHA-1; this computes git's id, not a security digest
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// Corroborating a reported write against the repository — RM-104 (#169).
//
// # What was unfalsifiable
//
// `record_event` validates `payload_digest` for SHAPE and compares it to
// nothing: any 64 hex digits are accepted. The ledger therefore recorded what a
// caller SAID it did. `staged_ref` is the opposite and the contrast is the
// point — `sign_commit` requires it to equal the repository's own index, so git
// is the authority and the caller cannot lie about it.
//
// # Why the digest is not the handle, though the issue proposed it
//
// #169 asks whether a claimed write's `payload_digest` appears as a blob in a
// tree the run signed. It cannot: the hook computes that digest over the whole
// event JSON — session id, cwd, tool name, inputs, responses — and a git blob id
// is taken over `blob <len>\x00<content>`. The two can never be equal, so the
// check would report nothing for an honest write and nothing for a forged one,
// which is worse than no check because it looks like one.
//
// What IS checkable is the retained BODY. A `Write` body carries the whole new
// file; an `Edit` body carries the file as it was plus the substitution made to
// it. Either reconstructs the content the agent claims to have produced, and
// that content has a git object id that either appears in a tree the run signed
// or does not.
//
// # What this buys, and what it does not
//
//   - A reported write can be CORROBORATED, which is strictly more than today
//     and strictly less than proof. Its ABSENCE is not evidence of anything —
//     see "WHY THIS PASS APPENDS NOTHING" for the measurement that settled it.
//   - OMISSION stays invisible. A write never reported leaves a blob nobody
//     claimed, which is indistinguishable from a build artifact.
//   - `Read` and `Bash` produce no blob and stay uncheckable. A model that
//     writes a file through `Bash` is outside this, exactly as it is outside
//     every hook.
//   - The bodies are local and expire by age (90 days by default), so this can
//     never be re-run over history the way a chain walk can. The ledger keeps
//     the digest forever and the content not at all.
//
// # What the DENOMINATOR is, and why it had to be narrowed
//
// Corroboration is reported as a rate (see "WHY THIS PASS APPENDS NOTHING"),
// so what is counted decides what the rate means. A claim naming a path in no
// repository this pass can read was never going to be corroborated by one, and
// counting it "not found" says the repository contradicted the claim when the
// repository was never asked. Those are UNCHECKABLE — the bucket that already
// meant "this check is silent about it".
//
// Deciding it needs the host-to-mount translation `describe_workspace`
// performs, for that tool's reason: a body records the path the HARNESS saw,
// and nothing in this process says what its own mount corresponds to. See
// WritesConfig.HostProjects.
//
// # How much it is worth, measured rather than projected
//
// Measured against this deployment's retained bodies on 2026-09-19: 37,880
// bodies, of which 7,183 carry a `file_path` and 4,291 are the `Write` and
// `Edit` calls this pass can reconstruct a claim from. Of those 4,291, 339
// (7.9%) name a path outside every repository the workspace links, and move
// from "not found" to "uncheckable".
//
// THE EARLIER PROJECTION WAS OF A DIFFERENT POPULATION and is worth writing
// down because it is the easy mistake here. #169 measured 75.8% of
// "file-path writes" landing in a scratch directory, and that number is over
// every body carrying a `file_path` — 2,895 of the 7,183 are `Read`, which
// ClaimFromBody discards before any of this runs (REC-014). Over the claims
// the pass actually judges the share is 7.9%, not four in five. The rule is
// still right; its effect on the rate is single digits.
//
// A deployment that has not been told translates nothing, admits every path,
// and is reported unscoped. And a gitignored path INSIDE a repository is still
// counted "not found": this rule asks where the write was, not whether git was
// ever going to track it.

// WriteClaim is one reported file write, reduced to what can be checked.
type WriteClaim struct {
	// EventID is the `tool_call` that claimed it.
	EventID string
	// RunID is the run that claimed it.
	RunID string
	// SPIFFEID is that run's identity. doc 02 §2 omits run_id and spiffe_id
	// TOGETHER, so a finding that names one must carry the other.
	SPIFFEID string
	// Path is the file the body names, as the body names it.
	Path string
	// BlobID is the git object id of the content the claim implies.
	BlobID string
}

// hookBody is the part of a retained tool-call body this check reads.
//
// Deliberately a narrow struct rather than a map: everything else in these
// bodies is the operator's own file contents and commands, and a reader that
// decoded the whole thing would be one refactor away from putting it somewhere.
type hookBody struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		FilePath   string `json:"file_path"`
		Content    string `json:"content"`
		OldString  string `json:"old_string"`
		NewString  string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
	} `json:"tool_input"`
	ToolResponse struct {
		OriginalFile string `json:"originalFile"`
	} `json:"tool_response"`
}

// ClaimFromBody reads one retained body and returns the write it claims.
//
// ok is false for every body that claims no file content — `Read`, `Bash`, an
// MCP call, a `Write` with no path. Those are not findings and must never be
// reported as ones: this check can only speak about writes whose content it can
// reconstruct.
func ClaimFromBody(raw []byte, eventID, runID string) (WriteClaim, bool) {
	var body hookBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return WriteClaim{}, false
	}
	if body.ToolInput.FilePath == "" {
		return WriteClaim{}, false
	}
	content, ok := contentAfter(body)
	if !ok {
		return WriteClaim{}, false
	}
	return WriteClaim{
		EventID: eventID,
		RunID:   runID,
		Path:    body.ToolInput.FilePath,
		BlobID:  BlobID(content),
	}, true
}

// contentAfter reconstructs the file as the claim leaves it.
//
// `Write` states it outright. `Edit` states the file as it was and the one
// substitution made to it, so the result is derived rather than taken on trust —
// which is the point: a body that claims an edit its own before-and-after do not
// produce is already contradicting itself.
//
// An `Edit` whose `old_string` does not occur in the original is exactly that
// case and yields no claim: there is nothing to check it against, and reporting
// it as a missing blob would name the wrong fault.
func contentAfter(body hookBody) (string, bool) {
	switch body.ToolName {
	case "Write":
		if body.ToolInput.Content == "" {
			return "", false
		}
		return body.ToolInput.Content, true
	case "Edit":
		original := body.ToolResponse.OriginalFile
		if original == "" || body.ToolInput.OldString == "" {
			return "", false
		}
		if !strings.Contains(original, body.ToolInput.OldString) {
			return "", false
		}
		n := 1
		if body.ToolInput.ReplaceAll {
			n = -1
		}
		return strings.Replace(original, body.ToolInput.OldString, body.ToolInput.NewString, n), true
	default:
		return "", false
	}
}

// BlobID is git's object id for content stored as a blob.
//
// `blob <len>\x00<content>`, SHA-1 — git's own construction, not a security
// digest, which is why the weak-hash lint is silenced at the import. This must
// equal what `git hash-object` prints or the whole check compares two different
// things and reports every honest write as missing.
func BlobID(content string) string {
	h := sha1.New() //nolint:gosec // G401: git's object id is SHA-1 by definition
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// TreeBlobs is every blob object id reachable from one tree.
//
// One `ls-tree -r` per tree rather than one `cat-file` per claim: a run with a
// thousand Edits against a handful of trees would otherwise be a thousand git
// invocations, and the answer is the same set either way.
//
// A tree git cannot read is not an empty tree. It returns an error, because
// "this repository does not have that object" and "that content was never
// written" are different findings and only one of them is about the agent.
func TreeBlobs(ctx context.Context, gitPath, repo, tree string) (map[string]struct{}, error) {
	git := gitPath
	if git == "" {
		git = "git"
	}
	out, err := exec.CommandContext(ctx, git, "-C", repo,
		"ls-tree", "-r", "--format=%(objectname) %(objecttype)", "--end-of-options", tree).Output()
	if err != nil {
		return nil, fmt.Errorf("listing tree %s in %s: %w", tree, repo, err)
	}
	blobs := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		id, kind, ok := strings.Cut(line, " ")
		if !ok || kind != "blob" {
			continue
		}
		blobs[id] = struct{}{}
	}
	return blobs, nil
}

// WriteVerdict is what the check concluded about one claim.
type WriteVerdict int

const (
	// WriteSupported: the content the claim implies is in a tree the run
	// signed. The claim is corroborated by git, which the caller does not
	// control.
	WriteSupported WriteVerdict = iota
	// WriteUnsupported: the content is in none of them. This is the finding.
	WriteUnsupported
	// WriteUncheckable: the run signed no tree this check could read, so
	// there was nothing to check against. Never a finding — an absence of
	// evidence reported as evidence is the failure mode this whole project
	// exists to avoid (doc 06 P2).
	WriteUncheckable
)

// JudgeWrite decides one claim against the blobs of every tree the run signed.
func JudgeWrite(claim WriteClaim, signed []map[string]struct{}) WriteVerdict {
	if len(signed) == 0 {
		return WriteUncheckable
	}
	for _, blobs := range signed {
		if _, found := blobs[claim.BlobID]; found {
			return WriteSupported
		}
	}
	return WriteUnsupported
}

// ---------------------------------------------------------------------------
// The pass — RM-104 (#169)
// ---------------------------------------------------------------------------

// WritesConfig turns the check on. Nil leaves it OFF.
type WritesConfig struct {
	// LogDir is where the harness writes tool-call bodies, one directory per
	// run. Required: the digest in the chain is over the event envelope and
	// says nothing about content, so the body is the only thing to check.
	//
	// READ-ONLY, and it holds the operator's own file contents. This pass opens
	// what a run's own events name and nothing else.
	LogDir string
	// Repos are the repository identifiers whose trees may be read. Required
	// for RebaseConfig.Repos' reason: a pass that discovered its own
	// repositories would read trees nobody asked it to.
	Repos []string

	// HostProjects, Projects and Workspace are what it takes to decide
	// whether a CLAIMED PATH is inside a repository this pass can read. All
	// three, or none: with any one missing the pass admits every path and
	// says so in WritesReport.Scoped.
	//
	// WHY A PATH RULE AT ALL. A body records the path as the HARNESS saw it,
	// and some of those paths are in no repository and never could be — an
	// agent's own scratch directory, a temporary file, a tree this deployment
	// does not serve. Counted "not found", they move the corroboration RATE
	// with how much scratch work an agent did rather than with anything about
	// integrity, and a rate like that is the kind of number #167 was filed
	// about. Measured here: 339 of 4,291 claims, 7.9%. See the file header
	// for the whole population and for the larger figure #169 projected from
	// a different one.
	//
	// HostProjects is the host directory the Projects mount corresponds to —
	// the same INNSEGL_HOST_PROJECTS `describe_workspace` is told, and told
	// for the same reason: the container knows where its mount IS and nothing
	// in it says what that mount CORRESPONDS TO. Nothing is guessed. The
	// plausible rules — strip to the first existing directory, match on a
	// repository's name — all answer confidently and some of the time answer
	// wrongly, and this one decides whether a claim is judged at all.
	HostProjects string
	// Projects is where HostProjects is mounted in THIS process.
	Projects string
	// Workspace is the root `host/org/name` resolves under, the same root
	// GitWorkspace is built on. A served repository is a symlink from there
	// into Projects, so it is resolved through symlinks before anything is
	// compared against it.
	Workspace string
}

// WritesReport is what one pass did.
type WritesReport struct {
	// Enabled is false when no WritesConfig was given, so a reader never
	// mistakes "not run" for "nothing to find".
	Enabled bool
	// Checked is how many claims this pass could reconstruct and judge.
	Checked int
	// Supported is how many were corroborated by a tree the run signed.
	Supported int
	// Unsupported is how many were not. This is the finding.
	Unsupported int
	// Uncheckable is how many there was nothing to check against: a run that
	// signed no readable tree, or — where Scoped is true — a claim naming a
	// path in no repository this pass can read, which no repository was ever
	// going to corroborate.
	//
	// Never a finding, and counted so that a deployment can see how much of
	// its activity this check is silent about.
	Uncheckable int
	// Unreadable is how many bodies could not be opened or parsed — expired
	// past the retention window, or never written. Also never a finding: the
	// body's absence is a fact about this machine, not about the agent.
	Unreadable int
	// Scoped is whether this pass could tell a claimed path inside a served
	// repository from one outside every repository it can read.
	//
	// False is a WEAKER report and has to say so rather than be inferred from
	// a number that looks the same either way: unscoped, a write to an
	// agent's scratch directory is counted `Unsupported`, and the
	// corroboration rate then moves with how much scratch work was done.
	// See WritesConfig.HostProjects.
	Scoped bool
}

// WHY THIS PASS APPENDS NOTHING.
//
// It was built to append a `ledger_drift_detected` for a claim the repository
// does not corroborate. That was wrong, and it was measured wrong on a real
// deployment: 617 findings from 1121 claims.
//
// Narrowing to the LAST write per path — the state that should end up committed
// — brings it to 85 of 267. Still a third of honest work, and those 85 are
// honest for reasons no rule removes: a run's last write to a path is not the
// final state, because another run edits it before anyone commits; a squash or
// rebase REWRITES the content, so the blob that was written never appears in
// the repository at all; and work gets abandoned.
//
// An alert that is wrong a third of the time is not an alert. It is noise that
// teaches an operator to ignore red, which this project deleted once already on
// the same day this was written. So corroboration is a NUMBER, never an
// accusation:
//
//   - A write the repository corroborates is evidence. It is counted.
//   - A write it does not is not evidence of anything. It is counted too.
//   - A corroboration RATE that falls is a signal a human can act on. A single
//     uncorroborated write is not.
//
// #169 is therefore half-answered, and it is the honest half: a reported write
// can be CORROBORATED, and its absence cannot be read as a lie.

// readRunBody opens one retained tool-call body.
//
// The same layout internal/api/runlog.go reads: one directory per run, one file
// per digest. The digest is validated before it is used as a path element and
// the run id is taken by base — both arrive from the ledger, and the guard
// belongs on the line that opens the file.
//
// A body that does not match its digest is treated as unreadable rather than as
// a claim: it would reconstruct content no tree holds, and counting that as
// uncorroborated would report the wrong thing about the agent.
func readRunBody(dir, runID, digest string) ([]byte, bool) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return nil, false
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(dir, filepath.Base(runID), hexPart+".json"))
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, false
	}
	return raw, true
}

// writesView is this pass's fold of the same chain walk: which run signed which
// trees, and which tool calls claimed to write something.
//
// One walk, three readers — drift.go and rebase.go fold the same records for
// their own questions. A second pass over the chain would be a second thing
// that can disagree about what the chain says.
type writesView struct {
	// trees is the set of tree hashes each run signed, in no order: the
	// question is membership, never sequence.
	trees map[string]map[string]struct{}
	// repoOf is the repository a run signed in. A run that signed in two is
	// unusual and the first wins, because the trees are looked up by tree
	// hash and a tree is in whichever repository holds it.
	repoOf map[string]string
	// claims are the tool calls that might have written something. Whether
	// they did is decided from the body, which the chain does not hold.
	claims []claimRef
}

// claimRef is a tool call as the chain holds it: enough to find its body.
type claimRef struct {
	eventID  string
	runID    string
	spiffeID string
	digest   string
}

func newWritesView() *writesView {
	return &writesView{
		trees:  map[string]map[string]struct{}{},
		repoOf: map[string]string{},
		claims: nil,
	}
}

// observe folds one event in. Called for EVERY event, like drift's.
func (v *writesView) observe(record event.Fields) {
	runID := recordString(record, event.FieldRunID)
	switch recordString(record, event.FieldEventType) {
	case event.EventTypeRunRegistered:
		// The repository a run worked in, from ADR-0045's `repo`. Read HERE and
		// not only from `commit_recorded`, because the runs this check is about
		// are mostly runs that never signed: taking the repository only from a
		// signing event left every subagent's claims with nothing to check.
		if runID != "" {
			if repo := recordString(record, event.FieldRepo); repo != "" {
				v.repoOf[runID] = repo
			}
		}

	case event.EventTypeCommitRecorded:
		// The trees a run signed are the evidence every claim of that run is
		// judged against. A superseding record names the same tree as the
		// original, so a rewrite adds nothing here and costs nothing either.
		tree := recordString(record, event.FieldTreeHash)
		if runID == "" || tree == "" {
			return
		}
		if v.trees[runID] == nil {
			v.trees[runID] = map[string]struct{}{}
		}
		v.trees[runID][tree] = struct{}{}
		if _, known := v.repoOf[runID]; !known {
			v.repoOf[runID] = recordString(record, event.FieldRepo)
		}

	case event.EventTypeToolCall:
		digest := recordString(record, event.FieldPayloadDigest)
		eventID := recordString(record, event.FieldEventID)
		if runID == "" || digest == "" || eventID == "" {
			return
		}
		v.claims = append(v.claims, claimRef{
			eventID:  eventID,
			runID:    runID,
			spiffeID: recordString(record, event.FieldSpiffeID),
			digest:   digest,
		})
	}
}

// checkWrites judges every claim this cycle can reconstruct.
//
// Ordered so the expensive thing happens once: trees are listed per run, not
// per claim, because a run with a thousand Edits against three trees is three
// git invocations and not a thousand.
//
// Nothing here is enforcement. record_event cannot know at write time which
// tree a later sign_commit will carry, and blocking on a digest that has not
// been committed yet would break the normal order of work. This is detection,
// after the fact, which is what #169 asked for.
func (r *Reconciler) checkWrites(
	ctx context.Context, view *writesView, cfg *WritesConfig,
) WritesReport {
	report := WritesReport{Enabled: true}
	served := map[string]struct{}{}
	for _, repo := range cfg.Repos {
		served[repo] = struct{}{}
	}
	scope := newWritesScope(cfg)
	report.Scoped = scope != nil
	// Per-run tree blobs, computed at most once each.
	blobsFor := map[string][]map[string]struct{}{}

	for _, claim := range view.claims {
		raw, ok := readRunBody(cfg.LogDir, claim.runID, claim.digest)
		if !ok {
			report.Unreadable++
			continue
		}
		write, ok := ClaimFromBody(raw, claim.eventID, claim.runID)
		if !ok {
			// Not a file write, or a body whose own before-and-after do not
			// produce its claim. Neither is a finding.
			continue
		}

		report.Checked++

		// WHERE THE CLAIM SAYS IT WROTE, BEFORE WHAT IT SAYS IT WROTE. A path
		// in no repository this pass can read was never going to be
		// corroborated by one, and counting it "not found" says the repository
		// contradicted the claim when the repository was never asked. Ahead of
		// the blob lookup so a scratch write costs no git walk either.
		if !scope.admits(write.Path) {
			report.Uncheckable++
			continue
		}

		repo := view.repoOf[claim.runID]
		holdings, known := blobsFor[repo]
		if !known {
			holdings = r.repoBlobs(ctx, repo, served)
			blobsFor[repo] = holdings
		}

		switch JudgeWrite(write, holdings) {
		case WriteSupported:
			report.Supported++
		case WriteUncheckable:
			report.Uncheckable++
		case WriteUnsupported:
			// Counted, never appended. See "WHY THIS PASS APPENDS NOTHING".
			report.Unsupported++
		}
	}
	return report
}

// writesScope decides whether a claimed path is inside a repository this pass
// can read. Nil admits everything, which is what an unconfigured deployment
// gets and what WritesReport.Scoped reports.
type writesScope struct {
	// hostProjects and projects are the same directory under two roots: the
	// harness's spelling and this process's.
	hostProjects string
	projects     string
	// roots are the served repositories as directories on THIS filesystem,
	// resolved through the symlink that puts each one at <workspace>/<repo>.
	roots []string
}

// newWritesScope resolves the served repositories, or returns nil.
//
// Nil rather than an error, and rather than a guess. Every way this can fail
// is a deployment that has not been told something — the mount's host
// directory, the workspace root, or a repository that is not on this machine —
// and none of them is a fact about an agent. The pass then judges content
// alone, exactly as it did before there was a path rule, and says it is
// unscoped so the weaker report is not read as the stronger one.
func newWritesScope(cfg *WritesConfig) *writesScope {
	if cfg.HostProjects == "" || cfg.Projects == "" || cfg.Workspace == "" {
		return nil
	}
	// Absolute on both sides or nothing: a relative root resolves against
	// whatever directory this process happens to be in, and the answer would
	// decide whether a claim is judged at all.
	if !filepath.IsAbs(cfg.HostProjects) || !filepath.IsAbs(cfg.Projects) {
		return nil
	}
	scope := &writesScope{
		hostProjects: filepath.Clean(cfg.HostProjects),
		projects:     filepath.Clean(cfg.Projects),
	}
	for _, repo := range cfg.Repos {
		// filepath.FromSlash, because `repo` is doc 02 §5's `host/org/name`
		// and slash-separated by definition. ValidateRepo holds each segment
		// to [A-Za-z0-9][A-Za-z0-9._-]*, so none can be `..` and none can
		// carry a separator — the same reason GitWorkspace needs no second
		// escape check.
		resolved, err := filepath.EvalSymlinks(
			filepath.Join(cfg.Workspace, filepath.FromSlash(repo)))
		if err != nil {
			continue
		}
		scope.roots = append(scope.roots, resolved)
	}
	if len(scope.roots) == 0 {
		return nil
	}
	return scope
}

// admits reports whether a claimed path could be in a repository this pass can
// read.
//
// It errs toward ADMITTING, and deliberately: a path this cannot place is left
// to the content check, which is where the judgement was before. Refusing to
// judge on a rule that is merely probably right would hide a real shortfall
// behind an "uncheckable", and that is the direction that costs something.
func (s *writesScope) admits(path string) bool {
	if s == nil {
		return true
	}
	if !filepath.IsAbs(path) {
		// A body records an absolute path; a relative one says nothing about
		// which directory it is relative TO, so there is no honest way to
		// place it and no reason to hold it against the claim.
		return true
	}
	local, ok := s.local(path)
	if !ok {
		return false
	}
	for _, root := range s.roots {
		if under(root, local) {
			return true
		}
	}
	return false
}

// local translates one claimed path into this process's namespace.
//
// The mount's OWN spelling is accepted first and untranslated, for
// localWorktreePath's reason: a second translation would prepend the mount to
// a path that already carries it. Everything else is the host's spelling and
// gets filepath.Rel over two cleaned absolute paths, which is the whole
// translation — lexical, because the host root does not exist in here and a
// rule that consulted the filesystem would answer differently depending on
// what happened to be mounted.
func (s *writesScope) local(path string) (string, bool) {
	cleaned := filepath.Clean(path)
	if rel, err := filepath.Rel(s.projects, cleaned); err == nil && !escapes(rel) {
		return cleaned, true
	}
	rel, err := filepath.Rel(s.hostProjects, cleaned)
	if err != nil || escapes(rel) {
		return "", false
	}
	if rel == "." {
		return s.projects, true
	}
	return filepath.Join(s.projects, rel), true
}

// under reports whether path is root itself or lives beneath it.
//
// filepath.Rel over a string compare, because "/a/repo-two" has "/a/repo" as a
// string prefix and is not inside it. Both sides are resolved through symlinks
// first: a served repository IS a symlink, and the path being tested usually
// is not, so comparing the two spellings straight would find every claim
// outside every repository.
func under(root, path string) bool {
	rel, err := filepath.Rel(resolveExisting(root), resolveExisting(path))
	return err == nil && !escapes(rel)
}

// escapes reports whether a relative path leaves the root it is relative to.
func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveExisting resolves the longest EXISTING prefix of a path through
// symlinks and puts the rest back on the end.
//
// filepath.EvalSymlinks alone is not enough here: it fails outright on a path
// whose last segments do not exist, and the claimed path of a file that was
// written to a scratch directory, or has since been deleted or rewritten, is
// exactly that. Falling back to the cleaned path in that case would compare a
// RESOLVED root against an UNRESOLVED path, which disagrees wherever any
// ancestor is a symlink — every temporary directory on macOS, and the
// workspace's own repository links.
func resolveExisting(p string) string {
	cleaned := filepath.Clean(p)
	rest := ""
	for cur := cleaned; ; {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return resolved
			}
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return cleaned
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// repoBlobs is every blob one repository holds, or nothing.
//
// A repository this pass was not asked to read, or one that cannot be read,
// contributes nothing and is NOT an error: it may simply not be on this
// machine. That produces an "uncheckable" count, which is the honest answer.
//
// Repository-wide rather than per-run, and that widening was measured: scoped
// to the trees a run itself signed, the check saw nothing at all on a real
// deployment — 63 runs made tool calls, 165 signed commits, and 15 did both,
// because subagents do the work and a separate run signs it. Following
// parent_run_id does not help; a subagent's parent is its session, and sessions
// sign nothing.
//
// The cost of widening is stated where it matters: corroboration now means the
// content EXISTS in this repository, not that this run produced it.
func (r *Reconciler) repoBlobs(
	ctx context.Context, repo string, served map[string]struct{},
) []map[string]struct{} {
	if repo == "" {
		return nil
	}
	if _, ok := served[repo]; !ok {
		return nil
	}
	blobs, err := r.cfg.Repos.ReachableBlobs(ctx, repo)
	if err != nil || len(blobs) == 0 {
		return nil
	}
	return []map[string]struct{}{blobs}
}

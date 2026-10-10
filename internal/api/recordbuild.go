// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// recordbuild.go assembles RunRecord (record.go) for GET
// /api/v1/runs/{run_id}/record — one read of the run's own chain
// (recordquery.go's runTimeline), the family tree, the retained bodies
// (recordbody.go) and the gateway's own snapshot store
// (recordfiles.go/snapshotstore.go), never a second opinion about anything
// internal/reconciler or internal/ledger already decided.
//
// # Brief and replies: verified with a CHECK-ONLY key, never the identity
// secret
//
// RecordMessage.Digest is always the ledger's own KEYED digest (ADR-0061
// decision 2, agent_message.payload_digest). The first version of this
// file never set Available true at all: verifying that digest needs the
// SAME per-deployment identity secret internal/mcp.DeriveAgentMessageKey
// derives a caller's own key from, and this process must not hold that
// secret — doc 05 §3 puts it behind no authentication of its own, and the
// identity secret is the ONE secret every run token, every pseudonym and
// every agent-message key in this deployment derives from
// (agentmessagekey.go's own domain-separation argument).
//
// The operator's own decision settles it: this process is instead given
// the DERIVED key alone (cmd/innsegl/gateway.go's own writeMessageKeyFile,
// read here via recordmessagekey.go), which computes a message digest and
// nothing else — it cannot mint a run token, a pseudonym, or an event this
// process could append anyway, since the read-only ledger role already
// forbids that. Verification is then recordmessagekey.go's
// verifyAgentMessage: brute force over the run's own small set of
// retained bodies, exact HMAC-SHA256 match against the chain's own
// digest, never a guess. messageKeyDir == "" (no -message-key-dir
// configured) still answers every message unavailable, the same "unset
// means off" posture this package holds every optional setting to.
//
// RecordStep.SpawnedRunID needs no key at all: it is resolved by
// EXACT-EQUALITY content addressing against the PLAIN digest the body is
// actually stored under (recordbody.go's spawnBodyMatches), the same
// mechanism ADR-0058 decision 3 itself uses. That is unaffected by any of
// the above.

// buildRunRecord is this file's one entry point.
func (rs *recordServer) buildRunRecord(ctx context.Context, runID string) (RunRecord, error) {
	now := time.Now().UTC()
	horizon := rs.store.RestoreHorizon()
	logDir := rs.logDir

	rows, err := rs.store.runTimeline(ctx, runID)
	if err != nil {
		return RunRecord{}, err
	}
	reg, found := registeredFieldsOf(rows)
	if !found {
		return RunRecord{}, fmt.Errorf("%w: no run %q in this ledger", ErrNotFound, runID)
	}

	facts := runFactsFromRows(rows)
	retiredAt, retired := retiredAtOf(rows)
	status, statusAt := statusAndAt(facts, retiredAt, retired, now, horizon)

	run := RecordRun{
		RunID: runID, SPIFFEID: reg.SpiffeID, AgentType: reg.AgentType, TaskRef: reg.TaskRef,
		Repo: reg.Repo, Branch: reg.Branch, Status: status, StatusAt: statusAt,
		RegisteredAt: reg.RegisteredAt, ParentRunID: reg.ParentRunID, ForkedFromRunID: reg.ForkedFromRunID,
	}

	brief, replies := briefAndReplies(rows, rs.messageKeyDir, runBodyCandidates(logDir, runID))

	family, err := rs.store.family(ctx, runID)
	if err != nil {
		return RunRecord{}, err
	}
	// RM-307: relatives out of the reader's scope are not part of this
	// record at all: not in the tree, the lineage, the children or the
	// run's own parent and fork fields.
	if family, err = rs.store.familyInScope(ctx, runID, family); err != nil {
		return RunRecord{}, err
	}
	if err = rs.store.hideRelativesOutOfScope(ctx, &run.ParentRunID, &run.ForkedFromRunID, &reg.ParentRunID); err != nil {
		return RunRecord{}, err
	}
	// Direct children, oldest-first — recordspawn.go's own FIFO rule for
	// matching a spawn step against its candidates. RunRecord.Children
	// itself is reordered newest-first separately (recordagent.go's own
	// buildChildren).
	children := childrenOfInFamily(family, runID)
	sort.Slice(children, func(i, j int) bool { return children[i].RegisteredAt.Before(children[j].RegisteredAt) })

	// #443 (RM-278): RecordAgent.Lineage needs every ancestor from the root
	// down to this run's own parent (ancestorChainOf, capped at 16).
	ancestors := ancestorChainOf(family, reg.ParentRunID)

	// Every parent whose own children this record needs linked and counted:
	// this run itself (Children), plus every ancestor (Lineage's own
	// title/spawned_at_step/agents) — ONE childCounts query for the union,
	// never a query per child (rule 4, rule 8).
	parents := append(append([]string{}, idsOf(ancestors)...), runID)
	childrenOfParent := make(map[string][]familyNode, len(parents))
	unionSeen := map[string]bool{}
	var unionIDs []string
	for _, p := range parents {
		kids := childrenOfInFamily(family, p)
		childrenOfParent[p] = kids
		for _, k := range kids {
			if !unionSeen[k.RunID] {
				unionSeen[k.RunID] = true
				unionIDs = append(unionIDs, k.RunID)
			}
		}
	}
	counts, err := rs.store.childCounts(ctx, unionIDs)
	if err != nil {
		return RunRecord{}, err
	}

	stepRefs := toolCallStepsFromRows(rows)
	agentRefs := make([]toolCallStepRef, 0)
	for _, ref := range stepRefs {
		if ref.Tool == "Agent" {
			agentRefs = append(agentRefs, ref)
		}
	}

	// #443 rule 2: link every parent-of-interest's own non-signing children
	// to the step that spawned them — gateway/brief, then agent id.
	links := make(map[string]map[string]spawnMatch, len(parents))
	for _, p := range parents {
		nonSigning := nonSigningChildrenOf(childrenOfParent[p], counts)
		var refs []toolCallStepRef
		if p == runID {
			refs = agentRefs
		} else {
			refs, err = rs.agentStepRefsFor(ctx, p)
			if err != nil {
				return RunRecord{}, err
			}
		}
		links[p] = rs.resolveChildLinks(logDir, p, refs, nonSigning)
	}

	spawnByEvent := map[string]string{}
	for childID, m := range links[runID] {
		spawnByEvent[m.StepEventID] = childID
	}

	commitRows, err := rs.store.commitsOf(ctx, runID)
	if err != nil {
		return RunRecord{}, err
	}

	// #443 rule 1: a signing identity's own commit is folded into this
	// run's own Commits — read in ONE grouped query, never one per signing
	// identity.
	var signingIDs []string
	for _, c := range children {
		if isSigningIdentity(counts[c.RunID]) {
			signingIDs = append(signingIDs, c.RunID)
		}
	}
	signingCommitRows, err := rs.store.commitsOfMany(ctx, signingIDs)
	if err != nil {
		return RunRecord{}, err
	}

	// Committed is checked against every commit a file's OWN contributor
	// made — this run's, any spawned child's whose write a step attributes
	// by_run_id, and any signing identity's — never against this run's
	// commits alone. A subagent commits its own work under ITS OWN run_id
	// (step4's own SpawnedCommits), and a file this run never touched
	// directly has nothing to be found in this run's own commit trees
	// regardless of whether the subagent committed it.
	committedCommits := append([]commitRow{}, commitRows...)
	for _, m := range links[runID] {
		childCommits, cerr := rs.store.commitsOf(ctx, m.ChildRunID)
		if cerr == nil {
			committedCommits = append(committedCommits, childCommits...)
		}
	}
	committedCommits = append(committedCommits, signingCommitRows...)

	steps, written, bodiesStored, bodiesVerified := rs.buildSteps(ctx, runID, reg, rows, commitRows, committedCommits, spawnByEvent, logDir, now)

	settleRunWitnesses(steps)

	allCommitRows := append(append([]commitRow{}, commitRows...), signingCommitRows...)
	commits := rs.buildCommits(ctx, reg.Repo, runID, allCommitRows, steps)

	var treeBeforeRun, treeAfterRun string
	for _, st := range steps {
		if st.TreeBefore != "" {
			treeBeforeRun = st.TreeBefore
			break
		}
	}
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].TreeAfter != "" {
			treeAfterRun = steps[i].TreeAfter
			break
		}
	}
	files, ferr := rs.buildWholeRunFiles(ctx, reg.Repo, treeBeforeRun, treeAfterRun, steps, committedCommits)
	if ferr != nil {
		files = nil
	}

	tree, err := rs.buildTree(ctx, family, logDir)
	if err != nil {
		return RunRecord{}, err
	}

	head, err := rs.store.chainHead(ctx)
	if err != nil {
		return RunRecord{}, err
	}

	// #443 (RM-278): this run seen as one agent, and the (non-signing)
	// agents it started.
	agent := buildAgentRecord(reg, runID, ancestors, links, childrenOfParent, counts, brief, replies, steps)
	nonSigningOwnChildren := nonSigningChildrenOf(children, counts)
	childrenOut, err := rs.buildChildren(ctx, nonSigningOwnChildren, links[runID], counts, now, horizon)
	if err != nil {
		return RunRecord{}, err
	}

	// Every list is [] when empty, never null: the contract types each one
	// as an array, and a run with nothing recorded (every run from before
	// the gateway) crashed the run page on null (#435).
	if replies == nil {
		replies = []RecordMessage{}
	}
	if steps == nil {
		steps = []RecordStep{}
	}
	if commits == nil {
		commits = []RecordCommit{}
	}
	return RunRecord{
		Run: run, Agent: agent, Children: nonNilChildren(childrenOut), Written: nonNilWritten(written),
		Tree: tree, Brief: brief, Replies: replies, Steps: steps,
		Files: nonNilFiles(files), Commits: commits, Witness: summarizeWitness(steps, bodiesStored, bodiesVerified),
		DataAsOf: now, ChainHead: head,
	}, nil
}

// briefAndReplies folds every agent_message of a run into record.go's
// Brief (role brief) and Replies (role assistant, chain order), verifying
// each one's own keyed digest against the run's own retained bodies
// (recordmessagekey.go's verifyAgentMessage) when this process has been
// given a directory to read the check-only key from. messageKeyDir == ""
// (no -message-key-dir configured) answers every message unavailable,
// exactly as it did before the operator's own decision to widen this: the
// "unset means off" posture this whole package already holds every
// optional setting to.
func briefAndReplies(rows []recordEventRow, messageKeyDir string, candidates [][]byte) (RecordMessage, []RecordMessage) {
	var brief RecordMessage
	var replies []RecordMessage
	for _, r := range rows {
		if r.EventType != event.EventTypeAgentMessage {
			continue
		}
		digest := stringOf(r.Body[event.FieldPayloadDigest])
		msg := RecordMessage{Digest: digest, At: r.TS}
		if messageKeyDir != "" {
			if text, ok := verifyAgentMessage(messageKeyDir, digest, candidates); ok {
				msg.Text = text
				msg.Available = true
			}
		}
		switch stringOf(r.Body[event.FieldRole]) {
		case "brief":
			if brief.Digest == "" {
				brief = msg
			}
		case "assistant":
			replies = append(replies, msg)
		}
	}
	return brief, replies
}

// ---------------------------------------------------------------------------
// Steps.
// ---------------------------------------------------------------------------

// buildSteps never fails the whole record over one step's own git or body
// read: a snapshot store this process cannot resolve, or a single commitsOf
// read for a spawned child, degrades that ONE step's own Files or
// SpawnedCommits to empty rather than turning one step's trouble into a 500
// for the whole run — the same "understate, never guess" posture
// recordfiles.go's own committedSet holds for a commit tree it could not
// read.
func (rs *recordServer) buildSteps(
	ctx context.Context, runID string, reg registeredFields, rows []recordEventRow,
	commits, committedCommits []commitRow, spawnByEvent map[string]string, logDir string, now time.Time,
) (steps []RecordStep, written []RecordWrite, bodiesStored, bodiesVerified int) {
	// #443 (RM-278) rule 6: one Written entry per path, the FIRST step that
	// wrote it — steps are walked in chain order below, so the first append
	// to a given path is already the earliest one.
	writtenSeen := map[string]bool{}
	var telemetryActive bool
	var telemetrySince time.Time
	if logDir != "" {
		if entries, ok := listTelemetryEntries(logDir); ok {
			telemetrySince, telemetryActive = telemetryActiveSinceEntries(entries)
		}
	}

	// committedCommits is this run's own commits PLUS every spawned child's
	// — see buildRunRecord's own comment on why Committed must not be
	// checked against this run's commits alone.
	committed := rs.committedSet(ctx, reg.Repo, committedCommits)

	n := 0
	lastTree := ""
	parentTreeBefore, parentTreeRead := "", false
	for _, r := range rows {
		if r.EventType != "tool_call" {
			continue
		}
		n++
		digest := stringOf(r.Body[event.FieldPayloadDigest])
		toolName := stringOf(r.Body[event.FieldToolName])
		treeAfter := stringOf(r.Body[event.FieldWorkspaceTreeHash])

		treeBefore := lastTree
		if treeBefore == "" && reg.ParentRunID != "" {
			// Looked up once per record (#440): the answer depends only on
			// the parent and this run's registration, and a run with no
			// snapshots of its own asked it again for every step.
			if !parentTreeRead {
				parentTreeRead = true
				if parentTree, perr := rs.store.parentSnapshotBefore(ctx, reg.ParentRunID, reg.RegisteredAt); perr == nil {
					parentTreeBefore = parentTree
				}
			}
			treeBefore = parentTreeBefore
		}
		if treeBefore == "" && n == 1 {
			// #437 (RM-274): a root run's own first step has no earlier
			// tool_call to chain a "before" from, and no parent run to
			// borrow one from either — the ONE remaining source is the
			// gateway's own baseline, taken before this run's first tool
			// ever ran (internal/gateway/snapshot.go's own SnapshotBaseline)
			// and read back from its snapshot store directly, never from a
			// chain member invented to hold it. "" here (a deployment from
			// before this landed, or a baseline this process cannot resolve
			// for any of the ordinary reasons a snapshot read can fail)
			// leaves step 1 exactly as it already was: an unknown before,
			// never guessed at.
			treeBefore = rs.runBaseline(ctx, reg.Repo, runID)
		}
		if treeAfter != "" {
			lastTree = treeAfter
		}

		body, bodyAvailable := stepBody(logDir, runID, digest)
		if bodyFilePresent(logDir, runID, digest) {
			bodiesStored++
		}
		if bodyAvailable {
			bodiesVerified++
		}

		step := RecordStep{
			N: n, EventID: r.EventID, ChainPosition: r.ChainPosition, At: r.TS,
			Tool: toolName, TreeBefore: treeBefore, TreeAfter: treeAfter,
		}
		if bodyAvailable {
			step.ToolUseID = body.ToolUseID
			step.Input = string(body.Input)
			step.Truncated = body.InputTruncated || body.ResultTruncated
			if body.ResultObserved {
				if text, ok := resultText(body.Result); ok {
					step.Output = text
				}
			}
			step.Outcome = outcomeOf(toolName, body)
			step.Summary = summaryOf(toolName, body)

			if toolName == "Bash" && !body.isError() {
				if short, ok := commitShortSHA(step.Output); ok {
					for _, c := range commits {
						if hasPrefixSHA(c.CommitSHA, short) {
							step.CommitSHA = c.CommitSHA
							break
						}
					}
				}
			}

			// #443 (RM-278) rule 6: this step wrote a file.
			if isWriteTool(toolName) {
				if path := writeFilePathOf(body.Input); path != "" {
					cwd := ""
					if body.hookShape {
						cwd = body.hookCwd
					}
					rel := relativeWritePath(path, cwd)
					if !writtenSeen[rel] {
						writtenSeen[rel] = true
						written = append(written, RecordWrite{
							Path: rel, Status: writeStatusOf(toolName, body, step.Output), Step: n,
						})
					}
				}
			}
		} else {
			step.Outcome = RecordOutcome{Kind: "unknown"}
		}

		// #443 (RM-278) rule 5: a step's own Kind.
		switch toolName {
		case "Agent":
			step.Kind = "spawn"
		case "SubagentHandback":
			step.Kind = "report"
		default:
			step.Kind = "tool"
		}

		if toolName == "Agent" {
			if childID, ok := spawnByEvent[r.EventID]; ok {
				step.SpawnedRunID = childID
				childCommits, cerr := rs.store.commitsOf(ctx, childID)
				if cerr == nil {
					for _, c := range childCommits {
						step.SpawnedCommits = append(step.SpawnedCommits, c.CommitSHA)
					}
				}
			}
		}
		step.SpawnedCommits = nonNilStrings(step.SpawnedCommits)

		byRunID := ""
		if step.SpawnedRunID != "" {
			byRunID = step.SpawnedRunID
		}
		changes, ferr := rs.filesInRange(ctx, reg.Repo, treeBefore, treeAfter)
		if ferr == nil {
			afterBlobs := discardBlobsError(rs.blobsAtTree(ctx, reg.Repo, treeAfter))
			for _, c := range changes {
				step.Files = append(step.Files, RecordFile{
					Path: c.Path, Status: c.Status, Additions: c.Additions, Deletions: c.Deletions,
					Steps: []int{n}, ByRunID: byRunID,
					Committed: isCommitted(afterBlobs, committed, c.Path),
				})
			}
		}
		step.Files = nonNilFiles(step.Files)

		step.Witnesses = stepWitnesses(logDir, body, bodyAvailable, treeBefore, treeAfter,
			telemetryActive, telemetrySince, r.TS, now, defaultRecordWitnessWindow)

		steps = append(steps, step)
	}
	return steps, written, bodiesStored, bodiesVerified
}

// bodyFilePresent reports whether a body FILE exists for digest under
// runID's own directory, regardless of whether its bytes still hash to
// digest — RecordWitness.BodiesStored's own evidence, distinct from
// BodiesVerified (stepBody's stricter check, which also requires the
// digest to match).
func bodyFilePresent(dir, runID, digest string) bool {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return false
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, filepath.Base(runID), hexPart+".json"))
	return err == nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilFiles(f []RecordFile) []RecordFile {
	if f == nil {
		return []RecordFile{}
	}
	return f
}

func hasPrefixSHA(full, short string) bool {
	return len(full) >= len(short) && full[:len(short)] == short
}

// ---------------------------------------------------------------------------
// Outcome and summary.
// ---------------------------------------------------------------------------

// outcomeOf derives RecordOutcome. See recordbody.go's exitCodeLine for
// the one textual signal this rule reads, and this file's own package
// comment for why "refused" is never produced: nothing in a retained body
// distinguishes a harness refusal from an ordinary tool error (ADR-0057:
// "a refused action surfaced the same way"), and this handler does not
// guess between them.
//
// ExitCode is populated ONLY for the Bash tool — the one tool whose result
// is a process's own exit status. For Bash: 0 on an observed success; an
// explicit "Exit code: N" read from the result text when one is present;
// otherwise 1, the conventional shell failure code, stated as a default
// rather than as a number this process observed.
//
// A hook-shape body (RM-273) carries none of ResultObserved/IsError at
// all — hookBodyAsGateway sets hookShape instead, and the outcome its own
// shape shows (hookOutcomeOf, computed once while mapping it) is read back
// here rather than re-derived from fields that mapping never set.
func outcomeOf(toolName string, body gatewayBody) RecordOutcome {
	if body.hookShape {
		return body.hookOutcome
	}
	if !body.ResultObserved {
		return RecordOutcome{Kind: "unknown"}
	}
	kind := "ok"
	if body.IsError {
		kind = "error"
	}
	out := RecordOutcome{Kind: kind}
	if toolName == "Bash" {
		code := 0
		if body.IsError {
			code = 1
			if text, ok := resultText(body.Result); ok {
				if n, ok := exitCodeFrom(text); ok {
					code = n
				}
			}
		}
		out.ExitCode = &code
	}
	return out
}

// bashInput is the one member this file reads out of a Bash step's own
// input — the command line, record.go's own summary text for a Bash step.
type bashInput struct {
	Command string `json:"command"`
}

// filePathInput is the one member most other tools' input carries that
// names a path.
type filePathInput struct {
	FilePath string `json:"file_path"`
}

// summaryOf is "the one line the timeline shows" (record.go): the Bash
// command, or the file path, or — for a spawn — the prompt it named.
// Whatever the tool, a summary this function cannot read from the input at
// all answers empty rather than a guess.
func summaryOf(toolName string, body gatewayBody) string {
	switch toolName {
	case "Bash":
		var in bashInput
		if json.Unmarshal(body.Input, &in) == nil {
			return truncateSummary(in.Command)
		}
	case "Agent":
		// #443 (RM-278) rule 5: the spawn's own description when it named
		// one; the prompt otherwise, exactly as before #443.
		if in, ok := agentSpawnInputOf(body.Input); ok && in.Description != "" {
			return truncateSummary(in.Description)
		}
		if prompt, ok := agentPromptOf(body.Input); ok {
			return truncateSummary(prompt)
		}
	default:
		var in filePathInput
		if json.Unmarshal(body.Input, &in) == nil && in.FilePath != "" {
			// Relative to the agent's own folder, as the Written list names
			// it (#443).
			return relativeWritePath(in.FilePath, body.hookCwd)
		}
	}
	return ""
}

// maxSummaryRunes bounds the timeline's one-line summary. record.go's own
// fixture truncates a spawn prompt with "…"; this is that same convention,
// generous enough that an ordinary Bash command is never cut.
const maxSummaryRunes = 80

func truncateSummary(s string) string {
	runes := []rune(s)
	if len(runes) <= maxSummaryRunes {
		return s
	}
	return string(runes[:maxSummaryRunes]) + "…"
}

// ---------------------------------------------------------------------------
// Commits.
// ---------------------------------------------------------------------------

// buildCommits turns rows into RecordCommit. rows is this run's own
// commit_recorded PLUS, since #443 (RM-278) rule 1, any signing identity's
// own — commitRow.RunID tells the two apart: SignedBy is always that run
// id, and Step is resolved differently for each. This run's own commit was
// made by a Bash step THIS run's chain already names (RecordStep.CommitSHA,
// matched by commitShortSHA in buildSteps); a signing identity's own commit
// was never a step of ITS run, let alone this one, so its Step is instead
// the step of THIS run whose own Output names it signed
// (signedStepFor, recordagent.go).
func (rs *recordServer) buildCommits(ctx context.Context, repo, runID string, rows []commitRow, steps []RecordStep) []RecordCommit {
	superseded := map[string]bool{}
	for _, c := range rows {
		if c.Supersedes != "" {
			superseded[c.Supersedes] = true
		}
	}

	// Landing and subjects are read once per repository, not per commit
	// (#443): a session holding its signing identities' commits ran two git
	// commands per commit for landing alone.
	land := rs.newLanding()
	var landedSHAs []string
	for _, c := range rows {
		if land.of(ctx, repo, c, superseded) == "landed" {
			landedSHAs = append(landedSHAs, c.CommitSHA)
		}
	}
	subjects := land.subjects(ctx, repo, landedSHAs)

	out := make([]RecordCommit, 0, len(rows))
	for _, c := range rows {
		rc := RecordCommit{SHA: c.CommitSHA, RekorLogIndex: c.RekorLogIndex, SignedBy: c.RunID}
		if c.RunID == runID {
			for _, st := range steps {
				if st.CommitSHA == c.CommitSHA {
					rc.Step = st.N
					break
				}
			}
		} else {
			rc.Step = signedStepFor(steps, c.CommitSHA)
		}
		if subject, ok := subjects[c.CommitSHA]; ok {
			rc.Subject = subject
		} else if subject, ok := rs.commitSubject(ctx, repo, c.CommitSHA); ok {
			rc.Subject = subject
		}
		rc.Landed = land.of(ctx, repo, c, superseded)
		if rc.Landed == "not_landed" {
			rc.LandedReason = notLandedReason(rs.logDir, c.RunID, rs.runCommitClaims(ctx, c.RunID))
		}
		out = append(out, rc)
	}
	return out
}

// commitSubject reads a commit's own subject line through the same
// checkout the proof BFF already has — Prover.CommitMessage, restricted to
// its first line. A commit this process cannot read (not a served
// repository, or the object simply is not there) answers false rather than
// a guessed subject.
func (rs *recordServer) commitSubject(ctx context.Context, repo, sha string) (string, bool) {
	if repo == "" || sha == "" {
		return "", false
	}
	// Prover.CommitMessage takes a checkout PATH, not the repository's own
	// NAME (it runs `git -C <repo> show ...` directly) — Prover.RepoPath is
	// the one place that resolves the name doc 02 §5 gives a repository
	// into the local path the proof BFF was configured with.
	repoDir, ok := rs.prover.RepoPath(repo)
	if !ok {
		return "", false
	}
	_, message, err := rs.prover.CommitMessage(ctx, repoDir, sha)
	if err != nil {
		return "", false
	}
	for i, c := range message {
		if c == '\n' {
			return message[:i], true
		}
	}
	return message, true
}

// ---------------------------------------------------------------------------
// Whole-run files.
// ---------------------------------------------------------------------------

// buildWholeRunFiles derives RunRecord.Files: the first step's tree_before
// to the last step's tree_after, PLUS record.go's own "R" rule for a path
// some step changed and the run's own net diff shows as unchanged — a
// revert, a round trip, or a file two steps left exactly where they found
// it. Those paths never appear in the before/after diff at all (git
// correctly reports no net change), so they are folded in separately from
// every step's own already-built Files, rather than re-derived from a
// second git walk.
func (rs *recordServer) buildWholeRunFiles(
	ctx context.Context, repo, before, after string, steps []RecordStep, commits []commitRow,
) ([]RecordFile, error) {
	touchedSteps := map[string][]int{}
	touchedBy := map[string]string{}
	for _, st := range steps {
		for _, f := range st.Files {
			touchedSteps[f.Path] = append(touchedSteps[f.Path], st.N)
			touchedBy[f.Path] = f.ByRunID
		}
	}

	changes, err := rs.filesInRange(ctx, repo, before, after)
	if err != nil {
		return nil, err
	}
	if len(changes) == 0 && len(touchedSteps) == 0 {
		// No file to judge: the commits' file set is not read (#443).
		return []RecordFile{}, nil
	}
	committed := rs.committedSet(ctx, repo, commits)
	afterBlobs := discardBlobsError(rs.blobsAtTree(ctx, repo, after))

	seen := map[string]bool{}
	out := make([]RecordFile, 0, len(changes))
	for _, c := range changes {
		seen[c.Path] = true
		out = append(out, RecordFile{
			Path: c.Path, Status: c.Status, Additions: c.Additions, Deletions: c.Deletions,
			Steps: nonNilInts(touchedSteps[c.Path]), ByRunID: touchedBy[c.Path],
			Committed: isCommitted(afterBlobs, committed, c.Path),
		})
	}
	for path, stepNs := range touchedSteps {
		if seen[path] {
			continue
		}
		out = append(out, RecordFile{
			Path: path, Status: "R", Steps: nonNilInts(stepNs), ByRunID: touchedBy[path],
			Committed: isCommitted(afterBlobs, committed, path),
		})
	}
	return out, nil
}

func nonNilInts(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

// ---------------------------------------------------------------------------
// The whole-run witness summary.
// ---------------------------------------------------------------------------

// summarizeWitness folds RecordWitness (record.go): per step, Agree when
// every AVAILABLE witness is consistent, Disagree when one of them actively
// says otherwise, and Unchecked when there was nothing yet to judge —
// either this step's own body could not be read at all (Outcome.Kind ==
// "unknown"), or its telemetry is still "pending" (inside the window,
// genuinely undecided, never a disagreement).
//
// "Inactive" telemetry (this deployment has none configured, or this call
// predates it) counts toward Agree rather than Disagree: it is not a
// contradiction, it is a witness this deployment never asked to keep.
func summarizeWitness(steps []RecordStep, bodiesStored, bodiesVerified int) RecordWitness {
	w := RecordWitness{Steps: len(steps), BodiesStored: bodiesStored, BodiesVerified: bodiesVerified}
	for _, st := range steps {
		switch {
		case st.Outcome.Kind == "unknown", st.Witnesses.Telemetry == "pending":
			w.Unchecked++
		case st.Witnesses.Gateway == "present" && st.Witnesses.Telemetry != "missing":
			w.Agree++
		default:
			w.Disagree++
		}
	}
	return w
}

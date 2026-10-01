// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// RPG-001 and RPG-002: the run page's read API against a REAL Postgres, a
// REAL served repository, and a REAL gateway snapshot store built with git
// in a temp directory — never a fixture standing in for any of the three.
//
// # The scenario
//
//	run-parent (root, repo recordIntegrationRepo)
//	  (baseline, #437/RM-274: the gateway's own SnapshotBaseline, taken
//	             before step 1's tool ever ran — here the genuinely empty
//	             tree, since the workspace holds nothing until step 1 writes
//	             a.txt)
//	  1. Write   creates a.txt              tree_before T0 (the baseline)
//	             tree_after  T1
//	  2. Bash    `git add a.txt && git commit...`, and DOES commit it
//	             tree_before T1  tree_after T1 (nothing in the tree moved)
//	             commit_recorded on this run, CommitSHA resolved on this step
//	  3. Bash    a command that fails, with an explicit "Exit code: 7"
//	             tree_before T1  tree_after T1
//	  4. Agent   spawns run-child with an exact prompt run-child's own body
//	             store holds as its brief
//	             tree_before T1  tree_after T2 (T2 adds b.txt, run-child's
//	             own write, attributed by_run_id)
//	run-child (parent run-parent)
//	  1. Write   creates b.txt
//	  commit_recorded on run-child
//
// telemetry is seeded for step 2's own tool_use_id only, so step 2 reads
// "matched" and the others — relayed within the same instant this test
// runs, well inside the window — read "pending": the honest answer for a
// run this fresh, not "missing" (RPG-005 already covers "missing" and
// "inactive" directly, where a test can hold the clock still without
// waiting out a real five minutes against a live Postgres).

const (
	recordIntegrationRepo = "github.com/innsegl-test/e19"
)

// recordFixture is everything one RPG-001/002 case needs, assembled once.
type recordFixture struct {
	t        *testing.T
	store    *Store
	repoDir  string
	rs       *recordServer
	logDir   string
	parentID string
	childID  string
}

func newRecordFixture(t *testing.T) *recordFixture {
	t.Helper()
	gitPath := requireGit(t)
	owner, _, readerDSN := migrated(t)
	store, _ := readStore(t, readerDSN)
	ctx := t.Context()

	// ---- the served repository --------------------------------------------
	repoDir := t.TempDir()
	runGitT(t, repoDir, "init", "-q", "-b", "main")

	blobA := hashObject(t, repoDir, gitPath, "a.txt content\n")
	treeT1 := mktreeIn(t, repoDir, gitPath, map[string]string{"a.txt": blobA})
	commitParent := commitTreeIn(t, repoDir, gitPath, treeT1, nil, "add a.txt")
	runGitT(t, repoDir, "update-ref", "refs/heads/main", commitParent)

	blobB := hashObject(t, repoDir, gitPath, "b.txt content\n")
	treeT2 := mktreeIn(t, repoDir, gitPath, map[string]string{"a.txt": blobA, "b.txt": blobB})

	// ---- the snapshot store -------------------------------------------------
	logDir := t.TempDir()
	snapshotRoot := filepath.Join(logDir, "gateway-snapshots")
	if err := os.MkdirAll(snapshotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := snapshotStoreConfig{root: snapshotRoot, gitPath: gitPath}
	key, ok := repoKey(ctx, cfg, repoDir)
	if !ok {
		t.Fatal("repoKey: could not derive a key from the fixture repository")
	}
	storeDir := filepath.Join(snapshotRoot, key)
	if err := os.MkdirAll(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	runGitDirT(t, storeDir, gitPath, "init", "-q", "--bare")
	// The SAME blob content, hashed into the store's own object database —
	// blob ids are content-addressed, so this needs no copy between the two
	// repositories for a "Committed" cross-check to agree (recordfiles.go's
	// own doc comment).
	storeBlobA := hashObject(t, storeDir, gitPath, "a.txt content\n")
	storeBlobB := hashObject(t, storeDir, gitPath, "b.txt content\n")
	if storeBlobA != blobA || storeBlobB != blobB {
		t.Fatalf("blob ids diverged between the two repositories: %s/%s vs %s/%s",
			storeBlobA, blobA, storeBlobB, blobB)
	}
	storeT1 := mktreeIn(t, storeDir, gitPath, map[string]string{"a.txt": blobA})
	storeT2 := mktreeIn(t, storeDir, gitPath, map[string]string{"a.txt": blobA, "b.txt": blobB})
	if storeT1 != treeT1 || storeT2 != treeT2 {
		t.Fatalf("tree ids diverged between the two repositories")
	}

	// ---- the parent run's own baseline (#437, RM-274) -----------------------
	// internal/gateway/snapshot.go's own SnapshotBaseline, restated here with
	// plain git rather than a real Snapshotter: the genuinely empty tree
	// (git mktree on empty stdin produces the well-known empty tree id),
	// protected under the SAME ref name runBaselineTree
	// (internal/api/snapshotstore.go) computes from a run id alone.
	emptyTree := mktreeIn(t, storeDir, gitPath, map[string]string{})
	baselineRef := baselineRefPrefix + hashRepoKey(baselineKeySource, "run-e19-parent")
	runGitDirT(t, storeDir, gitPath, "update-ref", baselineRef, emptyTree)

	// ---- the Prover (RepoPath/GitPath, and commit subjects) ----------------
	prover, err := NewProver(ProofConfig{
		FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:1",
		Repos:   map[string]string{recordIntegrationRepo: repoDir},
		GitPath: gitPath,
	})
	if err != nil {
		t.Fatalf("NewProver: %v", err)
	}

	// ---- the message key (the operator's own decision on top of E19) -------
	messageKeyDir := t.TempDir()
	writeTestMessageKey(t, messageKeyDir, recordFixtureMessageKeyID, recordFixtureMessageKey)

	rs := &recordServer{store: store, prover: prover, logDir: logDir, messageKeyDir: messageKeyDir, cfg: cfg}

	f := &recordFixture{
		t: t, store: store, repoDir: repoDir, rs: rs, logDir: logDir,
		parentID: "run-e19-parent", childID: "run-e19-child",
	}
	f.seedLedgerAndBodies(ctx, owner, commitParent, treeT1, treeT2)
	return f
}

// ---------------------------------------------------------------------------
// git helpers: plain git, never through this package's own isolated runner —
// that runner is what is UNDER TEST.
// ---------------------------------------------------------------------------

func runGitT(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return runGitDirT(t, dir, "git", args...)
}

func runGitDirT(t *testing.T, dir, gitPath string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), gitPath, append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_DIR="+dir, "HOME="+dir,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git -C %s %v: %v: %s", dir, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func hashObject(t *testing.T, dir, gitPath, content string) string {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), gitPath, "hash-object", "-w", "--stdin")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_DIR="+dir)
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	return trimNL(string(out))
}

func mktreeIn(t *testing.T, dir, gitPath string, entries map[string]string) string {
	t.Helper()
	var spec string
	for path, blob := range entries {
		spec += "100644 blob " + blob + "\t" + path + "\n"
	}
	cmd := exec.CommandContext(context.Background(), gitPath, "mktree")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_DIR="+dir)
	cmd.Stdin = strings.NewReader(spec)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git mktree: %v", err)
	}
	return trimNL(string(out))
}

func commitTreeIn(t *testing.T, dir, gitPath, tree string, parents []string, message string) string {
	t.Helper()
	args := []string{"commit-tree", tree}
	for _, p := range parents {
		args = append(args, "-p", p)
	}
	cmd := exec.CommandContext(context.Background(), gitPath, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_DIR="+dir,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	cmd.Stdin = strings.NewReader(message)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git commit-tree: %v", err)
	}
	return trimNL(string(out))
}

// ---------------------------------------------------------------------------
// The ledger and the retained bodies.
// ---------------------------------------------------------------------------

const (
	recordFixtureSpawnPrompt = "create b.txt for the parent run, exactly, report back"

	// The operator's own decision on top of E19 (#395-#397): a check-only
	// key this fixture writes exactly the way
	// cmd/innsegl/gateway.go's own writeMessageKeyFile would, and the
	// parent run's own brief, recorded and retained the same way
	// internal/mcp/agentmessage.go records one.
	recordFixtureMessageKeyID = "gateway-v1"
	recordFixtureMessageKey   = "e19-fixture-derived-key-0123456789"
	recordFixtureBriefText    = "do these three things in order and report back"
)

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeRunBody writes body under dir/runID/<its own plain digest>.json — the
// SAME layout readBody (runlog.go) and bodyFilePresent (recordbuild.go)
// read, and returns the digest a tool_call event names to find it again.
func writeRunBody(t *testing.T, dir, runID string, body []byte) string {
	t.Helper()
	runDir := filepath.Join(dir, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(body)
	hexPart, _ := splitDigestHex(digest)
	if err := os.WriteFile(filepath.Join(runDir, hexPart+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return digest
}

func marshalBody(t *testing.T, b gatewayBody) []byte {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeTelemetryFile(t *testing.T, logDir, toolUseID string) {
	t.Helper()
	dir := filepath.Join(logDir, "telemetry")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := struct {
		ToolUseID string    `json:"tool_use_id"`
		ToolName  string    `json:"tool_name"`
		Success   bool      `json:"success"`
		SessionID string    `json:"session_id"`
		Time      time.Time `json:"time"`
	}{ToolUseID: toolUseID, ToolName: "Bash", Success: true, SessionID: "sess-1", Time: time.Now().UTC()}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, toolUseID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedLedgerAndBodies appends this file's own scenario to owner, and writes
// every retained body it names.
func (f *recordFixture) seedLedgerAndBodies(ctx context.Context, owner *ledger.Store, commitParent, treeT1, treeT2 string) {
	t := f.t
	shortSHA := commitParent[:7]

	envelope := func(runID, spiffe, eventType string) event.Fields {
		return event.Fields{
			event.FieldEventType: eventType,
			event.FieldRunID:     runID,
			event.FieldSpiffeID:  spiffe,
			event.FieldSource:    event.SourceMCP,
		}
	}

	parentSpiffe := "spiffe://innsegl.dev/agent/main/e19/" + f.parentID
	childSpiffe := "spiffe://innsegl.dev/agent/general-purpose/e19/" + f.childID

	// ---- run_registered, parent ---------------------------------------------
	reg := envelope(f.parentID, parentSpiffe, event.EventTypeRunRegistered)
	reg[event.FieldAgentType] = "main"
	reg[event.FieldTaskRef] = "e19"
	reg[event.FieldRepo] = recordIntegrationRepo
	reg[event.FieldBranch] = "main"
	reg[event.FieldIdempotencyKey] = f.parentID + "-register"
	appendOrFail(ctx, t, owner, reg)

	// ---- the brief (the operator's own decision on top of E19) -------------
	briefEvt := envelope(f.parentID, parentSpiffe, event.EventTypeAgentMessage)
	briefEvt[event.FieldRole] = "brief"
	briefEvt[event.FieldPayloadDigest] = realKeyedDigest(recordFixtureMessageKey, recordFixtureMessageKeyID, []byte(recordFixtureBriefText))
	briefEvt[event.FieldIdempotencyKey] = f.parentID + "-brief"
	appendOrFail(ctx, t, owner, briefEvt)
	// The SAME body volume tool_call bodies live under, keyed by its own
	// PLAIN digest — internal/mcp/agentmessage.go's own layout, restated.
	writeRunBody(t, f.logDir, f.parentID, []byte(recordFixtureBriefText))

	// ---- step 1: Write a.txt -------------------------------------------------
	body1 := marshalBody(t, gatewayBody{
		Tool: "Write", ToolUseID: "toolu_1",
		Input:          json.RawMessage(`{"file_path":"a.txt","content":"a.txt content\n"}`),
		ResultObserved: true, Result: json.RawMessage(`"File created successfully at: a.txt"`),
	})
	d1 := writeRunBody(t, f.logDir, f.parentID, body1)
	tc1 := envelope(f.parentID, parentSpiffe, event.EventTypeToolCall)
	tc1[event.FieldToolName] = "Write"
	tc1[event.FieldPayloadDigest] = d1
	tc1[event.FieldWorkspaceTreeHash] = treeT1
	tc1[event.FieldIdempotencyKey] = f.parentID + "-tc-1"
	appendOrFail(ctx, t, owner, tc1)

	// ---- step 2: Bash, commits a.txt -----------------------------------------
	body2 := marshalBody(t, gatewayBody{
		Tool: "Bash", ToolUseID: "toolu_2",
		Input:          json.RawMessage(`{"command":"git add a.txt && git commit -m 'add a.txt'"}`),
		ResultObserved: true,
		Result: json.RawMessage(fmt.Sprintf(
			`"[main %s] add a.txt\n 1 file changed, 1 insertion(+)\n create mode 100644 a.txt"`, shortSHA)),
	})
	d2 := writeRunBody(t, f.logDir, f.parentID, body2)
	tc2 := envelope(f.parentID, parentSpiffe, event.EventTypeToolCall)
	tc2[event.FieldToolName] = "Bash"
	tc2[event.FieldPayloadDigest] = d2
	tc2[event.FieldWorkspaceTreeHash] = treeT1
	tc2[event.FieldIdempotencyKey] = f.parentID + "-tc-2"
	appendOrFail(ctx, t, owner, tc2)
	writeTelemetryFile(t, f.logDir, "toolu_2")

	// ---- the signed commit itself ---------------------------------------------
	intent := envelope(f.parentID, parentSpiffe, event.EventTypeCommitIntent)
	intent[event.FieldRepo] = recordIntegrationRepo
	intent[event.FieldTreeHash] = treeT1
	intent[event.FieldPatchID] = strings.Repeat("a", 40)
	intent[event.FieldIdempotencyKey] = f.parentID + "-intent"
	intentRec := appendOrFail(ctx, t, owner, intent)

	recorded := envelope(f.parentID, parentSpiffe, event.EventTypeCommitRecorded)
	recorded[event.FieldRepo] = recordIntegrationRepo
	recorded[event.FieldTreeHash] = treeT1
	recorded[event.FieldPatchID] = strings.Repeat("a", 40)
	recorded[event.FieldCommitSHA] = commitParent
	recorded[event.FieldIntentEventID] = intentRec[event.FieldEventID]
	recorded[event.FieldRekorEntryUUID] = strings.Repeat("b", 64)
	recorded[event.FieldRekorLogIndex] = int64(4242)
	recorded[event.FieldIdempotencyKey] = f.parentID + "-recorded"
	appendOrFail(ctx, t, owner, recorded)

	// ---- step 3: Bash, fails with an explicit exit code ------------------------
	body3 := marshalBody(t, gatewayBody{
		Tool: "Bash", ToolUseID: "toolu_3",
		Input:          json.RawMessage(`{"command":"exit 7"}`),
		ResultObserved: true, IsError: true,
		Result: json.RawMessage(`"boom\nExit code: 7\n"`),
	})
	d3 := writeRunBody(t, f.logDir, f.parentID, body3)
	tc3 := envelope(f.parentID, parentSpiffe, event.EventTypeToolCall)
	tc3[event.FieldToolName] = "Bash"
	tc3[event.FieldPayloadDigest] = d3
	tc3[event.FieldWorkspaceTreeHash] = treeT1
	tc3[event.FieldIdempotencyKey] = f.parentID + "-tc-3"
	appendOrFail(ctx, t, owner, tc3)

	// ---- step 4: Agent, spawns run-e19-child -----------------------------------
	promptJSON, err := json.Marshal(recordFixtureSpawnPrompt)
	if err != nil {
		t.Fatal(err)
	}
	body4 := marshalBody(t, gatewayBody{
		Tool: "Agent", ToolUseID: "toolu_4",
		Input:          json.RawMessage(`{"subagent_type":"general-purpose","prompt":` + string(promptJSON) + `}`),
		ResultObserved: true, Result: json.RawMessage(`"the subagent created b.txt and committed it"`),
	})
	d4 := writeRunBody(t, f.logDir, f.parentID, body4)
	tc4 := envelope(f.parentID, parentSpiffe, event.EventTypeToolCall)
	tc4[event.FieldToolName] = "Agent"
	tc4[event.FieldPayloadDigest] = d4
	tc4[event.FieldWorkspaceTreeHash] = treeT2
	tc4[event.FieldIdempotencyKey] = f.parentID + "-tc-4"
	appendOrFail(ctx, t, owner, tc4)

	// ---- a bare run: registered, nothing recorded (#435) -------------------------
	// Every run from before the gateway looks like this.
	bareID := "run-e19-bare"
	bareReg := envelope(bareID, "spiffe://innsegl.dev/agent/general-purpose/e19/"+bareID, event.EventTypeRunRegistered)
	bareReg[event.FieldAgentType] = "general-purpose"
	bareReg[event.FieldTaskRef] = "e19"
	bareReg[event.FieldRepo] = recordIntegrationRepo
	bareReg[event.FieldBranch] = "main"
	bareReg[event.FieldIdempotencyKey] = bareID + "-register"
	appendOrFail(ctx, t, owner, bareReg)

	// ---- the child run ----------------------------------------------------------
	childReg := envelope(f.childID, childSpiffe, event.EventTypeRunRegistered)
	childReg[event.FieldAgentType] = "general-purpose"
	childReg[event.FieldTaskRef] = "e19"
	childReg[event.FieldRepo] = recordIntegrationRepo
	childReg[event.FieldBranch] = "main"
	childReg[event.FieldParentRunID] = f.parentID
	childReg[event.FieldIdempotencyKey] = f.childID + "-register"
	appendOrFail(ctx, t, owner, childReg)

	bodyC1 := marshalBody(t, gatewayBody{
		Tool: "Write", ToolUseID: "toolu_c1",
		Input:          json.RawMessage(`{"file_path":"b.txt","content":"b.txt content\n"}`),
		ResultObserved: true, Result: json.RawMessage(`"File created successfully at: b.txt"`),
	})
	dc1 := writeRunBody(t, f.logDir, f.childID, bodyC1)
	tcc1 := envelope(f.childID, childSpiffe, event.EventTypeToolCall)
	tcc1[event.FieldToolName] = "Write"
	tcc1[event.FieldPayloadDigest] = dc1
	tcc1[event.FieldIdempotencyKey] = f.childID + "-tc-1"
	appendOrFail(ctx, t, owner, tcc1)

	childCommitSHA := strings.Repeat("c", 40)
	childIntent := envelope(f.childID, childSpiffe, event.EventTypeCommitIntent)
	childIntent[event.FieldRepo] = recordIntegrationRepo
	childIntent[event.FieldTreeHash] = treeT2
	childIntent[event.FieldPatchID] = strings.Repeat("d", 40)
	childIntent[event.FieldIdempotencyKey] = f.childID + "-intent"
	childIntentRec := appendOrFail(ctx, t, owner, childIntent)

	childRecorded := envelope(f.childID, childSpiffe, event.EventTypeCommitRecorded)
	childRecorded[event.FieldRepo] = recordIntegrationRepo
	childRecorded[event.FieldTreeHash] = treeT2
	childRecorded[event.FieldPatchID] = strings.Repeat("d", 40)
	childRecorded[event.FieldCommitSHA] = childCommitSHA
	childRecorded[event.FieldIntentEventID] = childIntentRec[event.FieldEventID]
	childRecorded[event.FieldRekorEntryUUID] = strings.Repeat("e", 64)
	childRecorded[event.FieldRekorLogIndex] = int64(4243)
	childRecorded[event.FieldIdempotencyKey] = f.childID + "-recorded"
	appendOrFail(ctx, t, owner, childRecorded)

	// The child's own brief, content-addressed under its own run directory —
	// no ledger digest needs to match it (recordbuild.go's own package
	// comment on why Brief/Replies stay unavailable); what SpawnedRunID
	// needs is this exact text, byte for byte, discoverable without a
	// secret (recordbody.go's spawnBodyMatches).
	writeRunBody(t, f.logDir, f.childID, []byte(recordFixtureSpawnPrompt))
}

// ---------------------------------------------------------------------------
// The two routes, over real HTTP.
// ---------------------------------------------------------------------------

func newRecordTestServer(t *testing.T, rs *recordServer) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/runs/{run_id}/record", rs.handleRunRecord)
	mux.HandleFunc("GET /api/v1/runs/{run_id}/steps/{n}/diff", rs.handleStepDiff)
	mux.HandleFunc("GET /api/v1/runs/{run_id}/steps/{n}", rs.handleStep)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestRPG001RunRecordAgainstRealPostgresAndGit is RPG-001.
func TestRPG001RunRecordAgainstRealPostgresAndGit(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)

	a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/record")
	if a.status != 200 {
		t.Fatalf("GET record: status %d: %s", a.status, a.body)
	}

	// The response decodes strictly into the contract, the same way
	// TestRunRecordFixtureMatchesTheContract holds the fixture to it — a
	// live response that carries a member the contract does not know, or
	// is missing one it requires, fails here exactly as a bad fixture would.
	dec := json.NewDecoder(strings.NewReader(string(a.body)))
	dec.DisallowUnknownFields()
	var rec RunRecord
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("the record does not decode strictly into the contract: %v", err)
	}

	if rec.Run.RunID != f.parentID || rec.Run.Repo != recordIntegrationRepo || rec.Run.Branch != "main" {
		t.Errorf("Run = %+v", rec.Run)
	}
	if rec.Run.Status != "active" {
		t.Errorf("Status = %q, want active (never retired or withdrawn)", rec.Run.Status)
	}
	if len(rec.Steps) != 4 {
		t.Fatalf("got %d steps, want 4: %+v", len(rec.Steps), rec.Steps)
	}

	step1, step2, step3, step4 := rec.Steps[0], rec.Steps[1], rec.Steps[2], rec.Steps[3]

	// Step 1: root run's first step. #437 (RM-274): the gateway's own
	// baseline, taken before this run's first tool ever ran, gives this
	// step a real "before" — here, the genuinely empty tree — so its own
	// diff and its own file both show, rather than the earlier "no known
	// baseline" gap this run's own fixture comment used to document.
	if step1.TreeBefore == "" {
		t.Error("step1.TreeBefore is empty, want the baseline's own tree (#437)")
	}
	if step1.TreeBefore == step1.TreeAfter {
		t.Errorf("step1.TreeBefore = step1.TreeAfter = %q, want the baseline distinct from T1", step1.TreeAfter)
	}
	var step1A *RecordFile
	for i := range step1.Files {
		if step1.Files[i].Path == "a.txt" {
			step1A = &step1.Files[i]
		}
	}
	if step1A == nil {
		t.Fatalf("step1.Files = %+v, want a.txt", step1.Files)
	}
	if step1A.Status != "A" {
		t.Errorf("step1 a.txt status = %q, want A", step1A.Status)
	}
	if step1A.ByRunID != "" {
		t.Errorf("step1 a.txt by_run_id = %q, want empty (the parent run's own write)", step1A.ByRunID)
	}
	if step1.Witnesses.Snapshot != "changed" {
		t.Errorf("step1.Witnesses.Snapshot = %q, want changed", step1.Witnesses.Snapshot)
	}

	// Step 2: the commit itself.
	if step2.CommitSHA == "" {
		t.Error("step2.CommitSHA is empty; the commit summary line should have matched it to the run's own commit_recorded")
	}
	if step2.Witnesses.Telemetry != "matched" {
		t.Errorf("step2.Witnesses.Telemetry = %q, want matched (a telemetry file was seeded for toolu_2)", step2.Witnesses.Telemetry)
	}
	if step2.Witnesses.Snapshot != "unchanged" {
		t.Errorf("step2.Witnesses.Snapshot = %q, want unchanged (committing does not change the tree)", step2.Witnesses.Snapshot)
	}

	// Step 3: the failed step, RPG-001's own "incl. a failed step with its
	// exit code".
	if step3.Outcome.Kind != "error" {
		t.Errorf("step3.Outcome.Kind = %q, want error", step3.Outcome.Kind)
	}
	if step3.Outcome.ExitCode == nil || *step3.Outcome.ExitCode != 7 {
		t.Errorf("step3.Outcome.ExitCode = %v, want 7 (read from the result's own \"Exit code: 7\")", step3.Outcome.ExitCode)
	}

	// Step 4: the spawn.
	if step4.SpawnedRunID != f.childID {
		t.Errorf("step4.SpawnedRunID = %q, want %q", step4.SpawnedRunID, f.childID)
	}
	if len(step4.SpawnedCommits) != 1 || step4.SpawnedCommits[0] != strings.Repeat("c", 40) {
		t.Errorf("step4.SpawnedCommits = %v, want [%s]", step4.SpawnedCommits, strings.Repeat("c", 40))
	}
	var foundBTxt bool
	for _, file := range step4.Files {
		if file.Path == "b.txt" {
			foundBTxt = true
			if file.Status != "A" {
				t.Errorf("b.txt status = %q, want A", file.Status)
			}
			if file.ByRunID != f.childID {
				t.Errorf("b.txt by_run_id = %q, want %q (the subagent's own write)", file.ByRunID, f.childID)
			}
		}
	}
	if !foundBTxt {
		t.Errorf("step4.Files = %+v, want b.txt", step4.Files)
	}

	// The whole run's own family tree.
	if rec.Tree.RootRunID != f.parentID {
		t.Errorf("Tree.RootRunID = %q, want %q", rec.Tree.RootRunID, f.parentID)
	}
	var childNode *RecordTreeNode
	for i := range rec.Tree.Nodes {
		if rec.Tree.Nodes[i].RunID == f.childID {
			childNode = &rec.Tree.Nodes[i]
		}
	}
	if childNode == nil {
		t.Fatalf("the child run is missing from the tree: %+v", rec.Tree.Nodes)
	}
	if childNode.SpawnedBy != 4 {
		t.Errorf("child node SpawnedBy = %d, want 4", childNode.SpawnedBy)
	}
	if childNode.ParentRunID != f.parentID {
		t.Errorf("child node ParentRunID = %q, want %q", childNode.ParentRunID, f.parentID)
	}

	// The run's own commits.
	if len(rec.Commits) != 1 {
		t.Fatalf("got %d commits, want 1: %+v", len(rec.Commits), rec.Commits)
	}
	c := rec.Commits[0]
	if c.Step != 2 {
		t.Errorf("commit.Step = %d, want 2", c.Step)
	}
	if c.Landed != "landed" {
		t.Errorf("commit.Landed = %q, want landed — the commit is reachable from refs/heads/main", c.Landed)
	}
	if c.Subject != "add a.txt" {
		t.Errorf("commit.Subject = %q, want %q", c.Subject, "add a.txt")
	}

	// The whole-run Files: from the run's own baseline (the empty tree,
	// #437/RM-274) to the last tree (T2) — a.txt's own creation is now
	// INSIDE that known range and must appear, attributed to the parent run
	// itself; b.txt must too, attributed to the child.
	var wholeRunA *RecordFile
	for i := range rec.Files {
		if rec.Files[i].Path == "a.txt" {
			wholeRunA = &rec.Files[i]
		}
	}
	if wholeRunA == nil {
		t.Fatalf("whole-run Files = %+v, want a.txt (#437)", rec.Files)
	}
	if wholeRunA.Status != "A" {
		t.Errorf("whole-run a.txt status = %q, want A", wholeRunA.Status)
	}
	if wholeRunA.ByRunID != "" {
		t.Errorf("whole-run a.txt by_run_id = %q, want empty (the parent run's own write)", wholeRunA.ByRunID)
	}
	if !wholeRunA.Committed {
		t.Error("whole-run a.txt should read Committed: its content is in the parent's own commit_recorded tree")
	}
	var wholeRunB *RecordFile
	for i := range rec.Files {
		if rec.Files[i].Path == "b.txt" {
			wholeRunB = &rec.Files[i]
		}
	}
	if wholeRunB == nil {
		t.Fatalf("whole-run Files = %+v, want b.txt", rec.Files)
	}
	if wholeRunB.ByRunID != f.childID {
		t.Errorf("whole-run b.txt by_run_id = %q, want %q", wholeRunB.ByRunID, f.childID)
	}
	if !wholeRunB.Committed {
		t.Error("whole-run b.txt should read Committed: its content is in the child's own commit_recorded tree")
	}

	// Brief: verified with the operator's own check-only key (E19's own
	// widening) — see recordbuild.go's own package comment.
	if !rec.Brief.Available {
		t.Error("Brief.Available = false; the fixture's own message key should have verified it")
	}
	if rec.Brief.Text != recordFixtureBriefText {
		t.Errorf("Brief.Text = %q, want %q", rec.Brief.Text, recordFixtureBriefText)
	}
	if rec.Brief.Digest == "" {
		t.Error("Brief.Digest should always be the ledger's own keyed digest")
	}

	if rec.ChainHead <= 0 {
		t.Error("ChainHead should be positive once events exist")
	}
	if rec.DataAsOf.IsZero() {
		t.Error("DataAsOf should be set")
	}
}

// TestRPG001UnknownRunIsNotFound checks the 404 path against real Postgres.
func TestRPG001UnknownRunIsNotFound(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)
	a := get(t, srv.URL, "/api/v1/runs/run-does-not-exist/record")
	if a.status != 404 {
		t.Errorf("status = %d, want 404: %s", a.status, a.body)
	}
}

// TestRPG001MissingKeyIDIsNeverVerified: the ledger's own digest names a
// key id this process holds no file for — a rotation the deployment has
// not finished catching up on, or simply a deployment with no
// -message-key-dir configured at all. Either way: unavailable, never a
// guess.
func TestRPG001MissingKeyIDIsNeverVerified(t *testing.T) {
	f := newRecordFixture(t)

	// A recordServer pointed at an EMPTY message-key directory — the
	// fixture's own key id ("gateway-v1") has no file under it.
	unconfigured := *f.rs
	unconfigured.messageKeyDir = t.TempDir()
	srv := newRecordTestServer(t, &unconfigured)

	a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/record")
	if a.status != 200 {
		t.Fatalf("GET record: status %d: %s", a.status, a.body)
	}
	var rec RunRecord
	decodeBody(t, a, &rec)
	if rec.Brief.Available {
		t.Error("Brief.Available = true, but no key file exists for this digest's own key id")
	}
	if rec.Brief.Text != "" {
		t.Errorf("Brief.Text = %q, want empty", rec.Brief.Text)
	}
	if rec.Brief.Digest == "" {
		t.Error("Brief.Digest should still be reported even when it cannot be verified")
	}
}

// TestRPG002StepDiffAgainstARealSnapshotStore is RPG-002.
func TestRPG002StepDiffAgainstARealSnapshotStore(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)

	// Step 1 (creates a.txt, against the run's own baseline, #437/RM-274):
	// one file, one hunk, added -- the diff route reuses buildRunRecord's
	// own tree_before/tree_after (diff.go's own doc comment), so fixing
	// step 1's TreeBefore fixes this route too, with no change of its own.
	first := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/1/diff")
	if first.status != 200 {
		t.Fatalf("GET diff step 1: status %d: %s", first.status, first.body)
	}
	var diff1 StepDiff
	decodeBody(t, first, &diff1)
	if len(diff1.Files) != 1 {
		t.Fatalf("got %d files, want 1: %+v", len(diff1.Files), diff1.Files)
	}
	df1 := diff1.Files[0]
	if df1.Path != "a.txt" || df1.Status != "A" || df1.Binary {
		t.Errorf("diff file = %+v, want Path=a.txt Status=A Binary=false", df1)
	}
	if len(df1.Hunks) != 1 || len(df1.Hunks[0].Lines) == 0 {
		t.Fatalf("hunks = %+v, want one hunk with content", df1.Hunks)
	}
	var sawAddA bool
	for _, line := range df1.Hunks[0].Lines {
		if line.Kind == "add" && line.Text == "a.txt content" {
			sawAddA = true
		}
	}
	if !sawAddA {
		t.Errorf("hunk lines = %+v, want an add line of \"a.txt content\"", df1.Hunks[0].Lines)
	}

	// Step 2 (commit, no tree change): no hunks.
	a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/2/diff")
	if a.status != 200 {
		t.Fatalf("GET diff step 2: status %d: %s", a.status, a.body)
	}
	var diff2 StepDiff
	decodeBody(t, a, &diff2)
	if len(diff2.Files) != 0 {
		t.Errorf("a no-change step should have no files: %+v", diff2.Files)
	}

	// Step 4 (adds b.txt): one file, one hunk, added.
	b := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/4/diff")
	if b.status != 200 {
		t.Fatalf("GET diff step 4: status %d: %s", b.status, b.body)
	}
	var diff4 StepDiff
	decodeBody(t, b, &diff4)
	if len(diff4.Files) != 1 {
		t.Fatalf("got %d files, want 1: %+v", len(diff4.Files), diff4.Files)
	}
	df := diff4.Files[0]
	if df.Path != "b.txt" || df.Status != "A" || df.Binary {
		t.Errorf("diff file = %+v, want Path=b.txt Status=A Binary=false", df)
	}
	if len(df.Hunks) != 1 || len(df.Hunks[0].Lines) == 0 {
		t.Fatalf("hunks = %+v, want one hunk with content", df.Hunks)
	}
	var sawAdd bool
	for _, line := range df.Hunks[0].Lines {
		if line.Kind == "add" && line.Text == "b.txt content" {
			sawAdd = true
		}
	}
	if !sawAdd {
		t.Errorf("hunk lines = %+v, want an add line of \"b.txt content\"", df.Hunks[0].Lines)
	}
}

// TestRPG002StepDiffUnknownStepIsNotFound.
func TestRPG002StepDiffUnknownStepIsNotFound(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)
	a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/99/diff")
	if a.status != 404 {
		t.Errorf("status = %d, want 404: %s", a.status, a.body)
	}
}

// TestParentSnapshotBefore is record.go's own rule for a subagent's first
// step, at the query level: the parent's own newest tree_hash at or before
// the instant named, and "" when the parent took none before it.
func TestParentSnapshotBefore(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	store, _ := readStore(t, readerDSN)
	ctx := t.Context()

	parent := event.Fields{
		event.FieldEventType: event.EventTypeRunRegistered, event.FieldRunID: "run-psb-parent",
		event.FieldSpiffeID: "spiffe://innsegl.dev/agent/main/e19/run-psb-parent",
		event.FieldSource:   event.SourceMCP, event.FieldAgentType: "main", event.FieldTaskRef: "e19",
		event.FieldRepo: recordIntegrationRepo, event.FieldBranch: "main",
		event.FieldIdempotencyKey: "run-psb-parent-register",
	}
	appendOrFail(ctx, t, owner, parent)

	tc := event.Fields{
		event.FieldEventType: event.EventTypeToolCall, event.FieldRunID: "run-psb-parent",
		event.FieldSpiffeID: "spiffe://innsegl.dev/agent/main/e19/run-psb-parent",
		event.FieldSource:   event.SourceMCP, event.FieldToolName: "Write",
		event.FieldPayloadDigest:     "sha256:" + hex.EncodeToString(sha256.New().Sum(nil)),
		event.FieldWorkspaceTreeHash: strings.Repeat("a", 40),
		event.FieldIdempotencyKey:    "run-psb-parent-tc-1",
	}
	beforeAppend := time.Now().UTC()
	appendOrFail(ctx, t, owner, tc)
	snapshotAt := time.Now().UTC()

	before := snapshotAt.Add(time.Minute)
	tree, err := store.parentSnapshotBefore(ctx, "run-psb-parent", before)
	if err != nil {
		t.Fatalf("parentSnapshotBefore: %v", err)
	}
	if tree != strings.Repeat("a", 40) {
		t.Errorf("tree = %q, want %q", tree, strings.Repeat("a", 40))
	}

	// A child registered BEFORE the parent ever took a snapshot finds none.
	tree, err = store.parentSnapshotBefore(ctx, "run-psb-parent", beforeAppend.Add(-time.Hour))
	if err != nil {
		t.Fatalf("parentSnapshotBefore: %v", err)
	}
	if tree != "" {
		t.Errorf("tree = %q, want \"\" — nothing was snapshotted before that instant", tree)
	}

	// An unrelated run has nothing at all.
	tree, err = store.parentSnapshotBefore(ctx, "run-does-not-exist", before)
	if err != nil {
		t.Fatalf("parentSnapshotBefore: %v", err)
	}
	if tree != "" {
		t.Errorf("tree = %q, want \"\"", tree)
	}
}

// TestLandingOfNotLandedAndUnknown covers landingOf's other two outcomes:
// RPG-001 already exercises "landed".
func TestLandingOfNotLandedAndUnknown(t *testing.T) {
	f := newRecordFixture(t)
	ctx := t.Context()

	// A commit_sha this repository never received: reachable, checked, and
	// answers false — not_landed.
	neverLanded := strings.Repeat("f", 40)
	got := f.rs.landingOf(ctx, recordIntegrationRepo, commitRow{
		RunID: f.parentID, CommitSHA: neverLanded,
	}, nil)
	if got != "not_landed" {
		t.Errorf("landingOf(never landed) = %q, want not_landed", got)
	}

	// A commit that WAS superseded reads as rewritten instead.
	supersededEventID := "evt-superseded"
	got = f.rs.landingOf(ctx, recordIntegrationRepo, commitRow{
		RunID: f.parentID, EventID: supersededEventID, CommitSHA: neverLanded,
	}, map[string]bool{supersededEventID: true})
	if got != "rewritten" {
		t.Errorf("landingOf(superseded) = %q, want rewritten", got)
	}

	// A repository this deployment does not serve at all, with no
	// corroborating tool-call result: unknown, never guessed either way.
	got = f.rs.landingOf(ctx, "github.com/nobody/nothing", commitRow{
		RunID: f.parentID, CommitSHA: neverLanded,
	}, nil)
	if got != "unknown" {
		t.Errorf("landingOf(unserved repo) = %q, want unknown", got)
	}
}

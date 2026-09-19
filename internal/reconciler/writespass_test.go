// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// writesRepo is a Repos holding exactly the blobs a case plants.
type writesRepo struct {
	// holds is the repository's reachable blobs, keyed by repo id.
	holds map[string]map[string]struct{}
	err   error
}

func (w *writesRepo) SignedCommitsWithTree(context.Context, string, string) ([]string, error) {
	return nil, nil
}

func (w *writesRepo) CommitsOnBranch(context.Context, string, string) ([]reconciler.RepoCommit, error) {
	return nil, nil
}

func (w *writesRepo) TreeBlobs(context.Context, string, string) (map[string]struct{}, error) {
	return nil, nil
}

func (w *writesRepo) ReachableBlobs(_ context.Context, repo string) (map[string]struct{}, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.holds[repo], nil
}

// plantBody writes a retained body where the pass will look for it and returns
// the digest the chain must carry — the digest over the ENVELOPE, which is the
// thing #169 mistook for a content hash.
func plantBody(t *testing.T, dir, runID string, body map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(dir, runID), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, runID, hex.EncodeToString(sum[:])+".json"), raw, 0o644); err != nil {
		t.Fatalf("writing the body: %v", err)
	}
	return digest
}

func runWritesPass(
	t *testing.T, m *memLedger, repos reconciler.Repos, logDir, repoID string,
) reconciler.WritesReport {
	t.Helper()
	return runWritesPassWith(t, m, repos,
		&reconciler.WritesConfig{LogDir: logDir, Repos: []string{repoID}})
}

func runWritesPassWith(
	t *testing.T, m *memLedger, repos reconciler.Repos, cfg *reconciler.WritesConfig,
) reconciler.WritesReport {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger:      m,
		Appender:    m,
		Repos:       repos,
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		Now:         rebaseClock,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Writes:      cfg,
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result.Writes
}

// The finding, and the silence around it.
//
// A run that claims to have written content in a tree it signed is corroborated
// by git, which the caller does not control. One that claims content in no tree
// it signed has made a statement nothing supports — which is the whole of what
// #169 asked for: a reported write becomes falsifiable.
func TestWritesPassReportsOnlyTheUnsupportedWrite(t *testing.T) {
	const repoID = "github.com/acme/api"
	const runID = "run-writes-1"
	const tree = "1111111111111111111111111111111111111111"
	logDir := t.TempDir()

	honest := "package a\n\nfunc A() {}\n"
	forged := "package a\n\nfunc Backdoor() {}\n"

	honestDigest := plantBody(t, logDir, runID, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.go", "content": honest},
	})
	forgedDigest := plantBody(t, logDir, runID, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.go", "content": forged},
	})

	m := newMemLedger(rebaseClock)
	seedRegistered(t, m, runID)
	honestEvent := seedTool(t, m, runID, honestDigest)
	forgedEvent := seedTool(t, m, runID, forgedDigest)
	seedSigned(t, m, runID, repoID, tree)

	repos := &writesRepo{holds: map[string]map[string]struct{}{
		repoID: {reconciler.BlobID(honest): {}},
	}}

	report := runWritesPass(t, m, repos, logDir, repoID)

	if !report.Enabled {
		t.Fatal("the pass reported itself disabled with a WritesConfig given")
	}
	if report.Checked != 2 {
		t.Errorf("checked %d claims, want 2", report.Checked)
	}
	if report.Supported != 1 {
		t.Errorf("supported %d, want 1 — the honest write is in the signed tree",
			report.Supported)
	}
	if report.Unsupported != 1 {
		t.Errorf("unsupported %d, want 1 — the forged write is in no signed tree",
			report.Unsupported)
	}

	// AND NOTHING IS APPENDED. Corroboration is a number, never an accusation:
	// measured on a real deployment, judging a claim against what a repository
	// holds is wrong about a third of honest work, because a squash or rebase
	// rewrites the content and a run's last write is often not the final state.
	// An alert wrong that often is noise that teaches an operator to ignore red.
	if got := len(driftSubjects(t, m)); got != 0 {
		t.Errorf("the pass appended %d findings; it must only count. %s was not "+
			"corroborated, which is not evidence that anything was fabricated",
			got, forgedEvent)
	}
	_ = honestEvent
}

// A repository that cannot be read is not an accusation. An absence of evidence
// reported as evidence is the failure doc 06 P2 exists to forbid.
func TestWritesPassDoesNotAccuseWhenTheRepositoryCannotBeRead(t *testing.T) {
	const repoID = "github.com/acme/api"
	const runID = "run-writes-2"
	logDir := t.TempDir()

	digest := plantBody(t, logDir, runID, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.go", "content": "anything\n"},
	})
	m := newMemLedger(rebaseClock)
	seedRegistered(t, m, runID)
	seedTool(t, m, runID, digest)

	report := runWritesPass(t, m, &writesRepo{}, logDir, repoID)

	if report.Unsupported != 0 {
		t.Fatalf("an unreadable repository produced %d findings, want 0",
			report.Unsupported)
	}
	if report.Uncheckable != 1 {
		t.Errorf("uncheckable %d, want 1 — the pass must SAY it could not check",
			report.Uncheckable)
	}
	if len(driftSubjects(t, m)) != 0 {
		t.Error("a finding was appended when there was nothing to check against")
	}
}

// A second pass reports the same thing and still appends nothing. REC-005 as an
// observable: a fresh process behaves identically to one running for a week.
func TestWritesPassIsIdempotent(t *testing.T) {
	const repoID = "github.com/acme/api"
	const runID = "run-writes-3"
	const tree = "2222222222222222222222222222222222222222"
	logDir := t.TempDir()

	digest := plantBody(t, logDir, runID, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.go", "content": "unsupported\n"},
	})
	m := newMemLedger(rebaseClock)
	seedRegistered(t, m, runID)
	seedTool(t, m, runID, digest)
	seedSigned(t, m, runID, repoID, tree)
	repos := &writesRepo{holds: map[string]map[string]struct{}{
		repoID: {reconciler.BlobID("something else\n"): {}},
	}}

	first := runWritesPass(t, m, repos, logDir, repoID)
	second := runWritesPass(t, m, repos, logDir, repoID)

	if first.Unsupported != 1 {
		t.Fatalf("the first pass counted %d uncorroborated, want 1", first.Unsupported)
	}
	if second.Unsupported != first.Unsupported {
		t.Errorf("the second pass counted %d and the first %d; the same chain and the "+
			"same repository must produce the same number",
			second.Unsupported, first.Unsupported)
	}
	if got := len(driftSubjects(t, m)); got != 0 {
		t.Errorf("the chain holds %d findings; this pass appends nothing", got)
	}
}

// A body that is gone — expired past the retention window, or never written —
// is not a finding. Its absence is a fact about this machine, not the agent.
func TestWritesPassCountsAMissingBodyAsUnreadable(t *testing.T) {
	const repoID = "github.com/acme/api"
	const runID = "run-writes-4"
	const tree = "3333333333333333333333333333333333333333"

	m := newMemLedger(rebaseClock)
	seedRegistered(t, m, runID)
	seedTool(t, m, runID,
		"sha256:"+"aa"+"00000000000000000000000000000000000000000000000000000000000000")
	seedSigned(t, m, runID, repoID, tree)

	report := runWritesPass(t, m, &writesRepo{
		holds: map[string]map[string]struct{}{
			repoID: {reconciler.BlobID("anything at all\n"): {}},
		},
	}, t.TempDir(), repoID)

	if report.Unsupported != 0 {
		t.Fatalf("a missing body produced %d findings, want 0", report.Unsupported)
	}
	if report.Unreadable != 1 {
		t.Errorf("unreadable %d, want 1", report.Unreadable)
	}
}

// servedLayout builds the three directories a deployment actually has: the
// projects directory as the HOST spells it, the same directory as this process
// mounts it, and the workspace root where `host/org/name` is a symlink into
// that mount. Returns the config those three describe.
//
// The symlink is not incidental. It is how a repository comes to be at
// `<root>/host/org/name` at all, and a rule that compared the unresolved path
// would find every claim outside every repository.
func servedLayout(t *testing.T, base, repoID, dirName string) *reconciler.WritesConfig {
	t.Helper()
	host := filepath.Join(base, "host")
	projects := filepath.Join(base, "projects")
	work := filepath.Join(base, "work")

	repoDir := filepath.Join(projects, dirName)
	if err := os.MkdirAll(filepath.Join(repoDir, "internal"), 0o755); err != nil {
		t.Fatalf("mkdir repository: %v", err)
	}
	link := filepath.Join(work, filepath.FromSlash(repoID))
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	if err := os.Symlink(repoDir, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, repoDir, err)
	}
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatalf("mkdir host projects: %v", err)
	}
	return &reconciler.WritesConfig{
		Repos:        []string{repoID},
		HostProjects: host,
		Projects:     projects,
		Workspace:    work,
	}
}

// A write to a path no served repository holds is UNCHECKABLE, not a shortfall.
//
// Measured against this deployment's retained bodies: 339 of 4,291
// reconstructable claims name a path outside every repository the workspace
// links — a scratch directory, a temporary file, a tree nobody serves. Counted
// "not found", each one says the repository contradicted the claim when the
// repository was never asked, and the corroboration rate then moves with how
// much scratch work an agent did. The bucket for "this check is silent about
// it" already existed; these belong in it.
func TestWritesPassCountsAWriteOutsideEveryServedRepositoryAsUncheckable(t *testing.T) {
	const repoID = "github.com/acme/api"
	const runID = "run-writes-5"
	const tree = "4444444444444444444444444444444444444444"

	base := t.TempDir()
	cfg := servedLayout(t, base, repoID, "api")
	cfg.LogDir = t.TempDir()

	inRepo := "package a\n\nfunc A() {}\n"
	inScratch := "notes\n"

	inRepoDigest := plantBody(t, cfg.LogDir, runID, map[string]any{
		"tool_name": "Write",
		"tool_input": map[string]any{
			"file_path": filepath.Join(cfg.HostProjects, "api", "internal", "a.go"),
			"content":   inRepo,
		},
	})
	scratchDigest := plantBody(t, cfg.LogDir, runID, map[string]any{
		"tool_name": "Write",
		"tool_input": map[string]any{
			"file_path": filepath.Join(base, "scratch", "notes.md"),
			"content":   inScratch,
		},
	})

	m := newMemLedger(rebaseClock)
	seedRegistered(t, m, runID)
	seedTool(t, m, runID, inRepoDigest)
	seedTool(t, m, runID, scratchDigest)
	seedSigned(t, m, runID, repoID, tree)

	// The repository holds neither, so the only thing separating the two
	// claims is where each one says it wrote.
	repos := &writesRepo{holds: map[string]map[string]struct{}{
		repoID: {reconciler.BlobID("something else\n"): {}},
	}}

	report := runWritesPassWith(t, m, repos, cfg)

	if !report.Scoped {
		t.Fatal("the pass reported itself unscoped with all three roots given; " +
			"it cannot then tell a scratch path from a repository path")
	}
	if report.Uncheckable != 1 {
		t.Errorf("uncheckable %d, want 1 — a write to %s is in no repository this "+
			"deployment serves, so there was never anything to check it against",
			report.Uncheckable, filepath.Join(base, "scratch", "notes.md"))
	}
	if report.Unsupported != 1 {
		t.Errorf("unsupported %d, want 1 — only the write INSIDE the repository is a "+
			"claim the repository can speak to", report.Unsupported)
	}
	if len(driftSubjects(t, m)) != 0 {
		t.Error("the pass appended a finding; it must only count")
	}
}

// Unscoped is SAID, not inferred from a number.
//
// A deployment that has not been told which host directory its mount
// corresponds to cannot translate a claimed path, so every path is admitted
// and a scratch write is counted "not found" exactly as it was before. That is
// a weaker report and the report has to say so: a rate a reader trusts more
// than it deserves is the failure #167 was filed about.
func TestWritesPassSaysWhenItCannotScopeAPath(t *testing.T) {
	const repoID = "github.com/acme/api"
	const runID = "run-writes-6"
	const tree = "5555555555555555555555555555555555555555"

	base := t.TempDir()
	logDir := t.TempDir()
	digest := plantBody(t, logDir, runID, map[string]any{
		"tool_name": "Write",
		"tool_input": map[string]any{
			"file_path": filepath.Join(base, "scratch", "notes.md"),
			"content":   "notes\n",
		},
	})

	m := newMemLedger(rebaseClock)
	seedRegistered(t, m, runID)
	seedTool(t, m, runID, digest)
	seedSigned(t, m, runID, repoID, tree)
	repos := &writesRepo{holds: map[string]map[string]struct{}{
		repoID: {reconciler.BlobID("something else\n"): {}},
	}}

	report := runWritesPass(t, m, repos, logDir, repoID)

	if report.Scoped {
		t.Fatal("the pass reported itself scoped with no host projects directory " +
			"given; nothing there can translate a host path")
	}
	if report.Unsupported != 1 {
		t.Errorf("unsupported %d, want 1 — unscoped, the path rule does not run and "+
			"the claim is judged on content alone, as it was before", report.Unsupported)
	}
}

// seedRegistered is the run_registered every seeded run needs.
func seedRegistered(t *testing.T, m *memLedger, runID string) {
	t.Helper()
	if _, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "register/" + runID,
		event.FieldAgentType:      "demo",
		event.FieldTaskRef:        "rm-104",
		event.FieldRepo:           "github.com/acme/api",
		event.FieldBranch:         "main",
	}); err != nil {
		t.Fatalf("seed run_registered: %v", err)
	}
}

// seedTool is one tool_call carrying a payload digest, which is all the chain
// holds about it — the body lives on disk and the digest is over the envelope.
func seedTool(t *testing.T, m *memLedger, runID, digest string) string {
	t.Helper()
	record, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "tool/" + runID + "/" + digest[7:19],
		event.FieldToolName:       "Write",
		event.FieldPayloadDigest:  digest,
	})
	if err != nil {
		t.Fatalf("seed tool_call: %v", err)
	}
	return str(record, event.FieldEventID)
}

// seedSigned is a commit_recorded naming the tree the run signed.
func seedSigned(t *testing.T, m *memLedger, runID, repo, tree string) {
	t.Helper()
	if _, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/recorded/" + runID,
		event.FieldRepo:           repo,
		event.FieldTreeHash:       tree,
		event.FieldPatchID:        strings.Repeat("e", 40),
		event.FieldCommitSHA:      strings.Repeat("f", 40),
		event.FieldIntentEventID:  "01a047a5-cc41-7c45-86fd-a88c8c2b5320",
		event.FieldRekorEntryUUID: strings.Repeat("d", 64),
		event.FieldRekorLogIndex:  int64(1),
	}); err != nil {
		t.Fatalf("seed commit_recorded: %v", err)
	}
}

// driftSubjects is every subject a ledger_drift_detected on the chain names.
func driftSubjects(t *testing.T, m *memLedger) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, rec := range m.records {
		if str(rec, event.FieldEventType) != event.EventTypeLedgerDriftDetected {
			continue
		}
		if s := str(rec, event.FieldSubjectEventID); s != "" {
			out[s] = struct{}{}
		}
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/signing"
)

// REC-003 and REC-004 against a real self-hosted Fulcio and Rekor, a real
// SPIRE, a real Postgres and the released gitsign binary (RM-036, #44).
//
// IP §2: "a mocked Fulcio proves nothing about I5". For REC-004 it is stronger
// than that — a mocked Rekor cannot prove the claim at all. The claim is that
// a fully compromised MCP cannot forge attribution because it cannot write to
// a transparency log it does not control (IP §6.10, E8). A fake log that
// answers "no entry" because the test told it to is the test agreeing with
// itself. The log here is the shipped one, the entry the compromised MCP names
// is one the log really does not hold, and the reader really asks it.
//
// # What is planted, and how
//
//	REC-003  A REAL gitsign signature — a real Fulcio certificate whose URI SAN
//	         is `spiffe://innsegl.dev/agent/demo/rm-036/run-planted`, a real
//	         commit object, a real Rekor entry — made by driving
//	         internal/signing directly with a JWT-SVID minted for that identity.
//	         The MCP is never involved, so NOTHING is appended to the chain: the
//	         ledger has never heard of the run. That is the exact state IP §6.5
//	         calls "a Rekor entry for our trust domain with no intent".
//
//	REC-004  A `commit_recorded` appended straight to the chain, naming a commit
//	         SHA no repository holds and a Rekor uuid the log does not hold. It
//	         is written with `source: mcp` because that is the story: threat
//	         model AB-03, "compromised MCP fabricates commit_recorded to frame
//	         an agent". Its intent and its run are real events, because a
//	         compromised MCP would write those too — the only thing it cannot
//	         write is the log entry.
//
// # The negative control
//
// A third run signs legitimately, through the same signer, and its intent, its
// signature and its `commit_recorded` all agree. It must raise NOTHING. Both
// planted cases would pass against a detector that alerts unconditionally; this
// is the one that fails against one.

const (
	driftIntegrationTimeout = 25 * time.Minute

	driftAgentType = "demo"
	driftTaskID    = "rm-036"

	driftLegitRun   = "run-legit"
	driftPlantedRun = "run-planted"
	driftFramedRun  = "run-framed"

	// I6's author policy for a scratch repository: a domain RFC 6761 reserves,
	// so no GitHub account can ever hold it (ADR-0028).
	driftAuthorName  = "innsegl drift test"
	driftAuthorEmail = "agent@innsegl.invalid"
)

// svidMinter is ADR-0019's path — one audience-bound JWT-SVID through the
// SPIRE server's admin socket — as a signing.CredentialSource.
//
// It mints for whatever SPIFFE ID it is given, including one the ledger has
// never heard of. That is not a weakness of the test: it is the capability the
// threat model already assumes (ADR-0011 — the admin socket is unauthenticated
// by construction and contained by a tmpfs, not by authorization), and REC-003
// is the detection control for exactly that.
type svidMinter struct {
	stack    *stack
	spiffeID string
	ttl      time.Duration
}

func (m svidMinter) Credential(ctx context.Context) (signing.Credential, error) {
	out, err := m.stack.spireServer(ctx, "jwt", "mint",
		"-spiffeID", m.spiffeID, "-audience", signing.AudienceSigstore,
		"-ttl", m.ttl.String(), "-output", "json")
	if err != nil {
		return signing.Credential{}, err
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "{") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		return signing.Credential{}, fmt.Errorf("no JSON in `jwt mint` output: %s", out)
	}
	var got struct {
		SVID struct {
			ExpiresAt string `json:"expires_at"`
			Token     string `json:"token"`
		} `json:"svid"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		return signing.Credential{}, fmt.Errorf("decoding `jwt mint` output: %w", err)
	}
	var unix int64
	if _, err := fmt.Sscanf(got.SVID.ExpiresAt, "%d", &unix); err != nil {
		return signing.Credential{}, fmt.Errorf("decoding expires_at %q: %w", got.SVID.ExpiresAt, err)
	}
	return signing.Credential{
		Token: got.SVID.Token, SPIFFEID: m.spiffeID, Audience: signing.AudienceSigstore,
		ExpiresAt: time.Unix(unix, 0).UTC(),
	}, nil
}

func driftSPIFFEID(runID string) string {
	return fmt.Sprintf("spiffe://%s/agent/%s/%s/%s",
		harnessTrustDomain, driftAgentType, driftTaskID, runID)
}

// driftSignature is one real signature, made outside the MCP.
type driftSignature struct {
	commitSHA string
	uuid      string
	logIndex  int64
	identity  string
	worktree  string
	treeHash  string
}

// signOutsideTheMCP stages a file in a scratch repository and signs it with a
// certificate for spiffeID. Nothing is appended to any ledger.
func signOutsideTheMCP(ctx context.Context, t *testing.T, st *stack, root, runID string) driftSignature {
	t.Helper()
	spiffeID := driftSPIFFEID(runID)
	worktree := filepath.Join(root, runID)
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "init", "-q", "-b", "main")
	git(t, worktree, "config", "user.name", driftAuthorName)
	git(t, worktree, "config", "user.email", driftAuthorEmail)
	if err := os.WriteFile(filepath.Join(worktree, "work.txt"),
		[]byte("innsegl RM-036 "+runID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "add", "work.txt")
	treeHash := git(t, worktree, "write-tree")

	signer, err := signing.NewSigner(signing.Config{
		FulcioURL:   st.fulcioURL,
		RekorURL:    st.rekorURL,
		Issuer:      harnessIssuer,
		GitsignPath: st.gitsignPath,
		Author:      signing.AuthorPolicy{AllowUnlinked: true},
	}, svidMinter{stack: st, spiffeID: spiffeID, ttl: 5 * time.Minute})
	if err != nil {
		t.Fatalf("signing.NewSigner(%s): %v", runID, err)
	}
	t.Cleanup(func() {
		if cerr := signer.Close(); cerr != nil {
			t.Logf("closing the signer for %s: %v", runID, cerr)
		}
	})

	result, err := signer.Sign(ctx, signing.Request{
		Repo:        worktree,
		Message:     "innsegl RM-036 " + runID,
		AuthorName:  driftAuthorName,
		AuthorEmail: driftAuthorEmail,
		Claim:       signing.Claim{Identity: spiffeID, Run: runID, Task: driftTaskID},
	})
	if err != nil {
		t.Fatalf("signing %s: %v", runID, err)
	}

	// The signature is real, asserted against git and against Rekor rather
	// than against what the signer said about itself.
	if !strings.Contains(git(t, worktree, "cat-file", "commit", "HEAD"), "gpgsig ") {
		t.Fatalf("%s's commit carries no signature", runID)
	}
	index, err := rekorEntryOf(ctx, st.rekorURL, result.Rekor.UUID)
	if err != nil {
		t.Fatalf("Rekor holds no entry %s for %s: %v", result.Rekor.UUID, runID, err)
	}
	if result.Certificate.SPIFFEID != spiffeID {
		t.Fatalf("%s signed under certificate identity %q, want %q",
			runID, result.Certificate.SPIFFEID, spiffeID)
	}
	return driftSignature{
		commitSHA: result.CommitSHA,
		uuid:      result.Rekor.UUID,
		logIndex:  index,
		identity:  spiffeID,
		worktree:  worktree,
		treeHash:  treeHash,
	}
}

func appendDrift(ctx context.Context, t *testing.T, store *ledger.Store, body event.Fields) event.Fields {
	t.Helper()
	record, err := store.Append(ctx, body)
	if err != nil {
		t.Fatalf("append %s: %v", body[event.FieldEventType], err)
	}
	return record
}

func seedDriftRun(ctx context.Context, t *testing.T, store *ledger.Store, runID string) {
	t.Helper()
	appendDrift(ctx, t, store, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       driftSPIFFEID(runID),
		event.FieldIdempotencyKey: "rm036/register/" + runID,
		event.FieldAgentType:      driftAgentType,
		event.FieldTaskRef:        driftTaskID,
	})
}

// TestREC003AndREC004AgainstARealRekorAndARealSignature is IP §6.10's
// demonstration.
//
//nolint:gocyclo // One measured fact per block; the stack's lifetime is the case's, and splitting it would separate the evidence from what it proves.
func TestREC003AndREC004AgainstARealRekorAndARealSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), driftIntegrationTimeout)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		requireStartup(t, err, "REC-004 is the claim that a compromised MCP cannot "+
			"forge attribution; a mocked Rekor cannot prove it — IP §2.")
	}
	store, _ := freshStore(t)

	st, err := startStack(ctx, repoRoot(t))
	if st != nil {
		t.Cleanup(st.stop)
	}
	if err != nil {
		// This is the gate that bit: a Docker network failure was reported here
		// as a skip, the package read `pass`, and this case — REC-003 and
		// REC-004, against a real Rekor — never ran (#101).
		requireStartup(t, fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w", err),
			fmt.Sprintf("REC-003 and REC-004 go unproven against a real log. "+
				"Start Docker, `go install github.com/sigstore/gitsign@%s`, and "+
				"re-run.", harnessGitsign))
	}
	root := t.TempDir()

	// -----------------------------------------------------------------------
	// The negative control: a run whose intent, signature and record all exist
	// and all agree.
	// -----------------------------------------------------------------------
	seedDriftRun(ctx, t, store, driftLegitRun)
	legit := signOutsideTheMCP(ctx, t, st, root, driftLegitRun)
	legitIntent := appendDrift(ctx, t, store, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          driftLegitRun,
		event.FieldSpiffeID:       legit.identity,
		event.FieldIdempotencyKey: "rm036/intent/" + driftLegitRun,
		event.FieldRepo:           "github.com/innsegl/" + driftLegitRun,
		event.FieldTreeHash:       legit.treeHash,
	})
	legitRecord := appendDrift(ctx, t, store, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          driftLegitRun,
		event.FieldSpiffeID:       legit.identity,
		event.FieldIdempotencyKey: "rm036/recorded/" + driftLegitRun,
		event.FieldRepo:           "github.com/innsegl/" + driftLegitRun,
		event.FieldTreeHash:       legit.treeHash,
		event.FieldCommitSHA:      legit.commitSHA,
		event.FieldRekorEntryUUID: legit.uuid,
		event.FieldRekorLogIndex:  legit.logIndex,
		event.FieldIntentEventID:  str(legitIntent, event.FieldEventID),
	})
	t.Logf("negative control: run %s, commit %s, rekor %s index %d, record %s",
		driftLegitRun, legit.commitSHA, legit.uuid, legit.logIndex,
		str(legitRecord, event.FieldEventID))

	// -----------------------------------------------------------------------
	// REC-003: a real signature under our trust domain, and a chain that has
	// never heard of it.
	// -----------------------------------------------------------------------
	planted := signOutsideTheMCP(ctx, t, st, root, driftPlantedRun)
	for _, rec := range allEvents(ctx, t, store) {
		if str(rec, event.FieldRunID) == driftPlantedRun ||
			str(rec, event.FieldSpiffeID) == planted.identity {
			t.Fatalf("the chain holds an event about the planted run: %v", rec)
		}
	}
	t.Logf("REC-003 plant: commit %s signed under %s, rekor %s index %d, nothing on the chain",
		planted.commitSHA, planted.identity, planted.uuid, planted.logIndex)

	// -----------------------------------------------------------------------
	// REC-004: a fabricated `commit_recorded` naming a commit and an entry
	// that do not exist. AB-03, written by the component it accuses.
	// -----------------------------------------------------------------------
	fabricatedCommit := fmt.Sprintf("%x", sha256.Sum256([]byte("innsegl rm-036 fabrication")))[:40]
	fabricatedUUID := hex.EncodeToString(fmt.Appendf(nil, "%x%x",
		sha256.Sum256([]byte("rm-036 uuid a")), sha256.Sum256([]byte("rm-036 uuid b"))))[:80]
	if _, held := rekorEntryOf(ctx, st.rekorURL, fabricatedUUID); held == nil {
		t.Fatalf("the log holds entry %s; the fabrication is not a fabrication", fabricatedUUID)
	}
	seedDriftRun(ctx, t, store, driftFramedRun)
	framedIntent := appendDrift(ctx, t, store, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          driftFramedRun,
		event.FieldSpiffeID:       driftSPIFFEID(driftFramedRun),
		event.FieldIdempotencyKey: "rm036/intent/" + driftFramedRun,
		event.FieldRepo:           "github.com/innsegl/" + driftFramedRun,
		event.FieldTreeHash:       legit.treeHash,
	})
	fabricated := appendDrift(ctx, t, store, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          driftFramedRun,
		event.FieldSpiffeID:       driftSPIFFEID(driftFramedRun),
		event.FieldIdempotencyKey: "rm036/recorded/" + driftFramedRun,
		event.FieldRepo:           "github.com/innsegl/" + driftFramedRun,
		event.FieldTreeHash:       legit.treeHash,
		event.FieldCommitSHA:      fabricatedCommit,
		event.FieldRekorEntryUUID: fabricatedUUID,
		event.FieldRekorLogIndex:  9999,
		event.FieldIntentEventID:  str(framedIntent, event.FieldEventID),
	})
	t.Logf("REC-004 fabrication: record %s claims commit %s and rekor %s, both absent",
		str(fabricated, event.FieldEventID), fabricatedCommit, fabricatedUUID)

	// -----------------------------------------------------------------------
	// The reconciler, reading the shipped log.
	// -----------------------------------------------------------------------
	log, err := reconciler.NewRekorLog(st.rekorURL, nil)
	if err != nil {
		t.Fatalf("NewRekorLog: %v", err)
	}
	repos, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	var alerts []reconciler.DriftFinding
	build := func() *reconciler.Reconciler {
		alerts = nil
		r, nerr := reconciler.New(reconciler.Config{
			Ledger: store, Appender: store, Repos: repos, Log: log,
			TrustDomain: harnessTrustDomain, ExpireAfter: 24 * time.Hour,
			Alert:   func(context.Context, reconciler.Finding) {},
			Observe: func(reconciler.Result, error) {},
			Drift: &reconciler.DriftConfig{
				Sweep: log,
				Alert: func(_ context.Context, d reconciler.DriftFinding) {
					alerts = append(alerts, d)
					t.Logf("drift alert: %s: %s", d.Kind, d.Detail)
				},
			},
		})
		if nerr != nil {
			t.Fatalf("reconciler.New: %v", nerr)
		}
		return r
	}

	first, err := build().Reconcile(ctx)
	if err != nil {
		t.Fatalf("the first cycle failed: %v", err)
	}
	if !first.Drift.Enabled {
		t.Fatal("drift detection reported itself disabled")
	}
	if first.Drift.Unresolved != 0 {
		t.Fatalf("the cycle could not resolve %d things against a live log: %+v",
			first.Drift.Unresolved, first.Drift.Findings)
	}

	// REC-003.
	if first.Drift.Unattributed != 1 {
		t.Fatalf("REC-003: the cycle found %d unattributed signatures, want 1: %+v",
			first.Drift.Unattributed, first.Drift.Findings)
	}
	unattributed := onlySystemEvent(ctx, t, store, event.EventTypeUnattributedSignatureDetected)
	if got := str(unattributed, event.FieldRekorEntryUUID); got != planted.uuid {
		t.Fatalf("REC-003: the alert names entry %s, want the planted %s", got, planted.uuid)
	}
	if got := member[int64](t, unattributed, event.FieldRekorLogIndex); got != planted.logIndex {
		t.Fatalf("REC-003: the alert names index %d, want %d", got, planted.logIndex)
	}
	if got := str(unattributed, event.FieldCertificateIdentity); got != planted.identity {
		t.Fatalf("REC-003: the alert names identity %s, want %s", got, planted.identity)
	}
	t.Logf("REC-003: unattributed_signature_detected %s names rekor %s under %s",
		str(unattributed, event.FieldEventID), planted.uuid, planted.identity)

	// REC-004.
	if first.Drift.Fabricated != 1 {
		t.Fatalf("REC-004: the cycle found %d fabricated records, want 1: %+v",
			first.Drift.Fabricated, first.Drift.Findings)
	}
	drift := onlySystemEvent(ctx, t, store, event.EventTypeLedgerDriftDetected)
	if got := str(drift, event.FieldSubjectEventID); got != str(fabricated, event.FieldEventID) {
		t.Fatalf("REC-004: the drift event names subject %s, want the fabricated record %s",
			got, str(fabricated, event.FieldEventID))
	}
	if got := str(drift, event.FieldRunID); got != driftFramedRun {
		t.Fatalf("REC-004: the drift event names run %q, want %q", got, driftFramedRun)
	}
	t.Logf("REC-004: ledger_drift_detected %s names subject %s, reason %q",
		str(drift, event.FieldEventID), str(drift, event.FieldSubjectEventID),
		str(drift, event.FieldReason))

	// The negative control: the legitimate record raised nothing, and the
	// legitimate entry was not called unattributed.
	if n := len(first.Drift.Findings); n != 2 {
		t.Fatalf("the cycle raised %d findings, want exactly the two planted ones: %+v",
			n, first.Drift.Findings)
	}
	for _, f := range first.Drift.Findings {
		if f.SubjectEventID == str(legitRecord, event.FieldEventID) {
			t.Fatalf("the legitimate commit_recorded was flagged: %+v", f)
		}
		if f.RekorEntryUUID == legit.uuid {
			t.Fatalf("the legitimate signature was called unattributed: %+v", f)
		}
	}
	if len(alerts) != 2 {
		t.Fatalf("the operator sink saw %d alerts, want 2: %+v", len(alerts), alerts)
	}
	t.Logf("negative control: the legitimate run's record and signature raised nothing")

	// -----------------------------------------------------------------------
	// Idempotency, with a reconciler that has never seen the first cycle.
	// -----------------------------------------------------------------------
	countBefore, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	second, err := build().Reconcile(ctx)
	if err != nil {
		t.Fatalf("the second cycle failed: %v", err)
	}
	if len(second.Drift.Appended) != 0 || len(second.Drift.Findings) != 0 {
		t.Fatalf("a fresh second reconciler appended %v and re-reported %+v",
			second.Drift.Appended, second.Drift.Findings)
	}
	countAfter, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if countAfter != countBefore {
		t.Fatalf("the second cycle grew the chain from %d to %d", countBefore, countAfter)
	}

	all, err := store.Events(ctx, 1, countAfter)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if _, verr := ledger.Verify(all); verr != nil {
		t.Fatalf("the chain does not verify after the alerts: %v", verr)
	}
	t.Logf("idempotent: cycle two appended nothing; the chain is %d events and verifies",
		countAfter)
}

func allEvents(ctx context.Context, t *testing.T, store *ledger.Store) []event.Fields {
	t.Helper()
	n, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n == 0 {
		return nil
	}
	all, err := store.Events(ctx, 1, n)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	return all
}

// onlySystemEvent returns the chain's one event of a type, whatever run scope
// it carries. onlyEvent in integration_test.go reads per run, and a
// system-scope alert belongs to no run.
func onlySystemEvent(ctx context.Context, t *testing.T, store *ledger.Store, eventType string) event.Fields {
	t.Helper()
	var got []event.Fields
	for _, rec := range allEvents(ctx, t, store) {
		if str(rec, event.FieldEventType) == eventType {
			got = append(got, rec)
		}
	}
	if len(got) != 1 {
		t.Fatalf("the chain holds %d %s events, want exactly 1", len(got), eventType)
	}
	return got[0]
}

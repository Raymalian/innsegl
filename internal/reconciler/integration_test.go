// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/rundir"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/spire"
)

// REC-001, REC-002 and REC-005 against a real Fulcio, a real Rekor, a real
// SPIRE, a real Postgres and the released gitsign binary.
//
// One top-level case, because the stack takes minutes to boot and because
// REC-002's assertion is a comparison BETWEEN two runs — a crashed one and an
// uncrashed one — which cannot be split across independent tests without
// splitting the evidence from what it proves.
//
// # How each crash window is produced
//
// Both are produced by driving the SHIPPED `sign_commit` tool over the shipped
// MCP transport, and breaking exactly one thing at the moment ADR-0033 says
// the window opens.
//
//	B → C   the tool's `Ledger` refuses the `commit_recorded` append and
//	        nothing else. Phase A ran, Phase B ran — a real certificate, a real
//	        commit object, a real Rekor entry — and Phase C did not. That is
//	        the same DURABLE residue a SIGKILL between B and C leaves, because
//	        Phase C's only effect on durable state is that append, and it is
//	        controllable to the exact boundary rather than to a sleep.
//	        The residue is then asserted directly, in all four places: the
//	        intent is on the chain, the commit object exists, Rekor holds its
//	        entry, and no `commit_recorded` names the intent.
//
//	A → B   Fulcio is STOPPED and the tool is handed a Sigstore probe that
//	        still answers healthy. ADR-0033 gate 7 probes Sigstore before Phase
//	        A precisely so an outage does not leave an intent behind; a stale
//	        probe is exactly the physical case it cannot cover, which ADR-0033
//	        names in as many words — "Fulcio can die between gate 7 and `git
//	        commit`; that residue is the A → B window". So the outage is real,
//	        gitsign's failure is real, and the intent is really dangling. It is
//	        the same shape RM-034 used for SIG-003 (ADR-0032).

const (
	integrationTimeout = 25 * time.Minute
	// The author I6 admits for these runs. AllowUnlinked is the policy the
	// signing suite uses for a scratch repository.
	testAuthorName  = "innsegl reconciler test"
	testAuthorEmail = "agent@innsegl.invalid"
	// FLAGGED, not worked around: `internal/rundir` uses `task_ref` VERBATIM
	// as the SPIFFE ID's {task_id}, and doc 02 §5 makes {task_id} lowercase —
	// so doc 02's own golden fixture 01, whose task_ref is "JIRA-118" and
	// whose SPIFFE ID holds "jira-118", would be refused by the run directory
	// as an identity that "does not name run ... of task ...". That is
	// internal/rundir's to answer (RM-068, #89) and this case does not paper
	// over it: it uses a task_ref that is already lowercase, so the run
	// resolves, and the finding is reported rather than fixed here.
	testTaskRef = "rm-035"
)

// crashAtPhaseC is the ledger the crashed arm's `sign_commit` is given. Every
// append reaches the real chain except the one that closes the protocol.
type crashAtPhaseC struct {
	store *ledger.Store
	mu    sync.Mutex
	armed bool
	fired int
}

func (c *crashAtPhaseC) Append(ctx context.Context, body event.Fields) (event.Fields, error) {
	if str(body, event.FieldEventType) == event.EventTypeCommitRecorded {
		c.mu.Lock()
		armed := c.armed
		if armed {
			c.fired++
		}
		c.mu.Unlock()
		if armed {
			return nil, errors.New("the ledger went away between Phase B and Phase C")
		}
	}
	return c.store.Append(ctx, body)
}

// healthyWhileStopped is ADR-0024's probe, frozen in the "reachable" answer.
// It stands in for the probe having run a moment before Fulcio died — the one
// case ADR-0033 gate 7 says it cannot cover, and therefore the A → B window.
type healthyWhileStopped struct{}

func (healthyWhileStopped) ProbeSigning(context.Context) error      { return nil }
func (healthyWhileStopped) ProbeTransparency(context.Context) error { return nil }

// openEntries is the SPIRE registration-entry gate. Whether SPIRE still holds
// an entry is get_credential's and TC-SPI's subject and is measured there; this
// case is about the ledger, the signature and the repair.
type openEntries struct{}

func (openEntries) RequireActiveRun(context.Context, spire.RunRef) error { return nil }

// stackMinter mints one audience-bound JWT-SVID through the SPIRE server's
// admin socket — ADR-0019's path, the one get_credential uses.
type stackMinter struct {
	stack *stack
	ttl   time.Duration
}

func (m stackMinter) MintJWTSVID(ctx context.Context, spiffeID, audience string) (mcp.MintedCredential, error) {
	out, err := m.stack.spireServer(ctx, "jwt", "mint",
		"-spiffeID", spiffeID, "-audience", audience,
		"-ttl", m.ttl.String(), "-output", "json")
	if err != nil {
		return mcp.MintedCredential{}, err
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "{") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		return mcp.MintedCredential{}, fmt.Errorf("no JSON in `jwt mint` output: %s", out)
	}
	var got struct {
		SVID struct {
			ExpiresAt string `json:"expires_at"`
			Token     string `json:"token"`
		} `json:"svid"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		return mcp.MintedCredential{}, fmt.Errorf("decoding `jwt mint` output: %w", err)
	}
	var unix int64
	if _, err := fmt.Sscanf(got.SVID.ExpiresAt, "%d", &unix); err != nil {
		return mcp.MintedCredential{}, fmt.Errorf("decoding expires_at %q: %w", got.SVID.ExpiresAt, err)
	}
	return mcp.MintedCredential{
		Token: got.SVID.Token, SPIFFEID: spiffeID, Audience: audience,
		ExpiresAt: time.Unix(unix, 0).UTC(),
	}, nil
}

// world is everything one integration case runs against.
type world struct {
	stack   *stack
	store   *ledger.Store
	session *sdk.ClientSession
	root    string
	crash   *crashAtPhaseC
	signers mcp.SignCommitSigners
	runs    mcp.CredentialRuns
	idem    *mcp.IdempotencyStore
	sigOK   mcp.HealthSigstore
}

// TestREC001And002And005AgainstRealSigstoreAndARealChain is the whole of this
// component's proof, on a real stack.
//
//nolint:gocyclo // One measured fact per block; splitting it would separate the evidence from what it proves, and the stack's lifetime is the case's.
func TestREC001And002And005AgainstRealSigstoreAndARealChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), integrationTimeout)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping: no docker (%v). REC-002 proves nothing about I3 or I5 "+
			"against a mock — IP §2, \"a mocked Fulcio proves nothing about I5\".", err)
	}
	store, dsn := freshStore(t)

	st, err := startStack(ctx, repoRoot(t))
	if st != nil {
		t.Cleanup(st.stop)
	}
	if err != nil {
		t.Skipf("skipping: could not start the SPIRE and Sigstore stacks (%v). "+
			"Both crash windows go unproven against a real signature. Start Docker, "+
			"`go install github.com/sigstore/gitsign@%s`, and re-run.", err, harnessGitsign)
	}

	w := newWorld(ctx, t, st, store, dsn)

	// -----------------------------------------------------------------------
	// The arm that did not crash. It is the definition REC-002's state diff is
	// measured against, so it runs first and through the same shipped tool.
	// -----------------------------------------------------------------------
	clean := w.run(ctx, t, "run-clean")
	w.configureSignCommit(t, w.crash.store, w.sigOK)
	cleanOut := w.signOK(ctx, t, clean, "the run that never crashed")

	// -----------------------------------------------------------------------
	// The B → C window, produced by refusing exactly the Phase C append.
	// -----------------------------------------------------------------------
	crashed := w.run(ctx, t, "run-crashed")
	w.configureSignCommit(t, w.crash, w.sigOK)
	w.crash.arm(true)
	if wire := w.signExpectingFailure(ctx, t, crashed, "the run that crashed"); wire == "" {
		t.Fatal("sign_commit succeeded with Phase C refused")
	}
	w.crash.arm(false)
	if w.crash.fired != 1 {
		t.Fatalf("the Phase C append was refused %d times, want 1", w.crash.fired)
	}

	// The residue, asserted in all four places rather than assumed.
	crashedIntent := onlyEvent(ctx, t, store, crashed.runID, event.EventTypeCommitIntent)
	intentID := member[string](t, crashedIntent, event.FieldEventID)
	if recs := eventsOfType(ctx, t, store, crashed.runID, event.EventTypeCommitRecorded); len(recs) != 0 {
		t.Fatalf("the crashed run already holds %d commit_recorded events", len(recs))
	}
	crashedHead := git(t, crashed.worktree, "rev-parse", "HEAD")
	if !strings.Contains(git(t, crashed.worktree, "cat-file", "commit", "HEAD"), "gpgsig ") {
		t.Fatal("the crashed run's commit carries no signature; the B → C window was not reached")
	}
	crashedTree := git(t, crashed.worktree, "rev-parse", "HEAD^{tree}")
	if got := member[string](t, crashedIntent, event.FieldTreeHash); got != crashedTree {
		t.Fatalf("the intent names tree %s and HEAD's tree is %s", got, crashedTree)
	}
	t.Logf("B → C residue: intent %s at position %d, commit %s, no commit_recorded",
		intentID, member[int64](t, crashedIntent, event.FieldChainPosition), crashedHead)

	// -----------------------------------------------------------------------
	// The A → B window: Fulcio really stopped, the probe stale.
	// -----------------------------------------------------------------------
	dangling := w.run(ctx, t, "run-dangling")
	if _, serr := st.compose(ctx, st.sigFiles, "stop", "fulcio"); serr != nil {
		t.Fatalf("stopping fulcio: %v", serr)
	}
	w.configureSignCommit(t, w.crash.store, healthyWhileStopped{})
	objectsBefore := commitObjects(t, dangling.worktree)
	if wire := w.signExpectingFailure(ctx, t, dangling, "the run whose CA died"); wire == "" {
		t.Fatal("sign_commit succeeded with Fulcio stopped")
	}
	if got := commitObjects(t, dangling.worktree); got != objectsBefore {
		t.Fatalf("the repository gained a commit object with Fulcio down: %d -> %d "+
			"(IP §6.3)", objectsBefore, got)
	}
	danglingIntent := onlyEvent(ctx, t, store, dangling.runID, event.EventTypeCommitIntent)
	danglingID := member[string](t, danglingIntent, event.FieldEventID)
	if _, serr := st.compose(ctx, st.sigFiles, "start", "fulcio"); serr != nil {
		t.Fatalf("restarting fulcio: %v", serr)
	}
	if aerr := st.awaitTrustMaterial(ctx); aerr != nil {
		t.Fatalf("fulcio never came back: %v", aerr)
	}
	t.Logf("A → B residue: intent %s, no commit object, no Rekor entry", danglingID)

	// -----------------------------------------------------------------------
	// The reconciler, built from nothing but the ledger, the workspace and the
	// log. It has never seen the tool that crashed.
	// -----------------------------------------------------------------------
	log, err := reconciler.NewRekorLog(st.rekorURL, nil)
	if err != nil {
		t.Fatalf("NewRekorLog: %v", err)
	}
	repos, err := reconciler.NewGitWorkspace(w.root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	build := func(expireAfter time.Duration) *reconciler.Reconciler {
		r, nerr := reconciler.New(reconciler.Config{
			Ledger: store, Appender: store, Repos: repos, Log: log,
			TrustDomain: harnessTrustDomain, ExpireAfter: expireAfter,
			Alert: func(_ context.Context, f reconciler.Finding) {
				t.Logf("alert: %s %s: %s", f.Outcome, f.IntentEventID, f.Detail)
			},
			Observe: func(reconciler.Result, error) {},
		})
		if nerr != nil {
			t.Fatalf("reconciler.New: %v", nerr)
		}
		return r
	}

	// A window nothing has aged past: the repair must still happen (a
	// signature that exists is not an in-flight one) and the expiry must not.
	early, err := build(24 * time.Hour).Reconcile(ctx)
	if err != nil {
		t.Fatalf("the first cycle failed: %v", err)
	}
	if early.Repaired != 1 || early.Expired != 0 {
		t.Fatalf("first cycle (24h window): Repaired=%d Expired=%d, want 1 and 0; %+v",
			early.Repaired, early.Expired, early.Findings)
	}

	// REC-001: a window everything has aged past. The dangling intent expires.
	late, err := build(time.Nanosecond).Reconcile(ctx)
	if err != nil {
		t.Fatalf("the second cycle failed: %v", err)
	}
	if late.Expired != 1 || late.Repaired != 0 {
		t.Fatalf("second cycle (0 window): Expired=%d Repaired=%d, want 1 and 0; %+v",
			late.Expired, late.Repaired, late.Findings)
	}
	expired := onlyEvent(ctx, t, store, dangling.runID, event.EventTypeCommitIntentExpired)
	if got := member[string](t, expired, event.FieldSource); got != event.SourceReconciler {
		t.Fatalf("the expiry carries source %q, want %q", got, event.SourceReconciler)
	}
	if got := member[string](t, expired, event.FieldIntentEventID); got != danglingID {
		t.Fatalf("the expiry names intent %s, want %s", got, danglingID)
	}

	// -----------------------------------------------------------------------
	// REC-002: the repair is real, and it is the entry Rekor actually holds.
	// -----------------------------------------------------------------------
	repaired := onlyEvent(ctx, t, store, crashed.runID, event.EventTypeCommitRecorded)
	if got := member[string](t, repaired, event.FieldSource); got != event.SourceReconciler {
		t.Fatalf("the repair carries source %q, want %q — doc 06 §3.3 labels repaired "+
			"history as repaired, and it can only do that if the record says so",
			got, event.SourceReconciler)
	}
	if got := member[string](t, repaired, event.FieldCommitSHA); got != crashedHead {
		t.Fatalf("the repair names commit %s and HEAD is %s", got, crashedHead)
	}
	uuid := member[string](t, repaired, event.FieldRekorEntryUUID)
	index, err := rekorEntryOf(ctx, st.rekorURL, uuid)
	if err != nil {
		t.Fatalf("the Rekor entry the repair names does not exist: %v", err)
	}
	if got := member[int64](t, repaired, event.FieldRekorLogIndex); got != index {
		t.Fatalf("the repair says log index %d and Rekor holds the entry at %d", got, index)
	}
	t.Logf("REC-002 repair: commit %s, rekor uuid %s index %d, intent %s",
		crashedHead, uuid, index, intentID)

	// -----------------------------------------------------------------------
	// REC-002, the part IP §6.5 states explicitly: "assert the ledger
	// converges to the same state as the no-crash run".
	// -----------------------------------------------------------------------
	cleanEvents := runEvents(ctx, t, store, clean.runID)
	crashedEvents := runEvents(ctx, t, store, crashed.runID)
	diff := diffRuns(t,
		projection{events: cleanEvents, run: clean, commitSHA: cleanOut.commit, rekorUUID: cleanOut.uuid},
		projection{events: crashedEvents, run: crashed, commitSHA: crashedHead, rekorUUID: uuid})

	want := []string{"commit_recorded.source: mcp -> reconciler"}
	if !slices.Equal(diff, want) {
		t.Fatalf("the repaired run and the uncrashed run differ in:\n  %s\nwant exactly:\n  %s",
			strings.Join(diff, "\n  "), strings.Join(want, "\n  "))
	}
	t.Logf("REC-002 state diff: the two runs are identical except %v", want)

	// -----------------------------------------------------------------------
	// REC-005: a fresh reconciler over the reconciled state appends nothing.
	// -----------------------------------------------------------------------
	countBefore, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	third, err := build(time.Nanosecond).Reconcile(ctx)
	if err != nil {
		t.Fatalf("the third cycle failed: %v", err)
	}
	if len(third.Appended) != 0 || third.Open != 0 {
		t.Fatalf("a fresh third reconciler appended %v and found %d open intents",
			third.Appended, third.Open)
	}
	countAfter, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if countAfter != countBefore {
		t.Fatalf("the third cycle grew the chain from %d to %d", countBefore, countAfter)
	}

	// And the chain still verifies end to end: nothing the reconciler wrote
	// broke the hash chain it wrote into.
	all, err := store.Events(ctx, 1, countAfter)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if _, verr := ledger.Verify(all); verr != nil {
		t.Fatalf("the chain does not verify after the repair: %v", verr)
	}
	t.Logf("REC-005: cycle three appended nothing; the chain is %d events and verifies",
		countAfter)
}

// ---------------------------------------------------------------------------
// The state diff.
// ---------------------------------------------------------------------------

type projection struct {
	events    []event.Fields
	run       testRun
	commitSHA string
	rekorUUID string
}

// diffRuns compares two runs' events member by member, after replacing every
// value that is legitimately per-run with a placeholder.
//
// The substitution map is built from values the CASE knows — this run's id, its
// SPIFFE ID, its repo, the commit git holds, the entry Rekor holds — so a
// member the reconciler filled in from the WRONG run would not be in the map
// and would show up as a literal difference. Anything not in the map has to
// match exactly. That is what makes this a state diff rather than a shape
// comparison: the only way to pass is to have written the same values, about
// the right things.
func diffRuns(t *testing.T, a, b projection) []string {
	t.Helper()
	left, right := a.normalise(t), b.normalise(t)
	if len(left) != len(right) {
		t.Fatalf("the two runs hold %d and %d events:\n%v\n%v",
			len(left), len(right), typesOf(a.events), typesOf(b.events))
	}

	var diff []string
	for i := range left {
		lt := str(a.events[i], event.FieldEventType)
		rt := str(b.events[i], event.FieldEventType)
		if lt != rt {
			diff = append(diff, fmt.Sprintf("position %d: %s -> %s", i, lt, rt))
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(union(left[i], right[i]))) {
			lv, lok := left[i][name]
			rv, rok := right[i][name]
			switch {
			case lok && !rok:
				diff = append(diff, fmt.Sprintf("%s.%s: %v -> absent", lt, name, lv))
			case !lok && rok:
				diff = append(diff, fmt.Sprintf("%s.%s: absent -> %v", lt, name, rv))
			case fmt.Sprint(lv) != fmt.Sprint(rv):
				diff = append(diff, fmt.Sprintf("%s.%s: %v -> %v", lt, name, lv, rv))
			}
		}
	}
	return diff
}

// normalise replaces this run's own identifiers with placeholders and drops the
// members the ledger assigns and which cannot be equal between two runs on one
// chain: event_id, chain_position, ts and the two hashes.
func (p projection) normalise(t *testing.T) []event.Fields {
	t.Helper()
	subst := map[string]string{
		p.run.runID:    "<run_id>",
		p.run.spiffeID: "<spiffe_id>",
		p.run.repo:     "<repo>",
		p.run.key:      "<idempotency_key>",
		p.commitSHA:    "<commit_sha>",
		p.rekorUUID:    "<rekor_entry_uuid>",
	}
	// The intent's event_id is what commit_recorded.intent_event_id names, so
	// it is a per-run value with a meaning and gets its own placeholder rather
	// than being dropped with the other assigned ids.
	for _, rec := range p.events {
		if str(rec, event.FieldEventType) == event.EventTypeCommitIntent {
			if id := str(rec, event.FieldEventID); id != "" {
				subst[id] = "<intent_event_id>"
			}
		}
	}
	// The derived phase keys carry a digest of the caller's key, which differs
	// per run by construction (ADR-0033 decision 5). The PREFIX is the part
	// that must agree, so the digest is replaced and the prefix is not.
	for _, rec := range p.events {
		if k, ok := rec[event.FieldIdempotencyKey].(string); ok {
			if rest, found := strings.CutPrefix(k, "sign_commit/intent/"); found {
				subst[rest] = "<key_digest>"
			}
		}
	}

	dropped := map[string]bool{
		event.FieldEventID: true, event.FieldChainPosition: true, event.FieldTS: true,
		event.EventHashField: true, event.FieldPrevEventHash: true,
		// credential_expiry is a wall-clock value from SPIRE; two runs cannot
		// agree on it and it says nothing about convergence.
		event.FieldCredentialExpiry: true,
		// The tree hash is the content of a scratch repository whose files
		// differ per run on purpose, so that the two runs cannot accidentally
		// share a commit. It is checked directly against git instead.
		event.FieldTreeHash: true,
	}

	out := make([]event.Fields, 0, len(p.events))
	for _, rec := range p.events {
		normalised := event.Fields{}
		for name, value := range rec {
			if dropped[name] {
				continue
			}
			if s, ok := value.(string); ok {
				normalised[name] = replaceAll(s, subst)
				continue
			}
			normalised[name] = value
		}
		// The Rekor log index is an integer assigned by the log in write
		// order; two runs cannot share one. Its correctness is asserted
		// against Rekor itself above.
		delete(normalised, event.FieldRekorLogIndex)
		out = append(out, normalised)
	}
	return out
}

// replaceAll substitutes longest key first, deterministically.
//
// Order matters and map order would not do: a run's SPIFFE ID and its repo
// both CONTAIN its run id, so substituting the run id first leaves
// "spiffe://innsegl.dev/agent/demo/rm-035/<run_id>" for one run and
// "<spiffe_id>" for the other, and the diff reports a difference that is the
// test's own nondeterminism rather than the ledger's. Longest first makes the
// projection a function of the events alone.
func replaceAll(s string, subst map[string]string) string {
	keys := slices.Collect(maps.Keys(subst))
	slices.SortFunc(keys, func(a, b string) int {
		if len(a) != len(b) {
			return len(b) - len(a)
		}
		return strings.Compare(a, b)
	})
	for _, from := range keys {
		if from == "" {
			continue
		}
		s = strings.ReplaceAll(s, from, subst[from])
	}
	return s
}

func union(a, b event.Fields) map[string]struct{} {
	out := map[string]struct{}{}
	for name := range a {
		out[name] = struct{}{}
	}
	for name := range b {
		out[name] = struct{}{}
	}
	return out
}

func typesOf(events []event.Fields) []string {
	out := make([]string, 0, len(events))
	for _, rec := range events {
		out = append(out, str(rec, event.FieldEventType)+"/"+str(rec, event.FieldSource))
	}
	return out
}

// ---------------------------------------------------------------------------
// Wiring.
// ---------------------------------------------------------------------------

type testRun struct {
	runID    string
	spiffeID string
	repo     string
	worktree string
	key      string
	staged   string
	taskRef  string
}

type signResult struct {
	commit string
	uuid   string
}

func newWorld(ctx context.Context, t *testing.T, st *stack, store *ledger.Store, dsn string) *world {
	t.Helper()

	runs, err := rundir.New(rundir.Config{Events: store})
	if err != nil {
		t.Fatalf("rundir.New: %v", err)
	}
	if cerr := mcp.ConfigureGetCredential(mcp.CredentialConfig{
		Runs:    runs,
		Entries: openEntries{},
		Minter:  stackMinter{stack: st, ttl: 5 * time.Minute},
		Ledger:  store,
	}); cerr != nil {
		t.Fatalf("ConfigureGetCredential: %v", cerr)
	}

	sigstore, err := mcp.NewSigstoreEndpoints(mcp.SigstoreConfig{
		FulcioURL: st.fulcioURL, RekorURL: st.rekorURL,
	})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	w := &world{
		stack: st,
		store: store,
		root:  t.TempDir(),
		crash: &crashAtPhaseC{store: store},
		signers: mcp.NewGitsignSigners(signing.Config{
			FulcioURL:   st.fulcioURL,
			RekorURL:    st.rekorURL,
			Issuer:      harnessIssuer,
			GitsignPath: st.gitsignPath,
			Author:      signing.AuthorPolicy{AllowUnlinked: true},
		}),
		runs:  runs,
		idem:  mcp.NewIdempotencyStore(pool),
		sigOK: sigstore,
	}

	srv, err := mcp.New(mcp.Config{Version: "v0.0.0-reconciler"})
	if err != nil {
		t.Fatalf("mcp.New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-reconciler-test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: httpSrv.URL}, nil)
	if err != nil {
		t.Fatalf("connecting to %s: %v", httpSrv.URL, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	w.session = session
	return w
}

// configureSignCommit installs the shipped tool with one dependency swapped.
// literalIdentity is identity mode `literal` — what the system did before
// RM-079 (#116), and what this harness's fixtures are written in terms of.
func literalIdentity(t *testing.T) *identity.Pseudonymiser {
	t.Helper()
	p, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return p
}

func (w *world) configureSignCommit(t *testing.T, appender mcp.SignCommitLedger, probe mcp.HealthSigstore) {
	t.Helper()
	workspace, err := mcp.NewWorkspace(w.root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	restore, err := mcp.ConfigureSignCommit(mcp.SignCommitConfig{
		Runs:        w.runs,
		Ledger:      appender,
		Idempotency: w.idem,
		Workspace:   workspace,
		Sigstore:    probe,
		Credentials: mcp.SignCommitThroughGetCredential{},
		Signers:     w.signers,
		AuthorName:  testAuthorName,
		AuthorEmail: testAuthorEmail,
		// Identity mode `literal`: this harness seeds literal SPIFFE IDs and
		// asserts against them. RM-079's pseudonymous default is measured in
		// internal/mcp (PRI-003) and in test/smoke (PRI-004).
		Pseudonyms: literalIdentity(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	t.Cleanup(restore)
}

// run seeds one registered run and a scratch repository with one staged file.
func (w *world) run(ctx context.Context, t *testing.T, runID string) testRun {
	t.Helper()
	const agentType = "demo"
	const taskID = "rm-035"
	spiffeID := fmt.Sprintf("spiffe://%s/agent/%s/%s/%s", harnessTrustDomain, agentType, taskID, runID)
	repo := "github.com/innsegl/" + runID

	if _, err := w.store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: "register-" + runID,
		event.FieldAgentType:      agentType,
		event.FieldTaskRef:        testTaskRef,
	}); err != nil {
		t.Fatalf("seed run_registered for %s: %v", runID, err)
	}

	worktree := filepath.Join(w.root, filepath.FromSlash(repo))
	if err := os.MkdirAll(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "init", "-q", "-b", "main")
	git(t, worktree, "config", "user.name", testAuthorName)
	git(t, worktree, "config", "user.email", testAuthorEmail)
	// A body unique to the run, so two runs can never share a tree hash and
	// the state diff cannot pass by two runs pointing at one commit.
	if err := os.WriteFile(filepath.Join(worktree, "work.txt"),
		[]byte("innsegl RM-035 "+runID+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, worktree, "add", "work.txt")
	staged := git(t, worktree, "write-tree")

	return testRun{
		runID: runID, spiffeID: spiffeID, repo: repo, worktree: worktree,
		key: "sign-" + runID, staged: staged, taskRef: testTaskRef,
	}
}

func (w *world) callSign(ctx context.Context, t *testing.T, r testRun, message string) *sdk.CallToolResult {
	t.Helper()
	res, err := w.session.CallTool(ctx, &sdk.CallToolParams{
		Name: string(mcp.ToolSignCommit),
		Arguments: map[string]any{
			"run_id":          r.runID,
			"repo":            r.repo,
			"staged_ref":      r.staged,
			"message":         message,
			"task_ref":        r.taskRef,
			"idempotency_key": r.key,
		},
	})
	if err != nil {
		t.Fatalf("tools/call sign_commit: transport failure: %v", err)
	}
	return res
}

func (w *world) signOK(ctx context.Context, t *testing.T, r testRun, message string) signResult {
	t.Helper()
	res := w.callSign(ctx, t, r, message)
	if res.IsError {
		t.Fatalf("sign_commit(%s) failed: %v", r.runID, res.StructuredContent)
	}
	raw, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("sign_commit returned %T", res.StructuredContent)
	}
	commit, isString := raw["commit_sha"].(string)
	if !isString {
		t.Fatalf("sign_commit returned no commit_sha: %v", raw)
	}
	entry, isObject := raw["rekor_entry"].(map[string]any)
	if !isObject {
		t.Fatalf("sign_commit returned no rekor_entry object: %v", raw)
	}
	uuid, isString := entry["uuid"].(string)
	if !isString {
		t.Fatalf("sign_commit's rekor_entry carries no uuid: %v", raw)
	}
	if commit == "" || uuid == "" {
		t.Fatalf("sign_commit returned no commit or no rekor entry: %v", raw)
	}
	return signResult{commit: commit, uuid: uuid}
}

func (w *world) signExpectingFailure(ctx context.Context, t *testing.T, r testRun, message string) string {
	t.Helper()
	res := w.callSign(ctx, t, r, message)
	if !res.IsError {
		return ""
	}
	return fmt.Sprint(res.StructuredContent)
}

func (c *crashAtPhaseC) arm(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armed = on
}

// ---------------------------------------------------------------------------
// Reading the chain back.
// ---------------------------------------------------------------------------

func runEvents(ctx context.Context, t *testing.T, store *ledger.Store, runID string) []event.Fields {
	t.Helper()
	events, err := store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun(%s): %v", runID, err)
	}
	return events
}

func eventsOfType(ctx context.Context, t *testing.T, store *ledger.Store, runID, eventType string) []event.Fields {
	t.Helper()
	var out []event.Fields
	for _, rec := range runEvents(ctx, t, store, runID) {
		if str(rec, event.FieldEventType) == eventType {
			out = append(out, rec)
		}
	}
	return out
}

func onlyEvent(ctx context.Context, t *testing.T, store *ledger.Store, runID, eventType string) event.Fields {
	t.Helper()
	got := eventsOfType(ctx, t, store, runID, eventType)
	if len(got) != 1 {
		t.Fatalf("run %s holds %d %s events, want exactly 1", runID, len(got), eventType)
	}
	return got[0]
}

// commitObjects counts commit objects in the repository, reachable or not —
// ADR-0032's question, which is what "the repo has no new commit object at
// all" (IP §6.3) is asserted against.
func commitObjects(t *testing.T, worktree string) int {
	t.Helper()
	out := git(t, worktree, "cat-file", "--batch-all-objects",
		"--batch-check=%(objectname) %(objecttype)")
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), " commit") {
			n++
		}
	}
	return n
}

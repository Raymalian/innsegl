// SPDX-License-Identifier: Apache-2.0

package chaos

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/reconciler"
	"innsegl.dev/innsegl/internal/segment"
)

// ===========================================================================
// TC-OPS, layer F — OPS-001, the dependency partition matrix (RM-051, #59).
//
// doc 07 OPS-001, verbatim, because every assertion below is one clause of it:
//
//	Dependency partition matrix: block each of {SPIRE, Postgres, Fulcio,
//	Rekor, object storage} singly and in pairs during mixed workload
//	-> Every operation fails with the correct error class; zero invariant
//	   violations after heal + reconcile. Proves: IP §6 (all).
//
// This is the case that turns IP §6's claims into measurements. Everything in
// §6 is written as an assertion about what happens when something is not
// there — "spire-server down at register_agent -> IDENTITY_UNAVAILABLE",
// "Postgres down at any record_event -> LEDGER_UNAVAILABLE", "Fulcio down ->
// SIGNING_UNAVAILABLE ... the commit is not created", "Rekor down -> signing
// fails (TRANSPARENCY_UNAVAILABLE)". Until something takes each of them away
// and reads the class off the wire, those are claims about code nobody ran.
//
// # THE EXPECTED CLASS IS DERIVED, NOT GUESSED
//
// prtExpect below is a total function from (operation, set of partitioned
// dependencies) to the IP §4 class the operation must report. For a single
// partition it is IP §6 read literally. For a PAIR it needs one more input,
// and getting it from the specification rather than from a guess is the
// difference between a test and a tautology: when two dependencies are down,
// the class a caller sees is decided by which one the tool touches FIRST, and
// that order is a property of the shipped code, MEASURED by reading it:
//
//	register_agent   idempotency(PG) -> ledger(PG) -> SPIRE
//	get_credential   ledger(PG) -> SPIRE -> SPIRE -> ledger(PG)
//	record_event     idempotency(PG) -> ledger(PG) -> ledger(PG)
//	retire_agent     ledger(PG) -> ledger(PG) -> SPIRE
//	sign_commit      idempotency(PG) -> ledger(PG) -> [Fulcio+Rekor probe]
//	                 -> SPIRE -> Phase A(PG) -> Phase B(Fulcio+Rekor) -> Phase C(PG)
//
// Two consequences fall straight out of that order and are asserted as such.
// Postgres shadows every other class, because every tool reaches the ledger or
// the idempotency store before anything else. And Sigstore shadows SPIRE in
// sign_commit, because IP §6.5 puts the reachability probe BEFORE Phase A on
// purpose: there is no point appending an intent that cannot be fulfilled.
//
// A cell whose observed class disagreed with this table would be one of two
// things and both are findings: the code changed which dependency it touches
// first, or IP §6's reading here is wrong. Neither may pass quietly, so the
// assertion is on the exact class and never on "some plausible class".
//
// # WHAT MAKES THESE ASSERTIONS NON-VACUOUS
//
// Every assertion in a partition test is at risk of passing for the wrong
// reason — an operation that never ran, a fixture that staged nothing, a
// harness that skipped. Five things are done about it:
//
//  1. A NEGATIVE CONTROL runs first, in the parent's body where `-run` cannot
//     filter it out, and gates everything below. It is the same workload
//     against the same server with every route intact, and it must SUCCEED in
//     every one of its seven operations. If it does not, no cell may report.
//  2. EVERY CELL HEALS AND RE-RUNS. An operation that failed under partition
//     is repeated once the route is back, in the same session, and must
//     succeed. A refusal followed by a success is a refusal that was one
//     healthy route away from working; a refusal on its own is
//     indistinguishable from a broken fixture.
//  3. THE PARTITION IS CONFIRMED BEFORE IT IS RELIED ON, twice over: the route
//     must refuse connections, AND the dependency behind it must still answer
//     a health probe that does not travel the route. The second half is what
//     makes the class a statement about REACHABILITY.
//  4. THE HEAL IS CONFIRMED TOO. A gate that re-bound is not a route that
//     works, so heal polls a real probe through the gate.
//  5. THE UNPARTITIONED DEPENDENCIES ARE ASSERTED HEALTHY in the same breath.
//     A cell in which everything is down proves nothing about which class
//     belongs to which dependency.
//
// # THE ONE THING A GATE CANNOT PROVE
//
// See partitionharness_test.go's header for why a partition here is a severed
// route rather than a stopped container. The honesty cost is that a gate says
// nothing about a dependency that has CRASHED. TestOPS001GateSeveranceMatches
// ARealOutage pins that down by taking Fulcio away for real, with `docker
// compose stop`, and requiring the same class the gate produced.
// ===========================================================================

// The operations of the mixed workload. The first five are the MCP tools of
// IP §4; the last two are the sealer and the anchorer, which are the only
// paths in this system that reach object storage and the only reason doc 07
// OPS-001 names object storage at all (measured: internal/mcp does not import
// internal/segment, so no MCP tool can reach a bucket).
const (
	prtOpRegister   = "register_agent"
	prtOpCredential = "get_credential"
	prtOpRecord     = "record_event"
	prtOpSign       = "sign_commit"
	prtOpRetire     = "retire_agent"
	prtOpSeal       = "seal_segment"
	prtOpAnchor     = "anchor_segment"
)

// prtOK is prtExpect's answer for "this operation must succeed".
const prtOK = ""

// prtRepo is the one repository the workload signs in, in doc 02 §5's
// `host/org/name` form.
const prtRepo = "github.com/innsegl/ops-001"

// prtCell is one cell of the matrix: the set of dependencies partitioned.
type prtCell struct{ down []string }

func (c prtCell) has(dep string) bool {
	for _, d := range c.down {
		if d == dep {
			return true
		}
	}
	return false
}

func (c prtCell) name() string {
	kind := "single"
	if len(c.down) == 2 {
		kind = "pair"
	}
	return fmt.Sprintf("%s %s", kind, strings.Join(c.down, "+"))
}

// prtMatrix is doc 07 OPS-001's "singly and in pairs" over the five
// dependencies: five singles and ten pairs, in a fixed order so a failing run
// names the same cell as every other run.
func prtMatrix() []prtCell {
	deps := prtDependencies()
	cells := make([]prtCell, 0, len(deps)+len(deps)*(len(deps)-1)/2)
	for _, d := range deps {
		cells = append(cells, prtCell{down: []string{d}})
	}
	for i := range deps {
		for j := i + 1; j < len(deps); j++ {
			cells = append(cells, prtCell{down: []string{deps[i], deps[j]}})
		}
	}
	return cells
}

// prtExpect is IP §6 as a function: the IP §4 error class an operation must
// report while the named dependencies are partitioned, or prtOK when the
// operation must still succeed.
//
// The order of the arms IS the dependency touch order quoted in the file
// header. It is not an ordering of severity or of plausibility.
func prtExpect(op string, c prtCell) string {
	switch op {
	// IP §6.4: "Postgres down at any record_event -> LEDGER_UNAVAILABLE."
	// record_event touches nothing else, and that is the claim: a tool must
	// not fail because a dependency it does not use is unreachable.
	case prtOpRecord:
		if c.has(prtPostgres) {
			return string(mcp.ClassLedgerUnavailable)
		}
		return prtOK

	// IP §6.1: "spire-server down at register_agent -> IDENTITY_UNAVAILABLE,
	// retryable." IP §6.4: identity-issuing operations fail closed when the
	// ledger is gone, because I3 admits no action without a record — and the
	// idempotency claim is the first thing register_agent does, so Postgres
	// shadows SPIRE in the pair.
	case prtOpRegister, prtOpCredential, prtOpRetire:
		switch {
		case c.has(prtPostgres):
			return string(mcp.ClassLedgerUnavailable)
		case c.has(prtSPIRE):
			return string(mcp.ClassIdentityUnavailable)
		default:
			return prtOK
		}

	// IP §6.3, both clauses, plus §6.5's ordering: the Sigstore reachability
	// probe runs BEFORE Phase A, so a Fulcio or Rekor partition is reported
	// before any credential is minted and before any intent is appended.
	// Fulcio shadows Rekor when both are down — internal/mcp/health.go reports
	// SIGNING_UNAVAILABLE for the both-down case, deliberately.
	case prtOpSign:
		switch {
		case c.has(prtPostgres):
			return string(mcp.ClassLedgerUnavailable)
		case c.has(prtFulcio):
			return string(mcp.ClassSigningUnavailable)
		case c.has(prtRekor):
			return string(mcp.ClassTransparencyUnavailable)
		case c.has(prtSPIRE):
			return string(mcp.ClassIdentityUnavailable)
		default:
			return prtOK
		}
	}
	panic("prtExpect: no expectation declared for operation " + op)
}

// ---------------------------------------------------------------------------

func TestOPS001DependencyPartitionMatrix(t *testing.T) {
	w := requirePartitionWorld(t)
	w.openLedger(t)
	w.openWORM(t)
	w.initRepo(t)
	w.startDaemon(t)

	// The control is a precondition, not a case, and it lives in the parent's
	// body for one reason: a subtest can be filtered out. `-run '.../pair
	// spire+rekor'` would skip a control subtest and run the cell anyway,
	// which is precisely the state in which "the operation failed" means
	// nothing. Its t.Fatalf stops the parent before any cell starts.
	prtNegativeControl(t, w, "the negative control: every route intact")

	for _, cell := range prtMatrix() {
		t.Run(cell.name(), func(t *testing.T) { prtRunCell(t, w, cell) })
	}

	// IP §6.5 through a partition rather than through a crash: the one window
	// the cells above cannot reach, because every cell partitions BEFORE the
	// call starts and the Sigstore probe then refuses ahead of Phase A.
	t.Run("mid-flight partition after Phase A", func(t *testing.T) {
		prtMidFlightRekorPartition(t, w)
	})

	// The control on the harness itself.
	t.Run("a severed route reports what a stopped container reports", func(t *testing.T) {
		prtGateFidelity(t, w)
	})

	// The closing sweep. Everything healed, the reconciler run to a fixed
	// point, the chain verified to its tip, and the whole workload run once
	// more — because "zero invariant violations after heal and reconcile" is a
	// claim about the END state and not about any one cell.
	prtNegativeControl(t, w, "the closing control: after fifteen partitions and a heal")
	prtRequireConverged(t, w, "the closing sweep")
	w.verifyChain(t, "the closing sweep")
	w.requireReady(t, "the closing sweep")
}

// ---------------------------------------------------------------------------
// One cell.
// ---------------------------------------------------------------------------

func prtRunCell(t *testing.T, w *prtWorld, cell prtCell) {
	t.Helper()

	// 1. The fixtures, made while every route is intact. A cell that could not
	//    even prepare its runs would report failures belonging to its own
	//    set-up.
	fx := w.prepare(t, cell.name())

	commitsBefore := w.commitObjects(t)

	// 2. Sever, and confirm — the route refuses, the dependency behind it is
	//    still healthy, and everything else is still reachable.
	w.severAndConfirm(t, cell)
	defer w.healQuiet(cell)

	// 3. The mixed workload, in flight, all at once.
	got := w.mixedWorkload(t, fx)

	// 4. Every operation against its expectation.
	for _, op := range prtWorkloadOps() {
		outcome, ok := got[op]
		if !ok {
			t.Fatalf("%s: the workload did not run %s at all", cell.name(), op)
		}
		prtAssertOutcome(t, cell, outcome)
	}

	// 5. IP §6.3, the absence clause: "with Fulcio blocked, assert the repo has
	//    no new commit object at all", and the same for Rekor. Asked of the
	//    OBJECT DATABASE rather than of HEAD, so a commit created and then not
	//    referenced is still caught.
	//
	//    Keyed on what sign_commit ACTUALLY did rather than on what it was
	//    expected to do: a cell in which the expectation was wrong has already
	//    reported that above, and asking "no commit" of a call that succeeded
	//    would report a second, misleading failure for the same cause.
	if signed := got[prtOpSign]; !signed.ok && signed.transport == nil {
		commitsAfter := w.commitObjects(t)
		if len(commitsAfter) != len(commitsBefore) {
			t.Errorf("%s: sign_commit failed with %s and the object database gained %d "+
				"commit object(s) anyway (%v -> %v).\n\nIP §6.3: \"The commit is not "+
				"created. There is no unsigned fallback, no local-key fallback, no "+
				"'sign later' queue.\"",
				cell.name(), signed.fail.Class,
				len(commitsAfter)-len(commitsBefore), commitsBefore, commitsAfter)
		}
	}

	// 6. IP §6.3's last clause: "No indefinite hangs holding repo locks."
	if stale := w.staleLocks(t); len(stale) != 0 {
		t.Errorf("%s: git locks left behind after the partition: %v", cell.name(), stale)
	}

	// 7. Heal, and the per-cell negative control: everything that failed must
	//    now succeed. This is what makes step 4 a measurement rather than an
	//    observation that something went wrong.
	w.healAndConfirm(t, cell)
	prtPerCellControl(t, w, cell, got)

	// 8. Heal and reconcile, then the invariants — doc 07 OPS-001's second
	//    clause, asked after every cell rather than once at the end, so a
	//    violation names the partition that caused it.
	prtRequireConverged(t, w, cell.name())
	w.verifyChain(t, cell.name())
	w.requireReady(t, cell.name())
}

func prtWorkloadOps() []string {
	return []string{
		prtOpRegister, prtOpCredential, prtOpRecord,
		prtOpSign, prtOpRetire, prtOpSeal, prtOpAnchor,
	}
}

// prtAssertOutcome is the whole of "every operation fails with the correct
// error class".
func prtAssertOutcome(t *testing.T, cell prtCell, o prtOutcome) {
	t.Helper()

	if o.transport != nil {
		t.Fatalf("%s: %s did not answer at all: %v\n\ndoc 04 §2 asks for "+
			"\"correct error classes, never silent degradation\"; a dropped transport "+
			"is neither a class nor a degradation an operator can read.",
			cell.name(), o.op, o.transport)
	}

	// The sealer and the anchorer are not MCP tools and carry no IP §4 class.
	// They are asserted against internal/segment's own vocabulary.
	switch o.op {
	case prtOpSeal, prtOpAnchor:
		prtAssertSegmentOutcome(t, cell, o)
		return
	}

	want := prtExpect(o.op, cell)
	if want == prtOK {
		if !o.ok {
			t.Errorf("%s: %s failed with %s while every dependency it uses was "+
				"reachable: %s\n\nIP §6 makes a tool fail closed on ITS OWN "+
				"dependencies. A tool that fails because something it does not use is "+
				"unreachable is coupled to a dependency nothing documents.",
				cell.name(), o.op, o.fail.Class, o.fail.Message)
		}
		return
	}
	if o.ok {
		t.Errorf("%s: %s SUCCEEDED while %s was partitioned; %s was required.\n\n"+
			"This is the silent-degradation failure doc 04 §2 names: an operation that "+
			"reports success without the dependency it needs has either used a route "+
			"nobody configured or skipped the work.",
			cell.name(), o.op, strings.Join(cell.down, " and "), want)
		return
	}
	if o.fail.Class != want {
		t.Errorf("%s: %s reported %s, want %s.\n\nmessage: %s\n\nThe class is the only "+
			"thing an agent can act on (IP §4). The expectation comes from IP §6 and "+
			"from the dependency touch order quoted at the head of this file; a "+
			"disagreement is either a change in that order or a wrong reading of IP §6, "+
			"and neither may pass quietly.",
			cell.name(), o.op, o.fail.Class, want, o.fail.Message)
		return
	}
	// IP §4 / ADR-0016: a class that names a dependency outage is retryable,
	// and a caller told otherwise gives up on a condition that will clear.
	if !o.fail.Retryable {
		t.Errorf("%s: %s reported %s with retryable=false. Every dependency-outage "+
			"class in IP §4 is retryable (ADR-0016): the condition is outside the "+
			"request and may clear on its own.", cell.name(), o.op, o.fail.Class)
	}
}

// prtAssertSegmentOutcome asserts the two operations that are not MCP tools.
//
// The sealer writes through the WORM store and the anchorer talks to Rekor.
// Neither has an IP §4 class — internal/segment keeps its own vocabulary, and
// deliberately so — so what is asserted is the sentinel, and above all the
// sentinel that must NOT appear.
func prtAssertSegmentOutcome(t *testing.T, cell prtCell, o prtOutcome) {
	t.Helper()
	down := cell.has(prtObject)
	if o.op == prtOpAnchor {
		down = cell.has(prtRekor)
	}
	if !down {
		if !o.ok {
			t.Errorf("%s: %s failed while its dependency was reachable: %s",
				cell.name(), o.op, o.fail.Message)
		}
		return
	}
	if o.ok {
		t.Errorf("%s: %s succeeded while its dependency was partitioned. IP §6.4 "+
			"admits anchoring lag as a bounded degradation and admits no silent "+
			"success at all.", cell.name(), o.op)
		return
	}
	if o.op == prtOpSeal && o.fail.Class == prtSealMisreadAsEmpty {
		t.Errorf("%s: the sealer read a partitioned object store as an EMPTY one "+
			"(%s). internal/segment/worm.go states the rule this breaks: \"the sealer "+
			"treats ErrObjectNotFound as 'go ahead and write', and a broken store must "+
			"not be mistaken for an empty one.\" Mistaking the two is how a segment "+
			"gets written twice, or written over.",
			cell.name(), segment.ErrObjectNotFound)
	}
}

// prtSealMisreadAsEmpty is the marker prtOutcome carries when a seal failed
// with segment.ErrObjectNotFound — the one failure mode a partitioned object
// store must never be reported as.
const prtSealMisreadAsEmpty = "SEGMENT_OBJECT_NOT_FOUND"

// ---------------------------------------------------------------------------
// The workload.
// ---------------------------------------------------------------------------

// prtFixtures is what one cell needs, all of it created while every route is
// intact so that nothing in the set-up can be blamed for a cell's result.
type prtFixtures struct {
	cell string
	// runA carries get_credential, record_event and sign_commit.
	runA string
	// runB is retired, so retirement cannot race the other three.
	runB string
	// stagedRef is a tree object id: `git write-tree` over a freshly staged
	// file, which is the only form sign_commit's StagedTree accepts (the tree
	// it names must equal the index, and must differ from HEAD).
	stagedRef string
	// records are the ledger events this cell's seal covers.
	records []event.Fields
	// sealed is the segment_sealed body the anchorer anchors.
	sealed event.Fields
}

func (w *prtWorld) prepare(t *testing.T, cell string) prtFixtures {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	fx := prtFixtures{cell: cell}
	fx.runA = w.mustRegister(ctx, t, "a")
	fx.runB = w.mustRegister(ctx, t, "b")
	fx.stagedRef = w.stage(t)

	// A segment to seal, taken off the chain the server has actually written.
	// A synthesised one would seal fine against a partitioned store and prove
	// nothing about the records this system produces.
	records, err := w.store.Events(ctx, 1, 8)
	if err != nil {
		t.Fatalf("%s: reading the first records off the chain to seal: %v", cell, err)
	}
	if len(records) == 0 {
		t.Fatalf("%s: the chain is empty, so there is nothing to seal and the "+
			"object-storage half of the matrix would be vacuous", cell)
	}
	fx.records = records

	sealer := &segment.Sealer{Store: prtMemStore{}}
	sealed, err := sealer.Seal(segment.Request{Records: records})
	if err != nil {
		t.Fatalf("%s: sealing into memory to build the anchorer's input: %v", cell, err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("%s: minting an event id: %v", cell, err)
	}
	body, err := sealed.Event(segment.EventMeta{
		EventID: id.String(),
		TS:      event.NewTimestamp(time.Now().UTC()),
	})
	if err != nil {
		t.Fatalf("%s: building the segment_sealed body: %v", cell, err)
	}
	fx.sealed = body
	return fx
}

// prtMemStore is an in-memory Store used ONLY to precompute a segment_sealed
// body for the anchorer. It is never the store under test: the sealer under
// test writes through w.worm, which is a real MinIO behind a real gate.
type prtMemStore map[string][]byte

func (m prtMemStore) Get(name string) ([]byte, error) {
	if b, ok := m[name]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("%w: %s", segment.ErrObjectNotFound, name)
}

func (m prtMemStore) Put(name string, data []byte) error {
	m[name] = data
	return nil
}

// mixedWorkload runs all seven operations concurrently, which is what "during
// a mixed workload" asks for: the partition lands on work that is in flight,
// not on an idle server.
func (w *prtWorld) mixedWorkload(t *testing.T, fx prtFixtures) map[string]prtOutcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var (
		mu  sync.Mutex
		out = map[string]prtOutcome{}
		wg  sync.WaitGroup
	)
	record := func(o prtOutcome) {
		mu.Lock()
		defer mu.Unlock()
		out[o.op] = o
	}
	run := func(f func() prtOutcome) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			record(f())
		}()
	}

	run(func() prtOutcome {
		return w.call(ctx, prtOpRegister, mcp.ToolRegisterAgent, map[string]any{
			"agent_type":      prtAgentType,
			"task_id":         prtTaskID,
			"idempotency_key": w.key("reg"),
		})
	})
	run(func() prtOutcome {
		return w.call(ctx, prtOpCredential, mcp.ToolGetCredential, map[string]any{
			"run_id":   fx.runA,
			"audience": "sigstore",
		})
	})
	run(func() prtOutcome {
		return w.call(ctx, prtOpRecord, mcp.ToolRecordEvent, map[string]any{
			"run_id":          fx.runA,
			"event_type":      "partition-probe",
			"payload_digest":  "",
			"idempotency_key": w.key("rec"),
		})
	})
	run(func() prtOutcome {
		return w.call(ctx, prtOpSign, mcp.ToolSignCommit, map[string]any{
			"run_id":          fx.runA,
			"repo":            prtRepo,
			"staged_ref":      fx.stagedRef,
			"message":         "OPS-001 " + fx.cell,
			"task_ref":        prtTaskID,
			"idempotency_key": w.key("sign"),
		})
	})
	run(func() prtOutcome {
		return w.call(ctx, prtOpRetire, mcp.ToolRetireAgent, map[string]any{
			"run_id": fx.runB,
		})
	})
	run(func() prtOutcome { return w.seal(ctx, fx) })
	run(func() prtOutcome { return w.anchor(ctx, fx) })

	wg.Wait()
	for _, op := range prtWorkloadOps() {
		t.Logf("  %s", out[op])
	}
	return out
}

// seal writes one segment through the REAL WORM store, which addresses the
// object-storage gate.
func (w *prtWorld) seal(ctx context.Context, fx prtFixtures) prtOutcome {
	started := time.Now()
	sealer := &segment.Sealer{Store: w.worm}
	_, err := sealer.Seal(segment.Request{Records: fx.records})
	took := time.Since(started)
	if err == nil {
		return prtOutcome{op: prtOpSeal, ok: true, took: took}
	}
	class := "SEGMENT_WRITE_FAILED"
	if errors.Is(err, segment.ErrObjectNotFound) {
		class = prtSealMisreadAsEmpty
	}
	_ = ctx
	return prtOutcome{op: prtOpSeal, fail: prtWireError{Class: class, Message: err.Error()}, took: took}
}

// anchor asks the anchorer to put one sealed segment's Merkle root into Rekor,
// through the Rekor gate.
//
// The retry policy is tightened from the shipped default (five attempts, one
// second base, five minute cap). IP §6.4 requires "retry with backoff and
// alert", and the shipped numbers are the right ones for a deployment; here
// they would spend five minutes per partitioned cell proving something the
// anchorer's own tests already prove. What this cell measures is the CLASS of
// the outcome, not the schedule.
func (w *prtWorld) anchor(ctx context.Context, fx prtFixtures) prtOutcome {
	started := time.Now()
	signer, err := segment.GenerateAnchorSigner()
	if err != nil {
		return prtOutcome{op: prtOpAnchor, took: time.Since(started),
			fail: prtWireError{Class: "SEGMENT_ANCHOR_CONFIG", Message: err.Error()}}
	}
	a := &segment.Anchorer{
		Log:    &segment.RekorClient{BaseURL: w.gate(prtRekor).url(), Signer: signer},
		Policy: segment.RetryPolicy{Attempts: 2, Base: 100 * time.Millisecond, Max: time.Second, Multiplier: 2},
	}
	_, err = a.Anchor(ctx, fx.sealed)
	took := time.Since(started)
	if err == nil {
		return prtOutcome{op: prtOpAnchor, ok: true, took: took}
	}
	return prtOutcome{op: prtOpAnchor, took: took,
		fail: prtWireError{Class: "SEGMENT_ANCHOR_FAILED", Message: err.Error()}}
}

// ---------------------------------------------------------------------------
// Severing, healing, and confirming both.
// ---------------------------------------------------------------------------

func (w *prtWorld) severAndConfirm(t *testing.T, cell prtCell) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, dep := range cell.down {
		g := w.gate(dep)
		if err := g.sever(); err != nil {
			t.Fatalf("%s: severing the route to %s: %v", cell.name(), dep, err)
		}
	}
	for _, dep := range cell.down {
		g := w.gate(dep)
		// (a) the route is gone. Polled rather than assumed: `sever` returns
		// when the listener is closed, and a case that asserted an error
		// before the port had actually stopped answering would be asserting
		// against a race — test/failure's stopSigService discipline.
		if !prtWaitFor(30*time.Second, g.refuses) {
			t.Fatalf("%s: the route to %s was severed and %s still accepts "+
				"connections; the partition this cell depends on did not happen",
				cell.name(), dep, g.addr())
		}
		// (b) the dependency behind it is STILL HEALTHY. Without this the cell
		// would be asserting against a dependency that had died for some other
		// reason, and the error class would be about the wrong thing.
		if err := g.health(ctx); err != nil {
			t.Fatalf("%s: %s is partitioned but it is also not healthy: %v\n\n"+
				"A partition is a healthy dependency that cannot be reached. If the "+
				"dependency is down, this cell measures an outage and not a partition.",
				cell.name(), dep, err)
		}
	}
	// (c) everything NOT in this cell is still reachable through its own gate.
	// A cell in which more than the named dependencies are unreachable proves
	// nothing about which class belongs to which.
	for _, dep := range prtDependencies() {
		if cell.has(dep) {
			continue
		}
		if w.gate(dep).refuses() {
			t.Fatalf("%s: %s is not in this cell and its route refuses connections "+
				"anyway; the cell would attribute its class to the wrong dependency",
				cell.name(), dep)
		}
	}
	t.Logf("partitioned %s (confirmed: route refuses, dependency healthy)",
		strings.Join(cell.down, " + "))
}

func (w *prtWorld) healAndConfirm(t *testing.T, cell prtCell) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, dep := range cell.down {
		if err := w.gate(dep).restore(ctx); err != nil {
			t.Fatalf("%s: %v", cell.name(), err)
		}
	}
	// A re-bound listener is not a working route. Confirmed with the same
	// probe the sever step used, but through the GATE this time.
	for _, dep := range cell.down {
		probe := w.probeThroughGate(dep)
		var last error
		if !prtWaitFor(90*time.Second, func() bool {
			last = probe(ctx)
			return last == nil
		}) {
			t.Fatalf("%s: the route to %s was restored and still does not carry "+
				"traffic: %v", cell.name(), dep, last)
		}
	}
	// And a route that carries the HARNESS's traffic is still not a healed
	// SYSTEM. MEASURED: with the SPIRE route back and answering a TCP dial,
	// register_agent still returned IDENTITY_UNAVAILABLE, because the server's
	// gRPC channel was in TRANSIENT_FAILURE and grpc.NewClient fails an RPC
	// fast rather than waiting for the channel to come back. A heal confirmed
	// only from this process would have made every per-cell control fail for a
	// reason that has nothing to do with the partition.
	//
	// So the heal is confirmed from the SERVER's own point of view, through the
	// endpoint an operator would use: /readyz, which probes SPIRE, the ledger
	// and Sigstore itself (IP §6.6).
	if err := w.awaitReady(t, 2*time.Minute); err != nil {
		t.Fatalf("%s: the routes are back and `innsegl serve` still does not report "+
			"itself ready: %v", cell.name(), err)
	}
}

// healQuiet is the last-resort restore a cell that failed leaves behind, so the
// next cell starts from a healthy world rather than from this one's wreckage.
// It asserts nothing: a t.Fatalf from a deferred call during an already-failing
// test replaces the failure the reader needs to see.
func (w *prtWorld) healQuiet(cell prtCell) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, dep := range cell.down {
		if err := w.gate(dep).restore(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: restoring the route to %s: %v\n", dep, err)
		}
	}
}

// probeThroughGate is the health probe of a dependency, aimed at its GATE.
func (w *prtWorld) probeThroughGate(dep string) func(context.Context) error {
	g := w.gate(dep)
	switch dep {
	case prtSPIRE:
		return func(ctx context.Context) error {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", g.addr())
			if err != nil {
				return err
			}
			return c.Close()
		}
	case prtPostgres:
		return func(ctx context.Context) error {
			return prtPingPostgres(ctx, prtDSN(g.addr(), prtPGDatabase))
		}
	case prtFulcio:
		return func(ctx context.Context) error { return w.probeFulcioAt(ctx, g.url()) }
	case prtRekor:
		return func(ctx context.Context) error { return w.probeRekorAt(ctx, g.url()) }
	case prtObject:
		return func(ctx context.Context) error { return prtMinIOReady(ctx, g.addr()) }
	}
	panic("probeThroughGate: no probe for " + dep)
}

// ---------------------------------------------------------------------------
// Controls.
// ---------------------------------------------------------------------------

// prtNegativeControl runs the whole workload with every route intact and
// requires every operation to succeed.
//
// This is the anti-vacuity gate. Every assertion in the matrix is of the form
// "this failed, and with this class"; every one of them is satisfied by a
// workload that never ran. What this establishes is the one thing that makes
// them mean anything: that this exact arrangement, left alone, WORKS.
func prtNegativeControl(t *testing.T, w *prtWorld, why string) {
	t.Helper()
	fx := w.prepare(t, why)
	got := w.mixedWorkload(t, fx)
	for _, op := range prtWorkloadOps() {
		o, ok := got[op]
		if !ok {
			t.Fatalf("%s: %s did not run", why, op)
		}
		if o.transport != nil {
			t.Fatalf("%s: %s did not answer: %v", why, op, o.transport)
		}
		if !o.ok {
			t.Fatalf("%s: %s failed with everything reachable (%s: %s).\n\nEvery "+
				"assertion in OPS-001 is that an operation FAILS under partition, and "+
				"every one of those is vacuous unless this control passes.",
				why, op, o.fail.Class, o.fail.Message)
		}
	}
	t.Logf("%s: all %d operations succeeded", why, len(prtWorkloadOps()))
}

// prtPerCellControl re-runs, once the routes are back, every operation this
// cell saw fail.
func prtPerCellControl(t *testing.T, w *prtWorld, cell prtCell, before map[string]prtOutcome) {
	t.Helper()
	failed := make([]string, 0, len(before))
	for _, op := range prtWorkloadOps() {
		if !before[op].ok {
			failed = append(failed, op)
		}
	}
	if len(failed) == 0 {
		return
	}
	fx := w.prepare(t, cell.name()+" (heal control)")
	got := w.mixedWorkload(t, fx)
	for _, op := range failed {
		o := got[op]
		if !o.ok {
			t.Errorf("%s: %s failed under partition AND after the heal (%s: %s).\n\n"+
				"A refusal that does not become a success once the route is back is "+
				"indistinguishable from a broken fixture, and proves nothing about the "+
				"partition.", cell.name(), op, o.fail.Class, o.fail.Message)
		}
	}
	sort.Strings(failed)
	t.Logf("heal control: %s succeeded again", strings.Join(failed, ", "))
}

// ---------------------------------------------------------------------------
// "Zero invariant violations after heal and reconcile."
// ---------------------------------------------------------------------------

func prtRequireConverged(t *testing.T, w *prtWorld, when string) {
	t.Helper()

	// An intent younger than the expiry window is not a violation — it is the
	// window doing its job. IP §6.5 says the reconciler "expires intents with
	// no matching Rekor entry AFTER A BOUNDED WINDOW", and a test that read
	// `open` as `unresolved` would be asserting that the bound does not exist.
	//
	// MEASURED: the mid-flight case healed, reconciled and asserted inside
	// 400ms, so its intent was younger than the window and the pass correctly
	// reported `open`. So the window is waited out rather than shortened to
	// nothing: an expiry window of zero would expire an intent whose signature
	// is still in flight, which is the false expiry the bound exists to
	// prevent, and a test that needed that to pass would be testing a
	// reconciler nobody deploys.
	first := w.reconcile(t, when)
	for attempt := 1; prtStillOpen(first) != 0 && attempt <= 4; attempt++ {
		t.Logf("%s: %d intent(s) still inside the %s expiry window; waiting it out",
			when, prtStillOpen(first), prtExpireAfter)
		time.Sleep(prtExpireAfter + 50*time.Millisecond)
		first = w.reconcile(t, when)
	}
	if n := prtStillOpen(first); n != 0 {
		t.Errorf("%s: %d intent(s) are still inside the expiry window after four "+
			"waits of %s. findings: %v", when, n, prtExpireAfter, first.Findings)
	}
	if first.Unresolved != 0 || first.Ambiguous != 0 {
		t.Errorf("%s: the reconciler left %d intent(s) unresolved and %d ambiguous "+
			"after the heal.\n\nIP §6.5 requires every intent to reach a terminal "+
			"state: repaired from Rekor, or expired. findings: %v",
			when, first.Unresolved, first.Ambiguous, first.Findings)
	}

	// A second pass over the same state must append NOTHING. That is what
	// "converged" means, and it is also the only way to tell a reconciler that
	// resolved the drift from one that is generating it.
	second := w.reconcile(t, when+" (second pass)")
	if len(second.Appended) != 0 {
		t.Errorf("%s: a second reconciliation pass appended %d event(s): %v.\n\n"+
			"IP §6.5's reconciler is idempotent by construction (deterministic "+
			"idempotency keys); a pass that keeps writing has not converged.",
			when, len(second.Appended), second.Appended)
	}
	if second.Unresolved != 0 || second.Ambiguous != 0 {
		t.Errorf("%s: after two passes, %d unresolved and %d ambiguous intent(s) remain",
			when, second.Unresolved, second.Ambiguous)
	}

	// The alert-level events. None of these may exist: an unattributed
	// signature is a bug or a compromise (IP §6.5), and ledger drift is the
	// anchorer having given up (IP §6.4). This matrix creates neither.
	//
	// HONEST SCOPE. The reconciler above runs with `Drift` unset, so it does
	// not SWEEP Rekor looking for signatures with no intent; what is asserted
	// here is that no such event is on the chain, which is a weaker claim.
	// Turning the sweep on would make every anchor this file writes to Rekor a
	// candidate finding and would put REC-004's subject inside OPS-001's
	// budget. REC-004 is where the sweep is proved; this is where its ABSENCE
	// of findings after a partition is checked.
	records := w.chain(t)
	for _, kind := range []string{
		event.EventTypeUnattributedSignatureDetected,
		event.EventTypeLedgerDriftDetected,
	} {
		if n := prtCountType(records, kind); n != 0 {
			t.Errorf("%s: the chain carries %d %s event(s). That is alert-level: "+
				"either this code has a defect or something signed outside the "+
				"attributed path (IP §6.5, §6.10).", when, n, kind)
		}
	}

	// Every intent terminal. Read straight off the chain rather than from the
	// reconciler's own report, because the report is the thing under test.
	open := prtOpenIntents(records)
	if len(open) != 0 {
		t.Errorf("%s: %d commit_intent event(s) have neither a commit_recorded nor a "+
			"commit_intent_expired after heal and reconcile: %v.\n\nIP §6.5: a dangling "+
			"intent is the partial-failure gap, and closing it is the reconciler's "+
			"whole job.", when, len(open), open)
	}
}

// prtStillOpen counts the intents a cycle found open and left open because the
// expiry window had not passed. They partition Open alongside Repaired,
// Expired, Unresolved and Ambiguous, and Result has no counter for them.
func prtStillOpen(res reconciler.Result) int {
	n := 0
	for _, f := range res.Findings {
		if f.Outcome == reconciler.OutcomeOpen {
			n++
		}
	}
	return n
}

func prtCountType(records []map[string]any, kind string) int {
	n := 0
	for _, r := range records {
		if got, ok := r[event.FieldEventType].(string); ok && got == kind {
			n++
		}
	}
	return n
}

// prtOpenIntents returns the event ids of every commit_intent with no
// commit_recorded and no commit_intent_expired referring to it.
func prtOpenIntents(records []map[string]any) []string {
	intents := map[string]bool{}
	for _, r := range records {
		kind, ok := r[event.FieldEventType].(string)
		if !ok || kind != event.EventTypeCommitIntent {
			continue
		}
		if id, ok := r[event.FieldEventID].(string); ok {
			intents[id] = true
		}
	}
	for _, r := range records {
		kind, ok := r[event.FieldEventType].(string)
		if !ok || (kind != event.EventTypeCommitRecorded &&
			kind != event.EventTypeCommitIntentExpired) {
			continue
		}
		if id, ok := r[event.FieldIntentEventID].(string); ok {
			delete(intents, id)
		}
	}
	out := make([]string, 0, len(intents))
	for id := range intents {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// requireReady asks the shipped /readyz endpoint whether every dependency is
// back. IP §6.6: "per-dependency status is exposed so operators see *which*
// dependency is failing" — a heal that the server itself does not report is
// not a heal an operator could act on.
func (w *prtWorld) requireReady(t *testing.T, when string) {
	t.Helper()
	if err := w.awaitReady(t, 90*time.Second); err != nil {
		t.Errorf("%s: %v", when, err)
	}
}

// awaitReady polls /readyz until the server reports every dependency reachable.
// The body is returned in the error, because IP §6.6 requires the per-dependency
// status to be there and "not ready" without saying WHICH is the report an
// operator cannot act on.
func (w *prtWorld) awaitReady(t *testing.T, within time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within+30*time.Second)
	defer cancel()
	var last string
	ok := prtWaitFor(within, func() bool {
		body, err := prtGET(ctx, "http://"+w.daemon.health+"/readyz")
		if err != nil {
			last = err.Error()
			return false
		}
		last = string(body)
		return strings.Contains(last, `"ready":true`)
	})
	if ok {
		return nil
	}
	return fmt.Errorf("/readyz never reported ready within %s. last: %s", within, last)
}

// ---------------------------------------------------------------------------
// IP §6.5 through a partition: sever Rekor once the intent is on the chain.
// ---------------------------------------------------------------------------

// The window the fifteen cells above cannot reach.
//
// Every cell partitions BEFORE the call starts, and sign_commit's Sigstore
// probe then refuses ahead of Phase A — which is correct, and which means no
// cell above ever leaves a dangling `commit_intent`. The partial-failure gap of
// IP §6.5 opens only when the dependency goes away AFTER the intent is
// appended, so this case waits for the intent to appear on the chain and cuts
// Rekor at that instant.

// prtMidFlightAttempts bounds how many times the window is chased.
//
// MEASURED on this machine: one sign_commit against a local Fulcio and Rekor
// takes about 400ms end to end, and the trigger polls every 2ms for a single
// indexed row, so the intent is seen long before Phase B finishes. A miss is
// therefore rare — and it is retried rather than SKIPPED, because a skip exits
// zero and this is the only case in the file that exercises IP §6.5's
// partial-failure gap (#101, and scripts/test-no-skips.sh).
const (
	prtMidFlightAttempts = 6
	prtMidFlightPoll     = 2 * time.Millisecond
	prtMidFlightBudget   = 60 * time.Second
)

// prtIntentKey rebuilds the idempotency key sign_commit derives for its Phase A
// append, so the trigger can watch for ONE indexed row instead of re-reading
// the whole chain every two milliseconds.
//
// internal/mcp keeps the derivation unexported, so it is transcribed. That is
// deliberate rather than regrettable: if the derivation ever changes, this
// trigger stops firing and the case FAILS saying the window never opened,
// which is the loud outcome. A test that read the key through the code that
// wrote it could not notice.
func prtIntentKey(callerKey string) string {
	digest := strings.TrimPrefix(event.Digest([]byte(strconv.Quote(callerKey))), event.HashPrefix)
	return "sign_commit/intent/" + digest[:32]
}

func prtMidFlightRekorPartition(t *testing.T, w *prtWorld) {
	t.Helper()

	for attempt := 1; attempt <= prtMidFlightAttempts; attempt++ {
		landed, o := prtChaseTheIntent(t, w, attempt)
		if !landed {
			t.Logf("attempt %d: sign_commit finished before the cut landed; retrying", attempt)
			continue
		}
		if o.transport != nil {
			t.Fatalf("sign_commit did not answer: %v", o.transport)
		}
		if o.ok {
			t.Logf("attempt %d: the cut landed after the signature completed; retrying", attempt)
			continue
		}
		if o.fail.Class != string(mcp.ClassTransparencyUnavailable) {
			t.Errorf("sign_commit cut at Rekor after Phase A reported %s, want %s.\n"+
				"message: %s\n\nIP §6.3: \"A signature without a transparency entry is "+
				"not non-repudiable and must not exist.\"",
				o.fail.Class, mcp.ClassTransparencyUnavailable, o.fail.Message)
		}

		// Heal, reconcile, converge. This is doc 07 OPS-001's second clause
		// with something actually at stake: the only intent in this file that
		// is left dangling by a partition rather than resolved inside the call.
		w.healAndConfirm(t, prtCell{down: []string{prtRekor}})
		prtRequireConverged(t, w, "after the mid-flight Rekor partition")
		w.verifyChain(t, "after the mid-flight Rekor partition")
		return
	}
	t.Fatalf("the IP §6.5 window never opened in %d attempts: every sign_commit "+
		"completed before Rekor could be cut between Phase A and Phase C. This case "+
		"reports rather than skips — a skip would exit zero with the partial-failure "+
		"gap unmeasured (#101).", prtMidFlightAttempts)
}

// prtChaseTheIntent runs one sign_commit and cuts Rekor the instant its
// `commit_intent` reaches the chain.
//
// The trigger is an OBSERVED one, not a sleep: internal/ledger's LED-009 polls
// pg_locks until the writers it parked are provably waiting, and MCP-011 fires
// its kills off state read from Postgres for the same reason. A delay chosen by
// hand would land somewhere nobody could reproduce.
func prtChaseTheIntent(t *testing.T, w *prtWorld, attempt int) (landed bool, out prtOutcome) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fx := w.prepare(t, fmt.Sprintf("mid-flight attempt %d", attempt))
	callerKey := w.key("midflight")
	intentKey := prtIntentKey(callerKey)

	done := make(chan prtOutcome, 1)
	go func() {
		done <- w.call(ctx, prtOpSign, mcp.ToolSignCommit, map[string]any{
			"run_id":          fx.runA,
			"repo":            prtRepo,
			"staged_ref":      fx.stagedRef,
			"message":         "OPS-001 mid-flight Rekor partition",
			"task_ref":        prtTaskID,
			"idempotency_key": callerKey,
		})
	}()

	deadline := time.Now().Add(prtMidFlightBudget)
	for time.Now().Before(deadline) {
		select {
		case o := <-done:
			// The call finished before the intent was seen. Nothing was cut,
			// so nothing is asserted; the caller retries.
			return false, o
		default:
		}
		_, found, err := w.store.EventByIdempotencyKey(ctx, intentKey)
		if err != nil {
			t.Fatalf("reading the chain for %s: %v", intentKey, err)
		}
		if found {
			if serr := w.gate(prtRekor).sever(); serr != nil {
				t.Fatalf("severing Rekor mid-flight: %v", serr)
			}
			if !prtWaitFor(30*time.Second, w.gate(prtRekor).refuses) {
				t.Fatalf("Rekor was severed mid-flight and its route still accepts " +
					"connections; the partition this case depends on did not happen")
			}
			t.Logf("attempt %d: Rekor severed after commit_intent %s reached the chain",
				attempt, intentKey)
			return true, <-done
		}
		time.Sleep(prtMidFlightPoll)
	}
	t.Fatalf("no commit_intent appeared under %s within %s, and sign_commit had not "+
		"returned either", intentKey, prtMidFlightBudget)
	return false, prtOutcome{}
}

// ---------------------------------------------------------------------------
// The gate's own fidelity, against a real outage.
// ---------------------------------------------------------------------------

// prtGateFidelity is the control on the harness itself.
//
// Everything above severs a ROUTE. This takes Fulcio away the way test/failure
// does — `docker compose stop`, the container gone, the outage confirmed by
// polling until the published endpoint stops serving trust material — and
// requires sign_commit to report the same class the corresponding gate cell
// reported. If the two ever disagreed, the matrix would be measuring the
// harness rather than the system, and this is the case that would say so.
//
// It is one container stop and one start, deliberately: it is the most
// expensive thing in this package, and one is enough to pin the equivalence.
// It is a subtest of the matrix rather than a test of its own because the
// world is torn down on its first caller's cleanup (ADR-0032's constraint,
// see partitionharness_test.go), and a second top-level test would rebuild
// two compose projects from scratch to make one assertion.
func prtGateFidelity(t *testing.T, w *prtWorld) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// The gate's answer.
	fxGate := w.prepare(t, "gate severance")
	w.severAndConfirm(t, prtCell{down: []string{prtFulcio}})
	viaGate := w.call(ctx, prtOpSign, mcp.ToolSignCommit, map[string]any{
		"run_id": fxGate.runA, "repo": prtRepo, "staged_ref": fxGate.stagedRef,
		"message": "OPS-001 fulcio via gate", "task_ref": prtTaskID,
		"idempotency_key": w.key("gate"),
	})
	w.healAndConfirm(t, prtCell{down: []string{prtFulcio}})

	// The real outage's answer.
	fxReal := w.prepare(t, "real outage")
	if _, err := w.compose(ctx, w.sigFiles, "stop", "--timeout", "20", "fulcio"); err != nil {
		t.Fatalf("stopping fulcio: %v", err)
	}
	restarted := false
	defer func() {
		if restarted {
			return
		}
		if _, err := w.compose(context.Background(), w.sigFiles, "start", "fulcio"); err != nil {
			t.Errorf("restarting fulcio: %v", err)
		}
	}()
	// The same confirmed-outage discipline: poll until the DIRECT port refuses,
	// so nothing below asserts against a race.
	if !prtWaitFor(90*time.Second, func() bool {
		return w.probeFulcioAt(ctx, "http://"+w.fulcioDirect) != nil
	}) {
		t.Fatalf("fulcio was stopped and %s still serves trust material; the outage "+
			"this case depends on did not happen", w.fulcioDirect)
	}
	viaOutage := w.call(ctx, prtOpSign, mcp.ToolSignCommit, map[string]any{
		"run_id": fxReal.runA, "repo": prtRepo, "staged_ref": fxReal.stagedRef,
		"message": "OPS-001 fulcio really down", "task_ref": prtTaskID,
		"idempotency_key": w.key("real"),
	})

	if _, err := w.compose(ctx, w.sigFiles, "start", "fulcio"); err != nil {
		t.Fatalf("restarting fulcio: %v", err)
	}
	restarted = true
	var last error
	if !prtWaitFor(4*time.Minute, func() bool {
		last = w.probeFulcioAt(ctx, "http://"+w.fulcioDirect)
		return last == nil
	}) {
		t.Fatalf("fulcio came back and is not serving trust material: %v", last)
	}

	switch {
	case viaGate.ok || viaOutage.ok:
		t.Fatalf("sign_commit succeeded with Fulcio away.\n  via gate:   %s\n  via outage: %s",
			viaGate, viaOutage)
	case viaGate.fail.Class != viaOutage.fail.Class:
		t.Fatalf("a severed route and a stopped container are reported differently:\n"+
			"  gate:   %s\n  outage: %s\n\nThe matrix partitions routes. If the two "+
			"disagree, the matrix is measuring this harness and not the system.",
			viaGate, viaOutage)
	case viaGate.fail.Class != string(mcp.ClassSigningUnavailable):
		t.Fatalf("Fulcio away reported %s, want %s (IP §6.3)",
			viaGate.fail.Class, mcp.ClassSigningUnavailable)
	}
	t.Logf("a severed route and a stopped fulcio both report %s", viaGate.fail.Class)

	// The negative control: with Fulcio back, the same call signs.
	fxBack := w.prepare(t, "after the real outage")
	back := w.call(ctx, prtOpSign, mcp.ToolSignCommit, map[string]any{
		"run_id": fxBack.runA, "repo": prtRepo, "staged_ref": fxBack.stagedRef,
		"message": "OPS-001 fulcio back", "task_ref": prtTaskID,
		"idempotency_key": w.key("back"),
	})
	if !back.ok {
		t.Fatalf("Fulcio is back and sign_commit still refuses (%s: %s); the two "+
			"refusals above prove nothing", back.fail.Class, back.fail.Message)
	}
}

// ---------------------------------------------------------------------------
// #101: an absent dependency is a skip, an infrastructure fault is a failure.
// ---------------------------------------------------------------------------

// TestOPS001AbsentDependencyIsASkipAndAFaultIsAFailure exercises BOTH branches
// of the routing this file's harness depends on.
//
// Eight harnesses in this repository report a failed dependency as a skip
// (#101), which makes `go test` exit zero while the tests carrying the
// invariant never run. internal/verify/verifyharness_test.go has the corrected
// shape and partitionharness_test.go copies it — but a routing rule with only
// one branch ever taken is a routing rule nobody has checked, so both are taken
// here. This test needs no Docker and no containers: the thing under test is
// the decision, not the world.
func TestOPS001AbsentDependencyIsASkipAndAFaultIsAFailure(t *testing.T) {
	t.Run("no docker is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_TEST_NO_DOCKER", "1")
		err := prtDockerUsable(t.Context())
		if err == nil {
			t.Fatal("prtDockerUsable answered nil with INNSEGL_TEST_NO_DOCKER set")
		}
		if !errors.Is(err, errPrtDependencyAbsent) {
			t.Fatalf("%v does not wrap errPrtDependencyAbsent, so it would be routed "+
				"to a FAILURE and a machine without Docker could not run the suite", err)
		}
		skip, failure := prtRoute(err)
		if skip == "" || failure != "" {
			t.Fatalf("prtRoute(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("no gitsign is a skip", func(t *testing.T) {
		t.Setenv("INNSEGL_GITSIGN", filepath.Join(t.TempDir(), "no-such-gitsign"))
		_, err := prtFindGitsign(t.Context())
		if err == nil {
			t.Fatal("prtFindGitsign accepted a path that does not exist")
		}
		skip, failure := prtRoute(err)
		if skip == "" || failure != "" {
			t.Fatalf("prtRoute(%v) = (%q, %q), want a skip and no failure", err, skip, failure)
		}
	})

	t.Run("an infrastructure fault is a failure", func(t *testing.T) {
		// The exact shape #100 produces on this machine: Docker refuses to
		// create the network because the predefined address pools are used up.
		// Every harness that reported this as a skip exited zero with nothing
		// having run.
		err := fmt.Errorf("bringing up the SPIRE stack: %w",
			errors.New("could not find an available, non-overlapping IPv4 address "+
				"pool among the defaults to assign to the network"))
		if errors.Is(err, errPrtDependencyAbsent) {
			t.Fatal("an exhausted Docker address pool wraps errPrtDependencyAbsent; " +
				"it would be reported as a skip and OPS-001 would silently not run")
		}
		skip, failure := prtRoute(err)
		if failure == "" || skip != "" {
			t.Fatalf("prtRoute(%v) = (%q, %q), want a failure and no skip", err, skip, failure)
		}
	})

	t.Run("a healthy bring-up is neither", func(t *testing.T) {
		skip, failure := prtRoute(nil)
		if skip != "" || failure != "" {
			t.Fatalf("prtRoute(nil) = (%q, %q), want both empty", skip, failure)
		}
	})
}

// ---------------------------------------------------------------------------
// The matrix's own shape.
// ---------------------------------------------------------------------------

// TestOPS001TheMatrixCoversWhatDoc07Names asserts the cell list itself.
//
// The matrix is generated, and a generator that quietly produced four
// dependencies or nine pairs would leave doc 07 OPS-001 partly unmeasured with
// every cell that DID run still green. So the shape is asserted, not assumed.
func TestOPS001TheMatrixCoversWhatDoc07Names(t *testing.T) {
	deps := prtDependencies()
	if len(deps) != 5 {
		t.Fatalf("doc 07 OPS-001 names five dependencies, this file has %d: %v", len(deps), deps)
	}
	for _, want := range []string{prtSPIRE, prtPostgres, prtFulcio, prtRekor, prtObject} {
		found := false
		for _, d := range deps {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Errorf("doc 07 OPS-001 names %q and the matrix does not partition it", want)
		}
	}

	cells := prtMatrix()
	singles, pairs := 0, 0
	seen := map[string]bool{}
	for _, c := range cells {
		if seen[c.name()] {
			t.Errorf("the matrix repeats the cell %q", c.name())
		}
		seen[c.name()] = true
		switch len(c.down) {
		case 1:
			singles++
		case 2:
			pairs++
		default:
			t.Errorf("cell %q partitions %d dependencies; doc 07 OPS-001 says "+
				"\"singly and in pairs\"", c.name(), len(c.down))
		}
	}
	if singles != 5 || pairs != 10 {
		t.Fatalf("the matrix has %d singles and %d pairs, want 5 and 10 "+
			"(five choose two)", singles, pairs)
	}

	// Every operation must have a declared expectation in every cell, or a
	// cell would run an operation nobody had said anything about.
	for _, c := range append(cells, prtCell{}) {
		for _, op := range []string{prtOpRegister, prtOpCredential, prtOpRecord, prtOpSign, prtOpRetire} {
			got := prtExpect(op, c)
			if got != prtOK && !mcp.Class(got).Valid() {
				t.Errorf("cell %q expects %s to report %q, which is not one of IP §4's "+
					"eleven classes", c.name(), op, got)
			}
		}
	}

	// The two shadowing rules the pairs exist to measure, asserted as
	// statements rather than left implicit in the table.
	if got := prtExpect(prtOpRegister, prtCell{down: []string{prtSPIRE, prtPostgres}}); got != string(mcp.ClassLedgerUnavailable) {
		t.Errorf("with SPIRE and Postgres both partitioned, register_agent is "+
			"expected to report %q; the idempotency claim is its first touch, so "+
			"Postgres shadows SPIRE", got)
	}
	if got := prtExpect(prtOpSign, prtCell{down: []string{prtSPIRE, prtFulcio}}); got != string(mcp.ClassSigningUnavailable) {
		t.Errorf("with SPIRE and Fulcio both partitioned, sign_commit is expected to "+
			"report %q; IP §6.5 puts the Sigstore probe before Phase A and before the "+
			"credential", got)
	}
}

// ---------------------------------------------------------------------------
// Repository fixtures.
// ---------------------------------------------------------------------------

func (w *prtWorld) initRepo(t *testing.T) {
	t.Helper()
	dir := filepath.Join(w.workDir, "workspace", filepath.FromSlash(prtRepo))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	w.git(t, dir, "init", "-q", "-b", "main")
}

func (w *prtWorld) repoDir() string {
	return filepath.Join(w.workDir, "workspace", filepath.FromSlash(prtRepo))
}

// stage writes one unique file, stages it, and returns the tree object id.
//
// The tree id IS the `staged_ref`: sign_commit's StagedTree requires the named
// tree to equal the index and to differ from HEAD, and a raw object id is the
// one reference that is always both after a fresh `git add`.
func (w *prtWorld) stage(t *testing.T) string {
	t.Helper()
	dir := w.repoDir()
	name := fmt.Sprintf("work-%d.txt", prtSeq.Add(1))
	if err := os.WriteFile(filepath.Join(dir, name),
		[]byte("innsegl OPS-001 "+name+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	w.git(t, dir, "add", name)
	return w.git(t, dir, "write-tree")
}

func (w *prtWorld) git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(dir, ".no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

// commitObjects enumerates the OBJECT DATABASE, not HEAD.
//
// "No commit was created" is satisfied by a signer that created a commit and
// merely failed to move a ref, so the question is asked of every object that
// exists. Blobs and trees may legitimately appear after a refused signature —
// `git add` writes the first and `write-tree` the second. A commit may not.
func (w *prtWorld) commitObjects(t *testing.T) []string {
	t.Helper()
	out := w.git(t, w.repoDir(), "cat-file", "--batch-all-objects",
		"--batch-check=%(objectname) %(objecttype)")
	var commits []string
	for _, line := range strings.Split(out, "\n") {
		name, kind, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && kind == "commit" {
			commits = append(commits, name)
		}
	}
	sort.Strings(commits)
	return commits
}

// staleLocks returns every `*.lock` left inside .git. git's locking protocol is
// a file created O_CREAT|O_EXCL beside the thing it protects; a writer that
// died holding one leaves it behind and every later writer refuses.
func (w *prtWorld) staleLocks(t *testing.T) []string {
	t.Helper()
	var stale []string
	root := filepath.Join(w.repoDir(), ".git")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".lock") {
			stale = append(stale, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return stale
}

func (w *prtWorld) mustRegister(ctx context.Context, t *testing.T, suffix string) string {
	t.Helper()
	o := w.call(ctx, prtOpRegister, mcp.ToolRegisterAgent, map[string]any{
		"agent_type":      prtAgentType,
		"task_id":         prtTaskID,
		"idempotency_key": w.key("prep-" + suffix),
	})
	if o.transport != nil {
		t.Fatalf("preparing a run: %v", o.transport)
	}
	if !o.ok {
		t.Fatalf("preparing a run failed with everything reachable (%s: %s)",
			o.fail.Class, o.fail.Message)
	}
	runID, ok := o.reply["run_id"].(string)
	if !ok || runID == "" {
		t.Fatalf("register_agent returned no run_id: %v", o.reply)
	}
	return runID
}

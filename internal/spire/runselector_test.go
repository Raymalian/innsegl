// SPDX-License-Identifier: Apache-2.0

package spire

import (
	"context"
	"slices"
	"testing"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ADR-0053 rests on one claim nothing in this repository had tested: that the
// SPIRE server stores a selector of a type no workload attestor emits. The
// server validates selector SHAPE (type and value non-empty), and upstream
// documents no registry of types, but "undocumented" is not "measured". If the
// server refused the type on create, register_agent would stop working; if it
// refused it on update, the start-up migration could not move a live run off
// the label selectors. So both are asked of the real server, through the admin
// API the MCP uses, with the MCP's own admin credential, and read back.
//
// These cases call the entry RPCs directly rather than through RegisterRun, on
// purpose: what is under test is the server, not this package.
func TestSPIRun001TheServerAcceptsTheInnseglRunSelectorOnCreate(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	run := newRun(t, "demo", "adr-0053")
	sel := RunSelector(run.RunID)

	entry := createRaw(t, c, s, run, []*types.Selector{{Type: sel.Type, Value: sel.Value}})
	assertOnlySelector(t, entry, sel)
}

func TestSPIRun002TheServerAcceptsTheInnseglRunSelectorOnUpdate(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	run := newRun(t, "demo", "adr-0053")

	var labels []*types.Selector
	for _, l := range runSelectors(run) {
		labels = append(labels, &types.Selector{Type: l.Type, Value: l.Value})
	}
	created := createRaw(t, c, s, run, labels)
	sel := RunSelector(run.RunID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.entries.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{
		Entries: []*types.Entry{{
			Id: created.GetId(),
			// authz-policy.rego scopes an update by the SPIFFE ID each entry in
			// the batch names, so the request carries it even though the mask
			// leaves it unchanged. Without it the policy denies the whole call
			// (measured: PermissionDenied, before SPIRE reads the selector).
			SpiffeId:  created.GetSpiffeId(),
			Selectors: []*types.Selector{{Type: sel.Type, Value: sel.Value}},
		}},
		InputMask: &types.EntryMask{Selectors: true},
	})
	if err != nil {
		t.Fatalf("BatchUpdateEntry: %v", err)
	}
	if n := len(resp.GetResults()); n != 1 {
		t.Fatalf("BatchUpdateEntry returned %d results for one entry", n)
	}
	st := resp.GetResults()[0].GetStatus()
	if codes.Code(st.GetCode()) != codes.OK {
		t.Fatalf("SPIRE refused selector %s on update: code=%d message=%q",
			sel, st.GetCode(), st.GetMessage())
	}

	got, found, err := c.LookupRun(ctx, run)
	if err != nil || !found {
		t.Fatalf("LookupRun after update: found=%v err=%v", found, err)
	}
	if got.ID != created.GetId() {
		t.Errorf("entry id changed on update: %q → %q", created.GetId(), got.ID)
	}
	want, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}
	if got.SPIFFEID != want {
		t.Errorf("SPIFFE ID changed on update: %q, want %q", got.SPIFFEID, want)
	}
	if len(got.Selectors) != 1 || got.Selectors[0] != sel {
		t.Errorf("selectors after update = %v, want exactly [%s]", got.Selectors, sel)
	}
}

// createRaw creates one run entry with the given selectors through the raw
// admin RPC and registers its cleanup.
func createRaw(t *testing.T, c *Client, s *stack, run RunRef, sels []*types.Selector) *types.Entry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id, err := run.SPIFFEID(testTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}
	target, err := splitID(id)
	if err != nil {
		t.Fatalf("splitID: %v", err)
	}
	parent, err := splitID(s.parentID)
	if err != nil {
		t.Fatalf("splitID(parent): %v", err)
	}
	results, err := c.createEntries(ctx, []*types.Entry{{
		ParentId: parent, SpiffeId: target, Selectors: sels,
		X509SvidTtl: int32(DefaultRunTTL.Seconds()), JwtSvidTtl: int32(DefaultRunTTL.Seconds()),
	}})
	if err != nil {
		t.Fatalf("BatchCreateEntry: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("BatchCreateEntry returned %d results for one entry", len(results))
	}
	st := results[0].GetStatus()
	if codes.Code(st.GetCode()) != codes.OK {
		t.Fatalf("SPIRE refused selectors %v on create: code=%d message=%q",
			sels, st.GetCode(), st.GetMessage())
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		if _, err := c.RetireRun(cctx, run); err != nil {
			t.Errorf("cleaning up %+v: %v", run, err)
		}
	})
	return results[0].GetEntry()
}

func assertOnlySelector(t *testing.T, e *types.Entry, want Selector) {
	t.Helper()
	got := fromWire(e).Selectors
	if len(got) != 1 || got[0] != want {
		t.Fatalf("SPIRE stored selectors %v, want exactly [%s]", got, want)
	}
}

// ADR-0053's migration rule, as a pure function: which entries the start-up
// rewrite moves. An entry is moved only when it still carries a legacy label
// selector and is not already what the deployment would register today. Any
// other entry — already on the run selector, or on selectors an operator chose
// for themselves — is not this migration's to touch.
func TestSPIRun003OnlyAnEntryOnTheLegacyLabelsIsMigrated(t *testing.T) {
	t.Parallel()
	run := RunRef{AgentType: "fix-ci", TaskID: "jira-118", RunID: "run-42"}
	want := []Selector{RunSelector(run.RunID)}
	for _, tc := range []struct {
		name string
		has  []Selector
		move bool
	}{
		{"the three legacy labels", runSelectors(run)[:3], true},
		{"the legacy labels plus a uid", runSelectors(run), true},
		{"one legacy label on its own", []Selector{{Type: "docker", Value: "label:dev.innsegl.run-id:run-42"}}, true},
		{"already on the run selector", want, false},
		{"an operator's own selectors", []Selector{{Type: "unix", Value: "uid:10001"}}, false},
		{"another project's docker label", []Selector{{Type: "docker", Value: "label:app:run-42"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := needsRunSelectorMigration(tc.has, want); got != tc.move {
				t.Errorf("needsRunSelectorMigration(%v) = %v, want %v", tc.has, got, tc.move)
			}
		})
	}
	// A deployment whose own selector function still returns the labels is not
	// rewritten against its will: the target equals what it has, in any order.
	labels := runSelectors(run)[:3]
	reversed := []Selector{labels[2], labels[1], labels[0]}
	if needsRunSelectorMigration(reversed, labels) {
		t.Error("an entry already equal to the configured selectors was marked for migration")
	}
}

// The start-up rewrite against the real server. Three runs, one per case the
// ADR names: a live run on the legacy labels (moved, same entry and SPIFFE
// ID), a live run already on the run selector (left alone), and a retired run
// (no entry, and none is created). A second pass moves nothing.
func TestSPIRun004TheStartupRewriteMovesOnlyLiveLabelEntries(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	want := func(r RunRef) []Selector { return []Selector{RunSelector(r.RunID)} }

	legacy := newRun(t, "demo", "adr-0053")
	legacyEntry := registerForTest(t, c, s, legacy)

	current := newRun(t, "demo", "adr-0053")
	currentEntry := registerWith(t, c, s, current, want(current))

	retired := newRun(t, "demo", "adr-0053")
	if _, err := c.RegisterRun(ctx, Registration{
		Run: retired, ParentID: s.parentID, Selectors: runSelectors(retired), TTL: DefaultRunTTL,
	}); err != nil {
		t.Fatalf("RegisterRun(%+v): %v", retired, err)
	}
	if _, err := c.RetireRun(ctx, retired); err != nil {
		t.Fatalf("RetireRun(%+v): %v", retired, err)
	}

	moved, err := c.MigrateRunSelectors(ctx, want)
	if err != nil {
		t.Fatalf("MigrateRunSelectors: %v", err)
	}
	if !slices.Contains(moved.Rewritten, legacy.RunID) {
		t.Errorf("the legacy entry for %s was not reported rewritten: %+v", legacy.RunID, moved)
	}
	for _, r := range []RunRef{current, retired} {
		if slices.Contains(moved.Rewritten, r.RunID) {
			t.Errorf("run %s was rewritten; it had nothing to migrate", r.RunID)
		}
	}

	got, found, err := c.LookupRun(ctx, legacy)
	if err != nil || !found {
		t.Fatalf("LookupRun(legacy): found=%v err=%v", found, err)
	}
	if got.ID != legacyEntry.ID || got.SPIFFEID != legacyEntry.SPIFFEID {
		t.Errorf("rewrite changed the entry: %s/%s → %s/%s",
			legacyEntry.ID, legacyEntry.SPIFFEID, got.ID, got.SPIFFEID)
	}
	if len(got.Selectors) != 1 || got.Selectors[0] != RunSelector(legacy.RunID) {
		t.Errorf("legacy entry selectors after rewrite = %v, want [%s]",
			got.Selectors, RunSelector(legacy.RunID))
	}

	kept, found, err := c.LookupRun(ctx, current)
	if err != nil || !found {
		t.Fatalf("LookupRun(current): found=%v err=%v", found, err)
	}
	if kept.ID != currentEntry.ID || len(kept.Selectors) != 1 || kept.Selectors[0] != RunSelector(current.RunID) {
		t.Errorf("the new-style entry changed: %+v → %+v", currentEntry, kept)
	}

	if _, found, lerr := c.LookupRun(ctx, retired); lerr != nil || found {
		t.Errorf("the retired run has an entry after the rewrite: found=%v err=%v", found, lerr)
	}

	again, err := c.MigrateRunSelectors(ctx, want)
	if err != nil {
		t.Fatalf("second MigrateRunSelectors: %v", err)
	}
	for _, r := range []RunRef{legacy, current, retired} {
		if slices.Contains(again.Rewritten, r.RunID) {
			t.Errorf("second pass rewrote %s; the rewrite is not idempotent", r.RunID)
		}
	}
}

// ADR-0053's headline test. A container carrying a live run's three labels
// and the Workload API socket is issued the run's SVID while the entry is on
// the labels — observed, as the positive control — and refused once the entry
// is on the run selector. A second run registered on the run selector from
// the start is refused too.
//
// The refusal after the rewrite is polled for, not assumed: the agent learns
// of the update through its cache (RM-014 measured 3–7 s), and until then it
// may still issue under the old selectors. What must hold is that it STOPS,
// and stays stopped.
func TestSPIRun005ALabelledContainerIsRefusedARunsIdentity(t *testing.T) {
	s := requireStack(t)
	c := s.adminClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	want := func(r RunRef) []Selector { return []Selector{RunSelector(r.RunID)} }

	legacy := newRun(t, "demo", "adr-0053")
	registerForTest(t, c, s, legacy)
	issued := s.probeUntilIssued(t, legacy, 90*time.Second)
	t.Logf("before the change, a labelled container was issued %s", issued.Outcome.SPIFFEID)

	// Registered before the rewrite, so once the agent has synced the rewrite
	// it has synced this create too.
	fresh := newRun(t, "demo", "adr-0053")
	registerWith(t, c, s, fresh, want(fresh))

	if _, err := c.MigrateRunSelectors(ctx, want); err != nil {
		t.Fatalf("MigrateRunSelectors: %v", err)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		last := s.runProbe(t, legacy, legacy)
		if last.ExitCode != 0 {
			t.Logf("after the rewrite, the same labelled container is refused: %s", last.Outcome.Message)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a labelled container was still issued %s 90s after the rewrite",
				last.Outcome.SPIFFEID)
		}
		time.Sleep(2 * time.Second)
	}

	// Refused, and still refused on later asks.
	for range 3 {
		for _, r := range []RunRef{legacy, fresh} {
			got := s.runProbe(t, r, r)
			if got.ExitCode == 0 {
				t.Fatalf("a container labelled as run %s was issued %q", r.RunID, got.Outcome.SPIFFEID)
			}
			if got.Outcome.Class != ClassAttestationFailed {
				t.Errorf("run %s: class = %q, want %s (raw: %s)",
					r.RunID, got.Outcome.Class, ClassAttestationFailed, got.Raw)
			}
		}
	}
}

// migrateStub is SPIRE's entry API reduced to a listing and an update whose
// answer the case chooses. The embedded interface is nil on purpose.
type migrateStub struct {
	entryv1.EntryClient
	list      []*types.Entry
	listErr   error
	updateErr error
	// answer, when set, replaces the per-entry result the stub reports.
	answer  func(id string) []*entryv1.BatchUpdateEntryResponse_Result
	updated []*types.Entry
}

func (s *migrateStub) ListEntries(context.Context, *entryv1.ListEntriesRequest,
	...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	return &entryv1.ListEntriesResponse{Entries: s.list}, s.listErr
}

func (s *migrateStub) BatchUpdateEntry(_ context.Context, in *entryv1.BatchUpdateEntryRequest,
	_ ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	s.updated = append(s.updated, in.GetEntries()...)
	id := in.GetEntries()[0].GetId()
	if s.answer != nil {
		return &entryv1.BatchUpdateEntryResponse{Results: s.answer(id)}, nil
	}
	return &entryv1.BatchUpdateEntryResponse{Results: []*entryv1.BatchUpdateEntryResponse_Result{
		{Status: &types.Status{Code: int32(codes.OK)}},
	}}, nil
}

func stubEntry(id, path string, sels ...Selector) *types.Entry {
	wire := make([]*types.Selector, 0, len(sels))
	for _, s := range sels {
		wire = append(wire, &types.Selector{Type: s.Type, Value: s.Value})
	}
	return &types.Entry{Id: id, SpiffeId: &types.SPIFFEID{TrustDomain: "innsegl.dev", Path: path}, Selectors: wire}
}

// The error paths of the rewrite, without a SPIRE: each failure is reported,
// one refused entry does not stop the others, and nothing is ever asked to
// carry no selectors.
func TestSPIRun006TheRewriteReportsEveryFailureAndKeepsGoing(t *testing.T) {
	t.Parallel()
	legacyA := RunRef{AgentType: "demo", TaskID: "t", RunID: "run-a"}
	legacyB := RunRef{AgentType: "demo", TaskID: "t", RunID: "run-b"}
	want := func(r RunRef) []Selector { return []Selector{RunSelector(r.RunID)} }
	listing := func() []*types.Entry {
		return []*types.Entry{
			stubEntry("e-a", "/agent/demo/t/run-a", runSelectors(legacyA)[:3]...),
			stubEntry("e-b", "/agent/demo/t/run-b", runSelectors(legacyB)[:3]...),
			// In the subtree, not a run: left alone.
			stubEntry("e-short", "/agent/demo/t", runSelectors(legacyA)[:1]...),
			stubEntry("e-new", "/agent/demo/t/run-c", RunSelector("run-c")),
		}
	}
	client := func(s *migrateStub) *Client {
		return &Client{entries: s, trustDomain: "innsegl.dev", timeout: 5 * time.Second}
	}

	t.Run("everything moves", func(t *testing.T) {
		t.Parallel()
		s := &migrateStub{list: listing()}
		got, err := client(s).MigrateRunSelectors(t.Context(), want)
		if err != nil {
			t.Fatalf("MigrateRunSelectors: %v", err)
		}
		if !slices.Equal(got.Rewritten, []string{"run-a", "run-b"}) || got.Unchanged != 2 {
			t.Errorf("got %+v, want run-a and run-b rewritten and two unchanged", got)
		}
		for _, u := range s.updated {
			if u.GetSpiffeId() == nil {
				t.Errorf("update of %s names no SPIFFE ID; the authz policy refuses that", u.GetId())
			}
		}
	})

	t.Run("a listing failure is returned", func(t *testing.T) {
		t.Parallel()
		s := &migrateStub{listErr: status.Error(codes.Unavailable, "down")}
		if _, err := client(s).MigrateRunSelectors(t.Context(), want); err == nil {
			t.Fatal("a failed listing was reported as success")
		}
	})

	t.Run("an RPC failure is returned after the pass", func(t *testing.T) {
		t.Parallel()
		s := &migrateStub{list: listing(), updateErr: status.Error(codes.PermissionDenied, "no")}
		got, err := client(s).MigrateRunSelectors(t.Context(), want)
		if err == nil || len(got.Rewritten) != 0 {
			t.Fatalf("got %+v, %v; want an error and nothing rewritten", got, err)
		}
	})

	t.Run("one refused entry does not stop the next", func(t *testing.T) {
		t.Parallel()
		s := &migrateStub{list: listing(), answer: func(id string) []*entryv1.BatchUpdateEntryResponse_Result {
			code := codes.OK
			if id == "e-a" {
				code = codes.InvalidArgument
			}
			return []*entryv1.BatchUpdateEntryResponse_Result{{Status: &types.Status{Code: int32(code)}}}
		}}
		got, err := client(s).MigrateRunSelectors(t.Context(), want)
		if err == nil {
			t.Fatal("a refused entry was not reported")
		}
		if !slices.Equal(got.Rewritten, []string{"run-b"}) {
			t.Errorf("rewritten = %v, want [run-b]", got.Rewritten)
		}
	})

	t.Run("a result count that is not one is an invariant violation", func(t *testing.T) {
		t.Parallel()
		s := &migrateStub{list: listing(), answer: func(string) []*entryv1.BatchUpdateEntryResponse_Result {
			return nil
		}}
		_, err := client(s).MigrateRunSelectors(t.Context(), want)
		if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
			t.Errorf("class = %q (ok=%v), want %s: %v", class, ok, ClassInvariantViolation, err)
		}
	})

	t.Run("an empty target is refused before SPIRE is asked", func(t *testing.T) {
		t.Parallel()
		s := &migrateStub{list: listing()}
		_, err := client(s).MigrateRunSelectors(t.Context(), func(RunRef) []Selector { return nil })
		if class, ok := ClassOf(err); !ok || class != ClassInvariantViolation {
			t.Errorf("class = %q (ok=%v), want %s: %v", class, ok, ClassInvariantViolation, err)
		}
		if len(s.updated) != 0 {
			t.Errorf("SPIRE was asked to give %d entries no selectors", len(s.updated))
		}
	})
}

// registerWith registers a run on the given selectors and retires it after.
func registerWith(t *testing.T, c *Client, s *stack, run RunRef, sels []Selector) Entry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entry, err := c.RegisterRun(ctx, Registration{
		Run: run, ParentID: s.parentID, Selectors: sels, TTL: DefaultRunTTL,
	})
	if err != nil {
		t.Fatalf("RegisterRun(%+v): %v", run, err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer ccancel()
		if _, err := c.RetireRun(cctx, run); err != nil {
			t.Errorf("cleaning up %+v: %v", run, err)
		}
	})
	return entry
}

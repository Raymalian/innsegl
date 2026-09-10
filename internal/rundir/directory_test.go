// SPDX-License-Identifier: Apache-2.0

package rundir

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
)

// ---------------------------------------------------------------------------
// A fake chain. These cases are about what the directory READS out of a set of
// events, and every one of them is a shape a real chain can hold; the
// Postgres-backed cases in directory_pg_test.go put the same reader on a real
// chain so that neither half is the only evidence.
// ---------------------------------------------------------------------------

type fakeEvents struct {
	records []event.Fields
	err     error
	asked   []string
}

func (f *fakeEvents) EventsForRun(_ context.Context, runID string) ([]event.Fields, error) {
	f.asked = append(f.asked, runID)
	if f.err != nil {
		return nil, f.err
	}
	return f.records, nil
}

const (
	testRunID = "run-42"
	testAgent = "fix-ci"
	testTask  = "jira-118"
	// ADR-0045, required under schema 2: a run records where it worked.
	testRepo     = "github.com/acme/api"
	testBranch   = "main"
	testSPIFFEID = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"
)

// registered is a `run_registered` record as the ledger returns one.
func registered(position int64, ts string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventID:       "01930000-0000-7000-8000-00000000000" + fmt.Sprint(position),
		event.FieldChainPosition: position,
		event.FieldEventType:     event.EventTypeRunRegistered,
		event.FieldTS:            ts,
		event.FieldRunID:         testRunID,
		event.FieldSpiffeID:      testSPIFFEID,
		event.FieldSource:        event.SourceMCP,
		event.FieldAgentType:     testAgent,
		event.FieldTaskRef:       testTask,
		event.FieldRepo:          testRepo,
		event.FieldBranch:        testBranch,
	}
}

// retired is a `run_retired` record as the ledger returns one.
func retired(position int64, ts string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventID:       "01930000-0000-7000-8000-00000000001" + fmt.Sprint(position),
		event.FieldChainPosition: position,
		event.FieldEventType:     event.EventTypeRunRetired,
		event.FieldTS:            ts,
		event.FieldRunID:         testRunID,
		event.FieldSpiffeID:      testSPIFFEID,
		event.FieldSource:        event.SourceMCP,
	}
}

func newDirectory(t *testing.T, records []event.Fields) *Directory {
	t.Helper()
	d, err := New(Config{Events: &fakeEvents{records: records}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := event.ParseTimestamp(s)
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", s, err)
	}
	return ts.Time()
}

// ---------------------------------------------------------------------------

// TestCredentialRunReadsTheRunOffTheChain is the ordinary path: a registered,
// live run.
func TestCredentialRunReadsTheRunOffTheChain(t *testing.T) {
	d := newDirectory(t, []event.Fields{registered(7, "2026-08-29T10:00:00.000Z")})

	run, found, err := d.CredentialRun(context.Background(), testRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if !found {
		t.Fatal("CredentialRun did not find a run that is registered on the chain")
	}
	if run.RunID != testRunID {
		t.Errorf("RunID is %q, want %q", run.RunID, testRunID)
	}
	if run.SPIFFEID != testSPIFFEID {
		t.Errorf("SPIFFEID is %q, want %q", run.SPIFFEID, testSPIFFEID)
	}
	if run.AgentType != testAgent {
		t.Errorf("AgentType is %q, want %q", run.AgentType, testAgent)
	}
	if run.TaskID != testTask {
		t.Errorf("TaskID is %q, want %q", run.TaskID, testTask)
	}
	if run.Retired() {
		t.Errorf("a run with no run_retired reports retired at %s", run.RetiredAt)
	}
}

// TestTheEarliestRunRetiredWinsWhenSeveralArePresent is ADR-0020 §5.
//
// Two genuinely concurrent FIRST retirements of one run can both find no
// record and both append, leaving several `run_retired` events in the chain,
// permanently (I4). The ADR states the contract that makes that survivable:
// "both callers are told the same instant, because the directory answers with
// the earliest". Until this directory shipped, nothing enforced it — RM-025
// implemented it in a test double, which is a statement about the double.
//
// The records are supplied with the EARLIEST instant LAST in chain order. A
// reader that took "the first run_retired it saw" would pass a test whose two
// orders agree, and every chain a single ledger writes has them agreeing,
// because `ts` is read inside the serialized append. So the disagreement is
// constructed here on purpose: it is the only shape that separates "earliest"
// from "first".
// This is the ONLY home for ADR-0020 §5 since migrations/0004. A real-chain
// variant lived in directory_pg_test.go and appended four retirements for one
// run; the ledger now refuses the second, so the state can no longer be built
// through the store. It can still be READ: a deployment that hit the bug the
// index closes carries its duplicates forever, because records are never
// rewritten (I4). That is why the rule stays and why it is tested here.
func TestTheEarliestRunRetiredWinsWhenSeveralArePresent(t *testing.T) {
	const earliest = "2026-08-29T10:00:01.000Z"
	d := newDirectory(t, []event.Fields{
		registered(7, "2026-08-29T10:00:00.000Z"),
		retired(8, "2026-08-29T10:00:03.000Z"),
		retired(9, "2026-08-29T10:00:02.000Z"),
		retired(10, earliest),
		retired(11, "2026-08-29T10:00:04.000Z"),
	})

	run, found, err := d.CredentialRun(context.Background(), testRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if !found {
		t.Fatal("CredentialRun did not find the run")
	}
	if !run.Retired() {
		t.Fatal("a run with four run_retired events is reported live")
	}
	if want := mustParse(t, earliest); !run.RetiredAt.Equal(want) {
		t.Fatalf("RetiredAt is %s, want the earliest of the four, %s. "+
			"ADR-0020 §5: two concurrent first retirements must be told the same instant.",
			event.NewTimestamp(run.RetiredAt), event.NewTimestamp(want))
	}
}

// TestOneRunRetiredIsTheRetirement guards the ordinary single-retirement case
// against an "earliest" rule that only fires with several.
func TestOneRunRetiredIsTheRetirement(t *testing.T) {
	const at = "2026-08-29T10:00:05.000Z"
	d := newDirectory(t, []event.Fields{
		registered(7, "2026-08-29T10:00:00.000Z"),
		retired(8, at),
	})

	run, _, err := d.CredentialRun(context.Background(), testRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if want := mustParse(t, at); !run.RetiredAt.Equal(want) {
		t.Fatalf("RetiredAt is %s, want %s", event.NewTimestamp(run.RetiredAt), event.NewTimestamp(want))
	}
}

// TestAnUnknownRunIsNotFoundAndNotAnError: the interface says so, and the tool
// turns it into RUN_NOT_FOUND.
func TestAnUnknownRunIsNotFoundAndNotAnError(t *testing.T) {
	d := newDirectory(t, nil)

	run, found, err := d.CredentialRun(context.Background(), "run-nobody")
	if err != nil {
		t.Fatalf("an unknown run is an error: %v", err)
	}
	if found {
		t.Fatalf("an unknown run was found: %+v", run)
	}
}

// TestARunWithEventsButNoRegistrationIsNotFound. A `tool_call` naming a run
// the chain never registered is not a run: answering "found" would hand the
// tools a CredentialRun with no identity at all.
func TestARunWithEventsButNoRegistrationIsNotFound(t *testing.T) {
	d := newDirectory(t, []event.Fields{{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldChainPosition: int64(3),
		event.FieldEventType:     event.EventTypeToolCall,
		event.FieldTS:            "2026-08-29T10:00:00.000Z",
		event.FieldRunID:         testRunID,
		event.FieldSource:        event.SourceMCP,
	}})

	_, found, err := d.CredentialRun(context.Background(), testRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if found {
		t.Fatal("a run with no run_registered was reported found")
	}
}

// TestTheLedgersOwnFailureIsCarriedAcross: a ledger outage must reach the tool
// as the ledger's own class, so LEDGER_UNAVAILABLE is not reported as a defect.
func TestTheLedgersOwnFailureIsCarriedAcross(t *testing.T) {
	sentinel := errors.New("connection refused")
	d, err := New(Config{Events: &fakeEvents{err: sentinel}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, _, err = d.CredentialRun(context.Background(), testRunID)
	if !errors.Is(err, sentinel) {
		t.Fatalf("CredentialRun lost the ledger's error: got %v", err)
	}
}

// TestMalformedRecordsAreRefusedRatherThanGuessedAt. Every case here is an
// event that cannot be read as the run it claims to describe. The directory
// feeds three tools that then mint, record and delete against its answer, so a
// field it cannot read is INVARIANT_VIOLATION and never a zero value.
func TestMalformedRecordsAreRefusedRatherThanGuessedAt(t *testing.T) {
	drop := func(base event.Fields, member string) event.Fields {
		out := make(event.Fields, len(base))
		for k, v := range base {
			out[k] = v
		}
		delete(out, member)
		return out
	}
	set := func(base event.Fields, member string, value any) event.Fields {
		out := drop(base, member)
		out[member] = value
		return out
	}

	reg := registered(7, "2026-08-29T10:00:00.000Z")
	ret := retired(8, "2026-08-29T10:00:01.000Z")

	cases := []struct {
		name    string
		records []event.Fields
	}{
		{"no event_type", []event.Fields{drop(reg, event.FieldEventType)}},
		{"event_type is not a string", []event.Fields{set(reg, event.FieldEventType, 7)}},
		{"run_registered with no spiffe_id", []event.Fields{drop(reg, event.FieldSpiffeID)}},
		{"run_registered with no agent_type", []event.Fields{drop(reg, event.FieldAgentType)}},
		{"run_registered with no task_ref", []event.Fields{drop(reg, event.FieldTaskRef)}},
		{"run_retired with no ts", []event.Fields{reg, drop(ret, event.FieldTS)}},
		{"run_retired with an unreadable ts", []event.Fields{reg, set(ret, event.FieldTS, "yesterday")}},
		{"run_retired with a non-string ts", []event.Fields{reg, set(ret, event.FieldTS, 1)}},
		{"an event for another run", []event.Fields{set(reg, event.FieldRunID, "run-99")}},
		{"an event with no run_id at all", []event.Fields{drop(reg, event.FieldRunID)}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDirectory(t, tc.records)
			_, _, err := d.CredentialRun(context.Background(), testRunID)
			if err == nil {
				t.Fatal("the record was accepted; a run the directory cannot read is not a run")
			}
			e := mcp.Classify(err)
			if e.Class != mcp.ClassInvariantViolation {
				t.Fatalf("class is %s, want %s: %v", e.Class, mcp.ClassInvariantViolation, err)
			}
			if e.RunID != testRunID {
				t.Errorf("the refusal is scoped to run %q, want %q", e.RunID, testRunID)
			}
		})
	}
}

// TestTwoRunRegisteredEventsAreRefused. The run id is derived and the ledger's
// idempotency key is UNIQUE, so one run registers once. Two registrations mean
// two identities could be described for one run, and picking one would be a
// guess about which identity a credential should be minted for (I2).
func TestTwoRunRegisteredEventsAreRefused(t *testing.T) {
	second := registered(9, "2026-08-29T10:00:02.000Z")
	second[event.FieldSpiffeID] = "spiffe://innsegl.dev/agent/other/task/run-42"
	d := newDirectory(t, []event.Fields{registered(7, "2026-08-29T10:00:00.000Z"), second})

	_, _, err := d.CredentialRun(context.Background(), testRunID)
	if err == nil {
		t.Fatal("two run_registered events for one run were accepted")
	}
	if e := mcp.Classify(err); e.Class != mcp.ClassInvariantViolation {
		t.Fatalf("class is %s, want %s", e.Class, mcp.ClassInvariantViolation)
	}
}

// TestNewRefusesADirectoryWithNoLedger: a directory with nothing to read would
// report every run unknown, which reads exactly like a fresh deployment.
func TestNewRefusesADirectoryWithNoLedger(t *testing.T) {
	d, err := New(Config{})
	if err == nil {
		t.Fatalf("New with no ledger returned %v", d)
	}
	if e := mcp.Classify(err); e.Class != mcp.ClassInvariantViolation {
		t.Fatalf("class is %s, want %s", e.Class, mcp.ClassInvariantViolation)
	}
}

// TestTheDirectoryAsksTheLedgerForTheRunItWasAskedAbout. The read is
// run-scoped, so the whole chain is never pulled through the directory.
func TestTheDirectoryAsksTheLedgerForTheRunItWasAskedAbout(t *testing.T) {
	events := &fakeEvents{}
	d, err := New(Config{Events: events})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := d.CredentialRun(context.Background(), "run-7"); err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if len(events.asked) != 1 || events.asked[0] != "run-7" {
		t.Fatalf("the directory asked the ledger for %v, want exactly [run-7]", events.asked)
	}
}

// ---------------------------------------------------------------------------
// RM-073 (#98): doc 02's golden fixture 01 carries task_ref "JIRA-118" against
// spiffe_id spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42 — the caller's
// casing next to its lowercased form. An earlier revision of the run
// directory's one caller (mcp.credentialRunIdentity, before RM-079/#116)
// reconstructed the identity by concatenating the recorded task_ref back onto
// "/agent/{agent_type}/{task_id}/{run_id}" and required an exact suffix match
// against the real spiffe_id. Run against these exact values that comparison
// is:
//
//	spiffeID     = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"
//	want(suffix) = "/agent/fix-ci/JIRA-118/run-42"
//	HasSuffix    = false
//
// which is golden fixture 01 refused by the shipped run directory, exactly as
// RM-073 found. Since RM-079 neither this package nor its caller reconstructs
// an identity that way any more: this package reads agent_type and task_ref
// off the event verbatim (see the package doc), and mcp.CredentialRun.Ref
// reads its three segments back OFF the recorded spiffe_id
// (spire.RunRefOf) instead of off AgentType/TaskID. The tests below pin that
// the case difference doc 02 §5 creates between task_ref and {task_id} can
// never again be compared to itself and found wanting.
// ---------------------------------------------------------------------------

const (
	fixture01AgentType = "fix-ci"
	fixture01TaskRef   = "JIRA-118"
	fixture01Repo      = "github.com/acme/api"
	fixture01Branch    = "main"
	fixture01RunID     = "run-42"
	fixture01SPIFFEID  = "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42"
)

// fixture01Registered is a `run_registered` record carrying golden fixture
// 01's own values, unmodified.
func fixture01Registered() event.Fields {
	return event.Fields{
		event.FieldSchemaVersion: event.SchemaVersion,
		event.FieldEventID:       "01930000-0000-7000-8000-000000000fx1",
		event.FieldChainPosition: int64(1),
		event.FieldEventType:     event.EventTypeRunRegistered,
		event.FieldTS:            "2026-08-29T10:00:00.000Z",
		event.FieldRunID:         fixture01RunID,
		event.FieldSpiffeID:      fixture01SPIFFEID,
		event.FieldSource:        event.SourceMCP,
		event.FieldAgentType:     fixture01AgentType,
		event.FieldTaskRef:       fixture01TaskRef,
		event.FieldRepo:          fixture01Repo,
		event.FieldBranch:        fixture01Branch,
	}
}

// TestFixture01ResolvesThroughTheRunDirectory is MCP-022 (RM-073, #98): the
// normative example doc 02's whole serialization is pinned to must resolve
// through the shipped run directory, verbatim casing and all.
func TestFixture01ResolvesThroughTheRunDirectory(t *testing.T) {
	d := newDirectory(t, []event.Fields{fixture01Registered()})

	run, found, err := d.CredentialRun(context.Background(), fixture01RunID)
	if err != nil {
		t.Fatalf("CredentialRun refused golden fixture 01's own values: %v", err)
	}
	if !found {
		t.Fatal("CredentialRun did not find golden fixture 01's run")
	}
	if run.AgentType != fixture01AgentType {
		t.Errorf("AgentType is %q, want %q", run.AgentType, fixture01AgentType)
	}
	if run.TaskID != fixture01TaskRef {
		t.Errorf("TaskID is %q, want the caller's own casing %q", run.TaskID, fixture01TaskRef)
	}
	if run.SPIFFEID != fixture01SPIFFEID {
		t.Errorf("SPIFFEID is %q, want %q", run.SPIFFEID, fixture01SPIFFEID)
	}
}

// TestFixture01SIdentityResolvesThroughRef is MCP-023 (RM-073, #98):
// mcp.CredentialRun.Ref is the run directory's one caller, and it is the
// caller that used to fail on this fixture. It must resolve the SPIFFE ID's
// own (lowercased) segment rather than the recorded task_ref, and it must
// resolve it without error.
func TestFixture01SIdentityResolvesThroughRef(t *testing.T) {
	d := newDirectory(t, []event.Fields{fixture01Registered()})

	run, found, err := d.CredentialRun(context.Background(), fixture01RunID)
	if err != nil || !found {
		t.Fatalf("CredentialRun(%q): found=%v err=%v", fixture01RunID, found, err)
	}

	ref, err := run.Ref()
	if err != nil {
		t.Fatalf("Ref refused golden fixture 01's identity: %v", err)
	}
	if ref.AgentType != fixture01AgentType {
		t.Errorf("Ref().AgentType is %q, want %q", ref.AgentType, fixture01AgentType)
	}
	if ref.TaskID != "jira-118" {
		t.Errorf("Ref().TaskID is %q, want the SPIFFE ID's own lowercased segment %q", ref.TaskID, "jira-118")
	}
	if ref.RunID != fixture01RunID {
		t.Errorf("Ref().RunID is %q, want %q", ref.RunID, fixture01RunID)
	}
}

// TestAGenerallyMismatchedRecordStillResolves is a companion to MCP-022 that
// generalizes past this one fixture: it is not fixture 01's specific letters
// that make this safe, it is that agent_type/task_ref are never compared
// against the SPIFFE ID's segments at all any more. An agent_type recorded
// with different casing than its SPIFFE segment — something fixture 01 does
// not exercise, because "fix-ci" is already lowercase — must resolve exactly
// the same way.
func TestAGenerallyMismatchedRecordStillResolves(t *testing.T) {
	rec := fixture01Registered()
	rec[event.FieldAgentType] = "Fix-CI"
	d := newDirectory(t, []event.Fields{rec})

	run, found, err := d.CredentialRun(context.Background(), fixture01RunID)
	if err != nil || !found {
		t.Fatalf("CredentialRun(%q): found=%v err=%v", fixture01RunID, found, err)
	}
	if run.AgentType != "Fix-CI" {
		t.Errorf("AgentType is %q, want the caller's own casing %q", run.AgentType, "Fix-CI")
	}

	ref, err := run.Ref()
	if err != nil {
		t.Fatalf("Ref refused a record whose agent_type casing differs from the SPIFFE ID's segment: %v", err)
	}
	if ref.AgentType != fixture01AgentType {
		t.Errorf("Ref().AgentType is %q, want the SPIFFE ID's own segment %q", ref.AgentType, fixture01AgentType)
	}
}

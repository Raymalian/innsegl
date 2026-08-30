// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
	"innsegl.dev/innsegl/internal/spire"
)

// ---------------------------------------------------------------------------
// RM-068 (#89): the shipped entry point, end to end.
//
// Everything below runs against `innsegl serve` as a subprocess, a real
// containerised Postgres and a real containerised SPIRE. That is not a style
// preference. The claim this issue exists to establish is that the WIRING
// works — that the four tools reach the dependencies a deployment gives them —
// and a server assembled out of doubles in a test binary would answer every
// call happily while proving nothing about it.
//
// So no case here is allowed to pass on the reply alone. Every one of them
// reads the consequence back out of a system the server does not control: the
// event off the hash chain through internal/ledger, the registration entry out
// of the SPIRE datastore through the admin API.
// ---------------------------------------------------------------------------

const (
	// serveTaskID is this file's task component. It differs from the crash
	// campaign's so that the two files' runs are distinguishable in the SPIRE
	// datastore.
	serveTaskID = "rm-068"
)

// runRefFor rebuilds the reference internal/spire takes for a run this file
// registered under one task.
func runRefFor(task, runID string) spire.RunRef {
	return spire.RunRef{AgentType: crashAgentType, TaskID: task, RunID: runID}
}

// healthAddrPattern reads the health address out of the server's own start-up
// log. The address is taken from what the process PUBLISHED rather than from a
// port this file picked: a port reserved here and passed in would be a port
// something else could take between the reserve and the bind.
var healthAddrPattern = regexp.MustCompile(`\bhealth=([^\s]+)`)

// healthAddr waits for the server to report where its health endpoints are.
func healthAddr(t *testing.T, d *daemon) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m := healthAddrPattern.FindStringSubmatch(d.stderr.String()); m != nil {
			return m[1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("`innsegl serve` never reported its health address. stderr:\n%s", d.stderr.String())
	return ""
}

// getJSON reads one health endpoint.
func getJSON(t *testing.T, url string, into any) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build a request for %s: %v", url, err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			t.Fatalf("%s returned %q, which is not the documented JSON: %v", url, body, err)
		}
	}
	return res.StatusCode
}

// livenessWire and readinessWire are the documented health shapes, declared
// here rather than imported: internal/mcp keeps its wire structs unexported,
// and a test that read the report through the same struct that wrote it would
// not be reading the wire at all.
type livenessWire struct {
	Alive        bool     `json:"alive"`
	Version      string   `json:"version"`
	ObservedAt   string   `json:"observed_at"`
	BoundTools   []string `json:"bound_tools"`
	MissingTools []string `json:"missing_tools"`
	// Dependencies must NOT appear: liveness contacts nothing.
	Dependencies []json.RawMessage `json:"dependencies"`
}

type readinessWire struct {
	Ready        bool     `json:"ready"`
	Version      string   `json:"version"`
	ObservedAt   string   `json:"observed_at"`
	MissingTools []string `json:"missing_tools"`
	Dependencies []struct {
		Dependency string `json:"dependency"`
		Reachable  bool   `json:"reachable"`
		Class      string `json:"error_class"`
		Retryable  bool   `json:"retryable"`
		Detail     string `json:"detail"`
		LatencyMS  int64  `json:"latency_ms"`
		CheckedAt  string `json:"checked_at"`
	} `json:"dependencies"`
}

// retireRun puts a run back, so this file leaves the shared SPIRE datastore as
// it found it and the crash campaign's whole-datastore census is not answering
// for entries another test created.
func retireRun(t *testing.T, c *campaign, session *sdk.ClientSession, runID string) {
	t.Helper()
	c.callOnce(t, session, mcp.ToolRetireAgent, map[string]any{"run_id": runID})
}

// ---------------------------------------------------------------------------

// TestServeAnswersARealMCPCallEndToEnd is the acceptance criterion of #89:
// `innsegl serve` starts, advertises the IP §4 surface, and answers a real MCP
// call against a real Postgres and a real SPIRE.
//
// The reply is not the evidence. After each call this test goes to the systems
// the server wrote to and reads the consequence back: the `run_registered`
// event out of the chain by its idempotency key, the whole chain walked from
// the genesis constant, and the run's registration entry out of the SPIRE
// datastore over the admin API.
func TestServeAnswersARealMCPCallEndToEnd(t *testing.T) {
	c := requireCrashCampaign(t)
	d := c.start(t)
	session := c.connect(t, d, d.addr)

	// --- the handshake ---------------------------------------------------
	init := session.InitializeResult()
	if init == nil {
		t.Fatal("the server returned no initialize result")
	}
	if init.ServerInfo == nil || init.ServerInfo.Name != mcp.ServerName {
		t.Fatalf("the server registered as %+v, want the protected name %q (IP §1)",
			init.ServerInfo, mcp.ServerName)
	}
	t.Logf("initialize: %s %s", init.ServerInfo.Name, init.ServerInfo.Version)

	// --- the advertised surface, and the fifth tool's absence -------------
	//
	// `sign_commit` is RM-033 and does not exist. ADR-0024 requires the gap to
	// be REPORTED rather than silent, and Server.MissingTools names that duty;
	// this asserts both halves at once — the tool is not advertised, and the
	// health surface says which one is missing and does not go unready for it.
	listCtx, cancelList := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelList()
	tools, err := session.ListTools(listCtx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	advertised := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		advertised = append(advertised, tool.Name)
	}
	slices.Sort(advertised)
	for _, want := range []mcp.ToolName{
		mcp.ToolRegisterAgent, mcp.ToolGetCredential, mcp.ToolRecordEvent, mcp.ToolRetireAgent,
	} {
		if !slices.Contains(advertised, string(want)) {
			t.Errorf("the server does not advertise %s; it advertises %v", want, advertised)
		}
	}
	if slices.Contains(advertised, string(mcp.ToolSignCommit)) {
		t.Errorf("the server advertises %s, which has no binder (RM-033, #41): %v",
			mcp.ToolSignCommit, advertised)
	}
	t.Logf("advertised tools: %v", advertised)

	health := healthAddr(t, d)
	var live livenessWire
	if code := getJSON(t, "http://"+health+mcp.LivePath, &live); code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", mcp.LivePath, code)
	}
	if !slices.Contains(live.MissingTools, string(mcp.ToolSignCommit)) {
		t.Errorf("%s reports missing_tools=%v; %s has no binder and must be named there "+
			"(ADR-0024)", mcp.LivePath, live.MissingTools, mcp.ToolSignCommit)
	}
	if len(live.BoundTools) != 4 {
		t.Errorf("%s reports %d bound tools (%v), want the four that exist",
			mcp.LivePath, len(live.BoundTools), live.BoundTools)
	}

	// --- register_agent, and the chain and SPIRE afterwards ---------------
	key := c.name("rm068-register")
	runID := ""
	{
		out := c.callOnce(t, session, mcp.ToolRegisterAgent, map[string]any{
			"agent_type":      crashAgentType,
			"task_id":         serveTaskID,
			"idempotency_key": key,
		})
		var reply registerReply
		decodeInto(t, out, &reply)
		if reply.RunID == "" || reply.SPIFFEID == "" {
			t.Fatalf("register_agent returned %+v", reply)
		}
		runID = reply.RunID
		t.Cleanup(func() { retireRun(t, c, session, runID) })

		// (1) The event is on the REAL chain, found by the key the caller
		//     supplied, and it says what the reply said.
		rec, found := c.eventByKey(t, key)
		if !found {
			t.Fatalf("register_agent replied %+v and the chain holds no event for "+
				"idempotency_key %q. The reply came from something that is not the ledger.",
				reply, key)
		}
		if kind, ok := rec[event.FieldEventType].(string); !ok || kind != event.EventTypeRunRegistered {
			t.Errorf("the event for %q is %q, want %q", key, kind, event.EventTypeRunRegistered)
		}
		if got, ok := rec[event.FieldRunID].(string); !ok || got != reply.RunID {
			t.Errorf("the chain records run_id %q, the reply said %q", got, reply.RunID)
		}
		if got, ok := rec[event.FieldSpiffeID].(string); !ok || got != reply.SPIFFEID {
			t.Errorf("the chain records spiffe_id %q, the reply said %q", got, reply.SPIFFEID)
		}
		if got, ok := rec[event.FieldSource].(string); !ok || got != event.SourceMCP {
			t.Errorf("the chain records source %q, want %q", got, event.SourceMCP)
		}
		pos, ok := rec[event.FieldChainPosition].(int64)
		if !ok || pos < 1 {
			t.Fatalf("the event carries no usable chain_position: %#v", rec[event.FieldChainPosition])
		}
		t.Logf("run_registered for %s is at chain_position %d, spiffe_id %s",
			reply.RunID, pos, reply.SPIFFEID)

		// (2) The chain the server appended to is a real hash chain: it walks
		//     from doc 02 §4.4's genesis constant to its stored head. A double
		//     that returned plausible events could not survive this.
		records := c.chain(t)
		head, verr := ledger.Verify(records)
		if verr != nil {
			t.Fatalf("the chain the server appended to does not verify: %v", verr)
		}
		t.Logf("the chain walks clean from the genesis constant over %d events to position %d",
			len(records), head.Position)

		// (3) SPIRE really holds the run's registration entry. This is the
		//     half a mocked identity provider would have made vacuous.
		if !c.hasEntry(t, runRefFor(serveTaskID, reply.RunID)) {
			t.Fatalf("register_agent returned %s and the SPIRE server holds no entry for it. "+
				"I1: no identity, no attribution.", reply.SPIFFEID)
		}
		ids, ierr := c.stack.allEntrySPIFFEIDs(context.Background())
		if ierr != nil {
			t.Fatalf("reading the SPIRE datastore: %v", ierr)
		}
		if !slices.Contains(ids, reply.SPIFFEID) {
			t.Fatalf("the SPIRE datastore does not hold %s; it holds %v", reply.SPIFFEID, ids)
		}
		t.Logf("SPIRE holds the entry for %s", reply.SPIFFEID)
	}

	// --- record_event, through the shipped run directory ------------------
	//
	// This tool begins by resolving run_id through mcp.CredentialRuns. Until
	// RM-068 nothing implemented it, so the call below could not have been
	// answered at all by a deployment; that it is answered here is the
	// directory working against a real chain.
	{
		recordKey := c.name("rm068-record")
		out := c.callOnce(t, session, mcp.ToolRecordEvent, map[string]any{
			"run_id": runID,
			// ADR-0021: this argument names the AGENT TOOL that was
			// invoked and becomes the event's tool_name; record_event writes
			// exactly one event type, tool_call, and the caller does not
			// choose it.
			"event_type":      "shell.exec",
			"payload_digest":  "sha256:1100000000000000000000000000000000000000000000000000000000000000",
			"idempotency_key": recordKey,
		})
		var reply recordReply
		decodeInto(t, out, &reply)

		rec, found := c.eventByKey(t, recordKey)
		if !found {
			t.Fatalf("record_event replied %+v and the chain holds nothing for %q", reply, recordKey)
		}
		if got, ok := rec[event.FieldEventID].(string); !ok || got != reply.EventID {
			t.Errorf("the chain records event_id %q, the reply said %q", got, reply.EventID)
		}
		if got, ok := rec[event.FieldChainPosition].(int64); !ok || got != reply.ChainPosition {
			t.Errorf("the chain records chain_position %d, the reply said %d", got, reply.ChainPosition)
		}
		t.Logf("record_event resolved run %s through the shipped run directory and appended at %d",
			runID, reply.ChainPosition)
	}

	// --- retire_agent, twice: ADR-0020 §5 through the SERVED tool ---------
	//
	// The second call is answered from the run directory's reading of the
	// chain, not from a cache and not from a clock the tool does not have. IP
	// §4: "Idempotent: retiring a retired run returns success with the
	// original timestamp."
	var firstRetiredAt string
	{
		var first, second retireReply
		decodeInto(t, c.callOnce(t, session, mcp.ToolRetireAgent,
			map[string]any{"run_id": runID}), &first)
		if first.RetiredAt == "" {
			t.Fatal("retire_agent returned an empty retired_at")
		}
		firstRetiredAt = first.RetiredAt

		decodeInto(t, c.callOnce(t, session, mcp.ToolRetireAgent,
			map[string]any{"run_id": runID}), &second)
		if second.RetiredAt != first.RetiredAt {
			t.Fatalf("retiring a retired run returned %s, want the original %s (IP §4, ADR-0020)",
				second.RetiredAt, first.RetiredAt)
		}
		if c.hasEntry(t, runRefFor(serveTaskID, runID)) {
			t.Errorf("run %s is retired and SPIRE still holds its entry (IP §1)", runID)
		}
		t.Logf("retire_agent is idempotent through the shipped server: both calls returned %s",
			first.RetiredAt)
	}

	// --- and every other tool now refuses the retired run (MCP-009) -------
	{
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		res, cerr := session.CallTool(ctx, &sdk.CallToolParams{
			Name: string(mcp.ToolGetCredential),
			Arguments: map[string]any{
				"run_id": runID, "audience": mcp.AudienceSigstore,
			},
		})
		if cerr != nil {
			t.Fatalf("get_credential after retirement: transport failure %v", cerr)
		}
		if !res.IsError {
			t.Fatalf("get_credential succeeded for retired run %s; retirement is effective "+
				"immediately (IP §6.2)", runID)
		}
		class, _, message := errorOnTheWire(t, res)
		if class != string(mcp.ClassRunAlreadyRetired) {
			t.Fatalf("get_credential for a retired run is %s, want %s: %s",
				class, mcp.ClassRunAlreadyRetired, message)
		}
		if firstRetiredAt != "" && !containsInstant(message, firstRetiredAt) {
			t.Logf("note: the refusal does not quote the retirement instant: %s", message)
		}
		t.Logf("get_credential for the retired run: %s", class)
	}
}

// containsInstant reports whether the message quotes ts.
func containsInstant(message, ts string) bool {
	return ts != "" && strings.Contains(message, ts)
}

// countRegistrations counts every `run_registered` on the chain, whatever run
// it names. The refused call's cost to the ledger is measured over the WHOLE
// chain rather than over one run id, because a meter that leaked would leak a
// run this test cannot name in advance.
func countRegistrations(records []event.Fields) int {
	n := 0
	for _, rec := range records {
		if kind, ok := rec[event.FieldEventType].(string); ok && kind == event.EventTypeRunRegistered {
			n++
		}
	}
	return n
}

// errorOnTheWire decodes IP §4's structured error off a tool result.
func errorOnTheWire(t *testing.T, res *sdk.CallToolResult) (class string, retryable bool, message string) {
	t.Helper()
	body, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("re-encoding the error result: %v", err)
	}
	var wire struct {
		Class     string `json:"error_class"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
		RunID     string `json:"run_id"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("the error result %s is not IP §4's object: %v", body, err)
	}
	if wire.Class == "" {
		t.Fatalf("the error result %s carries no error_class", body)
	}
	return wire.Class, wire.Retryable, wire.Message
}

// TestTheServedRegisterAgentIsMetered is ADR-0025 asserted where it can be got
// wrong.
//
// The ADR states the wiring rule: "`RateLimitRegisterAgent` must be called
// before `ConfigureRegisterAgent` or the tool is unmetered." Both orders
// compile, both produce a working `register_agent`, and the wrong one ships a
// tool that serves every caller at every rate with nothing anywhere reporting
// it — AB-07 recorded as mitigated and not mitigated. Nothing inside
// `internal/mcp` can catch that, because the mistake is not in `internal/mcp`.
//
// So this asserts the SERVED tool: it calls `register_agent` through the MCP
// transport of the shipped binary until the limit refuses it, and it does NOT
// inspect how the configuration was built.
//
// The negative control is the other half. A test that only saw a refusal could
// be seeing anything — an exhausted SPIRE, a full disk, a bug. The same two
// calls are made a second time against a server started UNMETERED, and there
// they must both succeed. The refusal is therefore attributable to the meter
// and to nothing else.
func TestTheServedRegisterAgentIsMetered(t *testing.T) {
	c := requireCrashCampaign(t)

	// One call per window: the second call is over the limit by construction,
	// and the window is long enough that no wall-clock delay in this test can
	// refill the bucket.
	metered := c.startWith(t,
		"-register-rate-calls", "1",
		"-register-rate-window", "1h",
	)
	session := c.connect(t, metered, metered.addr)

	task := serveTaskID + "-metered"
	call := func(s *sdk.ClientSession, n int) *sdk.CallToolResult {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		res, err := s.CallTool(ctx, &sdk.CallToolParams{
			Name: string(mcp.ToolRegisterAgent),
			Arguments: map[string]any{
				// One caller: the rate limiter's bucket is keyed on
				// (agent_type, task_ref), so both calls are the same caller.
				// Distinct idempotency keys, so the second is a NEW call and
				// not a replay the idempotency store would answer from its
				// record without the tool running at all.
				"agent_type":      crashAgentType,
				"task_id":         task,
				"idempotency_key": c.name(fmt.Sprintf("rm068-meter-%d", n)),
			},
		})
		if err != nil {
			t.Fatalf("register_agent #%d: transport failure %v", n, err)
		}
		return res
	}

	first := call(session, 1)
	if first.IsError {
		class, _, message := errorOnTheWire(t, first)
		t.Fatalf("the first register_agent inside the limit was refused as %s: %s", class, message)
	}
	var admitted registerReply
	decodeInto(t, first.StructuredContent, &admitted)
	t.Cleanup(func() { retireRun(t, c, session, admitted.RunID) })
	if !c.hasEntry(t, runRefFor(task, admitted.RunID)) {
		t.Fatalf("the admitted call returned %s and SPIRE holds no entry for it", admitted.SPIFFEID)
	}

	before := countRegistrations(c.chain(t))

	second := call(session, 2)
	if !second.IsError {
		var extra registerReply
		decodeInto(t, second.StructuredContent, &extra)
		t.Cleanup(func() { retireRun(t, c, session, extra.RunID) })
		t.Fatalf("the second register_agent from the same caller was ADMITTED, returning %s. "+
			"The server was started with -register-rate-calls=1: register_agent is being served "+
			"UNMETERED. ADR-0025: RateLimitRegisterAgent must wrap the configuration BEFORE "+
			"ConfigureRegisterAgent, and both orders compile.", extra.SPIFFEID)
	}
	class, retryable, message := errorOnTheWire(t, second)
	if class != string(mcp.ClassIdentityUnavailable) {
		t.Fatalf("the refused call is %s, want %s (ADR-0025 ships the wait as IDENTITY_UNAVAILABLE "+
			"because IP §4 has no class for \"slow down\"): %s",
			class, mcp.ClassIdentityUnavailable, message)
	}
	if !retryable {
		t.Errorf("a rate-limit refusal is not retryable on the wire; a caller told to wait must " +
			"be told the wait can succeed")
	}
	t.Logf("the served register_agent refused the second call: %s — %s", class, message)

	// Nothing durable happened on the refused call. The meter sits in front of
	// the tool's ledger, so a refusal must leave no event; if it left one, the
	// limit would be bounding replies and not work.
	after := countRegistrations(c.chain(t))
	if after != before {
		t.Errorf("the refused call appended %d run_registered event(s); a refusal must cost the "+
			"ledger nothing", after-before)
	}

	// --- the negative control --------------------------------------------
	unmetered := c.startWith(t, "-register-rate-calls", "0")
	control := c.connect(t, unmetered, unmetered.addr)
	controlTask := serveTaskID + "-control"
	for n := range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := control.CallTool(ctx, &sdk.CallToolParams{
			Name: string(mcp.ToolRegisterAgent),
			Arguments: map[string]any{
				"agent_type":      crashAgentType,
				"task_id":         controlTask,
				"idempotency_key": c.name(fmt.Sprintf("rm068-control-%d", n)),
			},
		})
		cancel()
		if err != nil {
			t.Fatalf("control register_agent #%d: transport failure %v", n, err)
		}
		if res.IsError {
			cls, _, msg := errorOnTheWire(t, res)
			t.Fatalf("control register_agent #%d was refused as %s: %s. Both control calls must "+
				"succeed, or the refusal above is not attributable to the rate limit.",
				n, cls, msg)
		}
		var reply registerReply
		decodeInto(t, res.StructuredContent, &reply)
		runID := reply.RunID
		t.Cleanup(func() { retireRun(t, c, control, runID) })
	}
	t.Log("negative control: with -register-rate-calls=0 the same two calls both succeed, " +
		"so the refusal above came from the meter")
}

// TestTheHealthEndpointsThroughTheShippedServer is IP §6.6 and ADR-0024 as the
// operator meets them.
//
// The stack this file runs against has a real SPIRE and a real Postgres and no
// Sigstore at all — RM-030 builds that — and the server is pointed at a closed
// port for Fulcio and Rekor. That is exactly the shape MCP-012 asks for: one
// dependency down, the other two up. `ready` must be false, the report must
// NAME the one that is down, and it must not go uniformly red.
func TestTheHealthEndpointsThroughTheShippedServer(t *testing.T) {
	c := requireCrashCampaign(t)
	d := c.start(t)
	base := "http://" + healthAddr(t, d)

	// --- /healthz contacts nothing ---------------------------------------
	//
	// Sigstore is unreachable for this process. If liveness were derived from
	// a dependency, this would be the request that showed it: an orchestrator
	// would restart every replica over somebody else's outage.
	var live livenessWire
	if code := getJSON(t, base+mcp.LivePath, &live); code != http.StatusOK {
		t.Fatalf("GET %s = %d with a dependency down, want 200. Liveness must not be derived "+
			"from a dependency (ADR-0024).", mcp.LivePath, code)
	}
	if !live.Alive {
		t.Errorf("%s answered and reported alive=false", mcp.LivePath)
	}
	if len(live.Dependencies) != 0 {
		t.Errorf("%s reported %d dependencies; it must contact none",
			mcp.LivePath, len(live.Dependencies))
	}
	if live.Version == "" {
		t.Errorf("%s reports no version", mcp.LivePath)
	}

	// --- /readyz names the one that is down -------------------------------
	var ready readinessWire
	code := getJSON(t, base+mcp.ReadyPath, &ready)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("GET %s = %d with Sigstore unreachable, want 503 (IP §6.6)", mcp.ReadyPath, code)
	}
	if ready.Ready {
		t.Errorf("%s reports ready=true while a dependency is unreachable", mcp.ReadyPath)
	}
	if len(ready.Dependencies) != len(mcp.Dependencies()) {
		t.Fatalf("%s reported %d dependencies, want one per IP §6.6 dependency (%d): %+v",
			mcp.ReadyPath, len(ready.Dependencies), len(mcp.Dependencies()), ready.Dependencies)
	}

	seen := map[string]bool{}
	for _, dep := range ready.Dependencies {
		seen[dep.Dependency] = dep.Reachable
		if dep.LatencyMS < 0 {
			t.Errorf("%s reports a negative latency for %s", mcp.ReadyPath, dep.Dependency)
		}
		switch dep.Dependency {
		case string(mcp.DependencySigstore):
			if dep.Reachable {
				t.Errorf("%s reports Sigstore reachable; this stack has none and the server is "+
					"pointed at a closed port", mcp.ReadyPath)
			}
			if dep.Class != string(mcp.ClassSigningUnavailable) &&
				dep.Class != string(mcp.ClassTransparencyUnavailable) {
				t.Errorf("the Sigstore failure is %q, want %s or %s (IP §6.3 gives the two "+
					"halves separate classes)", dep.Class,
					mcp.ClassSigningUnavailable, mcp.ClassTransparencyUnavailable)
			}
			if dep.Detail == "" {
				t.Errorf("the Sigstore failure carries no detail; an operator has nothing to act on")
			}
		default:
			// SPIRE and the ledger are real and up. This is the half MCP-012
			// exists for: one outage must not make the others LOOK broken.
			if !dep.Reachable {
				t.Errorf("%s reports %s unreachable (%s: %s). It is up in this stack; a report "+
					"that goes uniformly red during an incident names the wrong systems.",
					mcp.ReadyPath, dep.Dependency, dep.Class, dep.Detail)
			}
			if dep.Class != "" {
				t.Errorf("%s is reachable and carries error_class %q", dep.Dependency, dep.Class)
			}
		}
	}
	for _, want := range mcp.Dependencies() {
		if _, ok := seen[string(want)]; !ok {
			t.Errorf("%s does not report on %s", mcp.ReadyPath, want)
		}
	}

	// An incomplete tool surface is reported and never a reason to be unready.
	if !slices.Contains(ready.MissingTools, string(mcp.ToolSignCommit)) {
		t.Errorf("%s reports missing_tools=%v, want it to name %s (ADR-0024)",
			mcp.ReadyPath, ready.MissingTools, mcp.ToolSignCommit)
	}
	t.Logf("%s: ready=%v, dependencies=%+v", mcp.ReadyPath, ready.Ready, ready.Dependencies)

	// --- the endpoints are a read and nothing else ------------------------
	postCtx, cancelPost := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPost()
	req, err := http.NewRequestWithContext(postCtx, http.MethodPost, base+mcp.ReadyPath, nil)
	if err != nil {
		t.Fatalf("build a POST: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", mcp.ReadyPath, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST %s = %d, want 405. This process holds SPIRE admin (IP §1) and a health "+
			"surface that accepted a body would be a second door into it.",
			mcp.ReadyPath, res.StatusCode)
	}
}

// TestServeRunsUnderAnAppendOnlyDatabaseRole is doc 05 §1's least-privilege
// requirement, measured rather than asserted.
//
//	innsegl-mcp | built | The MCP server | Only service holding SPIRE admin credential
//
// and, one line down in the same table, `innsegl-dashboard`'s "No write
// credentials mounted — enforced by giving it a read-only DB role". The MCP's
// half of that shape is a role that can append and cannot delete.
//
// Nothing in the deployment enforces it today: migration 0001 revokes UPDATE,
// DELETE and TRUNCATE from PUBLIC and the append-only trigger refuses them, but
// a trigger is disableable by a superuser and a revoke does not bind the table
// owner. So `innsegl serve` measures its OWN role at start-up, and this case
// runs it both ways against a real Postgres:
//
//   - under a purpose-made append-only role it starts with
//     -require-append-only-role set, and registers an agent through the
//     served tool — so the role really is sufficient for the MCP's job, which a
//     test that only checked the privilege bits would not have shown;
//   - under the owning role, with the same flag, it refuses to start and names
//     what the role holds.
//
// The role's incapacity is checked directly too: a DELETE issued as that role
// over a raw connection is refused.
func TestServeRunsUnderAnAppendOnlyDatabaseRole(t *testing.T) {
	c := requireCrashCampaign(t)

	role := fmt.Sprintf("innsegl_mcp_%d", time.Now().UnixNano()%1000000)
	password := "least-privilege"
	appendOnlyDSN := grantAppendOnlyRole(t, c.dsn, role, password)

	// --- the append-only role serves ---------------------------------------
	d := c.startWith(t,
		"-dsn", appendOnlyDSN,
		"-require-append-only-role",
	)
	session := c.connect(t, d, d.addr)

	if log := d.stderr.String(); !strings.Contains(log, "append-only") {
		t.Errorf("the server did not report its database role at start-up. stderr:\n%s", log)
	}

	key := c.name("rm068-least-privilege")
	task := serveTaskID + "-role"
	out := c.callOnce(t, session, mcp.ToolRegisterAgent, map[string]any{
		"agent_type":      crashAgentType,
		"task_id":         task,
		"idempotency_key": key,
	})
	var reply registerReply
	decodeInto(t, out, &reply)
	t.Cleanup(func() { retireRun(t, c, session, reply.RunID) })

	if _, found := c.eventByKey(t, key); !found {
		t.Fatalf("register_agent replied %+v under the append-only role and the chain holds "+
			"nothing for %q", reply, key)
	}
	if !c.hasEntry(t, runRefFor(task, reply.RunID)) {
		t.Fatalf("SPIRE holds no entry for %s", reply.SPIFFEID)
	}
	t.Logf("role %q appended run_registered for %s and created its SPIRE entry", role, reply.RunID)

	// --- and cannot unmake what it wrote -----------------------------------
	requireDeleteRefused(t, appendOnlyDSN, role)

	// --- the owning role is refused when the flag is set --------------------
	code, stderr := runServeToCompletion(t, c, "-dsn", c.dsn, "-require-append-only-role")
	if code == 0 {
		t.Fatalf("`innsegl serve -require-append-only-role` started under the OWNING role, "+
			"which holds DELETE on innsegl.events. stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "DELETE") {
		t.Errorf("the refusal does not name what the role holds; an operator has nothing to "+
			"act on. stderr:\n%s", stderr)
	}
	t.Logf("the owning role is refused with -require-append-only-role, exit %d", code)
}

// grantAppendOnlyRole creates the role doc 05 §1 describes and returns a DSN
// for it. The grants are the smallest set that lets the MCP do its job: read
// the chain's identity, append events, and keep the idempotency store — which
// is UPDATEable by design (ADR-0017 records a reply into a claimed row) and
// whose TRUNCATE migration 0002 already revokes.
func grantAppendOnlyRole(t *testing.T, ownerDSN, role, password string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connect as the owner: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	database := databaseOf(t, ownerDSN)
	for _, stmt := range []string{
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, password),
		fmt.Sprintf("GRANT CONNECT ON DATABASE %q TO %s", database, role),
		fmt.Sprintf("GRANT USAGE ON SCHEMA innsegl TO %s", role),
		fmt.Sprintf("GRANT SELECT ON innsegl.chain TO %s", role),
		// The whole point: SELECT and INSERT, and nothing that unmakes a row.
		fmt.Sprintf("GRANT SELECT, INSERT ON innsegl.events TO %s", role),
		fmt.Sprintf("GRANT SELECT, INSERT, UPDATE ON innsegl.idempotency TO %s", role),
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancelCleanup()
		cleanup, cerr := pgx.Connect(cleanupCtx, ownerDSN)
		if cerr != nil {
			return
		}
		defer func() { _ = cleanup.Close(context.Background()) }()
		// A role that outlives its test is noise in a shared container, not a
		// failure of anything this case asserts, so a cleanup that cannot run
		// is reported and does not fail the test.
		for _, stmt := range []string{
			fmt.Sprintf("REASSIGN OWNED BY %s TO %s", role, pgUser),
			fmt.Sprintf("DROP OWNED BY %s", role),
			fmt.Sprintf("DROP ROLE IF EXISTS %s", role),
		} {
			if _, derr := cleanup.Exec(cleanupCtx, stmt); derr != nil {
				t.Logf("warning: cleaning up %s: %s: %v", role, stmt, derr)
			}
		}
	})

	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable",
		role, password, pgPort, database)
}

// databaseOf reads the database name out of a DSN this file built.
func databaseOf(t *testing.T, dsn string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %q: %v", dsn, err)
	}
	return cfg.Database
}

// requireDeleteRefused proves the role cannot unmake a written event, over a
// raw connection that bypasses every Go guard.
//
// The append-only TRIGGER would refuse this too, with SQLSTATE IN001. The
// refusal wanted here is the PRIVILEGE one — SQLSTATE 42501 — because that is
// the one a superuser cannot switch off, and it is what "runs under a role that
// can append but not delete" actually means.
func requireDeleteRefused(t *testing.T, dsn, role string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	_, err = conn.Exec(ctx, "DELETE FROM innsegl.events")
	if err == nil {
		t.Fatalf("role %s deleted from innsegl.events. doc 05 §1 requires a role that can "+
			"append and not delete, and I4 requires the record to be permanent.", role)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("DELETE as %s failed with %v, which is not a database refusal", role, err)
	}
	if pgErr.Code != "42501" {
		t.Errorf("DELETE as %s was refused with SQLSTATE %s (%s); want 42501, insufficient "+
			"privilege. A trigger refusal is disableable by a superuser and a privilege "+
			"refusal is not.", role, pgErr.Code, pgErr.Message)
	}
	t.Logf("DELETE as %s: SQLSTATE %s — %s", role, pgErr.Code, pgErr.Message)
}

// runServeToCompletion runs the shipped binary with extra flags and waits for
// it to exit, returning its status and stderr. It is for the cases where the
// server must REFUSE to start; c.startWith is for the ones where it must serve.
func runServeToCompletion(t *testing.T, c *campaign, extra ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	args := append([]string{"serve",
		"-dsn", c.dsn,
		"-spire-address", c.stack.socatAddr,
		"-trust-domain", failureTrustDomain,
		"-spire-server-id", failureServerID,
		"-parent-id", c.stack.parentID,
		"-svid", filepath.Join(c.pemDir, "svid.pem"),
		"-key", filepath.Join(c.pemDir, "key.pem"),
		"-bundle", filepath.Join(c.pemDir, "bundle.pem"),
		"-listen", "127.0.0.1:0",
		"-health-listen", "127.0.0.1:0",
		"-fulcio-url", "http://127.0.0.1:1",
		"-rekor-url", "http://127.0.0.1:1",
	}, extra...)

	cmd := exec.CommandContext(ctx, c.binary, args...)
	var stderr, stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err := cmd.Run()

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		// It started and served until the context expired, which is not a
		// refusal. Report it as exit 0 and let the caller fail.
		return 0, stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stderr.String()
	default:
		t.Fatalf("running the server: %v\nstderr:\n%s", err, stderr.String())
		return -1, ""
	}
}

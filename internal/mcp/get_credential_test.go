// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-023 (#31) — get_credential(run_id, audience) -> {jwt_svid, expires_at}.
//
// Doc 07 puts MCP-002, MCP-008 and MCP-014 at layer C — contract — and IP §2
// admits mocks there: "Mocks are allowed for unit and contract tests." What
// those cases are about is the tool's own decision procedure, which is the
// thing a double can exercise exhaustively and a container cannot.
//
// The integration half is TestGetCredentialAgainstRealSPIRE at the bottom of
// this file. It runs the SHIPPED minter against the SHIPPED compose stack —
// deploy/compose/spire.yml with deploy/compose/spire/authz-policy.rego — and
// is where the claim "MintJWTSVID is scoped to the agent subtree" is measured
// rather than asserted. Without Docker it skips, naming what went unproven.

// ---------------------------------------------------------------------------
// Test doubles.
// ---------------------------------------------------------------------------

const (
	credTrustDomain = "innsegl.dev"
	credAgentType   = "demo"
	credTaskID      = "rm-023"
)

// credRunID builds the SPIFFE ID of a run in the reference trust domain.
func credSPIFFEID(runID string) string {
	return "spiffe://" + credTrustDomain + "/agent/" + credAgentType + "/" + credTaskID + "/" + runID
}

func credRun(runID string) CredentialRun {
	return CredentialRun{
		RunID:     runID,
		AgentType: credAgentType,
		TaskID:    credTaskID,
		SPIFFEID:  credSPIFFEID(runID),
	}
}

// credRuns is the run directory get_credential resolves run_id against.
type credRuns struct {
	mu    sync.Mutex
	runs  map[string]CredentialRun
	err   error
	calls int
}

func newCredRuns(runs ...CredentialRun) *credRuns {
	d := &credRuns{runs: make(map[string]CredentialRun, len(runs))}
	for _, r := range runs {
		d.runs[r.RunID] = r
	}
	return d
}

func (d *credRuns) CredentialRun(_ context.Context, runID string) (CredentialRun, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.err != nil {
		return CredentialRun{}, false, d.err
	}
	r, ok := d.runs[runID]
	return r, ok, nil
}

// putAs files r under key, which is not always r.RunID: a directory that
// answers for the wrong run is one of the things this tool refuses.
func (d *credRuns) putAs(key string, r CredentialRun) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.runs[key] = r
}

func (d *credRuns) retire(runID string, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.runs[runID]
	r.RetiredAt = at
	d.runs[runID] = r
}

func (d *credRuns) fail(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

// credEntries stands in for SPIRE's own answer to "does this run still have a
// registration entry?". *spire.Client is the production implementation.
type credEntries struct {
	mu     sync.Mutex
	absent map[string]bool
	err    error
	seen   []spire.RunRef
}

func newCredEntries() *credEntries { return &credEntries{absent: map[string]bool{}} }

func (e *credEntries) RequireActiveRun(_ context.Context, run spire.RunRef) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen = append(e.seen, run)
	if e.err != nil {
		return e.err
	}
	if e.absent[run.RunID] {
		return &spire.Error{
			Class: spire.ClassRunNotFound, Op: "require_active_run", RunID: run.RunID,
			Message: "SPIRE holds no registration entry", Retryable: false,
		}
	}
	return nil
}

func (e *credEntries) delete(runID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.absent[runID] = true
}

func (e *credEntries) fail(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.err = err
}

func (e *credEntries) calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.seen)
}

// credMintCall is one MintJWTSVID the tool made.
type credMintCall struct {
	SPIFFEID string
	Audience string
}

// credMinter counts and records every mint. The count is what keeps MCP-008
// from passing vacuously: "the wrong audience was refused" means nothing
// unless the right one, on the same fixture, did mint.
type credMinter struct {
	mu       sync.Mutex
	calls    []credMintCall
	err      error
	ttl      time.Duration
	now      func() time.Time
	forceID  string
	forceAud string
	seq      int
}

func newCredMinter(now func() time.Time) *credMinter {
	return &credMinter{ttl: 5 * time.Minute, now: now}
}

func (m *credMinter) MintJWTSVID(_ context.Context, spiffeID, audience string) (MintedCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, credMintCall{SPIFFEID: spiffeID, Audience: audience})
	if m.err != nil {
		return MintedCredential{}, m.err
	}
	m.seq++
	id, aud := spiffeID, audience
	if m.forceID != "" {
		id = m.forceID
	}
	if m.forceAud != "" {
		aud = m.forceAud
	}
	return MintedCredential{
		Token:     fmt.Sprintf("jwt-svid-%d-for-%s", m.seq, spiffeID),
		SPIFFEID:  id,
		Audience:  aud,
		ExpiresAt: m.now().Add(m.ttl),
	}, nil
}

func (m *credMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *credMinter) last() credMintCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return credMintCall{}
	}
	return m.calls[len(m.calls)-1]
}

func (m *credMinter) fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

// credLedger records what the tool appended.
type credLedger struct {
	mu       sync.Mutex
	appended []event.Fields
	err      error
	next     int64
}

func (l *credLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	l.next++
	rec := body.Clone()
	rec[event.FieldEventID] = fmt.Sprintf("0192f0a0-0000-7000-8000-%012d", l.next)
	rec[event.FieldChainPosition] = l.next
	l.appended = append(l.appended, rec)
	return rec, nil
}

func (l *credLedger) fail(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
}

func (l *credLedger) records() []event.Fields {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]event.Fields, len(l.appended))
	copy(out, l.appended)
	return out
}

func (l *credLedger) countOf(eventType, runID string) int {
	n := 0
	for _, rec := range l.records() {
		if rec[event.FieldEventType] == eventType && rec[event.FieldRunID] == runID {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Fixture: the tool, bound through the real registration seam, served over the
// real HTTP transport, driven by a real MCP client.
// ---------------------------------------------------------------------------

type credFixture struct {
	t       *testing.T
	session *sdk.ClientSession
	runs    *credRuns
	entries *credEntries
	minter  *credMinter
	ledger  *credLedger
	clock   time.Time
}

// withCredentialConfig installs cfg for the duration of the test.
func withCredentialConfig(t *testing.T, cfg CredentialConfig) {
	t.Helper()
	credentialMu.Lock()
	saved := credentialActive
	credentialMu.Unlock()
	t.Cleanup(func() {
		credentialMu.Lock()
		credentialActive = saved
		credentialMu.Unlock()
	})
	if err := ConfigureGetCredential(cfg); err != nil {
		t.Fatalf("ConfigureGetCredential: %v", err)
	}
}

// serveGetCredential binds get_credential through RegisterTool/Bind — the same
// seam New uses in production — and serves it over the HTTP transport.
func serveGetCredential(t *testing.T) *sdk.ClientSession {
	t.Helper()
	withEmptyToolRegistry(t)
	RegisterTool(ToolGetCredential, bindGetCredential)
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return connect(t, httpSrv.URL)
}

func newCredFixture(t *testing.T, runs ...CredentialRun) *credFixture {
	t.Helper()
	f := &credFixture{
		t:       t,
		runs:    newCredRuns(runs...),
		entries: newCredEntries(),
		ledger:  &credLedger{},
		clock:   time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
	}
	f.minter = newCredMinter(func() time.Time { return f.clock })
	withCredentialConfig(t, CredentialConfig{
		Runs:    f.runs,
		Entries: f.entries,
		Minter:  f.minter,
		Ledger:  f.ledger,
		Now:     func() time.Time { return f.clock },
	})
	f.session = serveGetCredential(t)
	return f
}

// credReply is one tools/call result, decoded.
type credReply struct {
	isError bool
	wire    map[string]any
}

func (f *credFixture) call(t *testing.T, runID, audience string) credReply {
	t.Helper()
	res, err := f.session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolGetCredential),
		Arguments: map[string]any{"run_id": runID, "audience": audience},
	})
	if err != nil {
		t.Fatalf("tools/call get_credential(%q, %q): %v", runID, audience, err)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want a JSON object: %+v", res.StructuredContent, res.Content)
	}
	return credReply{isError: res.IsError, wire: wire}
}

// mustIssue requires a successful issuance and returns the reply object.
func (f *credFixture) mustIssue(t *testing.T, runID, audience string) map[string]any {
	t.Helper()
	r := f.call(t, runID, audience)
	if r.isError {
		t.Fatalf("get_credential(%q, %q) failed: %v", runID, audience, r.wire)
	}
	return r.wire
}

// mustRefuse requires the named class, and returns the wire error.
func (f *credFixture) mustRefuse(t *testing.T, runID, audience string, class Class) map[string]any {
	t.Helper()
	r := f.call(t, runID, audience)
	if !r.isError {
		t.Fatalf("get_credential(%q, %q) succeeded; want %s", runID, audience, class)
	}
	if got := r.wire["error_class"]; got != string(class) {
		t.Fatalf("get_credential(%q, %q): error_class = %v, want %s (message %v)",
			runID, audience, got, class, r.wire["message"])
	}
	if got, want := r.wire["retryable"], class.Retryable(); got != want {
		t.Errorf("retryable = %v, want %v for %s (ADR-0016)", got, want, class)
	}
	return r.wire
}

// ---------------------------------------------------------------------------
// MCP-002 — schema conformance: valid input -> documented result shape.
// ---------------------------------------------------------------------------

// TestMCP002GetCredentialSchemaConformance is doc 07 MCP-001..005 for this
// tool: "valid input → documented result shape | Exact schema match | IP §4".
//
// IP §4: get_credential(run_id, audience) → {jwt_svid, expires_at}. Two
// parameters and two result members, and — ADR-0004 — no idempotency_key on
// either side, because a repeat call is a legitimate re-fetch and not a retry.
func TestMCP002GetCredentialSchemaConformance(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))

	tools, err := f.session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var advertised *sdk.Tool
	for _, tool := range tools.Tools {
		if tool.Name == string(ToolGetCredential) {
			advertised = tool
		}
	}
	if advertised == nil {
		t.Fatalf("tools/list does not advertise get_credential: %+v", tools.Tools)
	}

	in := credSchemaMembers(t, advertised.InputSchema)
	if want := []string{"audience", "run_id"}; !equalStrings(in, want) {
		t.Errorf("input schema members = %v, IP §4 says get_credential(run_id, audience) = %v", in, want)
	}
	out := credSchemaMembers(t, advertised.OutputSchema)
	if want := []string{"expires_at", "jwt_svid"}; !equalStrings(out, want) {
		t.Errorf("result schema members = %v, IP §4 says {jwt_svid, expires_at} = %v", out, want)
	}

	reply := f.mustIssue(t, "run-a", AudienceSigstore)
	gotMembers := make([]string, 0, len(reply))
	for k := range reply {
		gotMembers = append(gotMembers, k)
	}
	if want := []string{"expires_at", "jwt_svid"}; !equalStrings(sortedStrings(gotMembers), want) {
		t.Errorf("result members = %v, IP §4 says %v", sortedStrings(gotMembers), want)
	}

	token, ok := reply["jwt_svid"].(string)
	if !ok || token == "" {
		t.Errorf("jwt_svid = %#v, want a non-empty string", reply["jwt_svid"])
	}
	expires, ok := reply["expires_at"].(string)
	if !ok {
		t.Fatalf("expires_at = %#v, want a string", reply["expires_at"])
	}
	// The reply's expiry is spelled exactly as the ledger spells it (doc 02
	// §1), so the two records of one issuance cannot disagree by format.
	ts, err := event.ParseTimestamp(expires)
	if err != nil {
		t.Errorf("expires_at %q is not a doc 02 §1 timestamp: %v", expires, err)
	}
	if want := f.clock.Add(5 * time.Minute); !ts.Time().Equal(want) {
		t.Errorf("expires_at = %s, want the minted expiry %s", ts, event.NewTimestamp(want))
	}

	// One issuance, one credential_issued event (doc 02 §3, I3).
	recs := f.ledger.records()
	if len(recs) != 1 {
		t.Fatalf("appended %d events for one issuance, want 1: %+v", len(recs), recs)
	}
	rec := recs[0]
	for _, c := range []struct{ name, want string }{
		{event.FieldEventType, event.EventTypeCredentialIssued},
		{event.FieldRunID, "run-a"},
		{event.FieldSpiffeID, credSPIFFEID("run-a")},
		{event.FieldSource, event.SourceMCP},
		{event.FieldAudience, AudienceSigstore},
		{event.FieldCredentialExpiry, expires},
		{event.FieldSchemaVersion, event.SchemaVersion},
	} {
		if got := rec[c.name]; got != c.want {
			t.Errorf("credential_issued[%s] = %#v, want %q", c.name, got, c.want)
		}
	}
	// ADR-0004: forbidden on credential_issued, whatever the source.
	if _, present := rec[event.FieldIdempotencyKey]; present {
		t.Errorf("credential_issued carries an idempotency_key; ADR-0004 forbids it")
	}
	// The ledger assigns these; a tool that supplies one is refused.
	for _, name := range []string{event.FieldTS, event.FieldPrevEventHash, event.EventHashField} {
		if _, present := rec[name]; present && name != event.FieldTS {
			t.Errorf("the tool supplied %s; the ledger assigns it (doc 02 §2)", name)
		}
	}
}

// credSchemaMembers reads the property names off an advertised JSON schema.
func credSchemaMembers(t *testing.T, schema any) []string {
	t.Helper()
	if schema == nil {
		t.Fatalf("tool advertises no schema")
	}
	raw, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	var decoded struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode schema %s: %v", raw, err)
	}
	names := make([]string, 0, len(decoded.Properties))
	for k := range decoded.Properties {
		names = append(names, k)
	}
	return sortedStrings(names)
}

func sortedStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// TestGetCredentialTakesNoIdempotencyKey. ADR-0004 in one assertion: a repeat
// call is a second issuance, not a replayed one, so the tool has no key to
// dedupe on and each call produces its own credential and its own event.
func TestGetCredentialTakesNoIdempotencyKey(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))

	first := f.mustIssue(t, "run-a", AudienceSigstore)
	second := f.mustIssue(t, "run-a", AudienceSigstore)

	if first["jwt_svid"] == second["jwt_svid"] {
		t.Errorf("two calls returned the same credential; IP §6.2's re-fetch must mint again")
	}
	if got := f.minter.count(); got != 2 {
		t.Errorf("minted %d credentials for two calls, want 2", got)
	}
	if got := f.ledger.countOf(event.EventTypeCredentialIssued, "run-a"); got != 2 {
		t.Errorf("appended %d credential_issued events for two issuances, want 2 — "+
			"collapsing them would hide credential churn from an auditor (ADR-0004)", got)
	}
	// A call carrying an idempotency_key is not a call this tool accepts.
	res, err := f.session.CallTool(t.Context(), &sdk.CallToolParams{
		Name: string(ToolGetCredential),
		Arguments: map[string]any{
			"run_id": "run-a", "audience": AudienceSigstore, "idempotency_key": "k-1",
		},
	})
	if err == nil && !res.IsError {
		t.Errorf("get_credential accepted an idempotency_key; IP §4 gives it none")
	}
}

// ---------------------------------------------------------------------------
// MCP-008 — audience allowlist, both directions (I2, IP §6.2).
// ---------------------------------------------------------------------------

// TestMCP008AudienceAllowlist is doc 07 MCP-008: "get_credential with audience
// not in allowlist → AUDIENCE_MISMATCH". IP §6.2 requires both directions to
// be tested:
//
//	Audience misuse: a credential minted for `sigstore` presented anywhere
//	else must fail server-side allowlisting (AUDIENCE_MISMATCH) and be
//	useless at the wrong relying party. Test both directions.
//
// HOW THIS CASE IS KEPT FROM PASSING VACUOUSLY. "The wrong audience was
// refused" is what a tool that never mints anything at all also does. So the
// allowed audience is issued FIRST, on this fixture, for this run — the
// positive control — and issued AGAIN afterwards on the same session, so a
// refusal in between cannot be explained by the fixture having gone bad. Each
// refusal additionally asserts the mint counter did not move: not merely that
// an error came back, but that no credential was minted for it.
func TestMCP008AudienceAllowlist(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))

	// (1) Positive control, before anything is refused.
	before := f.mustIssue(t, "run-a", AudienceSigstore)
	if got := f.minter.count(); got != 1 {
		t.Fatalf("the positive control minted %d credentials, want 1", got)
	}
	if got := f.minter.last().Audience; got != AudienceSigstore {
		t.Fatalf("the positive control minted for audience %q, want %q", got, AudienceSigstore)
	}
	baselineMints, baselineEvents := f.minter.count(), len(f.ledger.records())

	// (2) Direction one: an audience outside the allowlist is refused, and
	// nothing is minted for it.
	for _, audience := range []string{
		"",
		"fulcio",
		"rekor",
		"SIGSTORE",
		"sigstore ",
		" sigstore",
		"sigstore.dev",
		"https://oauth2.sigstore.dev/auth",
		"sigstore,fulcio",
	} {
		t.Run(fmt.Sprintf("audience=%q", audience), func(t *testing.T) {
			wire := f.mustRefuse(t, "run-a", audience, ClassAudienceMismatch)
			if got := wire["run_id"]; got != "run-a" {
				t.Errorf("run_id = %v, want the run the caller named", got)
			}
			if got := f.minter.count(); got != baselineMints {
				t.Errorf("a refused audience still minted a credential (%d -> %d)", baselineMints, got)
			}
			if got := len(f.ledger.records()); got != baselineEvents {
				t.Errorf("a refused audience still appended an event (%d -> %d)", baselineEvents, got)
			}
			// The refused audience must never reach SPIRE.
			if last := f.minter.last().Audience; last != AudienceSigstore {
				t.Errorf("the last mint asked for audience %q; the refusal leaked", last)
			}
		})
	}

	// (3) The positive control again, after the refusals, on the same session
	// and the same run. If this fails, every refusal above proved nothing.
	after := f.mustIssue(t, "run-a", AudienceSigstore)
	if before["jwt_svid"] == after["jwt_svid"] {
		t.Errorf("the second control returned the first credential")
	}
	if got := f.minter.count(); got != baselineMints+1 {
		t.Errorf("the trailing control minted %d credentials in total, want %d",
			got, baselineMints+1)
	}
}

// TestMCP008ACredentialIsUselessAtTheWrongRelyingParty is direction two of
// IP §6.2. The tool mints for exactly one audience — never a set — so the
// credential a run holds names the one relying party that may accept it, and
// the check a relying party makes is the same one this package publishes for
// RM-033 to call before Phase A.
func TestMCP008ACredentialIsUselessAtTheWrongRelyingParty(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.mustIssue(t, "run-a", AudienceSigstore)

	if got := f.minter.last(); got.Audience != AudienceSigstore {
		t.Fatalf("minted for %q, want a single audience %q", got.Audience, AudienceSigstore)
	}

	run := credRun("run-a")
	cred := MintedCredential{
		Token:     "jwt",
		SPIFFEID:  run.SPIFFEID,
		Audience:  AudienceSigstore,
		ExpiresAt: f.clock.Add(time.Minute),
	}
	// The relying party it was minted for accepts it — the positive control
	// without which the refusals below prove nothing.
	if err := RequireCredentialFor(cred, run, AudienceSigstore, f.clock); err != nil {
		t.Fatalf("a sigstore credential was refused at sigstore: %v", err)
	}
	for _, wrong := range []string{"fulcio", "rekor", "", "SIGSTORE", "sigstore.dev"} {
		err := RequireCredentialFor(cred, run, wrong, f.clock)
		if err == nil {
			t.Errorf("a credential minted for %q was accepted at %q", AudienceSigstore, wrong)
			continue
		}
		e := mcpError(t, err)
		if e.Class != ClassAudienceMismatch {
			t.Errorf("at relying party %q: class = %s, want %s", wrong, e.Class, ClassAudienceMismatch)
		}
		if e.Retryable {
			t.Errorf("at relying party %q: retryable = true; the allowlist does not change (ADR-0016)", wrong)
		}
	}
}

// TestGetCredentialNeverHandsOutAnExpiredCredential. IP §6.2: "Never sign with
// an expired credential; never extend TTLs to 'help'." A mint that comes back
// already outside its validity window is refused rather than returned.
func TestGetCredentialNeverHandsOutAnExpiredCredential(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.minter.ttl = -time.Second

	f.mustRefuse(t, "run-a", AudienceSigstore, ClassCredentialExpired)
	if got := f.ledger.countOf(event.EventTypeCredentialIssued, "run-a"); got != 0 {
		t.Errorf("appended %d credential_issued events for a credential never released, want 0", got)
	}

	// And the same guard, called directly, as RM-033 will call it.
	run := credRun("run-a")
	cred := MintedCredential{SPIFFEID: run.SPIFFEID, Audience: AudienceSigstore, ExpiresAt: f.clock}
	err := RequireCredentialFor(cred, run, AudienceSigstore, f.clock)
	if err == nil {
		t.Fatalf("a credential expiring exactly now was accepted")
	}
	if e := mcpError(t, err); e.Class != ClassCredentialExpired || e.Retryable {
		t.Errorf("class = %s retryable = %v, want %s and false", e.Class, e.Retryable, ClassCredentialExpired)
	}
}

// ---------------------------------------------------------------------------
// MCP-014 — a credential from run A used for run B.
// ---------------------------------------------------------------------------

// TestMCP014CredentialFromRunAUsedForRunB is doc 07 MCP-014:
//
//	Credential from run A used in sign_commit for run B
//	→ INVARIANT_VIOLATION; alert-level ledger event recorded
//	→ proves I2, IP §6.2
//
// WHAT THIS CASE PROVES
// ---------------------
//   - The binding between a credential and a run is established SERVER-SIDE and
//     is not a caller's to state. get_credential takes run_id and audience and
//     nothing else: there is no parameter through which a caller could ask for
//     run A's identity while naming run B, and the SPIFFE ID that reaches
//     SPIRE is the one the run directory holds for the run_id given. Asserted
//     below by reading what the minter was actually asked for.
//   - The binding is CHECKABLE by whatever is about to use the credential:
//     RequireCredentialFor is the published check, it returns
//     INVARIANT_VIOLATION with retryable=false for a cross-run credential, and
//     get_credential itself runs it on every mint before releasing one.
//   - A caller that performs the check first cannot reach Phase A of IP §6.5
//     with a cross-run credential: the stand-in below appends no commit_intent.
//
// WHAT THIS CASE DOES NOT PROVE, AND CANNOT HERE
// ----------------------------------------------
// That sign_commit performs the check. sign_commit does not exist — it is
// RM-033 (#41), E5. signCredentialPrelude below is a five-line model of the
// ordering IP §6.5 constrains (check the credential, only then append
// commit_intent); a model cannot prove the implementation obeys it. This
// follows the precedent RM-018 set for SPI-007 in test/failure/spire_test.go,
// which proves the half that is provable and says so rather than implying the
// rest.
//
// Nor does it record the alert-level ledger event MCP-014 asks for. That event
// is the refusing tool's to append, and the refusing tool is sign_commit. It
// is also, today, an event with no type: doc 02 §3's two alert rows are
// `unattributed_signature_detected` (a signature with no intent) and
// `ledger_drift_detected` (a ledger claim with no external proof), and a
// cross-run credential presented before any signature is neither. That gap is
// recorded in ADR-0019 and flagged for the human; it is not an implementing
// agent's to close by inventing an enum value in a protected schema.
//
// When RM-033 lands, this case must be extended to drive the real sign_commit
// and assert both halves: INVARIANT_VIOLATION, and the alert event.
func TestMCP014CredentialFromRunAUsedForRunB(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"), credRun("run-b"))

	replyA := f.mustIssue(t, "run-a", AudienceSigstore)
	mintA := f.minter.last()
	replyB := f.mustIssue(t, "run-b", AudienceSigstore)
	mintB := f.minter.last()

	// The identity that reached SPIRE is the run's, derived server-side.
	if mintA.SPIFFEID != credSPIFFEID("run-a") || mintB.SPIFFEID != credSPIFFEID("run-b") {
		t.Fatalf("mints were for %q and %q, want %q and %q",
			mintA.SPIFFEID, mintB.SPIFFEID, credSPIFFEID("run-a"), credSPIFFEID("run-b"))
	}
	if replyA["jwt_svid"] == replyB["jwt_svid"] {
		t.Fatalf("two runs were given the same credential")
	}

	runA, runB := credRun("run-a"), credRun("run-b")
	tokenA, ok := replyA["jwt_svid"].(string)
	if !ok {
		t.Fatalf("jwt_svid is %T, want a string", replyA["jwt_svid"])
	}
	credA := MintedCredential{
		Token:     tokenA,
		SPIFFEID:  runA.SPIFFEID,
		Audience:  AudienceSigstore,
		ExpiresAt: f.clock.Add(5 * time.Minute),
	}

	// The positive control: run A's credential is good for run A.
	if err := RequireCredentialFor(credA, runA, AudienceSigstore, f.clock); err != nil {
		t.Fatalf("run A's own credential was refused for run A: %v", err)
	}

	// MCP-014 proper: run A's credential, run B's commit.
	err := RequireCredentialFor(credA, runB, AudienceSigstore, f.clock)
	if err == nil {
		t.Fatalf("run A's credential was accepted for run B; that is I2 broken")
	}
	e := mcpError(t, err)
	if e.Class != ClassInvariantViolation {
		t.Errorf("class = %s, want %s (doc 07 MCP-014)", e.Class, ClassInvariantViolation)
	}
	if e.Retryable {
		t.Errorf("retryable = true; a retry repeats the violation (ADR-0016)")
	}
	if e.RunID != "run-b" {
		t.Errorf("run_id = %q, want the run the credential was being used FOR", e.RunID)
	}

	// A caller that checks first never reaches Phase A.
	reachedPhaseA := signCredentialPrelude(t, f.ledger, credA, runA, f.clock)
	if !reachedPhaseA {
		t.Fatalf("the prelude refused a matching credential; the model is broken, not the code")
	}
	if got := f.ledger.countOf(event.EventTypeCommitIntent, "run-a"); got != 1 {
		t.Fatalf("the matching prelude appended %d commit_intent events, want 1", got)
	}
	if signCredentialPrelude(t, f.ledger, credA, runB, f.clock) {
		t.Errorf("the prelude accepted run A's credential for run B")
	}
	if got := f.ledger.countOf(event.EventTypeCommitIntent, "run-b"); got != 0 {
		t.Errorf("a cross-run credential reached Phase A: %d commit_intent events for run B", got)
	}
}

// signCredentialPrelude is NOT sign_commit. See the block comment above.
//
// It is the ordering IP §6.5 requires of Phase A's caller and nothing else:
// check the credential against the run it is about to be used for, and only if
// that passes, append commit_intent. It returns whether Phase A was reached.
func signCredentialPrelude(t *testing.T, l *credLedger, cred MintedCredential, run CredentialRun, now time.Time) bool {
	t.Helper()
	if err := RequireCredentialFor(cred, run, AudienceSigstore, now); err != nil {
		return false
	}
	_, err := l.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       run.SPIFFEID,
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: "mcp014-" + run.RunID,
		event.FieldRepo:           "github.com/raymalian/innsegl",
		event.FieldTreeHash:       strings.Repeat("a1b2", 10),
	})
	if err != nil {
		t.Fatalf("appending commit_intent: %v", err)
	}
	return true
}

// TestGetCredentialRefusesACredentialSPIREIssuedForAnotherIdentity closes the
// same binding from the other side: if the mint comes back naming an identity
// that is not this run's, the credential is never released, whatever SPIRE
// said. A run must not be handed another run's identity by a defect either.
func TestGetCredentialRefusesACredentialSPIREIssuedForAnotherIdentity(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.minter.forceID = credSPIFFEID("run-b")

	wire := f.mustRefuse(t, "run-a", AudienceSigstore, ClassInvariantViolation)
	if got := wire["run_id"]; got != "run-a" {
		t.Errorf("run_id = %v, want run-a", got)
	}
	if got := f.ledger.countOf(event.EventTypeCredentialIssued, "run-a"); got != 0 {
		t.Errorf("recorded an issuance that was refused: %d events", got)
	}
}

// TestGetCredentialRefusesACredentialMintedForAnotherAudience is the same
// guard on the audience member of the reply.
func TestGetCredentialRefusesACredentialMintedForAnotherAudience(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.minter.forceAud = "fulcio"

	f.mustRefuse(t, "run-a", AudienceSigstore, ClassAudienceMismatch)
	if got := f.ledger.countOf(event.EventTypeCredentialIssued, "run-a"); got != 0 {
		t.Errorf("recorded an issuance that was refused: %d events", got)
	}
}

// ---------------------------------------------------------------------------
// Fail closed: retired run, missing entry, wrong audience (IP §4, §6.2).
// ---------------------------------------------------------------------------

// TestRetirementIsEffectiveImmediatelyThroughTheMCP. IP §6.2: "Retired run
// requests anything → RUN_ALREADY_RETIRED. Test that retirement is effective
// immediately (no cached-credential grace path through the MCP)."
//
// RM-014 measured SPIRE's own convergence at 3–7 seconds: a deleted entry has
// to fall out of the server's cache and then the agent's, and during that
// window an agent still serves an SVID it already minted. The immediacy is
// therefore the MCP's obligation, not SPIRE's, and it is discharged by asking
// authoritative state on every call and caching nothing. This case asserts
// that with no sleep anywhere in it — a test that waited would be measuring
// SPIRE's convergence instead of the MCP's refusal.
func TestRetirementIsEffectiveImmediatelyThroughTheMCP(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))

	f.mustIssue(t, "run-a", AudienceSigstore)
	minted := f.minter.count()

	// Retire, and ask again in the same breath.
	f.runs.retire("run-a", f.clock)
	f.entries.delete("run-a")

	started := time.Now()
	wire := f.mustRefuse(t, "run-a", AudienceSigstore, ClassRunAlreadyRetired)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("the refusal took %s; it must not wait for SPIRE to converge", elapsed)
	}
	if got := wire["run_id"]; got != "run-a" {
		t.Errorf("run_id = %v, want run-a", got)
	}
	if got := f.minter.count(); got != minted {
		t.Errorf("a retired run still minted a credential (%d -> %d)", minted, got)
	}
	if got := f.ledger.countOf(event.EventTypeCredentialIssued, "run-a"); got != 1 {
		t.Errorf("a retired run appended a second credential_issued: %d total", got)
	}
}

// TestAMissingSPIREEntryFailsClosed. IP §4: get_credential "fails closed if run
// retired, entry missing, or audience not in the allowlist". The entry is the
// second gate and it is asked of the SPIRE SERVER, whose datastore changes the
// instant a delete commits — not of an agent cache, which converges later.
func TestAMissingSPIREEntryFailsClosed(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.entries.delete("run-a")

	f.mustRefuse(t, "run-a", AudienceSigstore, ClassRunNotFound)
	if got := f.minter.count(); got != 0 {
		t.Errorf("minted %d credentials with no registration entry, want 0", got)
	}
	if got := len(f.entries.seen); got == 0 {
		t.Errorf("the tool never asked SPIRE whether the entry exists")
	}
}

// TestAnUnknownRunIsRefused. IP §4: RUN_NOT_FOUND.
func TestAnUnknownRunIsRefused(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.mustRefuse(t, "run-zz", AudienceSigstore, ClassRunNotFound)
	if got := f.minter.count(); got != 0 {
		t.Errorf("minted %d credentials for an unknown run", got)
	}
	if got := f.entries.calls(); got != 0 {
		t.Errorf("asked SPIRE about an unknown run %d times", got)
	}
}

// TestAMalformedRunIDNamesNoRun. A run_id that cannot be a run id names no
// run; it is refused before any dependency is consulted.
func TestAMalformedRunIDNamesNoRun(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	for _, bad := range []string{"", "Run-A", "run a", "-run", strings.Repeat("r", 64), "../run-a"} {
		t.Run(fmt.Sprintf("run_id=%q", bad), func(t *testing.T) {
			f.mustRefuse(t, bad, AudienceSigstore, ClassRunNotFound)
		})
	}
	if got := f.minter.count(); got != 0 {
		t.Errorf("minted %d credentials for a malformed run id", got)
	}
}

// TestADirectoryThatAnswersForTheWrongRunIsRefused. Defence in depth against
// the AB-10 route this tool opens: even a run directory that answers with
// another run's identity, or with an identity outside the /agent/ subtree,
// cannot make the MCP ask SPIRE to mint it.
func TestADirectoryThatAnswersForTheWrongRunIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  CredentialRun
	}{
		{"a different run id", CredentialRun{
			RunID: "run-b", AgentType: credAgentType, TaskID: credTaskID, SPIFFEID: credSPIFFEID("run-b"),
		}},
		{"an identity outside the agent subtree", CredentialRun{
			RunID: "run-a", AgentType: credAgentType, TaskID: credTaskID,
			SPIFFEID: "spiffe://innsegl.dev/innsegl/rogue",
		}},
		{"an identity naming another run", CredentialRun{
			RunID: "run-a", AgentType: credAgentType, TaskID: credTaskID, SPIFFEID: credSPIFFEID("run-b"),
		}},
		{"an identity naming another task", CredentialRun{
			RunID: "run-a", AgentType: credAgentType, TaskID: credTaskID,
			SPIFFEID: "spiffe://innsegl.dev/agent/demo/rm-999/run-a",
		}},
		{"no identity at all", CredentialRun{
			RunID: "run-a", AgentType: credAgentType, TaskID: credTaskID,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCredFixture(t)
			f.runs.putAs("run-a", tc.run)
			f.mustRefuse(t, "run-a", AudienceSigstore, ClassInvariantViolation)
			if got := f.minter.count(); got != 0 {
				t.Errorf("minted %d credentials for %q", got, tc.run.SPIFFEID)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Dependency failures: every error-return path (IP §2's 100% branch floor).
// ---------------------------------------------------------------------------

// TestTheLedgerIsTheLastGateAndItFailsClosed. I3: "no action without a record."
// A credential whose issuance could not be recorded is never released — the
// caller gets LEDGER_UNAVAILABLE and no token at all.
func TestTheLedgerIsTheLastGateAndItFailsClosed(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.ledger.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "append", Retryable: true,
		Err: errors.New("dial tcp 127.0.0.1:5432: connect: connection refused"),
	})

	wire := f.mustRefuse(t, "run-a", AudienceSigstore, ClassLedgerUnavailable)
	msg, isString := wire["message"].(string)
	if !isString {
		t.Fatalf("message is %T, want a string", wire["message"])
	}
	if strings.Contains(msg, "jwt-svid-") {
		t.Errorf("the error message carries the credential: %q", msg)
	}
	if got := f.minter.count(); got != 1 {
		t.Fatalf("the mint that this case is about did not happen (%d)", got)
	}
}

// TestALedgerRefusalIsNotReportedAsAnOutage: the ledger's own classes are
// carried across rather than flattened.
func TestALedgerRefusalIsNotReportedAsAnOutage(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.ledger.fail(&ledger.StoreError{
		Class: ledger.ClassInvariantViolation, Op: "append", Retryable: false,
		Err: errors.New("credential_issued: audience is required"),
	})
	f.mustRefuse(t, "run-a", AudienceSigstore, ClassInvariantViolation)
}

// TestAnUnclassifiedLedgerFailureFailsClosed.
func TestAnUnclassifiedLedgerFailureFailsClosed(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.ledger.fail(errors.New("something nobody classified"))
	f.mustRefuse(t, "run-a", AudienceSigstore, ClassInvariantViolation)
}

// TestAFailingRunDirectoryIsReportedAsTheLedgerFailureItIs.
func TestAFailingRunDirectoryIsReportedAsTheLedgerFailureItIs(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.runs.fail(&ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "read", Retryable: true,
		Err: errors.New("connection refused"),
	})
	f.mustRefuse(t, "run-a", AudienceSigstore, ClassLedgerUnavailable)
	if got := f.minter.count(); got != 0 {
		t.Errorf("minted %d credentials without resolving the run", got)
	}
}

// TestSPIREUnreachableAtTheEntryCheckIsRetryable. IP §6.1.
func TestSPIREUnreachableAtTheEntryCheckIsRetryable(t *testing.T) {
	f := newCredFixture(t, credRun("run-a"))
	f.entries.fail(&spire.Error{
		Class: spire.ClassIdentityUnavailable, Op: "lookup_run", RunID: "run-a",
		Message: "connection refused", Retryable: true,
	})
	wire := f.mustRefuse(t, "run-a", AudienceSigstore, ClassIdentityUnavailable)
	if wire["retryable"] != true {
		t.Errorf("retryable = %v, want true (IP §6.1)", wire["retryable"])
	}
	if got := f.minter.count(); got != 0 {
		t.Errorf("minted %d credentials while SPIRE was unreachable", got)
	}
}

// TestAMintFailureIsReportedWithItsOwnClass.
func TestAMintFailureIsReportedWithItsOwnClass(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		class     Class
		retryable bool
	}{
		{"authorization denied", status.Error(codes.PermissionDenied,
			"authorization denied for method /spire.api.server.svid.v1.SVID/MintJWTSVID"),
			ClassInvariantViolation, false},
		{"server down", status.Error(codes.Unavailable, "connection refused"),
			ClassIdentityUnavailable, true},
		{"no such identity", status.Error(codes.NotFound, "no such entry"),
			ClassRunNotFound, false},
		// ADR-0016: a layer closer to the failure may NARROW retryable and
		// never widen it. An answer this code cannot read is not known to be
		// transient, so IDENTITY_UNAVAILABLE arrives with the flag narrowed to
		// false rather than spinning a caller against it.
		{"an answer we cannot read", status.Error(codes.OutOfRange, "?"),
			ClassIdentityUnavailable, false},
		{"no gRPC status at all", errors.New("tls: handshake failure"),
			ClassIdentityUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCredFixture(t, credRun("run-a"))
			f.minter.fail(credentialMintError("run-a", tc.err))
			r := f.call(t, "run-a", AudienceSigstore)
			if !r.isError {
				t.Fatalf("a mint that failed with %v still issued a credential", tc.err)
			}
			if got := r.wire["error_class"]; got != string(tc.class) {
				t.Errorf("error_class = %v, want %s", got, tc.class)
			}
			if got := r.wire["retryable"]; got != tc.retryable {
				t.Errorf("retryable = %v, want %v", got, tc.retryable)
			}
			if got := f.ledger.countOf(event.EventTypeCredentialIssued, "run-a"); got != 0 {
				t.Errorf("recorded %d issuances for a mint that failed", got)
			}
		})
	}
}

// TestAnUnconfiguredServerRefusesRatherThanImprovises. A get_credential bound
// on a server with no SPIRE and no ledger behind it is a defect, and a defect
// is alert-level (ADR-0016).
func TestAnUnconfiguredServerRefusesRatherThanImprovises(t *testing.T) {
	credentialMu.Lock()
	saved := credentialActive
	credentialActive = nil
	credentialMu.Unlock()
	t.Cleanup(func() {
		credentialMu.Lock()
		credentialActive = saved
		credentialMu.Unlock()
	})

	session := serveGetCredential(t)
	res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
		Name:      string(ToolGetCredential),
		Arguments: map[string]any{"run_id": "run-a", "audience": AudienceSigstore},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if !res.IsError {
		t.Fatalf("an unconfigured get_credential returned a credential")
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T", res.StructuredContent)
	}
	if wire["error_class"] != string(ClassInvariantViolation) {
		t.Errorf("error_class = %v, want %s", wire["error_class"], ClassInvariantViolation)
	}
}

// TestConfigureGetCredentialRefusesAHalfWiredServer: every dependency is
// required, because each one is a gate and a missing gate is an open door.
func TestConfigureGetCredentialRefusesAHalfWiredServer(t *testing.T) {
	full := func() CredentialConfig {
		return CredentialConfig{
			Runs: newCredRuns(), Entries: newCredEntries(),
			Minter: newCredMinter(time.Now), Ledger: &credLedger{},
		}
	}
	for _, tc := range []struct {
		name string
		bend func(*CredentialConfig)
	}{
		{"no run directory", func(c *CredentialConfig) { c.Runs = nil }},
		{"no SPIRE entry check", func(c *CredentialConfig) { c.Entries = nil }},
		{"no minter", func(c *CredentialConfig) { c.Minter = nil }},
		{"no ledger", func(c *CredentialConfig) { c.Ledger = nil }},
		{"an empty audience allowlist", func(c *CredentialConfig) { c.Audiences = []string{} }},
		{"an empty audience in the allowlist", func(c *CredentialConfig) { c.Audiences = []string{""} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full()
			tc.bend(&cfg)
			if err := ConfigureGetCredential(cfg); err == nil {
				t.Fatalf("ConfigureGetCredential accepted a config with %s", tc.name)
			}
		})
	}
	cfg := full()
	if err := ConfigureGetCredential(cfg); err != nil {
		t.Fatalf("ConfigureGetCredential refused a complete config: %v", err)
	}
	credentialMu.Lock()
	defer credentialMu.Unlock()
	if credentialActive == nil {
		t.Fatalf("a complete config was not installed")
	}
	if got := credentialActive.audiences; !equalStrings(got, []string{AudienceSigstore}) {
		t.Errorf("default allowlist = %v, IP §4 says %v initially", got, []string{AudienceSigstore})
	}
	if credentialActive.now == nil {
		t.Errorf("no clock was installed")
	}
	credentialActive = nil
}

// TestTheAudienceAllowlistIsConfigurableButClosed. IP §4 says "`sigstore`
// initially"; a deployment that adds one adds it deliberately, and anything
// outside the configured set is still AUDIENCE_MISMATCH.
func TestTheAudienceAllowlistIsConfigurableButClosed(t *testing.T) {
	f := &credFixture{
		t: t, runs: newCredRuns(credRun("run-a")), entries: newCredEntries(),
		ledger: &credLedger{}, clock: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
	}
	f.minter = newCredMinter(func() time.Time { return f.clock })
	withCredentialConfig(t, CredentialConfig{
		Runs: f.runs, Entries: f.entries, Minter: f.minter, Ledger: f.ledger,
		Audiences: []string{AudienceSigstore, "fulcio"},
		Now:       func() time.Time { return f.clock },
	})
	f.session = serveGetCredential(t)

	f.mustIssue(t, "run-a", AudienceSigstore)
	f.mustIssue(t, "run-a", "fulcio")
	f.mustRefuse(t, "run-a", "rekor", ClassAudienceMismatch)
}

// ---------------------------------------------------------------------------
// The shipped SPIRE minter, unit level.
// ---------------------------------------------------------------------------

// credStubSVID is a svidv1.SVIDClient whose MintJWTSVID answers on cue. The
// embedded nil interface makes the other five methods panic if anything calls
// them, which is what we want: this tool uses exactly one RPC.
type credStubSVID struct {
	svidv1.SVIDClient
	req  *svidv1.MintJWTSVIDRequest
	resp *svidv1.MintJWTSVIDResponse
	err  error
}

func (s *credStubSVID) MintJWTSVID(_ context.Context, in *svidv1.MintJWTSVIDRequest,
	_ ...grpc.CallOption) (*svidv1.MintJWTSVIDResponse, error) {
	s.req = in
	return s.resp, s.err
}

// TestTheSPIREMinterAsksForOneAudienceAndNoTTL. IP §6.2: "never extend TTLs to
// 'help'." The request carries no ttl at all, so the server's own
// default_jwt_svid_ttl governs and this code has no way to lengthen it.
func TestTheSPIREMinterAsksForOneAudienceAndNoTTL(t *testing.T) {
	exp := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	stub := &credStubSVID{resp: &svidv1.MintJWTSVIDResponse{Svid: &types.JWTSVID{
		Token:     "header.payload.signature",
		Id:        &types.SPIFFEID{TrustDomain: credTrustDomain, Path: "/agent/demo/rm-023/run-a"},
		ExpiresAt: exp.Unix(),
	}}}
	m := &spireMinter{svid: stub}

	got, err := m.MintJWTSVID(context.Background(), credSPIFFEID("run-a"), AudienceSigstore)
	if err != nil {
		t.Fatalf("MintJWTSVID: %v", err)
	}
	if stub.req.GetTtl() != 0 {
		t.Errorf("the request carries ttl=%d; IP §6.2 forbids extending a TTL to help", stub.req.GetTtl())
	}
	if aud := stub.req.GetAudience(); !equalStrings(aud, []string{AudienceSigstore}) {
		t.Errorf("audience = %v, want exactly one audience %v", aud, []string{AudienceSigstore})
	}
	if id := stub.req.GetId(); id.GetTrustDomain() != credTrustDomain || id.GetPath() != "/agent/demo/rm-023/run-a" {
		t.Errorf("id = %+v, want the run's own identity", id)
	}
	if got.Token != "header.payload.signature" || got.Audience != AudienceSigstore {
		t.Errorf("minted = %+v", got)
	}
	if !got.ExpiresAt.Equal(exp.UTC()) {
		t.Errorf("expires_at = %s, want %s", got.ExpiresAt, exp.UTC())
	}
	if got.SPIFFEID != credSPIFFEID("run-a") {
		t.Errorf("spiffe_id = %q, want %q", got.SPIFFEID, credSPIFFEID("run-a"))
	}
}

// TestTheSPIREMinterRefusesAnUnusableAnswer.
func TestTheSPIREMinterRefusesAnUnusableAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		resp  *svidv1.MintJWTSVIDResponse
		err   error
		class Class
	}{
		{"no svid", &svidv1.MintJWTSVIDResponse{}, nil, ClassInvariantViolation},
		{"no token", &svidv1.MintJWTSVIDResponse{Svid: &types.JWTSVID{
			Id: &types.SPIFFEID{TrustDomain: credTrustDomain, Path: "/agent/demo/rm-023/run-a"},
		}}, nil, ClassInvariantViolation},
		{"no expiry", &svidv1.MintJWTSVIDResponse{Svid: &types.JWTSVID{
			Token: "a.b.c",
			Id:    &types.SPIFFEID{TrustDomain: credTrustDomain, Path: "/agent/demo/rm-023/run-a"},
		}}, nil, ClassInvariantViolation},
		{"authorization denied", nil,
			status.Error(codes.PermissionDenied, "authorization denied"), ClassInvariantViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &spireMinter{svid: &credStubSVID{resp: tc.resp, err: tc.err}}
			_, err := m.MintJWTSVID(context.Background(), credSPIFFEID("run-a"), AudienceSigstore)
			if err == nil {
				t.Fatalf("MintJWTSVID accepted %s", tc.name)
			}
			if e := mcpError(t, err); e.Class != tc.class {
				t.Errorf("class = %s, want %s", e.Class, tc.class)
			}
		})
	}
}

// TestTheSPIREMinterRefusesAnIdentityItCannotParse.
func TestTheSPIREMinterRefusesAnIdentityItCannotParse(t *testing.T) {
	m := &spireMinter{svid: &credStubSVID{}}
	for _, bad := range []string{"", "innsegl.dev/agent/a/b/c", "spiffe://innsegl.dev", "spiffe://"} {
		if _, err := m.MintJWTSVID(context.Background(), bad, AudienceSigstore); err == nil {
			t.Errorf("MintJWTSVID accepted %q as a SPIFFE ID", bad)
		}
	}
}

// TestNewSPIREMinterBindsTheSVIDAPI.
func TestNewSPIREMinterBindsTheSVIDAPI(t *testing.T) {
	conn, err := grpc.NewClient("passthrough:///127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if NewSPIREMinter(conn) == nil {
		t.Fatalf("NewSPIREMinter returned nil")
	}
}

// ---------------------------------------------------------------------------
// Integration — a real SPIRE from deploy/compose/spire.yml.
// ---------------------------------------------------------------------------

const (
	credComposeServer   = "innsegl-spire-server"
	credComposeAgent    = "innsegl-spire-agent"
	credAdminNetwork    = "innsegl-spire-admin"
	credAdminSocket     = "/run/spire/admin/api.sock"
	credAdminID         = "spiffe://innsegl.dev/innsegl/mcp"
	credServerID        = "spiffe://innsegl.dev/spire/server"
	credProxyImageDeflt = "alpine/socat:1.8.0.3"
)

// credStack is the running compose stack plus the two things the harness has
// to add to talk to it: a TCP proxy onto the admin network (ADR-0011 gives
// that network no published port, and innsegl-mcp is its only future member),
// and an admin SVID minted on the unauthenticated local socket, which is the
// operator path ADR-0011 describes.
type credStack struct {
	composeFile string
	startedByUs bool
	proxyName   string
	adminAddr   string
	parentID    string
}

func (s *credStack) compose(ctx context.Context, args ...string) (string, error) {
	return docker(ctx, append([]string{"compose", "-f", s.composeFile}, args...)...)
}

func (s *credStack) spireLocal(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", credAdminSocket)
	return s.compose(ctx, full...)
}

// credMintedSVID satisfies spire.Source from `spire-server x509 mint` output.
type credMintedSVID struct {
	svid  *x509svid.SVID
	roots []*x509.Certificate
}

func (m credMintedSVID) GetX509SVID() (*x509svid.SVID, error) { return m.svid, nil }

func (m credMintedSVID) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return x509bundle.FromX509Authorities(td, m.roots), nil
}

func (s *credStack) mintAdmin(ctx context.Context, id string) (credMintedSVID, error) {
	out, err := s.spireLocal(ctx, "x509", "mint", "-spiffeID", id, "-ttl", "1h")
	if err != nil {
		return credMintedSVID{}, fmt.Errorf("mint %s: %w", id, err)
	}
	const hSVID, hKey, hRoots = "X509-SVID:", "Private key:", "Root CAs:"
	i, j, k := strings.Index(out, hSVID), strings.Index(out, hKey), strings.Index(out, hRoots)
	if i < 0 || j < i || k < j {
		return credMintedSVID{}, fmt.Errorf("unrecognised `x509 mint` output: %.200q", out)
	}
	svid, err := x509svid.Parse([]byte(out[i+len(hSVID):j]), []byte(out[j+len(hKey):k]))
	if err != nil {
		return credMintedSVID{}, fmt.Errorf("parse minted SVID: %w", err)
	}
	var roots []*x509.Certificate
	rest := []byte(out[k+len(hRoots):])
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, perr := x509.ParseCertificate(blk.Bytes)
		if perr != nil {
			return credMintedSVID{}, perr
		}
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		return credMintedSVID{}, errors.New("no trust bundle in `x509 mint` output")
	}
	return credMintedSVID{svid: svid, roots: roots}, nil
}

// adminConn dials the admin API with a freshly minted admin SVID, exactly as
// innsegl-mcp will: mTLS over SPIFFE identities, the server authorized by ID.
func (s *credStack) adminConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	src, err := s.mintAdmin(ctx, credAdminID)
	if err != nil {
		t.Fatalf("mint the admin SVID: %v", err)
	}
	if got := src.svid.ID.String(); got != credAdminID {
		t.Fatalf("minted SVID is %s, want %s", got, credAdminID)
	}
	serverID, err := spiffeid.FromString(credServerID)
	if err != nil {
		t.Fatalf("server id: %v", err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(s.adminAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		t.Fatalf("dial %s: %v", s.adminAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (s *credStack) adminClient(t *testing.T) *spire.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	src, err := s.mintAdmin(ctx, credAdminID)
	if err != nil {
		t.Fatalf("mint the admin SVID: %v", err)
	}
	c, err := spire.Dial(ctx, spire.Config{
		Address: s.adminAddr, TrustDomain: credTrustDomain,
		ServerID: credServerID, Source: src,
	})
	if err != nil {
		t.Fatalf("spire.Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func credContainerRunning(ctx context.Context, name string) bool {
	out, err := docker(ctx, "inspect", "--format", "{{.State.Running}}", name)
	return err == nil && out == "true"
}

func startCredStack(ctx context.Context, root string) (*credStack, error) {
	s := &credStack{composeFile: filepath.Join(root, "deploy", "compose", "spire.yml")}
	s.startedByUs = !credContainerRunning(ctx, credComposeServer)
	if _, err := s.compose(ctx, "up", "--detach", "--wait", "spire-server", "spire-agent"); err != nil {
		return nil, fmt.Errorf("compose up: %w", err)
	}
	if !s.startedByUs {
		// SPIRE reads authz-policy.rego once, at startup, and the file is a
		// bind mount — so a server left running from before an edit is still
		// enforcing the old copy. Restarting it makes the policy under test
		// the policy on disk, rather than whatever was on disk last week.
		if _, err := s.compose(ctx, "restart", "spire-server"); err != nil {
			return s, fmt.Errorf("restart spire-server: %w", err)
		}
		if _, err := s.compose(ctx, "up", "--detach", "--wait", "spire-server"); err != nil {
			return s, fmt.Errorf("compose up after restart: %w", err)
		}
	}

	// The attested node every run entry is parented to. Polled: the agent
	// attests shortly after start.
	deadline := time.Now().Add(120 * time.Second)
	for s.parentID == "" {
		out, lerr := s.spireLocal(ctx, "agent", "list")
		if lerr == nil {
			for _, line := range strings.Split(out, "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
					s.parentID = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
					break
				}
			}
		}
		if s.parentID != "" {
			break
		}
		if time.Now().After(deadline) {
			return s, fmt.Errorf("no attested agent within the deadline, last error: %w", lerr)
		}
		time.Sleep(2 * time.Second)
	}

	port, err := freeHostPort(ctx)
	if err != nil {
		return s, fmt.Errorf("reserve a host port: %w", err)
	}
	s.proxyName = fmt.Sprintf("innsegl-test-credproxy-%d", os.Getpid()%100000)
	if _, rmErr := docker(ctx, "rm", "--force", s.proxyName); rmErr != nil {
		_ = rmErr // a leftover from an interrupted run; absence is the normal case
	}
	if _, err = docker(ctx, "run", "--detach", "--name", s.proxyName,
		"--publish", "127.0.0.1:"+port+":8081",
		credEnvOr("INNSEGL_TEST_PROXY_IMAGE", credProxyImageDeflt),
		"TCP-LISTEN:8081,fork,reuseaddr", "TCP:spire-server:8081",
	); err != nil {
		return s, fmt.Errorf("start the admin proxy: %w", err)
	}
	if _, err = docker(ctx, "network", "connect", credAdminNetwork, s.proxyName); err != nil {
		return s, fmt.Errorf("join %s: %w", credAdminNetwork, err)
	}
	s.adminAddr = "127.0.0.1:" + port
	return s, nil
}

func credEnvOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func (s *credStack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	if s.proxyName != "" {
		if _, err := docker(ctx, "rm", "--force", s.proxyName); err != nil {
			fmt.Fprintf(os.Stderr, "warning: removing %s: %v\n", s.proxyName, err)
		}
	}
	if !s.startedByUs || os.Getenv("INNSEGL_TEST_KEEP_SPIRE") != "" {
		return
	}
	if _, err := s.compose(ctx, "down", "--volumes", "--remove-orphans"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
	}
}

// credRepoRoot is the module root, two directories up from internal/mcp.
func credRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// TestGetCredentialAgainstRealSPIRE is the integration half of RM-023.
//
// It runs as ONE top-level case with subtests because the mcp package already
// has a TestMain (RM-021's Postgres harness) and Go allows one per binary; the
// stack's lifetime is therefore this function's.
//
// What it measures, on the shipped compose stack with the shipped policy:
//
//  1. MintJWTSVID inside spiffe://innsegl.dev/agent/{a}/{b}/{c} SUCCEEDS with
//     the admin credential. This is the positive control, and without it every
//     denial below would be explained equally well by the method being absent
//     from the allowlist, by the proxy being down, or by the SVID being
//     rejected at the TLS handshake.
//  2. MintJWTSVID for every shape of out-of-subtree identity is REFUSED by
//     SPIRE with PermissionDenied naming the method. That is the AB-10 route
//     this issue had to close before it could use the method at all.
//  3. The shipped get_credential, wired to the shipped minter and a real
//     ledger, returns a real JWT-SVID whose `aud` is exactly ["sigstore"] and
//     whose `sub` is the run's own SPIFFE ID — IP §6.2's audience binding,
//     read off the token rather than off our own struct.
//  4. A wrong audience is refused on that same connection and run.
func TestGetCredentialAgainstRealSPIRE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping: no docker (%v). This case is the only place the "+
			"MintJWTSVID authorization scope in deploy/compose/spire/authz-policy.rego "+
			"is measured; without it, AB-10 by way of the mint API goes unproven.", err)
	}
	stack, err := startCredStack(ctx, credRepoRoot(t))
	if stack != nil {
		// t.Cleanup, not defer: the entry cleanup registered below still needs
		// the admin proxy, and cleanups run last-registered-first.
		t.Cleanup(stack.stop)
	}
	if err != nil {
		t.Skipf("skipping: could not start deploy/compose/spire.yml (%v). "+
			"The MintJWTSVID authorization scope goes unproven.", err)
	}

	admin := stack.adminClient(t)
	conn := stack.adminConn(t)
	minter := NewSPIREMinter(conn)

	run := spire.RunRef{
		AgentType: credAgentType,
		TaskID:    credTaskID,
		RunID:     fmt.Sprintf("run-%d", time.Now().UnixNano()%100000),
	}
	runID, err := run.SPIFFEID(credTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID: %v", err)
	}
	if _, err := admin.RegisterRun(ctx, spire.Registration{
		Run:      run,
		ParentID: stack.parentID,
		Selectors: []spire.Selector{
			{Type: "docker", Value: "label:dev.innsegl.run-id:" + run.RunID},
			{Type: "docker", Value: "label:dev.innsegl.agent-type:" + run.AgentType},
			{Type: "docker", Value: "label:dev.innsegl.task-id:" + run.TaskID},
			{Type: "unix", Value: "uid:10001"},
		},
		TTL: spire.DefaultRunTTL,
	}); err != nil {
		t.Fatalf("RegisterRun(%+v): %v", run, err)
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanCancel()
		if _, err := admin.RetireRun(cleanCtx, run); err != nil {
			t.Errorf("cleaning up the entry for %+v: %v", run, err)
		}
	})

	// (1) The positive control, on this connection, with this credential.
	t.Run("MintJWTSVID is allowed inside the agent subtree", func(t *testing.T) {
		cred, err := minter.MintJWTSVID(ctx, runID, AudienceSigstore)
		if err != nil {
			t.Fatalf("MintJWTSVID(%s, %s): %v\n\n"+
				"If this is PermissionDenied, deploy/compose/spire/authz-policy.rego "+
				"does not allow the method the tool needs.", runID, AudienceSigstore, err)
		}
		if cred.Token == "" {
			t.Fatalf("SPIRE returned no token")
		}
		if cred.SPIFFEID != runID {
			t.Errorf("minted for %s, want %s", cred.SPIFFEID, runID)
		}
		t.Logf("positive control: the same admin credential minted a JWT-SVID for %s, expiring %s",
			runID, cred.ExpiresAt.UTC().Format(time.RFC3339))
	})

	// (2) The denial this issue's rego change had to come with.
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"a sibling of the agent subtree", "spiffe://innsegl.dev/innsegl/rogue"},
		{"the MCP's own admin identity", credAdminID},
		{"a node identity", "spiffe://innsegl.dev/spire/agent/x509pop/deadbeef"},
		{"the SPIRE server itself", credServerID},
		{"the agent subtree itself", "spiffe://innsegl.dev/agent"},
		{"one level short of a run", "spiffe://innsegl.dev/agent/demo/rm-023"},
		{"one level past a run", "spiffe://innsegl.dev/agent/demo/rm-023/run-1/extra"},
		{"a path that only looks like the subtree", "spiffe://innsegl.dev/agentx/demo/rm-023/run-1"},
		{"another trust domain", "spiffe://evil.example/agent/demo/rm-023/run-1"},
	} {
		t.Run("MintJWTSVID is denied for "+tc.name, func(t *testing.T) {
			cred, err := minter.MintJWTSVID(ctx, tc.id, AudienceSigstore)
			if err == nil {
				t.Fatalf("SPIRE MINTED a JWT-SVID for %s (token %d bytes). That is AB-10 by "+
					"way of the mint API: a stolen admin credential minting identities "+
					"outside the agent subtree.", tc.id, len(cred.Token))
			}
			st, ok := status.FromError(credUnwrapAll(err))
			if !ok || st.Code() != codes.PermissionDenied {
				t.Fatalf("the refusal was not a gRPC PermissionDenied from SPIRE: %v", err)
			}
			if !strings.Contains(st.Message(), "MintJWTSVID") {
				t.Errorf("PermissionDenied message %q does not name the method; "+
					"the denial may not be the authorization policy's", st.Message())
			}
			t.Logf("refused: %s -> %s", tc.id, st.Message())
		})
	}

	// (3) and (4): the shipped tool, the shipped minter, a real ledger.
	t.Run("the tool issues a real audience-bound JWT-SVID", func(t *testing.T) {
		pg := requirePG(t)
		dsn := freshDSN(t, pg)
		migrate(t, dsn)
		store, err := ledger.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("ledger.Open: %v", err)
		}
		t.Cleanup(store.Close)

		directory := newCredRuns(CredentialRun{
			RunID: run.RunID, AgentType: run.AgentType, TaskID: run.TaskID, SPIFFEID: runID,
		})
		withCredentialConfig(t, CredentialConfig{
			Runs: directory, Entries: admin, Minter: minter, Ledger: store,
		})
		session := serveGetCredential(t)

		res, err := session.CallTool(t.Context(), &sdk.CallToolParams{
			Name:      string(ToolGetCredential),
			Arguments: map[string]any{"run_id": run.RunID, "audience": AudienceSigstore},
		})
		if err != nil {
			t.Fatalf("tools/call: %v", err)
		}
		if res.IsError {
			t.Fatalf("get_credential failed against real SPIRE: %+v", res.StructuredContent)
		}
		wire, ok := res.StructuredContent.(map[string]any)
		if !ok {
			t.Fatalf("structuredContent is %T", res.StructuredContent)
		}
		token, isString := wire["jwt_svid"].(string)
		if !isString {
			t.Fatalf("jwt_svid is %T, want a string", wire["jwt_svid"])
		}
		claims := credJWTClaims(t, token)
		if aud := credAudiences(t, claims); !equalStrings(aud, []string{AudienceSigstore}) {
			t.Errorf("the token's aud is %v, want exactly %v — a multi-audience "+
				"credential is usable at more than one relying party (IP §6.2)",
				aud, []string{AudienceSigstore})
		}
		sub, isString := claims["sub"].(string)
		if !isString {
			t.Fatalf("the token's sub is %T, want a string", claims["sub"])
		}
		if sub != runID {
			t.Errorf("the token's sub is %q, want the run's identity %q", sub, runID)
		}
		t.Logf("real JWT-SVID: sub=%v aud=%v exp=%v", claims["sub"], claims["aud"], claims["exp"])

		// The ledger holds exactly one credential_issued for it.
		count, err := store.Count(ctx)
		if err != nil {
			t.Fatalf("ledger.Count: %v", err)
		}
		records, err := store.Events(ctx, 1, count)
		if err != nil {
			t.Fatalf("ledger.Events: %v", err)
		}
		issued := 0
		for _, rec := range records {
			if rec[event.FieldEventType] == event.EventTypeCredentialIssued {
				issued++
				if rec[event.FieldAudience] != AudienceSigstore {
					t.Errorf("credential_issued audience = %v", rec[event.FieldAudience])
				}
				if _, present := rec[event.FieldIdempotencyKey]; present {
					t.Errorf("credential_issued carries an idempotency_key (ADR-0004)")
				}
			}
		}
		if issued != 1 {
			t.Errorf("the ledger holds %d credential_issued events for one issuance", issued)
		}

		// (4) A wrong audience, same connection, same run.
		bad, err := session.CallTool(t.Context(), &sdk.CallToolParams{
			Name:      string(ToolGetCredential),
			Arguments: map[string]any{"run_id": run.RunID, "audience": "fulcio"},
		})
		if err != nil {
			t.Fatalf("tools/call: %v", err)
		}
		if !bad.IsError {
			t.Fatalf("an audience outside the allowlist was issued against real SPIRE")
		}
		badWire, ok := bad.StructuredContent.(map[string]any)
		if !ok {
			t.Fatalf("structuredContent is %T", bad.StructuredContent)
		}
		if badWire["error_class"] != string(ClassAudienceMismatch) {
			t.Errorf("error_class = %v, want %s", badWire["error_class"], ClassAudienceMismatch)
		}
	})
}

// credJWTClaims decodes a JWT's claim set WITHOUT verifying its signature.
// That is deliberate and it is not a security check: what is being read here
// is what SPIRE put in the token, and the assertion is about the `aud` and
// `sub` members. Verifying the signature is RM-033's and the verifier's job.
func credJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("decode claims %s: %v", raw, err)
	}
	return claims
}

// credAudiences reads `aud`, which RFC 7519 allows to be a string or an array.
func credAudiences(t *testing.T, claims map[string]any) []string {
	t.Helper()
	switch v := claims["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			s, ok := a.(string)
			if !ok {
				t.Fatalf("aud member is %T", a)
			}
			out = append(out, s)
		}
		return sortedStrings(out)
	default:
		t.Fatalf("aud is %T, want a string or an array", claims["aud"])
		return nil
	}
}

func credUnwrapAll(err error) error {
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
}

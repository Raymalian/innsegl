// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
)

// The per-tool repository binding (#264), through the shipped transport.
//
// MCP-088 the argument-scoped tools, MCP-089 the run-scoped ones, MCP-091 the
// credential in no log, MCP-093 the credential outside the idempotency
// fingerprint. See admincred_test.go for why these ids and not the ones #264
// names.

// ---------------------------------------------------------------------------
// A served, credential-scoped listener.
// ---------------------------------------------------------------------------

// bearerTransport puts one credential on every request the client makes. It is
// how a caller presents one; the MCP client has no notion of a bearer of its
// own, and putting it here rather than on a hand-rolled request means the test
// drives the SAME streamable transport an agent's harness does.
type bearerTransport struct {
	token string
	next  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	if b.token != "" {
		clone.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.next.RoundTrip(clone)
}

// scopedServe serves the named tools behind a credential check and returns the
// listener's URL. The binders are the SHIPPED ones, so what a test calls is
// what a harness calls.
func scopedServe(t *testing.T, v *AdminCredentialVerifier, binders map[ToolName]ToolBinder, logger *slog.Logger) string {
	t.Helper()
	withEmptyToolRegistry(t)
	tools := make([]ToolName, 0, len(binders))
	for _, name := range ToolNames() {
		if bind, ok := binders[name]; ok {
			RegisterTool(name, bind)
			tools = append(tools, name)
		}
	}
	srv, err := New(Config{
		Version:         "v0.0.0-test",
		Tools:           tools,
		AdminCredential: v,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv.URL
}

// connectAs opens a session presenting token.
func connectAs(t *testing.T, url, token string) *sdk.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	client := sdk.NewClient(&sdk.Implementation{Name: "innsegl-contract-test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Transport: bearerTransport{token: token, next: http.DefaultTransport}},
	}, nil)
	if err != nil {
		t.Fatalf("connecting to %s: %v", url, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// callWire returns a call's result as the two things a caller can read: the
// structured IP §4 object and the text content beside it.
func callWire(t *testing.T, session *sdk.ClientSession, tool ToolName, args map[string]any) (*sdk.CallToolResult, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdk.CallToolParams{Name: string(tool), Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s: %v", tool, err)
	}
	rendered, err := json.Marshal(struct {
		IsError    bool          `json:"is_error"`
		Structured any           `json:"structured"`
		Content    []sdk.Content `json:"content"`
	}{res.IsError, res.StructuredContent, res.Content})
	if err != nil {
		t.Fatalf("rendering the reply: %v", err)
	}
	return res, string(rendered)
}

// forget removes a run from the fake directory, so the same run id can be
// asked about twice: once held by another repository, once held by nobody.
func (d *credRuns) forget(runID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.runs, runID)
}

// ---------------------------------------------------------------------------
// MCP-088 — a credential for one repository used against another.
// ---------------------------------------------------------------------------

// TestMCP088RegisterAgentRefusesARepositoryTheCredentialDoesNotAuthorise.
//
// This is the tool the whole check exists for: it MINTS a run. A caller that
// could mint one for any repository is doc 04's AB-13 and AB-15 whatever the
// other five tools do. Nothing is appended and no identity is created.
func TestMCP088RegisterAgentRefusesARepositoryTheCredentialDoesNotAuthorise(t *testing.T) {
	env := raSetup(t, 0, nil)
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRegisterAgent: bindRegisterAgent}, nil)

	// A credential for a repository that is not the one the arguments name.
	elsewhere := issuer.mint(t, goodClaims("github.com/acme/elsewhere"))
	session := connectAs(t, url, elsewhere)

	args := raArgs("rm160-wrong-repo")
	res, _ := callWire(t, session, ToolRegisterAgent, args)
	if !res.IsError {
		t.Fatalf("register_agent succeeded for a repository the credential does not "+
			"authorise: %#v", res.StructuredContent)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want IP §4's error object", res.StructuredContent)
	}
	if wire["error_class"] != string(ClassInvariantViolation) {
		t.Errorf("error_class = %v, want %s", wire["error_class"], ClassInvariantViolation)
	}
	// NEITHER REPOSITORY IS NAMED. The credential's own is nothing the caller
	// needs told back, and confirming the one it asked about would answer a
	// probe.
	message, isString := wire["message"].(string)
	if !isString {
		t.Fatalf("the refusal carries no message: %#v", wire)
	}
	for _, secret := range []string{"github.com/acme/elsewhere", raRepo} {
		if strings.Contains(message, secret) {
			t.Errorf("the refusal names %q: %q", secret, message)
		}
	}

	// NOTHING APPENDED, NO IDENTITY. Both are checked rather than one: a run
	// that reached SPIRE and not the ledger is exactly the state I3 forbids.
	if got := env.identities.entryCount(); got != 0 {
		t.Errorf("SPIRE holds %d entries after a refused registration, want 0", got)
	}
	if rows := env.runRegisteredFor(t, raRunID("rm160-wrong-repo")); len(rows) != 0 {
		t.Errorf("%d run_registered events were appended for a refused registration", len(rows))
	}
	if _, claimed, err := env.idem.Lookup(t.Context(), "rm160-wrong-repo"); err == nil && claimed {
		t.Error("a refused registration claimed its idempotency key; the check is made " +
			"before the claim so a refusal leaves nothing behind")
	}
}

// TestMCP088TheSameCredentialAdmitsItsOwnRepository is the positive control.
// Without it the test above passes for a server that refuses everything.
func TestMCP088TheSameCredentialAdmitsItsOwnRepository(t *testing.T) {
	raSetup(t, 0, nil)
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRegisterAgent: bindRegisterAgent}, nil)

	session := connectAs(t, url, issuer.mint(t, goodClaims(raRepo)))
	res, rendered := callWire(t, session, ToolRegisterAgent, raArgs("rm160-right-repo"))
	if res.IsError {
		t.Fatalf("register_agent was refused for its own repository: %s", rendered)
	}
}

// ---------------------------------------------------------------------------
// MCP-089 — a run-scoped mismatch is a run that does not exist.
// ---------------------------------------------------------------------------

// TestMCP089ARunInAnotherRepositoryIsAnsweredAsARunThatDoesNotExist.
//
// A run id is public: it is in the Agent-Run trailer of every commit, on the
// dashboard and in the query API. An answer that distinguished "that run is
// not yours" from "there is no such run" would turn every trailer into a query
// over which repository holds which run.
//
// The comparison is made on the SAME run id, because the id is in the message
// and the caller supplied it. What must not differ is anything else.
func TestMCP089ARunInAnotherRepositoryIsAnsweredAsARunThatDoesNotExist(t *testing.T) {
	const runID = reRunID
	env := reSetup(t, nil)
	// The run exists, and it belongs to a repository this credential is not
	// for.
	held := credRun(runID)
	held.Repo = "github.com/acme/elsewhere"
	env.runs.putAs(runID, held)

	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRecordEvent: bindRecordEvent}, nil)
	session := connectAs(t, url, issuer.mint(t, goodClaims("github.com/acme/widgets")))

	_, mismatch := callWire(t, session, ToolRecordEvent, reArgs("rm160-mismatch"))

	// Now the same id names no run at all.
	env.runs.forget(runID)
	_, absent := callWire(t, session, ToolRecordEvent, reArgs("rm160-absent"))

	if mismatch != absent {
		t.Errorf("a run in another repository is answered differently from a run that does "+
			"not exist:\n  mismatch: %s\n  absent:   %s", mismatch, absent)
	}
	if !strings.Contains(absent, string(ClassRunNotFound)) {
		t.Errorf("the control is not %s: %s", ClassRunNotFound, absent)
	}

	// And nothing was appended for either.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := env.ledger.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if n != 0 {
		t.Errorf("%d events were appended by two refused calls, want 0", n)
	}
}

// TestMCP089ARetiredRunInAnotherRepositoryIsAlsoJustAbsent. The retirement
// check runs AFTER the repository comparison on purpose: answering
// RUN_ALREADY_RETIRED would say the run exists.
func TestMCP089ARetiredRunInAnotherRepositoryIsAlsoJustAbsent(t *testing.T) {
	const runID = reRunID
	env := reSetup(t, nil)
	held := credRun(runID)
	held.Repo = "github.com/acme/elsewhere"
	held.RetiredAt = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	env.runs.putAs(runID, held)

	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRecordEvent: bindRecordEvent}, nil)
	session := connectAs(t, url, issuer.mint(t, goodClaims("github.com/acme/widgets")))

	_, got := callWire(t, session, ToolRecordEvent, reArgs("rm160-retired-elsewhere"))
	if strings.Contains(got, string(ClassRunAlreadyRetired)) {
		t.Errorf("a retired run in another repository reported its retirement: %s", got)
	}
	if !strings.Contains(got, string(ClassRunNotFound)) {
		t.Errorf("want %s, got %s", ClassRunNotFound, got)
	}
}

// TestMCP089TheSameRunInTheCredentialsOwnRepositoryIsRecorded is the positive
// control for both cases above.
func TestMCP089TheSameRunInTheCredentialsOwnRepositoryIsRecorded(t *testing.T) {
	const runID = reRunID
	env := reSetup(t, nil)
	held := credRun(runID)
	held.Repo = "github.com/acme/widgets"
	env.runs.putAs(runID, held)

	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRecordEvent: bindRecordEvent}, nil)
	session := connectAs(t, url, issuer.mint(t, goodClaims("github.com/acme/widgets")))

	res, rendered := callWire(t, session, ToolRecordEvent, reArgs("rm160-own-repo"))
	if res.IsError {
		t.Fatalf("record_event was refused for a run in its credential's own repository: %s", rendered)
	}
}

// TestARunRegisteredBeforeADR0045IsAdmittedByNoCredential. Such a run carries
// no `repo` on the chain. It is readable — history stays readable — and it is
// not this credential's, because nothing can show that it is.
func TestARunRegisteredBeforeADR0045IsAdmittedByNoCredential(t *testing.T) {
	const runID = reRunID
	env := reSetup(t, nil)
	env.runs.putAs(runID, credRun(runID)) // Repo empty: a pre-ADR-0045 run.

	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRecordEvent: bindRecordEvent}, nil)
	session := connectAs(t, url, issuer.mint(t, goodClaims("github.com/acme/widgets")))

	res, rendered := callWire(t, session, ToolRecordEvent, reArgs("rm160-legacy"))
	if !res.IsError || !strings.Contains(rendered, string(ClassRunNotFound)) {
		t.Errorf("a run with no recorded repository was admitted: %s", rendered)
	}
}

// ---------------------------------------------------------------------------
// MCP-093 — the credential is outside the idempotency fingerprint.
// ---------------------------------------------------------------------------

// TestMCP093AReplayUnderADifferentCredentialReturnsTheOriginalResult.
//
// The fingerprint is taken over the tool name and its ARGUMENTS (RFC 8785,
// doc 02 §4.2). A credential inside it would make a replay depend on which
// token was used, so the same call retried after a token expired would be
// refused as DUPLICATE_REQUEST — the one thing IP §6.6 forbids.
func TestMCP093AReplayUnderADifferentCredentialReturnsTheOriginalResult(t *testing.T) {
	raSetup(t, 0, nil)
	issuer := newTestIssuer(t)
	second := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer, second))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRegisterAgent: bindRegisterAgent}, nil)

	first := connectAs(t, url, issuer.mint(t, goodClaims(raRepo)))
	original := raCallOK(t, first, raArgs("rm160-replay"))

	// A DIFFERENT credential for the same repository: a different jti, a
	// different issuance instant, a different signing key.
	replayed := connectAs(t, url, second.mint(t, goodClaims(raRepo)))
	again := raCallOK(t, replayed, raArgs("rm160-replay"))

	if again.RunID != original.RunID || again.SPIFFEID != original.SPIFFEID {
		t.Errorf("a replay under a different credential produced a different run:\n "+
			"first  %+v\n second %+v\nthe credential is a transport header and must be "+
			"outside the idempotency fingerprint", original, again)
	}
}

// TestTheIdempotencyFingerprintIsTheToolAndItsArguments is the direct reading
// of the same property: the digest is computed from Call, which has no member
// a credential could be put in.
func TestTheIdempotencyFingerprintIsTheToolAndItsArguments(t *testing.T) {
	call := Call{Tool: string(ToolRegisterAgent), Key: "k", Params: map[string]any{"a": 1}}
	want, err := call.fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	// Whatever a caller presented at the transport, the same tool and the same
	// arguments fingerprint the same. There is no third input.
	got, err := (&Call{Tool: call.Tool, Key: call.Key, Params: call.Params}).fingerprint()
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint is not a function of the tool and its arguments alone")
	}
	canonical, err := event.Canonicalize(map[string]any{"tool": call.Tool, "params": call.Params})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if event.Digest(canonical) != want {
		t.Fatalf("the fingerprint is not the canonical digest of {tool, params}; something " +
			"else has been mixed into it")
	}
}

// ---------------------------------------------------------------------------
// MCP-091 — the credential appears in no log.
// ---------------------------------------------------------------------------

// TestMCP091TheCredentialValueAppearsInNoLog.
//
// An admitted call and a refused one, with the server's own logger captured.
// The token is what a replay needs (doc 04 AB-20); a log line holding one is a
// credential at rest in a place nobody protects like one.
func TestMCP091TheCredentialValueAppearsInNoLog(t *testing.T) {
	raSetup(t, 0, nil)
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))

	var captured bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&captured, &slog.HandlerOptions{Level: slog.LevelDebug}))
	url := scopedServe(t, v, map[ToolName]ToolBinder{ToolRegisterAgent: bindRegisterAgent}, logger)

	admitted := issuer.mint(t, goodClaims(raRepo))
	session := connectAs(t, url, admitted)
	raCallOK(t, session, raArgs("rm160-logging"))

	// And one that is refused, which is where a server is most tempted to log
	// what it was given.
	refused := issuer.mint(t, goodClaims("github.com/acme/elsewhere"))
	res := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+refused)
	v.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(res, req)

	for name, token := range map[string]string{"admitted": admitted, "refused": refused} {
		if strings.Contains(captured.String(), token) {
			t.Errorf("the %s credential appears in the server log", name)
		}
		// The signature alone is enough to look for: it is the part that
		// cannot be guessed, and finding it means the whole token is there.
		signature := token[strings.LastIndex(token, ".")+1:]
		if strings.Contains(captured.String(), signature) {
			t.Errorf("the %s credential's signature appears in the server log", name)
		}
	}
	if strings.Contains(res.Body.String(), refused) {
		t.Errorf("the refusal echoes the credential back: %q", res.Body.String())
	}
}

// ---------------------------------------------------------------------------
// The tool layer cannot be separated from the transport check.
// ---------------------------------------------------------------------------

// TestAScopedServerRefusesACallCarryingNoVerifiedRepository.
//
// The only way to reach a handler on such a server is through the middleware,
// which sets the scope on every admitted request. An empty one means the two
// were separated, and the failure mode of guessing "no scope" is a listener
// that believes it is authenticated and serves every caller.
func TestAScopedServerRefusesACallCarryingNoVerifiedRepository(t *testing.T) {
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))
	srv, err := New(Config{Version: "v0.0.0-test", AdminCredential: v})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, unscopedErr := srv.scopeCall(t.Context(), nil); unscopedErr == nil {
		t.Error("a call with no verified repository was admitted on a scoped server")
	}
	scoped, err := srv.scopeCall(t.Context(), &sdk.CallToolRequest{
		Extra: &sdk.RequestExtra{Header: http.Header{adminScopeHeader: []string{"github.com/acme/widgets"}}},
	})
	if err != nil {
		t.Fatalf("scopeCall with a verified repository: %v", err)
	}
	if !adminScopeAdmits(scoped, "github.com/acme/widgets") {
		t.Error("the verified repository did not reach the tool's context")
	}
}

// TestASeparatedToolLayerRefusesTheCallInsteadOfRunningTheTool.
//
// The check above is scopeCall's own answer. This is what the BOUND TOOL does
// with it, which is the half a caller meets: every handler is wrapped, and the
// wrapper turns that refusal into an MCP tool error before the tool body runs.
//
// The wiring here is the mistake the refusal exists for. Handler() is what
// carries the credential middleware; this serves the MCP session layer
// directly, which is a deployment that configured a credential and then put
// the tools somewhere the middleware is not. The failure mode of guessing "no
// scope" there would be a listener that believes it is authenticated and
// serves every caller.
func TestASeparatedToolLayerRefusesTheCallInsteadOfRunningTheTool(t *testing.T) {
	issuer := newTestIssuer(t)
	v := verifierFor(t, jwksFile(t, issuer))

	// A probe that records whether it ran. What is under test is that the
	// tool's own body is never entered, which no error class can show.
	var ran atomic.Bool
	withEmptyToolRegistry(t)
	RegisterTool(ToolRegisterAgent, func(s *Server) error {
		return Bind(s, &sdk.Tool{Name: string(ToolRegisterAgent), Description: "probe"},
			Handler[probeIn, probeOut](func(context.Context, *sdk.CallToolRequest, probeIn) (probeOut, error) {
				ran.Store(true)
				return probeOut{Tool: string(ToolRegisterAgent)}, nil
			}))
	})
	srv, err := New(Config{
		Version: "v0.0.0-test", Tools: []ToolName{ToolRegisterAgent}, AdminCredential: v,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	separated := httptest.NewServer(sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return srv.sdk }, nil))
	t.Cleanup(separated.Close)

	res, rendered := callWire(t, connect(t, separated.URL), ToolRegisterAgent, map[string]any{})
	if !res.IsError {
		t.Fatalf("a call carrying no verified repository was served: %s", rendered)
	}
	wire, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want IP §4's error object", res.StructuredContent)
	}
	// INVARIANT_VIOLATION: IP §4 defines it as "either this code has a defect
	// or something is using a credential it should not have", and a tool layer
	// reachable without the transport check is the first half.
	if wire["error_class"] != string(ClassInvariantViolation) {
		t.Errorf("error_class = %v, want %s", wire["error_class"], ClassInvariantViolation)
	}
	if ran.Load() {
		t.Error("the tool ran for a call carrying no verified repository; the refusal is " +
			"in front of the handler, not a reading of what it returned")
	}

	// The positive control, over the SAME server through Handler(): the probe
	// does run once the middleware in front of it has verified a credential.
	// Without this the case above passes for a server that refuses everything.
	wired := httptest.NewServer(srv.Handler())
	t.Cleanup(wired.Close)
	session := connectAs(t, wired.URL, issuer.mint(t, goodClaims("github.com/acme/widgets")))
	if res, rendered := callWire(t, session, ToolRegisterAgent, map[string]any{}); res.IsError {
		t.Fatalf("the probe was refused behind its own middleware: %s", rendered)
	}
	if !ran.Load() {
		t.Error("the probe never ran even with a verified credential; the refusal above " +
			"was not about the scope")
	}
}

// TestAnUnscopedServerIgnoresTheScopeHeader. A client on the agent listener
// that sets the internal header is talking to a server that never reads it.
func TestAnUnscopedServerIgnoresTheScopeHeader(t *testing.T) {
	srv, err := New(Config{Version: "v0.0.0-test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	scoped, err := srv.scopeCall(t.Context(), &sdk.CallToolRequest{
		Extra: &sdk.RequestExtra{Header: http.Header{adminScopeHeader: []string{"github.com/acme/forged"}}},
	})
	if err != nil {
		t.Fatalf("scopeCall: %v", err)
	}
	if _, enforced := adminScopeOf(scoped); enforced {
		t.Error("a forged scope header was honoured on a server with no credential configured")
	}
}

// ---------------------------------------------------------------------------
// MCP-088 and MCP-089 for the other four tools.
//
// These call the tool functions directly under a scoped context rather than
// over the transport. The transport half is asserted above and in
// admincred_test.go; what is left to prove per tool is the BINDING, and a
// context is exactly what Bind hands each of them.
// ---------------------------------------------------------------------------

// scoped is a context carrying a verified credential for repo.
func scoped(t *testing.T, repo string) context.Context {
	t.Helper()
	return withAdminScope(t.Context(), AdminScope{Repo: repo})
}

// TestMCP089RetireAgentAnswersARunInAnotherRepositoryAsAbsent, and asks SPIRE
// to delete nothing. A retirement is the one admin tool whose effect is a
// DELETION, so a wrong-repo call that reached SPIRE would remove an identity
// the caller has no claim on.
func TestMCP089RetireAgentAnswersARunInAnotherRepositoryAsAbsent(t *testing.T) {
	const runID = "run-rm160-retire"
	held := retireRunRef(runID)
	held.Repo = "github.com/acme/elsewhere"

	chain := newRetireLedger()
	entries := newRetireEntries(runID)
	withRetireConfig(t, RetireAgentConfig{
		Runs:    newRetireRuns(chain, held),
		Entries: entries,
		Ledger:  chain,
	})

	_, err := retireAgent(scoped(t, "github.com/acme/widgets"), nil, retireAgentIn{RunID: runID})
	var classified *Error
	if !errors.As(err, &classified) || classified.Class != ClassRunNotFound {
		t.Fatalf("retire_agent answered %v, want %s", err, ClassRunNotFound)
	}
	// Byte-identical to the answer for a run nothing holds.
	absent := Errorf(ClassRunNotFound, runID, "no run %q", runID)
	if classified.Error() != absent.Error() {
		t.Errorf("a run in another repository is answered differently from one that does "+
			"not exist:\n got  %q\n want %q", classified.Error(), absent.Error())
	}
	if len(entries.deletes) != 0 {
		t.Errorf("SPIRE was asked to delete %d entries for a run in another repository",
			len(entries.deletes))
	}
	if len(chain.stored) != 0 {
		t.Errorf("%d events were appended for a refused retirement", len(chain.stored))
	}

	// The positive control: its own repository still retires.
	if _, err := retireAgent(scoped(t, held.Repo), nil, retireAgentIn{RunID: runID}); err != nil {
		t.Fatalf("retire_agent was refused for a run in its credential's own repository: %v", err)
	}
}

// TestMCP089ObserveToolCallAnswersARunInAnotherRepositoryAsAbsent, and writes
// no body. A body is file contents and commands (doc 05); writing one for a
// run the caller has no claim on would put another repository's evidence on
// this deployment's volume under that run's name.
func TestMCP089ObserveToolCallAnswersARunInAnotherRepositoryAsAbsent(t *testing.T) {
	env := otcSetup(t, nil)
	held := credRun(otcRunID)
	held.Repo = "github.com/acme/elsewhere"
	env.runs.putAs(otcRunID, held)

	_, err := observeToolCall(scoped(t, "github.com/acme/widgets"), nil, observeToolCallIn{
		RunID: otcRunID, Tool: otcTool, Body: otcBody,
	})
	var classified *Error
	if !errors.As(err, &classified) || classified.Class != ClassRunNotFound {
		t.Fatalf("observe_tool_call answered %v, want %s", err, ClassRunNotFound)
	}
	absent := Errorf(ClassRunNotFound, otcRunID, "no run %q", otcRunID)
	if classified.Error() != absent.Error() {
		t.Errorf("a run in another repository is answered differently from one that does "+
			"not exist:\n got  %q\n want %q", classified.Error(), absent.Error())
	}
	if len(env.ledger.appended) != 0 {
		t.Errorf("%d events were appended for a refused observation", len(env.ledger.appended))
	}
	if entries, err := os.ReadDir(env.bodyDir); err == nil && len(entries) != 0 {
		t.Errorf("%d body directories were written for a refused observation", len(entries))
	}
}

// TestMCP088DescribeWorkspaceRefusesATreeOutsideTheCredentialsRepository.
//
// It writes nothing, which is exactly why it is scoped: it is the tool that
// makes the other two addressable, and an unscoped one would let one
// repository's credential walk another's worktrees, branches and tasks out of
// this deployment's mount.
func TestMCP088DescribeWorkspaceRefusesATreeOutsideTheCredentialsRepository(t *testing.T) {
	tree := newWorkspaceTree(t, "git@github.com:Example-Org/Example-Repo.git")
	configureWorkspace(t, tree.projects, tree.projects)

	// The positive control first, so "refused" below cannot be the fixture.
	out, err := describeWorkspace(scoped(t, osRepo), nil,
		describeWorkspaceIn{CWD: tree.repo})
	if err != nil {
		t.Fatalf("describe_workspace refused a tree in its credential's own repository: %v", err)
	}
	if out.Repo != osRepo {
		t.Fatalf("the fixture resolves to %q; the case below is about another repository", out.Repo)
	}

	_, err = describeWorkspace(scoped(t, "github.com/acme/elsewhere"), nil,
		describeWorkspaceIn{CWD: tree.repo})
	var classified *Error
	if !errors.As(err, &classified) || classified.Class != ClassInvariantViolation {
		t.Fatalf("describe_workspace answered %v, want %s", err, ClassInvariantViolation)
	}
	// THE DERIVED REPOSITORY IS NOT NAMED. Answering "that is someone else's"
	// would confirm what a probe was guessing.
	if strings.Contains(classified.Message, out.Repo) {
		t.Errorf("the refusal names the repository it derived: %q", classified.Message)
	}
}

// TestMCP088ObserveSessionStartIsBoundToTheWorkspaceItDerives. The start path
// reaches describe_workspace and register_agent in process, so the binding is
// made once for both and nothing is registered for a tree the credential does
// not authorise.
func TestMCP088ObserveSessionStartIsBoundToTheWorkspaceItDerives(t *testing.T) {
	env := osSetup(t, nil)

	_, err := observeSession(scoped(t, "github.com/acme/elsewhere"), nil, observeSessionIn{
		SessionID: osSessionID, Phase: ObserveSessionPhaseStart, CWD: env.tree.repo,
	})
	if err == nil {
		t.Fatal("observe_session started a session in a tree the credential does not authorise")
	}
	if n := len(env.chain(t)); n != 0 {
		t.Errorf("%d events were appended by a refused session start", n)
	}
}

// A START FOR A SESSION THIS DEPLOYMENT ALREADY HOLDS is checked against the
// repository the MARKER records, not against one derived now.
//
// The case above is a session nothing has seen: the refusal comes from
// describe_workspace, on the tree. This is the other half, and it is the one
// that carries the reply — a start for a known session REPLAYS that session's
// run id, SPIFFE ID, workspace and task, so without this check a caller
// holding another repository's credential would be handed all four by naming a
// session id. It is a refusal rather than the "unknown session" a stop
// answers with: an unknown session and a session held by someone else are
// different here, and only one of them may be written to.
func TestASessionHeldByAnotherRepositoryIsRefusedRatherThanReplayed(t *testing.T) {
	env := osSetup(t, nil)
	started := env.mustStart(t, osSessionID)
	if started.RunID == "" || started.SPIFFEID == "" {
		t.Fatalf("the fixture registered nothing to be replayed: %+v", started)
	}
	before := len(env.chain(t))

	out, err := observeSession(scoped(t, "github.com/acme/elsewhere"), nil, observeSessionIn{
		SessionID: osSessionID, Phase: ObserveSessionPhaseStart, CWD: env.tree.repo,
	})
	if err == nil {
		t.Fatalf("a start under another repository's credential was answered with %+v", out)
	}
	// The package's own refusal for a repository a credential does not
	// authorise, byte for byte — not a workspace refusal that happens to look
	// like one.
	if got, want := err.Error(), adminScopeRefusal(ToolObserveSession).Error(); got != want {
		t.Errorf("the refusal is\n got  %q\n want %q", got, want)
	}
	var classified *Error
	if !errors.As(err, &classified) || classified.Class != ClassInvariantViolation {
		t.Fatalf("observe_session answered %v, want %s", err, ClassInvariantViolation)
	}

	// NOTHING OF THE SESSION COMES BACK WITH THE REFUSAL. The reply a start
	// carries is the whole of what this check exists to withhold.
	if out != (observeSessionOut{}) {
		t.Errorf("the refusal carried the session's own reply: %+v", out)
	}
	if strings.Contains(classified.Message, osRepo) ||
		strings.Contains(classified.Message, "github.com/acme/elsewhere") {
		t.Errorf("the refusal names a repository: %q", classified.Message)
	}

	// NOTHING WAS REGISTERED OVER IT. A second run for one session is the
	// state this refusal exists to prevent, and the marker is the only thing
	// that would have said the session was already held.
	if n := len(env.chain(t)); n != before {
		t.Errorf("a refused start appended %d event(s)", n-before)
	}
	if n := env.countEvents(t, started.RunID, event.EventTypeRunRegistered); n != 1 {
		t.Errorf("the session has %d run_registered after a refused start, want 1", n)
	}

	// AND THE MARKER IS UNTOUCHED, which is what makes the refusal free: the
	// session's own harness carries on afterwards.
	marker, found, err := observeSessionReadMarker(env.markerDir, osSessionID)
	if err != nil || !found {
		t.Fatalf("the marker is gone after a refused start: found=%v err=%v", found, err)
	}
	if marker.Repo != osRepo || marker.RunID != started.RunID || marker.RetiredAt != "" {
		t.Errorf("the marker was written over by a refused start: %+v", marker)
	}

	// The positive control: its own credential still replays the same run.
	replayed, err := observeSession(scoped(t, osRepo), nil, observeSessionIn{
		SessionID: osSessionID, Phase: ObserveSessionPhaseStart, CWD: env.tree.repo,
	})
	if err != nil {
		t.Fatalf("a start was refused for the session's own repository: %v", err)
	}
	if replayed.RunID != started.RunID {
		t.Errorf("the session replayed run %q, want its own %q", replayed.RunID, started.RunID)
	}
}

// TestMCP089ObserveSessionStopAnswersAnotherRepositorysSessionAsUnknown.
//
// A stop names a session id and nothing else. An answer that distinguished
// "held by someone else" from "never seen" would make this tool a lookup from
// session id to a run id, a SPIFFE ID and a workspace across every repository
// at once — and the reply carries all three.
func TestMCP089ObserveSessionStopAnswersAnotherRepositorysSessionAsUnknown(t *testing.T) {
	env := osSetup(t, nil)
	started := env.mustStart(t, osSessionID)
	if started.RunID == "" {
		t.Fatal("the fixture registered no run")
	}

	elsewhere, err := observeSession(scoped(t, "github.com/acme/elsewhere"), nil,
		observeSessionIn{SessionID: osSessionID, Phase: ObserveSessionPhaseStop})
	if err != nil {
		t.Fatalf("observe_session stop refused: %v. A stop never blocks (IP §4)", err)
	}
	unknown, err := observeSession(scoped(t, "github.com/acme/elsewhere"), nil,
		observeSessionIn{SessionID: "11111111-2222-3333-4444-555555555555",
			Phase: ObserveSessionPhaseStop})
	if err != nil {
		t.Fatalf("observe_session stop for an unknown session refused: %v", err)
	}

	elsewhere.SessionID, unknown.SessionID = "", ""
	if elsewhere != unknown {
		t.Errorf("another repository's session is answered differently from one this "+
			"deployment never saw:\n held:    %+v\n unknown: %+v", elsewhere, unknown)
	}
	if env.countEvents(t, started.RunID, event.EventTypeRunRetired) != 0 {
		t.Error("a stop from another repository's credential retired the run")
	}

	// The positive control: its own credential still ends it.
	ended, err := observeSession(scoped(t, osRepo), nil,
		observeSessionIn{SessionID: osSessionID, Phase: ObserveSessionPhaseStop})
	if err != nil {
		t.Fatalf("observe_session stop refused for its own repository: %v", err)
	}
	if !ended.Retired {
		t.Errorf("the session was not retired by its own credential: %+v", ended)
	}
}

// ---------------------------------------------------------------------------
// Health reports whether the check is enforced — on the health listener only.
// ---------------------------------------------------------------------------

// TestReadinessReportsWhetherTheAdminCredentialIsEnforced.
//
// A control whose state nobody can see is one nobody can audit, and the one
// state an operator must not have to infer is the OPEN one — so the field is
// always present rather than omitted when absent.
//
// It is never a reason to be unready: a deployment that has not split its
// listeners requires no credential and is perfectly ready.
func TestReadinessReportsWhetherTheAdminCredentialIsEnforced(t *testing.T) {
	for _, tc := range []struct {
		enforced bool
		want     string
	}{{true, "enforced"}, {false, "absent"}} {
		h := healthWithFakes(t, HealthConfig{AdminCredentialEnforced: tc.enforced})
		ready := h.Ready(t.Context())
		if !ready.Ready {
			t.Fatalf("three succeeding probes did not produce ready")
		}
		body, err := json.Marshal(ready)
		if err != nil {
			t.Fatalf("marshalling readiness: %v", err)
		}
		var wire map[string]any
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatalf("unmarshalling readiness: %v", err)
		}
		if wire["admin_credential"] != tc.want {
			t.Errorf("admin_credential = %v, want %q", wire["admin_credential"], tc.want)
		}
	}
}

// TestTheMCPTransportReportsNothingAboutTheCredential. doc 05 gives this
// process three listeners and the health one is the operator's. "This listener
// is open", published where a stranger can reach it, is an invitation.
func TestTheMCPTransportReportsNothingAboutTheCredential(t *testing.T) {
	_, url := serveProbes(t)
	session := connect(t, url)
	init := session.InitializeResult()
	rendered, err := json.Marshal(init)
	if err != nil {
		t.Fatalf("marshalling the handshake: %v", err)
	}
	for _, leak := range []string{"admin_credential", "enforced", adminScopeHeader} {
		if strings.Contains(string(rendered), leak) {
			t.Errorf("the initialize handshake carries %q: %s", leak, rendered)
		}
	}

	// And the liveness endpoint, which some deployments publish beside the
	// transport, says nothing about it either.
	live := healthWithFakes(t, HealthConfig{AdminCredentialEnforced: true}).Live()
	liveBody, err := json.Marshal(live)
	if err != nil {
		t.Fatalf("marshalling liveness: %v", err)
	}
	if strings.Contains(string(liveBody), "admin_credential") {
		t.Errorf("liveness reports the credential's state: %s", liveBody)
	}
}

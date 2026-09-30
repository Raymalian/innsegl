// SPDX-License-Identifier: Apache-2.0

package main

// gatewayagentmessage_test.go — RM-237 (#382), E16 integration: the
// agent-message recorder wired in PRODUCTION through cmd/innsegl/gateway.go's
// own openIdentityStack (configureGatewayAgentMessages), driven end to end
// through the real openGateway -- the same real listener, real HTTP round
// trips and real Postgres gatewayrecord_test.go and gatewayidentity_test.go
// already drive, reusing their own fixtures rather than building new ones.
//
// The two settings that turn this recording on, -identity-secret and
// -agent-message-key-id, are exercised through the REAL command-line flag
// parsing (runGateway/parseGatewayFlags), not by calling
// mcp.ConfigureAgentMessageRecorder directly: this test's own claim is that
// the PROCESS wires it, not that internal/mcp's own recorder works, which
// internal/mcp/agentmessage_test.go already measures on its own.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/mcp"
)

// startGWAgentMessageGateway is startGWIdentityGateway's own sibling
// (gatewayidentity_test.go): the two differences are -identity-secret and
// -agent-message-key-id, RM-237's own settings, and that stderr is
// captured rather than discarded, so a canary scan can prove the secret
// this recorder derives its key from never reaches the log.
func startGWAgentMessageGateway(
	t *testing.T, dsn, upstreamURL string, upstreamClient *http.Client, identitySecret, keyID string,
) (addr string, client *http.Client, stderr *syncBuffer, stop func()) {
	t.Helper()
	stderr = &syncBuffer{}
	keyDir, certDir := gatewayTestCADirs(t)
	addrCh := make(chan string, 1)
	deps := gatewayDeps{open: func(ctx context.Context, o gatewayOptions, log *serveLog) (servedGateway, error) {
		o.upstreamClient = upstreamClient
		o.caKeyDir = keyDir
		o.caCertDir = certDir
		srv, err := openGateway(ctx, o, log)
		if err == nil {
			addrCh <- srv.Addr()
		}
		return srv, err
	}}

	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"-listen", "127.0.0.1:0", "-upstream", upstreamURL, "-dsn", dsn,
		"-identity-secret", identitySecret, "-agent-message-key-id", keyID,
		"-ca-key-dir", keyDir, "-ca-cert-dir", certDir,
	}
	done := make(chan int, 1)
	go func() { done <- runGateway(ctx, args, io.Discard, stderr, deps) }()

	select {
	case addr = <-addrCh:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("the gateway never announced a bound address")
	}
	client = gatewayTrustingClient(t, certDir)

	stop = func() {
		cancel()
		select {
		case code := <-done:
			if code != exitOK {
				t.Errorf("runGateway after its context was cancelled = %d, want %d (exitOK)", code, exitOK)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the gateway did not stop within 10s of its context being cancelled")
		}
	}
	return addr, client, stderr, stop
}

// waitForAgentMessageEvents polls f's own chain until runID carries at
// least want agent_message events, or fails t after ten seconds --
// recording is always asynchronous (messages.go's own doc comment,
// "Witness, never a gate"), the same reasoning waitForToolCallEvents
// (gatewayrecord_test.go) already gives its own poll.
func waitForAgentMessageEvents(t *testing.T, f *gwIdentityFixture, runID string, want int) []event.Fields {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		recs, err := f.store.EventsForRun(ctx, runID)
		cancel()
		if err != nil {
			t.Fatalf("EventsForRun(%q): %v", runID, err)
		}
		var got []event.Fields
		for _, r := range recs {
			if r[event.FieldEventType] == event.EventTypeAgentMessage {
				got = append(got, r)
			}
		}
		if len(got) >= want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d agent_message events on run %q; got %d: %+v",
				want, runID, len(got), got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestGREC005AgentMessagesEndToEndThroughRealOpenGateway is RM-237 (#382)'s
// own end-to-end proof, run through the SAME production wiring E16's
// integration wave puts the tool-call recorder through: a request
// carrying a brief, then (on the NEXT request, once Claude Code's own
// resent history carries it -- messages.go's own doc comment on why an
// assistant turn is read from the request's history and never from the
// reply being streamed back) a reply's own assistant text. Exactly one
// `agent_message` of each role lands on the run's own ledger, each
// validates under internal/event's own schema (v4, doc 02 §3's errata),
// carries a keyed digest (ValidateKeyedDigest), and the identity secret
// this recorder derives that key from -- and the derived key itself --
// appear in no event, no log line and no body file
// (assertCredentialCanaryNowhere, GW-010's own scanner, reused rather than
// re-invented).
func TestGREC005AgentMessagesEndToEndThroughRealOpenGateway(t *testing.T) {
	f := newGWIdentityFixture(t)
	bodyDir := configureGRECObserveToolCall(t, f)
	_, repo := configureGWIdentityWorkspace(t)
	t.Setenv(envObserveBodyDir, bodyDir) // the SAME env var configureGatewayAgentMessages reads.

	identitySecret := newIdentitySecretCanary(t)
	const keyID = "grec005-key"

	upstream := newGRECUpstream(t,
		func(t *testing.T, w http.ResponseWriter) { writeGRECTextSSE(t, w, "the endpoint is live") },
		func(t *testing.T, w http.ResponseWriter) { writeGRECTextSSE(t, w, "done") },
	)

	addr, client, stderr, stop := startGWAgentMessageGateway(t, f.dsn, upstream.URL, upstream.Client(), identitySecret, keyID)
	defer stop()

	const session = "b3a1c2d4-5e6f-4708-9a0b-1c2d3e4f5a6b"
	const brief = "add a health endpoint"
	const assistantText = "the endpoint is live"

	conv := &grecConversation{}
	conv.addUserBrief(t, repo, brief)

	firstResp := sendAndReadGREC(t, addr, client, session, conv.body(t))
	runID := grecRunID(t, f.dsn, session)

	// The upstream's own reply becomes history on the NEXT request --
	// exactly the mechanism messages_test.go's own
	// TestMessageRecorderRecordsTheBriefOnceAndEachNewAssistantTurn already
	// measures at the package level; this is that same mechanism, once,
	// through the real command.
	conv.messages = append(conv.messages, grecMessage{
		Role:    "assistant",
		Content: []grecBlock{{Type: "text", Text: assistantText}},
	})
	secondResp := sendAndReadGREC(t, addr, client, session, conv.body(t))

	events := waitForAgentMessageEvents(t, f, runID, 2)

	var briefs, assistants int
	for _, e := range events {
		if err := event.ValidateEvent(e); err != nil {
			t.Errorf("recorded agent_message does not validate under internal/event (v4): %v (%+v)", err, e)
		}
		digest, ok := e[event.FieldPayloadDigest].(string)
		if !ok || digest == "" {
			t.Fatalf("agent_message carries no payload_digest: %+v", e)
		}
		if err := event.ValidateKeyedDigest(digest); err != nil {
			t.Errorf("payload_digest %q is not a valid keyed digest: %v", digest, err)
		}
		switch e[event.FieldRole] {
		case mcp.AgentMessageRoleBrief:
			briefs++
		case mcp.AgentMessageRoleAssistant:
			assistants++
		default:
			t.Errorf("agent_message has an unexpected role %v: %+v", e[event.FieldRole], e)
		}
	}
	if briefs != 1 || assistants != 1 {
		t.Fatalf("got %d brief and %d assistant agent_message events, want exactly one each: %+v",
			briefs, assistants, events)
	}

	derivedKey, err := mcp.DeriveAgentMessageKey(identitySecret, keyID)
	if err != nil {
		t.Fatalf("DeriveAgentMessageKey: %v", err)
	}
	for _, canary := range []string{identitySecret, derivedKey} {
		assertCredentialCanaryNowhere(t, "agent-message identity secret/derived key", canary,
			[]byte(stderr.String()),
			map[string][]byte{"first response body": firstResp, "second response body": secondResp},
			[]string{bodyDir})
		for _, e := range events {
			for field, v := range e {
				if s, ok := v.(string); ok && strings.Contains(s, canary) {
					t.Errorf("event field %q contains the canary %q: %+v", field, canary, e)
				}
			}
		}
	}
}

// newIdentitySecretCanary mirrors newCredentialCanary's own construction
// (gatewaycanary_test.go): a fresh, random value so a match in the scan
// below can only be this test's own secret.
func newIdentitySecretCanary(t *testing.T) string {
	t.Helper()
	return "innsegl-identity-secret-canary-" + randomCanarySuffix(t)
}

// sendAndReadGREC is sendAndDrainGREC's own sibling (gatewayrecord_test.go):
// the one difference is that the response body is read and returned rather
// than discarded, so a canary scan can check it.
func sendAndReadGREC(t *testing.T, addr string, client *http.Client, sessionID, body string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://"+addr+"/v1/messages", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("X-Claude-Code-Session-Id", sessionID)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return respBody
}

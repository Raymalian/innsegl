// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Telemetry is the harness's own witness of each tool call. While the core
// is down it used to be lost -- Claude Code does not resend an export -- and
// every tool call in the outage became a "no telemetry" drift alert
// (measured 2026-10-03: a core restart, about fifty alerts). The client
// keeps the export and delivers it once the core answers.
func TestTelemetryHeldWhileTheCoreIsDownIsDeliveredAfter(t *testing.T) {
	core, paths := enrolled(t)
	got := make(chan string, 4)
	core.Mux.HandleFunc("/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the export: %v", err)
		}
		got <- string(b)
		w.WriteHeader(http.StatusOK)
	})
	srv, front, _ := startClient(t, paths)
	core.Stop() // the core stops answering

	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"claude_code.tool_result"},"attributes":[{"key":"event.name","value":{"stringValue":"claude_code.tool_result"}},{"key":"tool_use_id","value":{"stringValue":"toolu_telemetry_1"}},{"key":"tool_name","value":{"stringValue":"Bash"}},{"key":"success","value":{"boolValue":true}},{"key":"session.id","value":{"stringValue":"session"}}]}]}]}]}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, front.URL+"/v1/logs", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d while the core was down, want 200: the export is kept", resp.StatusCode)
	}
	if n := srv.outbox.status().Kinds[KindTelemetry]; n != 1 {
		t.Fatalf("held exports %d, want 1", n)
	}

	core.Restart(t) // the core answers again
	if _, err := srv.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	select {
	case b := <-got:
		if b != body {
			t.Fatalf("the core received %q, want the held export", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held export never reached the core")
	}
	if n := srv.outbox.status().Kinds[KindTelemetry]; n != 0 {
		t.Fatalf("held exports %d after delivery, want 0", n)
	}
}

func TestCodexTelemetryIsScrubbedBeforeOutageQueueAndDelivery(t *testing.T) {
	core, paths := enrolled(t)
	got := make(chan string, 2)
	core.Mux.HandleFunc(TelemetryLogsPath, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading the export: %v", err)
		}
		got <- string(b)
		w.WriteHeader(http.StatusOK)
	})
	srv, front, _ := startClient(t, paths)
	core.Stop()

	body := `{"resourceLogs":[{"resource":{"attributes":[{"key":"user.email","value":{"stringValue":"private@example.invalid"}}]},"scopeLogs":[{"scope":{"name":"codex_otel"},"logRecords":[{"body":{"stringValue":"codex.tool_result"},"attributes":[` +
		`{"key":"event.name","value":{"stringValue":"codex.tool_result"}},` +
		`{"key":"call_id","value":{"stringValue":"call_1234567890abcdef"}},` +
		`{"key":"tool_name","value":{"stringValue":"exec_command"}},` +
		`{"key":"success","value":{"stringValue":"true"}},` +
		`{"key":"conversation.id","value":{"stringValue":"codex-session"}},` +
		`{"key":"arguments","value":{"stringValue":"PRIVATE COMMAND"}},` +
		`{"key":"output","value":{"stringValue":"PRIVATE TOOL OUTPUT"}}]}]}]}]}`
	if status, _, _ := postJSON(t, front.URL+TelemetryLogsPath, body, map[string]string{"Content-Type": "application/json"}); status != http.StatusOK {
		t.Fatalf("telemetry while the core is down: %d, want 200 (scrubbed export held)", status)
	}
	pending := srv.outbox.pending()
	if len(pending) != 1 || pending[0].kind != KindTelemetry {
		t.Fatalf("outbox items = %+v, want one telemetry export", pending)
	}
	held, err := srv.outbox.read(pending[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PRIVATE COMMAND", "PRIVATE TOOL OUTPUT", "private@example.invalid", "codex_otel"} {
		if strings.Contains(string(held), secret) {
			t.Errorf("held telemetry contains %q: %s", secret, held)
		}
	}
	for _, required := range []string{"codex.tool_result", "call_1234567890abcdef", "exec_command", "codex-session"} {
		if !strings.Contains(string(held), required) {
			t.Errorf("held telemetry lost %q: %s", required, held)
		}
	}

	core.Restart(t)
	if _, err := srv.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	select {
	case delivered := <-got:
		if string(held) != delivered {
			t.Errorf("core received %s, want the same scrubbed export as the outbox", delivered)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the scrubbed telemetry export never reached the core")
	}
}

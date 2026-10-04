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

	body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"claude_code.tool_result"}}]}]}]}`
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

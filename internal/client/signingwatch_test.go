// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// SIG-015 (RM-339, #583), the operator's half: the client service reads the
// core's signing probe and notifies once, on the first failure; it says so
// again only after signing has recovered and failed anew.

type notes struct {
	mu   sync.Mutex
	sent []string
}

func (n *notes) notify(_ context.Context, title, body string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, title+"|"+body)
	return nil
}

func (n *notes) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.sent...)
}

func TestSIG015TheClientNotifiesOnTheFirstSigningFailure(t *testing.T) {
	core, paths := enrolled(t)
	var mu sync.Mutex
	body := `{"components":[{"name":"ledger","up":true},{"name":"signing","up":true,"detail":"a certificate was issued at 2026-10-11T09:00:00Z"}]}`
	core.Mux.HandleFunc(CoreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		write(t, w, body)
	})
	set := func(b string) { mu.Lock(); body = b; mu.Unlock() }
	failing := `{"components":[{"name":"signing","up":false,"detail":"FAILING since 2026-10-11T09:05:00Z — the CA refused the certificate: HTTP 500: error communicating with CA backend"}]}`

	s, err := NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	n := &notes{}
	ctx := t.Context()

	s.CheckSigning(ctx, n.notify)
	if got := n.all(); len(got) != 0 {
		t.Fatalf("notified while signing works: %v", got)
	}

	set(failing)
	s.CheckSigning(ctx, n.notify)
	s.CheckSigning(ctx, n.notify)
	got := n.all()
	if len(got) != 1 {
		t.Fatalf("%d notifications for one outage, want exactly one: %v", len(got), got)
	}
	if !strings.Contains(got[0], "signing: FAILING since 2026-10-11T09:05:00Z — the CA refused the certificate") {
		t.Fatalf("the notification %q does not say since when and why", got[0])
	}

	// A core that does not answer is not news about signing.
	core.SetUnavailable(true)
	s.CheckSigning(ctx, n.notify)
	core.SetUnavailable(false)

	set(`{"components":[{"name":"signing","up":true}]}`)
	s.CheckSigning(ctx, n.notify)
	set(failing)
	s.CheckSigning(ctx, n.notify)
	if got := n.all(); len(got) != 2 {
		t.Fatalf("after a recovery and a new failure: %d notifications, want 2: %v", len(got), got)
	}

	// A core with no signing probe (older than RM-339) is never a failure.
	set(`{"components":[{"name":"ledger","up":true}]}`)
	s.CheckSigning(ctx, n.notify)
	set(`not json`)
	s.CheckSigning(ctx, n.notify)
	if got := n.all(); len(got) != 2 {
		t.Fatalf("a core with no probe, or an unreadable answer, notified: %v", got)
	}
}

// JRN-011 (#584): the hook asks the client service, not the core, whether
// signing is down: GET /_client/status carries the probe's last reading,
// and SigningOutage reads it from where core.json says the service listens.
func TestJRN011TheClientServiceTellsTheHookSigningIsDown(t *testing.T) {
	core, paths := enrolled(t)
	var mu sync.Mutex
	body := `{"components":[{"name":"signing","up":false,"detail":"FAILING since 2026-10-11T09:05:00Z — the CA store token was revoked"}]}`
	core.Mux.HandleFunc(CoreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if body == "" {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		write(t, w, body)
	})
	set := func(b string) { mu.Lock(); body = b; mu.Unlock() }

	// No service listening: nothing is known, and nothing is said.
	setListen(t, paths, "127.0.0.1:1")
	if _, _, down := SigningOutage(t.Context(), paths); down {
		t.Fatal("an outage read from a service that is not running")
	}

	srv, front, _ := startClient(t, paths)
	setListen(t, paths, strings.TrimPrefix(front.URL, "http://"))
	if _, _, down := SigningOutage(t.Context(), paths); down {
		t.Fatal("an outage before the service has read the probe")
	}

	srv.CheckSigning(t.Context(), (&notes{}).notify)
	since, reason, down := SigningOutage(t.Context(), paths)
	if !down || !since.Equal(time.Date(2026, 10, 11, 9, 5, 0, 0, time.UTC)) ||
		reason != "the CA store token was revoked" {
		t.Fatalf("SigningOutage = %v %q %v", since, reason, down)
	}

	set(`{"components":[{"name":"signing","up":true,"detail":"a certificate was issued at 2026-10-11T09:10:00Z"}]}`)
	srv.CheckSigning(t.Context(), (&notes{}).notify)
	if _, _, down := SigningOutage(t.Context(), paths); down {
		t.Fatal("an outage after signing recovered")
	}

	// A core that stops answering says nothing about signing: the last
	// reading is dropped, not kept as news.
	set(`{"components":[{"name":"signing","up":false,"detail":"FAILING since 2026-10-11T09:20:00Z — x"}]}`)
	srv.CheckSigning(t.Context(), (&notes{}).notify)
	set("")
	srv.CheckSigning(t.Context(), (&notes{}).notify)
	if _, _, down := SigningOutage(t.Context(), paths); down {
		t.Fatal("an outage kept after the core stopped answering")
	}

	// Not enrolled: nothing.
	if _, _, down := SigningOutage(t.Context(), ClientPaths(t.TempDir())); down {
		t.Fatal("an outage on a machine that is not connected")
	}
	// A listen address that is not loopback is never asked.
	setListen(t, paths, "192.0.2.1:28195")
	if _, _, down := SigningOutage(t.Context(), paths); down {
		t.Fatal("an outage read from a non-loopback address")
	}
}

func TestRunSigningWatchChecksOnSchedule(t *testing.T) {
	core, paths := enrolled(t)
	var mu sync.Mutex
	calls := 0
	core.Mux.HandleFunc(CoreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		write(t, w, `{"components":[]}`)
	})
	s, err := NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
	defer cancel()
	s.RunSigningWatch(ctx, 20*time.Millisecond, (&notes{}).notify)
	mu.Lock()
	defer mu.Unlock()
	if calls < 3 {
		t.Fatalf("%d checks in 120ms at 20ms", calls)
	}
}

// The desktop notifier runs osascript on macOS with the text as arguments,
// never inside the script, and does nothing elsewhere.
func TestDesktopNotifier(t *testing.T) {
	var ran [][]string
	run := func(_ context.Context, name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	if err := desktopNotifier("linux", run)(t.Context(), "t", "b"); err != nil || len(ran) != 0 {
		t.Fatalf("linux: %v %v", err, ran)
	}
	if err := desktopNotifier("darwin", run)(t.Context(), `innsegl "x"`, `it's; do shell script "rm"`); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || ran[0][0] != "osascript" {
		t.Fatalf("%v", ran)
	}
	args := strings.Join(ran[0], "\x00")
	if !strings.HasSuffix(args, "\x00innsegl \"x\"\x00it's; do shell script \"rm\"") {
		t.Fatalf("the text is not passed as arguments: %q", ran[0])
	}
	if DesktopNotifier("plan9") == nil {
		t.Fatal("no notifier")
	}
}

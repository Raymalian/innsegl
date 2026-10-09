// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// statusFixture is an enrolled machine whose core answers status with
// components, and whose local client service answers or not.
func statusFixture(t *testing.T, components string, serviceUp bool, extra ...string) statusDeps {
	t.Helper()
	more := strings.Join(extra, "")
	f := newConnectFixture(t)
	f.core.Mux.HandleFunc(coreStatusPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"version":"v0.4.0","components":`+components+`,`+
			`"installation":{"id":"inst-1","name":"dev-laptop","kind":"workstation","status":"active",`+
			`"organisation":"example-org","repos":["*"]}`+more+`}`); err != nil {
			t.Error(err)
		}
	})
	// The machine's own client service: its status route says what this
	// test wants; everything else, the CLI's calls to the core included, is
	// the real service.
	svc := f.connectServed(t, func(service http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != client.StatusPath {
				service.ServeHTTP(w, r)
				return
			}
			if _, err := io.WriteString(w, `{"core_reachable":true,"revoked":false,"certificate_expires_at":"2026-10-04T00:00:00Z"}`); err != nil {
				t.Error(err)
			}
		})
	})
	local := "http://127.0.0.1:1" // nothing listens
	if serviceUp {
		local = svc.URL
	}
	return statusDeps{home: f.home, localURL: local}
}

// CLI-019 (PROPOSED for doc 07) — with the client service down, status says
// so, names how to start it, and says the core was not asked: the core is
// reached through the service.
func TestCLI019StatusSaysTheServiceIsDownAndHowToStartIt(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true}]`, false)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code == exitOK {
		t.Fatalf("exit 0 with the client service down; stdout:\n%s", out.String())
	}
	if got := errOut.String(); !strings.Contains(got, "down: client service, core") {
		t.Errorf("stderr does not name what is down:\n%s", got)
	}
	if !strings.Contains(out.String(), client.RestartCommand(runtime.GOOS)) {
		t.Errorf("stdout does not say how to start the service:\n%s", out.String())
	}
}

// #472: one command says what is up, what is down, the versions and the
// machine's scope.
func TestStatusSaysEverythingIsUp(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true},{"name":"sigstore","up":true}]`, true)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
		t.Fatalf("exit %d; stderr:\n%s", code, errOut.String())
	}
	for _, want := range []string{"client service", "up", "core", "v0.4.0", "ledger", "sigstore",
		"dev-laptop", "workstation", "example-org", "all repositories"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
}

// Anything down is named, and the exit is non-zero.
func TestStatusNamesWhatIsDown(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true},{"name":"sigstore","up":false}]`, true)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code == exitOK {
		t.Fatalf("exit 0 with sigstore down; stdout:\n%s", out.String())
	}
	if got := errOut.String(); !strings.Contains(got, "down: sigstore") {
		t.Errorf("stderr does not name what is down:\n%s", got)
	}
}

// The client's own status asks the core and waits up to three seconds when
// the core does not answer. `innsegl status` gave the client those same
// three seconds, so a core outage read as the client service being down too
// (measured 2026-10-04). A client that answers slowly is up.
func TestStatusWaitsLongerThanTheClientsOwnCoreProbe(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true}]`, false)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(4 * time.Second)
		if _, err := io.WriteString(w, `{"core_reachable":false,"revoked":false,"certificate_expires_at":"2026-10-05T00:00:00Z"}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(slow.Close)
	deps.localURL = slow.URL
	var out, errOut bytes.Buffer
	runStatus(t.Context(), nil, &out, &errOut, deps)
	if strings.Contains(errOut.String(), "client service") {
		t.Fatalf("a client that answered in four seconds was reported down:\n%s", errOut.String())
	}
}

// ADR-0073: the core's status carries when each CA in use expires, and
// `innsegl status` lists them and warns a year and 90 days ahead. A warning is
// not an outage: the exit stays zero.
func TestStatusWarnsBeforeACAInUseExpires(t *testing.T) {
	soon := time.Now().AddDate(0, 0, 60).UTC().Format(time.RFC3339)
	deps := statusFixture(t, `[{"name":"ledger","up":true}]`, true,
		`,"trust_expiries":[`+
			`{"name":"Fulcio root CA","kind":"fulcio_root","key_id":"aa","not_after":"2036-09-13T00:00:00Z"},`+
			`{"name":"gateway CA","kind":"gateway_ca","key_id":"bb","not_after":"`+soon+`","warning":"expires within 90 days"}]`)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
		t.Fatalf("exit %d; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Fulcio root CA") || !strings.Contains(out.String(), "2036-09-13") {
		t.Errorf("stdout does not list the Fulcio root's expiry:\n%s", out.String())
	}
	if !regexp.MustCompile(`trust +WARN +the gateway CA expires within 90 days`).MatchString(out.String()) {
		t.Errorf("stdout has no WARN line for the gateway CA:\n%s", out.String())
	}
}

// A sentinel that stopped verifying is shown as a WARN line with the time it
// was first seen. It is not an outage: the exit stays zero.
func TestStatusShowsTheTrustWatchsProblems(t *testing.T) {
	deps := statusFixture(t, `[{"name":"ledger","up":true}]`, true,
		`,"trust_problems":[{"text":"sentinel 6e55aa in github.com/o/r (era \"x\") should verify as verified: it verified as failed","since":"2026-10-06T09:00:00Z"}]`)
	var out, errOut bytes.Buffer
	if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
		t.Fatalf("exit %d; stderr:\n%s", code, errOut.String())
	}
	if !regexp.MustCompile(`trust +WARN +sentinel 6e55aa .*since 2026-10-06T09:00:00Z`).MatchString(out.String()) {
		t.Errorf("stdout has no WARN line for the sentinel:\n%s", out.String())
	}
}

// ADR-0074: status says how old the newest local copy of the trust-key
// backup is, and warns when it is missing or more than two days old. A
// warning, not an outage: the exit status does not change.
func TestStatusSaysHowOldTheLocalTrustBackupIs(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	keep := func(t *testing.T, deps statusDeps, created time.Time) {
		t.Helper()
		st := &trustbackup.Store{Dir: client.ClientPaths(deps.home).TrustBackups, Keep: 5}
		body := "ciphertext"
		h := sha256.Sum256([]byte(body))
		name := "trust-backup-" + created.UTC().Format("20060102T150405Z") + ".tar.age"
		if _, err := st.Put(name, strings.NewReader(body), hex.EncodeToString(h[:])); err != nil {
			t.Fatal(err)
		}
	}
	run := func(t *testing.T, deps statusDeps) string {
		t.Helper()
		deps.now = func() time.Time { return now }
		var out, errOut bytes.Buffer
		if code := runStatus(t.Context(), nil, &out, &errOut, deps); code != exitOK {
			t.Fatalf("exit %d; stderr:\n%s", code, errOut.String())
		}
		return out.String()
	}
	trustLine := regexp.MustCompile(`(?m)^trust backup .*$`)
	components := `[{"name":"ledger","up":true}]`

	deps := statusFixture(t, components, true)
	out := run(t, deps)
	if l := trustLine.FindString(out); !strings.Contains(l, "WARN") || !strings.Contains(l, "no local copy") {
		t.Fatalf("missing: %q\n%s", l, out)
	}

	deps = statusFixture(t, components, true)
	keep(t, deps, now.Add(-5*time.Hour))
	out = run(t, deps)
	if l := trustLine.FindString(out); strings.Contains(l, "WARN") || !strings.Contains(l, "5h") {
		t.Fatalf("fresh: %q\n%s", l, out)
	}

	deps = statusFixture(t, components, true)
	keep(t, deps, now.Add(-73*time.Hour))
	out = run(t, deps)
	if l := trustLine.FindString(out); !strings.Contains(l, "WARN") || !strings.Contains(l, "3 days") {
		t.Fatalf("stale: %q\n%s", l, out)
	}
}

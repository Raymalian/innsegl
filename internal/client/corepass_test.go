// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"innsegl.dev/innsegl/internal/client/clienttest"
	"innsegl.dev/innsegl/internal/trustbackup"
)

// ---------------------------------------------------------------------------
// CLI-017..CLI-019 (PROPOSED for doc 07) — the CLI reaches the core through
// the client service on loopback, never by dialling the core itself. On
// macOS a terminal-started binary without the Local Network permission
// cannot reach a LAN core ("no route to host"), while the launchd service
// can; loopback is never "local network". The service passes through only
// an explicit list of core routes, for this installation, over its own
// certificate.
// ---------------------------------------------------------------------------

// coreLog records every request the fake core received, by method and path.
type coreLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *coreLog) add(r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, r.Method+" "+r.URL.RequestURI())
}

func (l *coreLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

// passCore is an enrolled machine whose fake core answers every allowlisted
// route with its own method and path, and records everything it was asked.
func passCore(t *testing.T) (*clienttest.Core, Paths, *coreLog) {
	t.Helper()
	core, paths := enrolled(t)
	log := &coreLog{}
	core.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.add(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(trustbackup.HeaderSHA256, "abc")
		if err := json.NewEncoder(w).Encode(map[string]string{"method": r.Method, "path": r.URL.Path}); err != nil {
			t.Error(err)
		}
	})
	return core, paths, log
}

// serveFor starts this enrolment's client service on a loopback port and
// writes that address into core.json, as `innsegl connect --listen` would.
// The CLI then finds it where a real one is found.
func serveFor(t *testing.T, paths Paths) *httptest.Server {
	t.Helper()
	_, front, _ := startClient(t, paths)
	setListen(t, paths, strings.TrimPrefix(front.URL, "http://"))
	return front
}

// enrolledServed is enrolled with its own client service running, for a
// test of a CLI call.
func enrolledServed(t *testing.T) (*clienttest.Core, Paths) {
	t.Helper()
	core, paths := enrolled(t)
	serveFor(t, paths)
	return core, paths
}

func setListen(t *testing.T, paths Paths, listen string) {
	t.Helper()
	cfg, err := ReadCoreConfig(paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = listen
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Core, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func installationOf(t *testing.T, paths Paths) string {
	t.Helper()
	cfg, err := ReadCoreConfig(paths)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.InstallationID
}

// CLI-017 (PROPOSED) — every allowlisted route goes through the service to
// the core with the machine's certificate, and the core's answer (status,
// headers, body) comes back unchanged, marked as passed through.
func TestCLI017TheServicePassesTheCLIsCoreRoutesThrough(t *testing.T) {
	_, paths, log := passCore(t)
	front := serveFor(t, paths)
	id := installationOf(t, paths)

	for _, route := range CorePassRoutes {
		var body io.Reader = http.NoBody
		if route.Method == http.MethodPost {
			body = strings.NewReader(`{"name":"x"}`)
		}
		req, err := http.NewRequestWithContext(t.Context(), route.Method, front.URL+CorePassPrefix+route.Path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(CorePassInstallationHeader, id)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", route.Method, route.Path, err)
		}
		var got map[string]string
		derr := json.NewDecoder(resp.Body).Decode(&got)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || derr != nil || got["path"] != route.Path || got["method"] != route.Method {
			t.Errorf("%s %s: %d %v %v", route.Method, route.Path, resp.StatusCode, got, derr)
		}
		if resp.Header.Get(CorePassHeader) == "" || resp.Header.Get(trustbackup.HeaderSHA256) != "abc" {
			t.Errorf("%s %s: headers %v", route.Method, route.Path, resp.Header)
		}
	}
	if n := len(log.all()); n != len(CorePassRoutes) {
		t.Fatalf("the core was asked %d times, want %d: %v", n, len(CorePassRoutes), log.all())
	}
}

// CLI-018 (PROPOSED) — anything not on the list is refused by the service
// itself and never reaches the core: another path, another method, a path
// that only starts like an allowed one, a query, and a caller that names
// another installation.
func TestCLI018TheServiceRefusesWhatIsNotOnTheList(t *testing.T) {
	_, paths, log := passCore(t)
	front := serveFor(t, paths)
	id := installationOf(t, paths)

	cases := []struct {
		name, method, path, installation string
		want                             int
	}{
		{"enrolment", http.MethodPost, "/_core/enrol", id, http.StatusForbidden},
		{"renewal", http.MethodPost, "/_core/renew", id, http.StatusForbidden},
		{"the mirror", http.MethodGet, "/_core/git/github.com/o/r.git/info/refs", id, http.StatusForbidden},
		{"the journal", http.MethodPost, "/_core/journal", id, http.StatusForbidden},
		{"a model route", http.MethodPost, "/v1/messages", id, http.StatusForbidden},
		{"the wrong method", http.MethodDelete, "/_core/status", id, http.StatusForbidden},
		{"a status POST", http.MethodPost, "/_core/status", id, http.StatusForbidden},
		{"a dot-dot path", http.MethodGet, "/_core/trust-backup/../renew", id, http.StatusForbidden},
		{"a longer path", http.MethodGet, "/_core/status/x", id, http.StatusForbidden},
		{"a query", http.MethodGet, "/_core/status?x=1", id, http.StatusForbidden},
		{"the bare prefix", http.MethodGet, "", id, http.StatusForbidden},
		{"no installation", http.MethodGet, "/_core/status", "", http.StatusConflict},
		{"another installation", http.MethodGet, "/_core/status", "inst-someone-else", http.StatusConflict},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A raw request line, so nothing on this side cleans the path.
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(front.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			head := c.method + " " + CorePassPrefix + c.path + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 0\r\n"
			if c.installation != "" {
				head += CorePassInstallationHeader + ": " + c.installation + "\r\n"
			}
			if _, werr := io.WriteString(conn, head+"\r\n"); werr != nil {
				t.Fatal(werr)
			}
			raw, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			if !strings.Contains(strings.SplitN(text, "\r\n", 2)[0], " "+strconv.Itoa(c.want)+" ") {
				t.Errorf("answer:\n%s\nwant %d", text, c.want)
			}
			if !strings.Contains(text, CorePassHeader) {
				t.Errorf("the refusal is not marked as the pass-through's own:\n%s", text)
			}
		})
	}
	if seen := log.all(); len(seen) != 0 {
		t.Fatalf("refused requests reached the core: %v", seen)
	}
}

// CLI-018 (PROPOSED) — a revoked installation's service refuses the CLI as
// it refuses everything else, and says so in the CLI's own shape.
func TestCLI018ARevokedServiceRefusesTheCLIToo(t *testing.T) {
	_, paths, log := passCore(t)
	srv, front, _ := startClient(t, paths)
	srv.revoked.Store(true)
	setListen(t, paths, strings.TrimPrefix(front.URL, "http://"))
	_, err := FetchCoreStatus(t.Context(), paths, "")
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("FetchCoreStatus through a revoked service: %v", err)
	}
	if seen := log.all(); len(seen) != 0 {
		t.Fatalf("a revoked service passed requests to the core: %v", seen)
	}
}

// CLI-019 (PROPOSED) — the CLI says plainly when the service is down (and
// how to start it), when it is older than the CLI, and when the core did not
// answer the service: three different things, none of them "unreachable"
// alone.
func TestCLI019TheCLISaysWhichPartIsNotAnswering(t *testing.T) {
	t.Run("the service is down", func(t *testing.T) {
		_, paths, _ := passCore(t)
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close() // nothing listens there now
		setListen(t, paths, addr)
		_, err = FetchCoreStatus(t.Context(), paths, "")
		if !errors.Is(err, ErrClientServiceDown) || !strings.Contains(err.Error(), addr) ||
			!strings.Contains(err.Error(), RestartCommand(runtime.GOOS)) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the service is older than the CLI", func(t *testing.T) {
		_, paths, _ := passCore(t)
		old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "innsegl gateway: unrecognised harness shape", http.StatusBadRequest)
		}))
		t.Cleanup(old.Close)
		setListen(t, paths, strings.TrimPrefix(old.URL, "http://"))
		_, err := FetchCoreStatus(t.Context(), paths, "")
		if !errors.Is(err, ErrClientServiceOld) || !strings.Contains(err.Error(), RestartCommand(runtime.GOOS)) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the core did not answer the service", func(t *testing.T) {
		core, paths, _ := passCore(t)
		serveFor(t, paths)
		core.Stop()
		_, err := FetchCoreStatus(t.Context(), paths, "")
		if !errors.Is(err, ErrCoreUnreachable) || errors.Is(err, ErrClientServiceDown) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a listen address that is not loopback is never dialled", func(t *testing.T) {
		_, paths, _ := passCore(t)
		setListen(t, paths, "192.0.2.1:28195")
		_, err := FetchCoreStatus(t.Context(), paths, "")
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("err = %v", err)
		}
	})
	for goos, want := range map[string]string{
		"darwin": "launchctl kickstart -k gui/$(id -u)/" + LaunchdLabel,
		"linux":  "systemctl --user restart " + SystemdUnit,
	} {
		if got := RestartCommand(goos); got != want {
			t.Errorf("RestartCommand(%s) = %q, want %q", goos, got, want)
		}
	}
}

// CLI-017 (PROPOSED) — the CLI's own calls (status, CA custody, the trust
// backup, the operator author) all arrive at the core through the service.
func TestCLI017EveryCLICallGoesThroughTheService(t *testing.T) {
	core, paths, log := passCore(t)
	cc, id, _ := sealedCustody(t)
	cc.mount(t, core)
	serveFor(t, paths)

	if _, err := FetchCoreStatus(t.Context(), paths, ""); err != nil {
		t.Fatalf("FetchCoreStatus: %v", err)
	}
	if unlocked, err := UnlockCA(t.Context(), paths, identitiesOf(id)); err != nil || !unlocked {
		t.Fatalf("UnlockCA = %v, %v", unlocked, err)
	}
	if st, err := CAStatus(t.Context(), paths); err != nil || st.Sealed {
		t.Fatalf("CAStatus = %+v, %v", st, err)
	}
	if _, err := ReportOperatorAuthor(t.Context(), paths, "octo", "1+octo@users.noreply.github.com"); err != nil {
		t.Fatalf("ReportOperatorAuthor: %v", err)
	}
	seen := strings.Join(log.all(), "\n")
	for _, want := range []string{"GET " + CoreStatusPath, "POST " + OperatorAuthorPath} {
		if !strings.Contains(seen, want) {
			t.Errorf("the core did not see %q; it saw:\n%s", want, seen)
		}
	}
}

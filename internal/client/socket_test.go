// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CLI-043..CLI-044 (PROPOSED for doc 07, #600) — the CLI's calls to the core
// go over a unix socket in the client folder, which only the service's own
// user may use; the loopback TCP address no longer passes them.
// ---------------------------------------------------------------------------

// shortTempDir is a fresh folder short enough to hold a unix socket: a
// socket's path is limited to about a hundred bytes, and t.TempDir() on
// macOS is longer than that once a test's name is in it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "isg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveSocket serves srv's CLI routes on path, admitting uid, until the test
// ends.
func serveSocket(t *testing.T, srv *Server, path string, uid int) {
	t.Helper()
	ln, err := listenSocket(t.Context(), path, uid, srv.log.Printf)
	if err != nil {
		t.Fatalf("listenSocket: %v", err)
	}
	hs := &http.Server{Handler: srv.SocketHandler(), ReadHeaderTimeout: 10 * time.Second}
	served := make(chan error, 1) // Serve ends with ErrServerClosed at cleanup
	go func() { served <- hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
}

// CLI-043 (PROPOSED) — the socket admits only the service's own user. The
// kernel names the caller (LOCAL_PEERCRED on macOS, SO_PEERCRED on Linux);
// a caller of any other uid is closed before a byte of HTTP is read, and
// nothing reaches the core.
func TestCLI043TheSocketRefusesAnotherUser(t *testing.T) {
	_, paths, log := passCore(t)
	srv, _, logs := startClient(t, paths)
	// The test cannot run as another user; the service is told to expect
	// one, so the caller (this process) is the other user.
	serveSocket(t, srv, SocketPath(paths), os.Getuid()+1)

	_, err := FetchCoreStatus(t.Context(), paths, "")
	if !errors.Is(err, ErrClientServiceDown) {
		t.Fatalf("FetchCoreStatus from another uid: %v; want the connection refused", err)
	}
	if seen := log.all(); len(seen) != 0 {
		t.Fatalf("another user's call reached the core: %v", seen)
	}
	if !strings.Contains(logs.String(), "refused a connection") {
		t.Errorf("the service's log does not say it refused the caller:\n%s", logs.String())
	}
}

// CLI-043 (PROPOSED) — the same call from the service's own user passes, the
// socket is 0600 in a 0700 folder, and the uid the kernel reports is this
// process's.
func TestCLI043TheSocketAdmitsTheServicesUser(t *testing.T) {
	_, paths, log := passCore(t)
	srv, _, _ := startClient(t, paths)
	serveSocket(t, srv, SocketPath(paths), os.Getuid())

	if _, err := FetchCoreStatus(t.Context(), paths, ""); err != nil {
		t.Fatalf("FetchCoreStatus: %v", err)
	}
	if n := len(log.all()); n != 1 {
		t.Fatalf("the core was asked %d times: %v", n, log.all())
	}
	fi, err := os.Lstat(SocketPath(paths))
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket %s: %v, %v; want a 0600 socket", SocketPath(paths), fi.Mode(), err)
	}
	di, err := os.Stat(filepath.Dir(SocketPath(paths)))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("socket folder: %v, %v; want 0700", di.Mode(), err)
	}

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", SocketPath(paths))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(shortTempDir(t), "p.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, derr := (&net.Dialer{}).DialContext(t.Context(), "unix", ln.Addr().String())
		if derr == nil {
			defer c.Close()
			if _, cerr := io.Copy(io.Discard, c); cerr != nil {
				return
			}
		}
	}()
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	uid, err := peerUID(accepted)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("peerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}

// CLI-043 (PROPOSED) — the service never removes a file at the socket's path
// that is not a socket, and refuses a path too long to bind.
func TestCLI043TheSocketPathIsChecked(t *testing.T) {
	dir := shortTempDir(t)
	file := filepath.Join(dir, "client.sock")
	if err := os.WriteFile(file, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenSocket(t.Context(), file, nil); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("ListenSocket over a regular file: %v", err)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "mine" {
		t.Fatalf("the file was changed: %q, %v", b, err)
	}
	long := filepath.Join(dir, strings.Repeat("x", 120), "client.sock")
	if _, err := ListenSocket(t.Context(), long, nil); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("ListenSocket at a %d-byte path: %v", len(long), err)
	}
}

// CLI-044 (PROPOSED) — the loopback TCP address no longer passes the CLI's
// calls to the core: the harness's address refuses them without asking the
// core, while the model route and the status it serves are unchanged.
func TestCLI044TheTCPPassThroughIsGone(t *testing.T) {
	_, paths, log := passCore(t)
	_, front, _ := startClient(t, paths)
	id := installationOf(t, paths)

	for _, route := range CorePassRoutes {
		req, err := http.NewRequestWithContext(t.Context(), route.Method, front.URL+CorePassPrefix+route.Path, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(CorePassInstallationHeader, id)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, rerr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if rerr != nil {
			t.Fatal(rerr)
		}
		if resp.StatusCode != http.StatusGone || !strings.Contains(string(body), SocketName) {
			t.Errorf("%s %s over TCP: %d %s; want 410 naming the socket", route.Method, route.Path, resp.StatusCode, body)
		}
	}
	if seen := log.all(); len(seen) != 0 {
		t.Fatalf("the TCP address passed calls to the core: %v", seen)
	}
	resp, err := http.Get(front.URL + StatusPath) //nolint:noctx // a test's one request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the status over TCP: %d; the hooks read it there", resp.StatusCode)
	}
}

// CLI-044 (PROPOSED) — the socket serves the CLI and nothing else: a model
// request or any other harness route sent to it is refused there.
func TestCLI044TheSocketServesOnlyTheCLI(t *testing.T) {
	_, paths, log := passCore(t)
	srv, _, _ := startClient(t, paths)
	serveSocket(t, srv, SocketPath(paths), os.Getuid())
	c := &http.Client{Transport: SocketTransport(SocketPath(paths))}

	for _, p := range []string{"/v1/messages", SessionStatementPath, "/"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, SocketBase+p, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s on the socket: %d; want 404", p, resp.StatusCode)
		}
	}
	resp, err := c.Get(SocketBase + StatusPath) //nolint:noctx // a test's one request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the status on the socket: %d", resp.StatusCode)
	}
	// The status asks the core GET / to say whether it answers; nothing
	// else may have reached it.
	for _, seen := range log.all() {
		if seen != "GET /" {
			t.Fatalf("the socket passed harness routes to the core: %v", log.all())
		}
	}
}

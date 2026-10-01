// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client/clienttest"
)

// enrolled starts a fake core and enrols a client into a scratch home, the
// way `innsegl connect` does, returning the core and the client's paths.
func enrolled(t *testing.T) (*clienttest.Core, Paths) {
	t.Helper()
	core, err := clienttest.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Close)
	paths := ClientPaths(t.TempDir())
	e, err := Enrol(context.Background(), EnrolOptions{
		CoreURL: core.URL(), Token: clienttest.Token, Name: "dev-laptop", CA: core.CA,
	})
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	if err := WriteEnrolment(paths, e, "127.0.0.1:28195"); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	return core, paths
}

func startClient(t *testing.T, paths Paths) (*Server, *httptest.Server, *syncWriter) {
	t.Helper()
	logs := &syncWriter{}
	srv, err := NewServer(paths, logs)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	front := httptest.NewServer(srv.Handler())
	t.Cleanup(front.Close)
	return srv, front, logs
}

func TestCLI016ForwardsWithTheClientCertificateAndKeepsHeaders(t *testing.T) {
	core, paths := enrolled(t)
	type seen struct {
		Auth, Version, Body, Host string
	}
	got := make(chan seen, 1)
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got <- seen{r.Header.Get("Authorization"), r.Header.Get("Anthropic-Version"), string(b), r.Host}
		w.Header().Set("X-Core", "yes")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"ok":true}`)
	})
	_, front, _ := startClient(t, paths)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, front.URL+"/v1/messages?beta=true", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer provider-secret")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp.Body)
	if resp.StatusCode != http.StatusCreated || string(body) != `{"ok":true}` || resp.Header.Get("X-Core") != "yes" {
		t.Fatalf("response = %d %q %v", resp.StatusCode, body, resp.Header)
	}
	s := <-got
	if s.Auth != "Bearer provider-secret" || s.Version != "2023-06-01" || s.Body != `{"model":"m"}` {
		t.Fatalf("the core saw %+v", s)
	}
	if s.Host != core.HostPort() {
		t.Errorf("Host = %q, want the core's own %q", s.Host, core.HostPort())
	}
	serials := core.SeenSerials()
	if len(serials) != 1 || serials[0] == nil {
		t.Fatalf("the core saw no client certificate: %v", serials)
	}
}

func TestCLI016StreamsSSEIncrementally(t *testing.T) {
	core, paths := enrolled(t)
	release := make(chan struct{})
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: one\ndata: {}\n\n")
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		<-release
		fmt.Fprint(w, "event: two\ndata: {}\n\n")
	})
	_, front, _ := startClient(t, paths)
	defer close(release)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, front.URL+"/v1/messages", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	stream := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		line, rerr := stream.ReadString('\n')
		if rerr != nil {
			line = "read error: " + rerr.Error()
		}
		first <- line
	}()
	select {
	case line := <-first:
		if line != "event: one\n" {
			t.Fatalf("first line = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first event did not arrive before the stream ended: the proxy buffers")
	}
}

func TestCLI016RenewsAtHalfLife(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "pong") })
	srv, front, _ := startClient(t, paths)
	leaf := srv.Leaf()
	before := readFile(t, paths.Cert)

	srv.Now = func() time.Time { return leaf.NotBefore.Add(11 * time.Hour) }
	renewed, err := srv.MaybeRenew(context.Background())
	if err != nil || renewed {
		t.Fatalf("before half-life: renewed=%v err=%v", renewed, err)
	}
	if _, n := core.Counts(); n != 0 {
		t.Fatalf("renew called %d times before half-life", n)
	}
	if want := leaf.NotBefore.Add(12 * time.Hour); !srv.RenewAt().Equal(want) {
		t.Fatalf("RenewAt = %v, want %v", srv.RenewAt(), want)
	}

	srv.Now = func() time.Time { return leaf.NotBefore.Add(13 * time.Hour) }
	renewed, err = srv.MaybeRenew(context.Background())
	if err != nil || !renewed {
		t.Fatalf("after half-life: renewed=%v err=%v", renewed, err)
	}
	if srv.Leaf().SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		t.Fatal("the certificate was not replaced")
	}
	newPub, ok := srv.Leaf().PublicKey.(*ecdsa.PublicKey)
	if !ok || !newPub.Equal(leaf.PublicKey) {
		t.Fatal("renewal changed the key; it must keep the same one")
	}
	after := readFile(t, paths.Cert)
	if bytes.Equal(before, after) {
		t.Fatal("cert.pem was not rewritten")
	}

	// The next forwarded request presents the new certificate.
	resp, err := http.Get(front.URL + "/ping") //nolint:noctx // a one-shot test request
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	serials := core.SeenSerials()
	if len(serials) == 0 || serials[len(serials)-1].Cmp(srv.Leaf().SerialNumber) != 0 {
		t.Fatalf("the core saw %v, want the renewed serial %v", serials, srv.Leaf().SerialNumber)
	}

	// A restarted service loads the renewed certificate from disk.
	again, err := NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if again.Leaf().SerialNumber.Cmp(srv.Leaf().SerialNumber) != 0 {
		t.Fatal("a restart did not load the renewed certificate")
	}
}

func TestCLI016StopsForwardingAfterARenew401(t *testing.T) {
	core, paths := enrolled(t)
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	srv, front, logs := startClient(t, paths)
	leaf := srv.Leaf()
	core.SetRevoked(true)

	srv.Now = func() time.Time { return leaf.NotBefore.Add(13 * time.Hour) }
	_, err := srv.MaybeRenew(context.Background())
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("err = %v, want ErrRevoked", err)
	}
	if !strings.Contains(logs.String(), "revoked") {
		t.Errorf("the log does not say the installation was revoked: %q", logs.String())
	}
	before := len(core.SeenSerials())
	resp, err := http.Post(front.URL+"/v1/messages", "application/json", strings.NewReader("{}")) //nolint:noctx // a one-shot test request
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "revoked") {
		t.Fatalf("after revocation: %d %q", resp.StatusCode, body)
	}
	if len(core.SeenSerials()) != before {
		t.Fatal("a request reached the core after the renew 401")
	}
	// It keeps refusing, and does not ask again.
	if _, err = srv.MaybeRenew(context.Background()); !errors.Is(err, ErrRevoked) {
		t.Fatalf("second MaybeRenew: %v", err)
	}
	if _, n := core.Counts(); n != 1 {
		t.Fatalf("renew was asked %d times after a 401, want 1", n)
	}
	// And a restart keeps refusing too.
	again, err := NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	again.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/messages", strings.NewReader("{}")))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a restarted service forwarded after revocation: %d", rec.Code)
	}
}

func TestCLI016StatusReportsInstallationExpiryAndReachability(t *testing.T) {
	core, paths := enrolled(t)
	srv, front, _ := startClient(t, paths)
	resp, err := http.Get(front.URL + "/_client/status") //nolint:noctx // a one-shot test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st Status
	if err = json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.InstallationID != clienttest.InstallationID || !st.CoreReachable || st.Revoked {
		t.Fatalf("status = %+v", st)
	}
	if !st.CertificateExpiresAt.Equal(srv.Leaf().NotAfter) {
		t.Fatalf("expiry = %v, want %v", st.CertificateExpiresAt, srv.Leaf().NotAfter)
	}
	if len(core.SeenSerials()) != 0 {
		// Reachability is asked without reaching a guarded route's handler.
		t.Logf("status probe reached the core's routes %d times", len(core.SeenSerials()))
	}
	core.Close()
	resp2, err := http.Get(front.URL + "/_client/status") //nolint:noctx // a one-shot test request
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var st2 Status
	if err := json.NewDecoder(resp2.Body).Decode(&st2); err != nil {
		t.Fatal(err)
	}
	if st2.CoreReachable {
		t.Fatal("a closed core is reported reachable")
	}
}

func TestCLI016RefusesANonLoopbackListener(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:28195", "192.168.1.5:28195", ":28195", "example.com:28195"} {
		if err := CheckLoopback(addr); err == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:28195", "[::1]:28195", "localhost:28195"} {
		if err := CheckLoopback(addr); err != nil {
			t.Errorf("%s refused: %v", addr, err)
		}
	}
}

type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

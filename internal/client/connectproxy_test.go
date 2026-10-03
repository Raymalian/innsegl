// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// RM-329 (#500): Claude Code reaches the provider through HTTPS_PROXY, the
// client service. The client opens only the provider's API: a model
// request goes into the recorded path to the core, every other request to
// the provider passes straight through, and every other host is tunnelled
// unopened. Claude Code keeps its own base URL, so it turns nothing off.

// viaProxy is an HTTP client that sends everything through the client
// service as its proxy and trusts the client's proxy CA, the way Claude
// Code does with HTTPS_PROXY and NODE_EXTRA_CA_CERTS.
func viaProxy(t *testing.T, front *httptest.Server, paths Paths, extraRoots ...*x509.Certificate) *http.Client {
	t.Helper()
	pemCA, err := os.ReadFile(paths.ProxyCA)
	if err != nil {
		t.Fatalf("the client service wrote no proxy CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCA) {
		t.Fatal("the proxy CA is not PEM")
	}
	for _, c := range extraRoots {
		roots.AddCert(c)
	}
	proxyURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
}

func TestRM329AModelRequestThroughTheProxyIsRecordedByTheCore(t *testing.T) {
	core, paths := enrolled(t)
	got := make(chan string, 1)
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Claude-Code-Session-Id")
		w.Header().Set("X-Innsegl-Recorded", "true")
		fmt.Fprint(w, `{"ok":true}`)
	})
	_, front, _ := startClient(t, paths)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://"+ProviderAPIHost+"/v1/messages", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Claude-Code-Session-Id", "11111111-1111-4111-8111-111111111111")
	resp, err := viaProxy(t, front, paths).Do(req)
	if err != nil {
		t.Fatalf("a model request through the proxy failed: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("status %d body %q, want the core's answer", resp.StatusCode, body)
	}
	if s := <-got; s != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("the core saw session %q", s)
	}
}

func TestRM329OtherProviderRequestsPassStraightThrough(t *testing.T) {
	_, paths := enrolled(t)
	seen := make(chan string, 1)
	prov := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path
		fmt.Fprint(w, "provider")
	}))
	t.Cleanup(prov.Close)
	srv, err := NewServerWith(paths, &syncWriter{}, ServerOptions{ProviderURL: prov.URL, ProviderClient: prov.Client()})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(srv.Handler())
	t.Cleanup(front.Close)
	resp, err := viaProxy(t, front, paths).Do(getReq(t, "https://"+ProviderAPIHost+"/v1/code/sessions/cse_1/worker"))
	if err != nil {
		t.Fatalf("a Remote Control request through the proxy failed: %v", err)
	}
	body := readBody(t, resp)
	if string(body) != "provider" {
		t.Fatalf("body %q, want the provider's", body)
	}
	if s := <-seen; s != "GET /v1/code/sessions/cse_1/worker" {
		t.Errorf("the provider saw %q", s)
	}
}

func TestRM329OtherHostsAreTunnelledUnopened(t *testing.T) {
	_, paths := enrolled(t)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "other host")
	}))
	t.Cleanup(other.Close)
	_, front, _ := startClient(t, paths)
	// Trusting only the other host's own certificate proves the client did
	// not open the connection: its proxy CA could not have answered for it.
	resp, err := viaProxy(t, front, paths, other.Certificate()).Do(getReq(t, other.URL+"/x"))
	if err != nil {
		t.Fatalf("a tunnelled request failed: %v", err)
	}
	body := readBody(t, resp)
	if string(body) != "other host" {
		t.Fatalf("body %q", body)
	}
}

// A tunnel that cannot be opened is a 502, never a 403: Remote Control
// gives up on a session that its proxy refuses.
func TestRM329AnUnreachableTunnelIsABadGateway(t *testing.T) {
	_, paths := enrolled(t)
	_, front, _ := startClient(t, paths)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", closed, closed)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", resp.StatusCode)
	}
}

// A plain-HTTP request in proxy form (HTTP_PROXY) is forwarded as asked,
// never to the core.
func TestRM329APlainProxyRequestIsForwarded(t *testing.T) {
	_, paths := enrolled(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "plain "+r.URL.Path)
	}))
	t.Cleanup(plain.Close)
	_, front, _ := startClient(t, paths)
	resp, err := viaProxy(t, front, paths).Do(getReq(t, plain.URL+"/y"))
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if string(body) != "plain /y" {
		t.Fatalf("body %q", body)
	}
}

// The client's own outbound connections never go through a proxy: started
// from a shell that has HTTPS_PROXY pointing at itself, it would loop.
func TestRM329TheClientNeverProxiesItself(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	if providerTransport().Proxy != nil {
		t.Fatal("the provider transport reads the proxy environment")
	}
}

func getReq(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RM-329: whether the core recorded what went through is visible on the
// machine: GET /_client/status counts the core's answers by what it said.
func TestRM329TheStatusCountsWhatTheCoreRecorded(t *testing.T) {
	core, paths := enrolled(t)
	answers := []string{"true", "none", "true"}
	n := 0
	core.Mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Innsegl-Recorded", answers[n])
		n++
		fmt.Fprint(w, `{}`)
	})
	srv, front, _ := startClient(t, paths)
	for range answers {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			"https://"+ProviderAPIHost+"/v1/messages", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := viaProxy(t, front, paths).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readBody(t, resp)
	}
	got := srv.Status(context.Background()).Recorded
	if got["true"] != 2 || got["none"] != 1 {
		t.Fatalf("recorded counts %v, want true=2 none=1", got)
	}
}

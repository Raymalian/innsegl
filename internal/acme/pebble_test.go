// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/dockertest"
)

// A local ACME server and a fake DNS for every test here: Pebble, the ACME
// test server, and its challenge test server, which answers DNS for any
// name and takes TXT records over a management API. No test ever reaches a
// real certificate authority.

const (
	pebbleImage     = "ghcr.io/letsencrypt/pebble:2.8.0"
	challtestImage  = "ghcr.io/letsencrypt/pebble-challtestsrv:2.8.0"
	pebbleTestRoot  = "/test/certs/pebble.minica.pem"
	pebbleContainer = "/app"
)

// pebble is a running local ACME server.
type pebble struct {
	directory  string // ACME directory URL, reachable from this process
	management string // Pebble's management URL (issued roots)
	dnsAPI     string // challenge test server's management URL
	client     *http.Client
}

// cleanup removes what a test started, and says when it could not.
func cleanup(t *testing.T, args ...string) {
	if _, err := dockertest.Docker(context.Background(), args...); err != nil {
		t.Logf("cleanup: %v", err)
	}
}

func dock(t *testing.T, args ...string) string {
	t.Helper()
	out, err := dockertest.Docker(context.Background(), args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// startPebble runs both containers on a network of their own, on an explicit
// subnet (the default address pools may be full), and answers how to reach
// them from the test process.
func startPebble(t *testing.T) *pebble {
	t.Helper()
	ctx := context.Background()
	if err := dockertest.Usable(ctx); err != nil {
		t.Skipf("docker: %v", err)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(200))
	if err != nil {
		t.Fatal(err)
	}
	tag := fmt.Sprintf("innsegl-acmetest-%d-%d", os.Getpid(), n.Int64())
	subnet := fmt.Sprintf("10.231.%d.0/24", 20+n.Int64())
	dock(t, "network", "create", "--subnet", subnet, tag)
	t.Cleanup(func() { cleanup(t, "network", "rm", tag) })

	dns := tag + "-dns"
	dock(t, "run", "-d", "--rm", "--name", dns, "--network", tag, "--network-alias", "challtestsrv",
		"-p", "127.0.0.1::8055", challtestImage,
		"-dns01", ":8053", "-management", ":8055", "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	t.Cleanup(func() { cleanup(t, "rm", "-f", dns) })

	ca := tag + "-ca"
	dock(t, "run", "-d", "--rm", "--name", ca, "--network", tag,
		"-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0",
		"-p", "127.0.0.1::14000", "-p", "127.0.0.1::15000", pebbleImage,
		"-config", "test/config/pebble-config.json", "-dnsserver", "challtestsrv:8053")
	t.Cleanup(func() { cleanup(t, "rm", "-f", ca) })

	port := func(name, p string) string {
		out := dock(t, "port", name, p)
		_, hp, _ := strings.Cut(strings.Split(out, "\n")[0], ":")
		return hp
	}
	root := filepath.Join(t.TempDir(), "pebble-root.pem")
	dock(t, "cp", ca+":"+pebbleTestRoot, root)
	pemRoot, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemRoot)
	p := &pebble{
		directory:  "https://localhost:" + port(ca, "14000") + "/dir",
		management: "https://localhost:" + port(ca, "15000"),
		dnsAPI:     "http://127.0.0.1:" + port(dns, "8055"),
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, gerr := p.client.Get(p.directory) //nolint:noctx // a readiness probe
		if gerr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("pebble did not answer at %s: %v", p.directory, gerr)
		}
		time.Sleep(300 * time.Millisecond)
	}
	return p
}

// issuedRoots is the pool of roots Pebble signs issued certificates under.
func (p *pebble) issuedRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	resp, err := p.client.Get(p.management + "/roots/0") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(body) {
		t.Fatalf("pebble's issuing root is not PEM: %s", body)
	}
	return pool
}

// fakeDNS is a DNS-01 provider that writes the TXT record into the challenge
// test server, which Pebble asks.
type fakeDNS struct {
	api    string
	client *http.Client
	posts  int
}

func (f *fakeDNS) post(path string, body map[string]string) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := f.client.Post(f.api+path, "application/json", bytes.NewReader(raw)) //nolint:noctx // test
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d", path, resp.StatusCode)
	}
	return nil
}

func (f *fakeDNS) Present(domain, _, keyAuth string) error {
	f.posts++
	fqdn, value := txtRecord(domain, keyAuth)
	return f.post("/set-txt", map[string]string{"host": fqdn, "value": value})
}

func (f *fakeDNS) CleanUp(domain, _, keyAuth string) error {
	fqdn, _ := txtRecord(domain, keyAuth)
	return f.post("/clear-txt", map[string]string{"host": fqdn})
}

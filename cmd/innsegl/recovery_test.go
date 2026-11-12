// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/spire"
)

// RCV-001..004: the public recovery path must authenticate independent device
// proof, not rely on traffic-certificate age or a restarted process's memory.
func TestRCV002RecoveryIssuesForTheSameInstallationWithoutATrafficCertificate(t *testing.T) {
	f := newEnFixture(t)
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := mustRecoveryJSON(t, map[string]string{"token": f.token(t), "csr": c.ownCSR(t), "name": "device", "recovery_key": base64.StdEncoding.EncodeToString(pub)})
	status, raw := g.post(t, g.client(t, nil), coreEnrolPath, string(body), nil)
	if status != 200 {
		t.Fatalf("enroll: %d %s", status, raw)
	}
	csr := c.ownCSR(t)
	body = mustRecoveryJSON(t, map[string]string{"installation_id": c.id, "csr": csr})
	status, raw = g.post(t, g.client(t, nil), "/_core/recovery/challenge", string(body), nil)
	if status != 200 {
		t.Fatalf("recovery challenge after reconnect: %d %s; want 200 without a traffic certificate", status, raw)
	}
	var challenge struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(raw), &challenge); err != nil || challenge.Challenge == "" {
		t.Fatalf("challenge: %s %v", raw, err)
	}
	// Literal wire fields, independent of the production proof encoder.
	proof := mustRecoveryJSON(t, struct {
		Version      string `json:"version"`
		Origin       string `json:"origin"`
		Installation string `json:"installation_id"`
		Operation    string `json:"operation"`
		Challenge    string `json:"challenge"`
		CSR          string `json:"csr"`
	}{"innsegl recovery v1", "https://" + g.addr, c.id, "recover", challenge.Challenge, csr})
	body = mustRecoveryJSON(t, map[string]string{"installation_id": c.id, "csr": csr, "challenge": challenge.Challenge, "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, proof))})
	status, raw = g.post(t, g.client(t, nil), "/_core/recovery/issue", string(body), nil)
	if status != http.StatusOK {
		t.Fatalf("recover: %d %s", status, raw)
	}
	if got := parseIssued(t, raw); got.InstallationID != c.id {
		t.Fatal("recovery changed installation")
	}
	status, raw = g.post(t, g.client(t, nil), "/_core/recovery/issue", string(body), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("replayed proof: %d %s", status, raw)
	}
	if n := f.count(t, `SELECT count(*) FROM innsegl_auth.installations`); n != 1 {
		t.Fatalf("recovery created %d installations", n)
	}
}

// RCV-002: reproduce the incident through the actual client, gateway and store.
func TestRCV002ClientRecoversAfterLongOfflineAndRestartWithRefusalMarker(t *testing.T) {
	checkOfflineRecovery(t, nil, false)
}

// Exercise the same client/core/database path with certificates minted by the
// real SPIRE authority. The shared harness also supplies real Fulcio and Rekor.
func checkOfflineRecoveryWithRealSPIRE(t *testing.T, stack *signE2EStack) {
	t.Helper()
	ctx := t.Context()
	source, closeSource, err := openInitCredentialSource(ctx, smokeTestRequest{SVIDFile: stack.svidPath, KeyFile: stack.keyPath, BundleFile: stack.bundlePath, TrustDomain: signE2ETrustDomain})
	if err != nil {
		t.Fatal(err)
	}
	defer closeSource()
	authority, err := spire.Dial(ctx, spire.Config{Address: stack.adminAddr, TrustDomain: signE2ETrustDomain, ServerID: signE2EServerID, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := authority.Close(); err != nil {
			t.Error(err)
		}
	}()
	checkOfflineRecovery(t, authority, true)
}

// RCV-002/005: an incoming harness request recovers before it is forwarded.
func TestRCV002ClientRequestRecoversAfterLongOffline(t *testing.T) {
	checkOfflineRecovery(t, nil, true)
}

func checkOfflineRecovery(t *testing.T, authority clientAuthority, requestRecovery bool) {
	t.Helper()
	f := newEnFixture(t)
	if authority != nil {
		t.Cleanup(publishClientAuthority(authority))
	}
	g := startHostedGateway(t, f)
	caBytes, err := os.ReadFile(filepath.Join(g.certDir, gateway.CACertFileName))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caBytes)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	e, err := client.Enrol(t.Context(), client.EnrolOptions{CoreURL: "https://" + g.addr, Token: f.token(t), Name: "device", CA: ca})
	if err != nil {
		t.Fatal(err)
	}
	paths := client.ClientPaths(t.TempDir())
	if writeErr := client.WriteEnrolment(paths, e, "127.0.0.1:1"); writeErr != nil {
		t.Fatal(writeErr)
	}
	// Simulate the certificate left on disk after an outage longer than grace.
	old := &x509.Certificate{SerialNumber: big.NewInt(100), NotBefore: time.Now().Add(-96 * time.Hour), NotAfter: time.Now().Add(-72 * time.Hour), URIs: e.Chain[0].URIs, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, old, f.authority.cert, e.Key.Public(), f.authority.key)
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(paths.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := os.WriteFile(paths.Refused, []byte("old unknown refusal"), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if mkdirErr := os.MkdirAll(paths.Outbox, 0700); mkdirErr != nil {
		t.Fatal(mkdirErr)
	}
	sentinel := filepath.Join(paths.Outbox, "keep-pending")
	if writeErr := os.WriteFile(sentinel, []byte("pending"), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	srv, err := client.NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if requestRecovery {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_client/capabilities", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("request did not recover after restart: %d %s", w.Code, w.Body)
		}
	} else {
		ok, renewErr := srv.MaybeRenew(t.Context())
		if renewErr != nil || !ok {
			t.Fatalf("reconnect did not recover after restart: %v %v", ok, renewErr)
		}
	}
	if !srv.Leaf().NotAfter.After(time.Now()) {
		t.Fatal("no valid certificate")
	}
	if _, statErr := os.Stat(paths.Refused); !os.IsNotExist(statErr) {
		t.Fatalf("refusal survived successful recovery: %v", statErr)
	}
	if raw, readErr := os.ReadFile(sentinel); readErr != nil || string(raw) != "pending" {
		t.Fatalf("pending data lost: %s %v", raw, readErr)
	}
	cfg, err := client.ReadCoreConfig(paths)
	if err != nil || cfg.InstallationID != e.InstallationID {
		t.Fatal("installation changed")
	}
	// A second restart must load the certificate that actually reached disk.
	again, err := client.NewServer(paths, io.Discard)
	if err != nil || !again.Leaf().NotAfter.After(time.Now()) {
		t.Fatalf("restart: %v", err)
	}
}

func mustRecoveryJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

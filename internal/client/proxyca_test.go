// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RM-329 (#500): the client opens the provider's traffic with a CA of its
// own. The CA can vouch for the provider's API name and nothing else: a
// leaf it signs for any other name fails verification, so a process that
// trusts it (NODE_EXTRA_CA_CERTS) can be fooled about no other site.
func TestRM329TheProxyCAVouchesOnlyForTheProviderAPI(t *testing.T) {
	dir := t.TempDir()
	ca, err := loadOrCreateProxyCA(filepath.Join(dir, "proxy-ca.pem"), filepath.Join(dir, "proxy-ca-key.pem"))
	if err != nil {
		t.Fatalf("loadOrCreateProxyCA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	now := time.Now()

	leaf, err := ca.leaf(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: ProviderAPIHost, CurrentTime: now}); err != nil {
		t.Fatalf("the provider's leaf does not verify: %v", err)
	}

	forged, err := ca.issue("claude.ai", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = forged.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "claude.ai", CurrentTime: now}); err == nil {
		t.Fatal("a leaf for claude.ai verified under the proxy CA; it must be name-constrained")
	}
}

// The CA survives a restart (Claude Code reads NODE_EXTRA_CA_CERTS once,
// at start), its key is 0600, and a fresh leaf is reused until it is due.
func TestRM329TheProxyCAIsKeptAndItsLeafReused(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "proxy-ca.pem"), filepath.Join(dir, "proxy-ca-key.pem")
	first, err := loadOrCreateProxyCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateProxyCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !first.cert.Equal(second.cert) {
		t.Fatal("a second start made a new CA; running sessions would stop trusting the client")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the CA key is %o, want 0600", info.Mode().Perm())
	}
	now := time.Now()
	a, err := second.leaf(now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.leaf(now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("a fresh leaf was not reused")
	}
	c, err := second.leaf(now.Add(proxyLeafValidity))
	if err != nil {
		t.Fatal(err)
	}
	if c == a {
		t.Error("an expired leaf was reused")
	}
}

func TestRM329AProxyCAKeyThatIsNotTheCertificatesIsRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateProxyCA(filepath.Join(dir, "a.pem"), filepath.Join(dir, "a-key.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateProxyCA(filepath.Join(dir, "b.pem"), filepath.Join(dir, "b-key.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateProxyCA(filepath.Join(dir, "a.pem"), filepath.Join(dir, "b-key.pem")); err == nil {
		t.Fatal("a CA certificate was loaded with another CA's key")
	}
}

// connect makes sure the CA exists before it writes the settings that name
// it: Claude Code reads NODE_EXTRA_CA_CERTS once, at start, and without the
// file it cannot reach the provider through the client.
func TestRM329EnsureProxyCAWritesTheCAOnceAndForTheUser(t *testing.T) {
	paths := ClientPaths(t.TempDir())
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureProxyCA(paths, os.Getuid(), false); err != nil {
		t.Fatalf("EnsureProxyCA: %v", err)
	}
	first, err := os.ReadFile(paths.ProxyCA)
	if err != nil {
		t.Fatal(err)
	}
	if err = EnsureProxyCA(paths, os.Getuid(), true); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(paths.ProxyCA)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("a second call replaced the CA")
	}
}

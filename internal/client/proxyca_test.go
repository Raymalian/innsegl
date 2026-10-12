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
	ca, err := loadOrCreateProxyCA(filepath.Join(dir, "proxy-ca.pem"), filepath.Join(dir, "proxy-ca-key.pem"), time.Now())
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
	first, err := loadOrCreateProxyCA(certPath, keyPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateProxyCA(certPath, keyPath, time.Now())
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
	if _, err := loadOrCreateProxyCA(filepath.Join(dir, "a.pem"), filepath.Join(dir, "a-key.pem"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateProxyCA(filepath.Join(dir, "b.pem"), filepath.Join(dir, "b-key.pem"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateProxyCA(filepath.Join(dir, "a.pem"), filepath.Join(dir, "b-key.pem"), time.Now()); err == nil {
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
	if _, err := EnsureProxyCA(paths, os.Getuid(), false); err != nil {
		t.Fatalf("EnsureProxyCA: %v", err)
	}
	first, err := os.ReadFile(paths.ProxyCA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = EnsureProxyCA(paths, os.Getuid(), true); err != nil {
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

// validity is how long c is valid for, from its NotBefore.
func validity(c *x509.Certificate) time.Duration { return c.NotAfter.Sub(c.NotBefore) }

// CLI-058 (PROPOSED for doc 07's TC-CLI) — the proxy CA lives one year, not
// ten (privilege review N8). `connect --update` replaces a CA that is
// older-style (more than a year of life) or has less than proxyCARotateBefore
// left, and keeps any other; the running service mints from the replacement
// without a restart; the service itself replaces only a CA already expired;
// and no leaf outlives its CA.
func TestCLI058TheProxyCALivesAYearAndIsReplacedAtUpdate(t *testing.T) {
	paths := ClientPaths(t.TempDir())
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	read := func() *x509.Certificate {
		t.Helper()
		c, err := loadCerts(paths.ProxyCA)
		if err != nil {
			t.Fatal(err)
		}
		return c[0]
	}

	// A new CA lives a year.
	if rotated, err := ensureProxyCAAt(paths, os.Getuid(), false, now); err != nil || rotated {
		t.Fatalf("first EnsureProxyCA: rotated=%v err=%v", rotated, err)
	}
	fresh := read()
	if v := validity(fresh); v > 365*24*time.Hour+proxyClockSkew || v < 364*24*time.Hour {
		t.Fatalf("a new proxy CA is valid for %v, want one year", v)
	}
	// One with most of its year left is kept.
	if rotated, err := ensureProxyCAAt(paths, os.Getuid(), false, now.Add(200*24*time.Hour)); err != nil || rotated {
		t.Fatalf("a CA with 165 days left: rotated=%v err=%v; it must be kept", rotated, err)
	}
	if !read().Equal(fresh) {
		t.Fatal("a CA with most of its life left was replaced")
	}

	// A running service holds the CA.
	running, err := loadOrCreateProxyCA(paths.ProxyCA, paths.ProxyCAKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = running.leaf(now); err != nil {
		t.Fatal(err)
	}

	// Less than proxyCARotateBefore left: --update replaces it.
	late := fresh.NotAfter.Add(-proxyCARotateBefore + time.Hour)
	rotated, err := ensureProxyCAAt(paths, os.Getuid(), false, late)
	if err != nil || !rotated {
		t.Fatalf("a CA with less than %v left: rotated=%v err=%v", proxyCARotateBefore, rotated, err)
	}
	next := read()
	if next.Equal(fresh) {
		t.Fatal("the CA on disk is unchanged")
	}
	// The running service mints from the replacement without a restart.
	leaf, err := running.leaf(late)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(next)
	if _, err = leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: ProviderAPIHost, CurrentTime: late}); err != nil {
		t.Fatalf("the running service's leaf does not verify under the replaced CA: %v", err)
	}
	if leaf.Leaf.NotAfter.After(next.NotAfter) {
		t.Fatal("a leaf outlives its CA")
	}

	// A ten-year CA from before N8 is replaced at the next --update.
	legacy := ClientPaths(t.TempDir())
	if err = os.MkdirAll(legacy.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = createProxyCA(legacy.ProxyCA, legacy.ProxyCAKey, now, 10*365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if rotated, err = ensureProxyCAAt(legacy, os.Getuid(), false, now); err != nil || !rotated {
		t.Fatalf("a ten-year CA: rotated=%v err=%v; --update must replace it", rotated, err)
	}
	c, err := loadCerts(legacy.ProxyCA)
	if err != nil {
		t.Fatal(err)
	}
	if v := validity(c[0]); v > 365*24*time.Hour+proxyClockSkew {
		t.Fatalf("the replacement is valid for %v", v)
	}

	// The service replaces only an expired CA; a CA near its end is left
	// for --update, which also tells the operator to restart Claude Code.
	near := fresh.NotAfter.Add(-time.Hour)
	expiring := ClientPaths(t.TempDir())
	if err = os.MkdirAll(expiring.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = createProxyCA(expiring.ProxyCA, expiring.ProxyCAKey, now, proxyCAValidity); err != nil {
		t.Fatal(err)
	}
	before, err := loadOrCreateProxyCA(expiring.ProxyCA, expiring.ProxyCAKey, near)
	if err != nil {
		t.Fatal(err)
	}
	after, err := loadOrCreateProxyCA(expiring.ProxyCA, expiring.ProxyCAKey, fresh.NotAfter.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if after.cert.Equal(before.cert) || !after.cert.NotAfter.After(fresh.NotAfter.Add(time.Hour)) {
		t.Fatal("the service kept an expired proxy CA")
	}
}

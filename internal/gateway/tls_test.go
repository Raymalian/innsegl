// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTLS001CAIsCreatedOnFirstStart is TLS-001's own CA-lifecycle half: a
// fresh KeyDir gets a self-signed ECDSA P-256 CA, its private key written
// only under KeyDir (0600, in a 0700 directory), and a copy of the
// certificate (never the key) published to PublicDir.
func TestTLS001CAIsCreatedOnFirstStart(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "key")
	pubDir := filepath.Join(t.TempDir(), "pub")

	ca, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir, PublicDir: pubDir})
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	if ca == nil {
		t.Fatal("LoadOrCreateCA returned a nil CA with no error")
	}

	// The key directory: 0700, holding exactly the key and the CA's own
	// copy of its certificate.
	fi, err := os.Stat(keyDir)
	if err != nil {
		t.Fatalf("stat KeyDir: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("KeyDir %s is not a directory", keyDir)
	}
	if mode := fi.Mode().Perm(); mode != 0o700 {
		t.Errorf("KeyDir mode = %o, want 0700", mode)
	}

	keyPath := filepath.Join(keyDir, "gateway-ca-key.pem")
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat the CA private key: %v", err)
	}
	if mode := keyInfo.Mode().Perm(); mode != 0o600 {
		t.Errorf("CA key file mode = %o, want 0600", mode)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read the CA private key: %v", err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Errorf("the CA key file does not look like a PEM private key")
	}

	// The CA's own certificate, in KeyDir.
	caCertPath := filepath.Join(keyDir, CACertFileName)
	certPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read the CA's own certificate copy in KeyDir: %v", err)
	}
	cert := parsePEMCertForTest(t, certPEM)
	if !cert.IsCA {
		t.Error("the CA certificate does not have IsCA set")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("the CA public key is %T, want *ecdsa.PublicKey (P-256)", cert.PublicKey)
	} else if pub.Curve.Params().Name != "P-256" {
		t.Errorf("the CA key's curve = %s, want P-256", pub.Curve.Params().Name)
	}

	// PublicDir gets the SAME certificate, and nothing that looks like a
	// private key.
	pubCertPath := filepath.Join(pubDir, CACertFileName)
	pubCertPEM, err := os.ReadFile(pubCertPath)
	if err != nil {
		t.Fatalf("read the published CA certificate: %v", err)
	}
	if string(pubCertPEM) != string(certPEM) {
		t.Error("the published certificate differs from the CA's own copy")
	}
	if err := filepath.Walk(pubDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(data), "PRIVATE KEY") {
			t.Errorf("a private key was found outside KeyDir, at %s", path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk PublicDir: %v", err)
	}

	pemFromCACertPEM := ca.CACertPEM()
	if string(pemFromCACertPEM) != string(certPEM) {
		t.Error("CA.CACertPEM() does not match the file written to KeyDir")
	}
}

// TestTLS001RestartingKeepsTheSameCA: a second LoadOrCreateCA against the
// SAME KeyDir (a fresh process, as a restart would be) loads the identical
// CA -- same key, same certificate, byte for byte -- rather than minting a
// new one.
func TestTLS001RestartingKeepsTheSameCA(t *testing.T) {
	keyDir := t.TempDir()
	pubDir := t.TempDir()

	first, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir, PublicDir: pubDir})
	if err != nil {
		t.Fatalf("first LoadOrCreateCA: %v", err)
	}
	second, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir, PublicDir: pubDir})
	if err != nil {
		t.Fatalf("second LoadOrCreateCA (the 'restart'): %v", err)
	}
	if string(first.CACertPEM()) != string(second.CACertPEM()) {
		t.Error("a second LoadOrCreateCA against the same KeyDir minted a different CA certificate")
	}

	// And a FRESH leaf from the reloaded CA is valid against a pool built
	// from the CA certificate.
	leaf, err := second.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after reload: %v", err)
	}
	assertLeafValidForCA(t, leaf, second.CACertPEM())
}

// TestTLS001LeafNamesLoopbackAndIsShortLivedECDSAP256 is TLS-001's leaf
// half: 127.0.0.1 and localhost SANs, ECDSA P-256, signed by the CA, and
// short-lived.
func TestTLS001LeafNamesLoopbackAndIsShortLivedECDSAP256(t *testing.T) {
	keyDir, pubDir := t.TempDir(), t.TempDir()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir, PublicDir: pubDir, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	tlsCert, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf := assertLeafValidForCA(t, tlsCert, ca.CACertPEM())

	var haveIP, haveDNS bool
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			haveIP = true
		}
	}
	for _, name := range leaf.DNSNames {
		if name == "localhost" {
			haveDNS = true
		}
	}
	if !haveIP {
		t.Errorf("leaf IP SANs = %v, want 127.0.0.1", leaf.IPAddresses)
	}
	if !haveDNS {
		t.Errorf("leaf DNS SANs = %v, want localhost", leaf.DNSNames)
	}
	if _, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("leaf private key is %T, want *ecdsa.PrivateKey", tlsCert.PrivateKey)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > 25*time.Hour {
		t.Errorf("leaf validity = %s, want short-lived (around 24h)", leaf.NotAfter.Sub(leaf.NotBefore))
	}
	if !leaf.NotAfter.After(now) {
		t.Errorf("leaf NotAfter = %s, want it to be after now (%s)", leaf.NotAfter, now)
	}
}

// TestTLS001GetCertificateReusesAFreshLeafAndRenewsAStaleOne is the renewal
// window: a leaf well inside its validity is reused byte for byte (no churn
// on every handshake); a leaf close to expiry is replaced with a fresh one.
func TestTLS001GetCertificateReusesAFreshLeafAndRenewsAStaleOne(t *testing.T) {
	keyDir, pubDir := t.TempDir(), t.TempDir()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	clock := now
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir, PublicDir: pubDir, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}

	first, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (first): %v", err)
	}

	// One hour later: well inside a ~24h leaf's validity. Must be the SAME
	// certificate.
	clock = now.Add(1 * time.Hour)
	second, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (one hour later): %v", err)
	}
	if string(second.Certificate[0]) != string(first.Certificate[0]) {
		t.Error("GetCertificate minted a new leaf although the current one is still fresh")
	}

	// Now within the renewal window of the leaf's own expiry: must renew.
	clock = first.Leaf.NotAfter.Add(-1 * time.Hour)
	third, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate (near expiry): %v", err)
	}
	if string(third.Certificate[0]) == string(first.Certificate[0]) {
		t.Error("GetCertificate did not renew a leaf close to its own expiry")
	}
	if !third.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Errorf("the renewed leaf's NotAfter (%s) is not later than the old one's (%s)",
			third.Leaf.NotAfter, first.Leaf.NotAfter)
	}
}

// TestTLS001ServerTLSConfigRequiresTLS12Minimum: TLS 1.2+ only.
func TestTLS001ServerTLSConfigRequiresTLS12Minimum(t *testing.T) {
	keyDir, pubDir := t.TempDir(), t.TempDir()
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir, PublicDir: pubDir})
	if err != nil {
		t.Fatalf("LoadOrCreateCA: %v", err)
	}
	cfg := ca.ServerTLSConfig()
	if cfg == nil {
		t.Fatal("ServerTLSConfig returned nil")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want at least TLS 1.2 (%#x)", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.GetCertificate == nil {
		t.Error("ServerTLSConfig has no GetCertificate -- nothing would issue a leaf")
	}
}

// TestTLS001LoadOrCreateCARequiresAKeyDir: an empty KeyDir is refused,
// rather than falling back to a default this package would have to
// document twice (once here, once at every caller).
func TestTLS001LoadOrCreateCARequiresAKeyDir(t *testing.T) {
	if _, err := LoadOrCreateCA(CAConfig{}); err == nil {
		t.Fatal("LoadOrCreateCA with an empty KeyDir succeeded, want a refusal")
	}
}

// TestTLS001PublicDirEmptySkipsThePublish: PublicDir is optional (a unit
// test that only cares about the CA's own persistence, and the seam
// upstream tests already use for a package-level default client).
func TestTLS001PublicDirEmptySkipsThePublish(t *testing.T) {
	keyDir := t.TempDir()
	if _, err := LoadOrCreateCA(CAConfig{KeyDir: keyDir}); err != nil {
		t.Fatalf("LoadOrCreateCA with no PublicDir: %v", err)
	}
}

// parsePEMCertForTest decodes a single PEM certificate, failing the test on
// any error -- shared shape with upstream_test.go's own certificate
// helpers, kept separate here because CA-minted certificates carry
// IsCA/BasicConstraints assertions upstream_test.go has no reason to make.
func parsePEMCertForTest(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("not a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// assertLeafValidForCA verifies tlsCert's leaf chains to and is signed by
// the CA named by caCertPEM, and its usage is a TLS server certificate --
// the same check a real TLS client performs, run directly against the
// x509 package rather than through a live handshake, so the CA-lifecycle
// tests above stay fast unit tests.
func assertLeafValidForCA(t *testing.T, tlsCert *tls.Certificate, caCertPEM []byte) *x509.Certificate {
	t.Helper()
	if tlsCert == nil || len(tlsCert.Certificate) == 0 {
		t.Fatal("nil or empty tls.Certificate")
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	caCert := parsePEMCertForTest(t, caCertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("the leaf does not verify against its own CA: %v", err)
	}
	return leaf
}

// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RM-311 (#493): the dashboard is served over HTTPS at the core's name with a
// certificate from the core's own CA, which clients already trust (ADR-0066).
// It has its own key: whoever reads the dashboard's key cannot present the
// gateway's.
func TestRM311TheDashboardCertificateNamesTheCoreAndHasItsOwnKey(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ca, err := LoadOrCreateCA(CAConfig{
		KeyDir: filepath.Join(t.TempDir(), "key"), DNSNames: []string{"core.example.test"},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "dashboard-tls")
	notAfter, err := ca.WriteDashboardCert(dir)
	if err != nil {
		t.Fatalf("WriteDashboardCert: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, DashboardTLSFileName), filepath.Join(dir, DashboardTLSFileName))
	if err != nil {
		t.Fatalf("the written pair does not load: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.NotAfter.Equal(notAfter) {
		t.Errorf("returned NotAfter %s, certificate says %s", notAfter, leaf.NotAfter)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "core.example.test", CurrentTime: now}); err != nil {
		t.Errorf("the dashboard certificate does not verify for the core's name: %v", err)
	}
	gw, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	gwKey, ok := gw.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the gateway key is %T", gw.Leaf.PublicKey)
	}
	if gwKey.Equal(leaf.PublicKey) {
		t.Error("the dashboard certificate carries the gateway's own key")
	}
	info, err := os.Stat(filepath.Join(dir, DashboardTLSFileName))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the dashboard key is %o, want 0600", mode)
	}
}

// A renewal replaces the certificate and key together: one file, one rename.
func TestRM311RewritingTheDashboardCertificateReplacesThePair(t *testing.T) {
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: filepath.Join(t.TempDir(), "key")})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err = ca.WriteDashboardCert(dir); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(dir, DashboardTLSFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ca.WriteDashboardCert(dir); err != nil {
		t.Fatal(err)
	}
	if _, err = tls.LoadX509KeyPair(filepath.Join(dir, DashboardTLSFileName), filepath.Join(dir, DashboardTLSFileName)); err != nil {
		t.Fatalf("after a rewrite the pair does not load: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, DashboardTLSFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(second) {
		t.Error("a rewrite kept the old key")
	}
}

func TestRM311WriteDashboardCertRefusesAnUnwritableDir(t *testing.T) {
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: filepath.Join(t.TempDir(), "key")})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.WriteDashboardCert(file); err == nil {
		t.Fatal("a directory that is a file was accepted")
	}
}

// The dashboard's certificate is renewed with the gateway leaf's own slack.
func TestRM311TheDashboardCertificateIsRenewedBeforeItExpires(t *testing.T) {
	notAfter := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if got := DashboardCertRenewAt(notAfter); !got.Equal(notAfter.Add(-leafRenewBefore)) {
		t.Errorf("renew at %s, want %s", got, notAfter.Add(-leafRenewBefore))
	}
}

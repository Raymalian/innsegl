// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

// verifyAs checks the CA's served leaf against a pool trusting only the CA.
func verifyAs(t *testing.T, ca *CA, name string) error {
	t.Helper()
	cert, err := ca.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CACertPEM()) {
		t.Fatal("CA PEM did not parse")
	}
	inter := x509.NewCertPool()
	_, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func TestTLS003ConfiguredNamesVerifyAndOthersDoNot(t *testing.T) {
	ca, err := LoadOrCreateCA(CAConfig{
		KeyDir:   t.TempDir(),
		DNSNames: []string{"core.example.test"},
		IPs:      []net.IP{net.ParseIP("192.0.2.10")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"core.example.test", "192.0.2.10", "localhost", "127.0.0.1"} {
		if err := verifyAs(t, ca, n); err != nil {
			t.Errorf("verify %q: %v", n, err)
		}
	}
	if err := verifyAs(t, ca, "other.example.test"); err == nil {
		t.Error("an unconfigured DNS name verified")
	}
	if err := verifyAs(t, ca, "192.0.2.11"); err == nil {
		t.Error("an unconfigured IP verified")
	}
}

func TestTLS003LoopbackVerifiesWithNoConfiguration(t *testing.T) {
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"localhost", "127.0.0.1"} {
		if err := verifyAs(t, ca, n); err != nil {
			t.Errorf("verify %q: %v", n, err)
		}
	}
	if err := verifyAs(t, ca, "core.example.test"); err == nil {
		t.Error("an unconfigured name verified")
	}
}

func TestTLS003ChangingNamesReissuesTheLeafUnderTheSameCA(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(CAConfig{KeyDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if verifyAs(t, first, "core.example.test") == nil {
		t.Fatal("name verified before it was configured")
	}
	second, err := LoadOrCreateCA(CAConfig{KeyDir: dir, DNSNames: []string{"core.example.test"}, IPs: []net.IP{net.ParseIP("192.0.2.10")}})
	if err != nil {
		t.Fatal(err)
	}
	if string(first.CACertPEM()) != string(second.CACertPEM()) {
		t.Error("the CA changed when only the names did")
	}
	for _, n := range []string{"core.example.test", "192.0.2.10", "localhost"} {
		if err := verifyAs(t, second, n); err != nil {
			t.Errorf("verify %q: %v", n, err)
		}
	}
}

func TestTLS003DuplicateAndLoopbackNamesAreNotRepeated(t *testing.T) {
	ca, err := LoadOrCreateCA(CAConfig{KeyDir: t.TempDir(), DNSNames: []string{"localhost", "a.test", "a.test"}, IPs: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.DNSNames) != 2 || len(cert.Leaf.IPAddresses) != 2 {
		t.Errorf("DNS %v IPs %v", cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
	}
}

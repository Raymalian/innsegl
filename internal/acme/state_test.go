// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TLS-005's local half: what is kept in the state directory, read back and
// refused when it cannot be used, with no ACME server involved.

func selfSigned(t *testing.T, name string, lifetime time.Duration) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: []string{name},
		NotBefore: now, NotAfter: now.Add(lifetime)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestTLS005KeptCertificatesAreReadBackOnlyWhenTheyStillFit(t *testing.T) {
	state := t.TempDir()
	m := &Manager{cfg: Config{StateDir: state, Names: []string{testName}}, certs: map[string]*tls.Certificate{}}
	if _, ok := m.loadCert(kindGateway); ok {
		t.Fatal("a certificate was read from an empty state directory")
	}
	data, err := encodeTLSCert(selfSigned(t, testName, 90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExact(state, kindGateway+".pem", data); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.loadCert(kindGateway); !ok {
		t.Fatal("a kept certificate for the configured name was not read back")
	}
	m.cfg.Names = []string{"other.innsegl.test"}
	if _, ok := m.loadCert(kindGateway); ok {
		t.Fatal("a kept certificate that does not cover the configured names was reused")
	}
	if err := os.WriteFile(filepath.Join(state, kindDashboard+".pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.loadCert(kindDashboard); ok {
		t.Fatal("an unreadable kept certificate was used")
	}
}

func TestTLS005RenewalIsAThirdOfTheLifetimeUnlessSet(t *testing.T) {
	c := selfSigned(t, testName, 90*24*time.Hour)
	m := &Manager{cfg: Config{}, certs: map[string]*tls.Certificate{kindGateway: c}}
	if got, want := m.RenewAt(c.Leaf), c.Leaf.NotAfter.Add(-30*24*time.Hour); !got.Equal(want) {
		t.Errorf("RenewAt = %v, want %v", got, want)
	}
	if got := m.NextRenewal(); !got.Equal(m.RenewAt(c.Leaf)) {
		t.Errorf("NextRenewal = %v", got)
	}
	m.cfg.RenewBefore = time.Hour
	if got, want := m.RenewAt(c.Leaf), c.Leaf.NotAfter.Add(-time.Hour); !got.Equal(want) {
		t.Errorf("RenewAt with RenewBefore set = %v, want %v", got, want)
	}
	if !(&Manager{}).NextRenewal().IsZero() {
		t.Error("a manager with no certificates has a next renewal")
	}
}

func TestTLS005AnEmptyManagerServesNothingAndTheAccountIsReadBack(t *testing.T) {
	m := &Manager{cfg: Config{StateDir: t.TempDir(), Email: "a@innsegl.test"}, certs: map[string]*tls.Certificate{}}
	if _, err := m.GetCertificate(nil); err == nil {
		t.Error("an empty manager served a gateway certificate")
	}
	if _, err := m.WriteDashboardCert(t.TempDir()); err == nil {
		t.Error("an empty manager wrote a dashboard certificate")
	}
	if st := m.Status(); st.Source != SourceACME || !st.NotAfter.IsZero() {
		t.Errorf("Status = %+v", st)
	}

	a, err := m.loadAccount()
	if err != nil || a.GetEmail() != "a@innsegl.test" || a.GetPrivateKey() == nil || a.GetRegistration() != nil {
		t.Fatalf("a new account = %+v %v", a, err)
	}
	if err = m.saveAccount(a); err != nil {
		t.Fatal(err)
	}
	again, err := m.loadAccount()
	if err != nil || again.GetEmail() != a.GetEmail() {
		t.Fatalf("the kept account = %+v %v", again, err)
	}
	if err = os.WriteFile(filepath.Join(m.cfg.StateDir, "account.json"), []byte(`{"key":"not pem"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.loadAccount(); err == nil {
		t.Error("an account whose key is not PEM was read")
	}
	if err = os.WriteFile(filepath.Join(m.cfg.StateDir, "account.json"), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.loadAccount(); err == nil {
		t.Error("an account that is not JSON was read")
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.saveAccount(&account{key: edKey}); err == nil {
		t.Error("an account with a key that is not ECDSA was saved")
	}
	if _, err := encodeTLSCert(&tls.Certificate{PrivateKey: edKey}); err == nil {
		t.Error("a certificate with a key that is not ECDSA was encoded")
	}
}

// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
)

const testName = "core.innsegl.test"

func testConfig(p *pebble, state string, dns *fakeDNS) Config {
	return Config{
		Email:        "operator@innsegl.test",
		DirectoryURL: p.directory,
		Names:        []string{testName},
		Zone:         "innsegl.test",
		StateDir:     state,
		Provider:     dns,
		HTTPClient:   p.client,
		// The fake DNS answers at once; nothing to wait for.
		ChallengeOptions: []dns01.ChallengeOption{dns01.PropagationWait(0, true)},
	}
}

func verifies(t *testing.T, leaf *x509.Certificate, roots *x509.CertPool, intermediates []*x509.Certificate) {
	t.Helper()
	inter := x509.NewCertPool()
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: testName, Roots: roots, Intermediates: inter}); err != nil {
		t.Fatalf("the certificate does not verify for %s: %v", testName, err)
	}
}

// TLS-004: the core obtains a publicly trusted certificate (here, from the
// local ACME server) for its name through a DNS-01 challenge, for the
// gateway and, with a key of its own, for the dashboard; and says so.
func TestTLS004ObtainsTheServerCertificatesThroughDNS01(t *testing.T) {
	p := startPebble(t)
	dns := &fakeDNS{api: p.dnsAPI, client: p.client}
	state := t.TempDir()
	m, err := New(t.Context(), testConfig(p, state, dns))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	roots := p.issuedRoots(t)

	gw, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for _, der := range gw.Certificate {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			t.Fatal(perr)
		}
		chain = append(chain, c)
	}
	verifies(t, chain[0], roots, chain[1:])

	dir := t.TempDir()
	notAfter, err := m.WriteDashboardCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, DashboardTLSFileName))
	if err != nil {
		t.Fatal(err)
	}
	var dash []*x509.Certificate
	var dashKey []byte
	for rest := raw; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			c, perr := x509.ParseCertificate(b.Bytes)
			if perr != nil {
				t.Fatal(perr)
			}
			dash = append(dash, c)
		} else {
			dashKey = b.Bytes
		}
	}
	if len(dash) == 0 || len(dashKey) == 0 {
		t.Fatalf("the dashboard file holds %d certificates and a key of %d bytes", len(dash), len(dashKey))
	}
	verifies(t, dash[0], roots, dash[1:])
	if !notAfter.Equal(dash[0].NotAfter) {
		t.Errorf("WriteDashboardCert answered %v, the file's certificate expires %v", notAfter, dash[0].NotAfter)
	}
	if bytes.Equal(dash[0].RawSubjectPublicKeyInfo, chain[0].RawSubjectPublicKeyInfo) {
		t.Error("the dashboard's certificate has the gateway's key; it must have its own")
	}

	st := m.Status()
	if st.Source != SourceACME || !st.NotAfter.Equal(chain[0].NotAfter) || len(st.Names) != 1 {
		t.Errorf("Status = %+v", st)
	}
	if info, serr := os.Stat(filepath.Join(state, "gateway.pem")); serr != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the gateway's certificate and key are not kept 0600 in the state directory: %v", serr)
	}
}

// TLS-005: a restart reuses what was obtained (no new order), and renewal
// before expiry swaps the certificate in place, with no restart.
func TestTLS005ARestartReusesTheCertificatesAndRenewalSwapsThemInPlace(t *testing.T) {
	p := startPebble(t)
	dns := &fakeDNS{api: p.dnsAPI, client: p.client}
	state := t.TempDir()
	if _, err := New(t.Context(), testConfig(p, state, dns)); err != nil {
		t.Fatal(err)
	}
	ordered := dns.posts

	cfg := testConfig(p, state, dns)
	m, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if dns.posts != ordered {
		t.Fatalf("a restart ordered again: %d challenges, want %d", dns.posts, ordered)
	}
	before, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Nothing is due a day after issuance with the default window.
	if renewed, rerr := m.RenewDue(t.Context()); rerr != nil || renewed != 0 {
		for kind, c := range m.certs {
			t.Logf("%s: %v to %v", kind, c.Leaf.NotBefore, c.Leaf.NotAfter)
		}
		t.Fatalf("RenewDue on fresh certificates = %d %v, want none", renewed, rerr)
	}
	// Inside the renewal window (here: anything under 100 days left).
	m.cfg.RenewBefore = 100 * 24 * time.Hour
	renewed, err := m.RenewDue(t.Context())
	if err != nil || renewed != 2 {
		t.Fatalf("RenewDue = %d %v, want both certificates renewed", renewed, err)
	}
	after, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if after.Leaf.SerialNumber.Cmp(before.Leaf.SerialNumber) == 0 {
		t.Fatal("the gateway still serves the certificate it had before renewal")
	}
}

// TLS-006: the names must all be in the one zone the DNS credential is for,
// and the settings it needs must be there.
func TestTLS006RefusesNamesOutsideTheZoneAndIncompleteSettings(t *testing.T) {
	good := Config{Email: "a@innsegl.test", DirectoryURL: "https://localhost:1/dir", Names: []string{"core.innsegl.test"},
		Zone: "innsegl.test", StateDir: t.TempDir(), Provider: &fakeDNS{}}
	for name, mutate := range map[string]func(*Config){
		"a name outside the zone": func(c *Config) { c.Names = []string{"core.example.test"} },
		"a zone's look-alike":     func(c *Config) { c.Names = []string{"core.notinnsegl.test"} },
		"no names":                func(c *Config) { c.Names = nil },
		"no zone":                 func(c *Config) { c.Zone = "" },
		"no email":                func(c *Config) { c.Email = "" },
		"no state directory":      func(c *Config) { c.StateDir = "" },
		"no provider":             func(c *Config) { c.Provider = nil; c.ProviderName = "" },
		"an unknown provider":     func(c *Config) { c.Provider = nil; c.ProviderName = "no-such-dns" },
		"a plain-http directory":  func(c *Config) { c.DirectoryURL = "http://localhost:1/dir" },
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			mutate(&c)
			if _, err := New(t.Context(), c); err == nil || !strings.Contains(err.Error(), "acme") {
				t.Fatalf("New accepted %s: %v", name, err)
			}
		})
	}
}

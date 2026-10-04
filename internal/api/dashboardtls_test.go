// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The dashboard's TLS, terminated by `innsegl api` (#475) from the file the
// core writes (RM-311, ADR-0066's amendment): one PEM file holding the
// certificate chain and its key, replaced by a rename when the core renews
// it. The server reads it when it changes, never only once at start.

// writeDashboardPEM writes a self-signed certificate for name and its EC
// key, in one file, the way the core's WriteDashboardCert does: chain
// first, key after, renamed into place.
func writeDashboardPEM(t *testing.T, path, name string, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// touchLater moves a file's modification time forward, so a renewal that
// lands within the filesystem's timestamp granularity is still seen.
func touchLater(t *testing.T, path string, d time.Duration) {
	t.Helper()
	at := time.Now().Add(d)
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

// servedSerial completes a handshake against srv and reports the serial of
// the certificate it presented.
func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("handshake with %s: %v", addr, err)
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("dialled a %T, not a TLS connection", conn)
	}
	return tc.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

// serveDashboardTLS serves an empty handler over cfg on a loopback port.
// Not httptest's StartTLS: it installs its own certificate, which would
// win over GetCertificate and hide the one under test.
func serveDashboardTLS(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Error(err)
		}
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

func TestDashboardTLSServesTheCoresCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tls.pem")
	writeDashboardPEM(t, path, "core.example.test", 1)
	cfg := DashboardTLSConfig(path)

	if got := servedSerial(t, serveDashboardTLS(t, cfg)); got != 1 {
		t.Fatalf("served serial %d, want 1", got)
	}
	if v := cfg.MinVersion; v != tls.VersionTLS12 {
		t.Errorf("MinVersion %x, want TLS 1.2", v)
	}
}

// The core renews the certificate before it expires (DashboardCertRenewAt)
// and writes it by rename. The next handshake presents the new one, with
// no restart.
func TestDashboardTLSPicksUpARenewedCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tls.pem")
	writeDashboardPEM(t, path, "core.example.test", 1)

	addr := serveDashboardTLS(t, DashboardTLSConfig(path))

	if got := servedSerial(t, addr); got != 1 {
		t.Fatalf("before renewal: serial %d, want 1", got)
	}
	writeDashboardPEM(t, path, "core.example.test", 2)
	touchLater(t, path, 2*time.Second)
	if got := servedSerial(t, addr); got != 2 {
		t.Fatalf("after renewal: serial %d, want 2", got)
	}
}

// The api can start before the core has written the file (they start in
// parallel), so an absent file is a failed handshake, not a failed start;
// the first handshake after the core writes it succeeds.
func TestDashboardTLSBeforeTheCoreWritesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tls.pem")
	cfg := DashboardTLSConfig(path)
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("no file yet, and a certificate was returned")
	}
	writeDashboardPEM(t, path, "core.example.test", 7)
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("after the core wrote it: %v", err)
	}
	if cert.Leaf == nil || cert.Leaf.SerialNumber.Int64() != 7 {
		t.Fatalf("got %+v, want serial 7", cert.Leaf)
	}
}

// A file that cannot be parsed never replaces a good certificate: the core
// writes by rename, so a bad file is a fault elsewhere, and the browser
// keeps a working page while it is found.
func TestDashboardTLSKeepsTheLastGoodCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tls.pem")
	writeDashboardPEM(t, path, "core.example.test", 3)
	cfg := DashboardTLSConfig(path)
	if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	touchLater(t, path, 2*time.Second)
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("a bad file replaced a good certificate: %v", err)
	}
	if cert.Leaf.SerialNumber.Int64() != 3 {
		t.Fatalf("serial %d, want the last good 3", cert.Leaf.SerialNumber.Int64())
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if cert, err = cfg.GetCertificate(&tls.ClientHelloInfo{}); err != nil || cert.Leaf.SerialNumber.Int64() != 3 {
		t.Fatalf("a removed file: %v, %v; want the last good certificate", cert, err)
	}
}

func TestDashboardTLSUnparsableFirstFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard-tls.pem")
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DashboardTLSConfig(path).GetCertificate(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("an unparsable file served a certificate")
	}
}

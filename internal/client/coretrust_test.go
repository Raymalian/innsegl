// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TLS-010 (#473): a core whose server certificate is publicly trusted
// (ACME) is reached through the system's roots as well as its own CA; a
// core on its own CA is reached through that CA alone, as before.

// testCA is a CA and a server certificate for 127.0.0.1 it issued.
func testCA(t *testing.T) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return root, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

func tlsServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTLS010APublicServerCertificateIsTrustedThroughTheSystemsRoots(t *testing.T) {
	own, _ := testCA(t)
	public, publicLeaf := testCA(t)
	srv := tlsServer(t, publicLeaf)
	restore := setSystemRoots(func() (*x509.CertPool, error) {
		p := x509.NewCertPool()
		p.AddCert(public)
		return p, nil
	})
	t.Cleanup(restore)

	isPublic, err := ProbeServerCertificate(t.Context(), srv.URL, own)
	if err != nil || !isPublic {
		t.Fatalf("probe of a core with a public certificate = %v %v, want public", isPublic, err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: CoreRoots(own, true), MinVersion: tls.VersionTLS12}}}
	resp, err := client.Get(srv.URL) //nolint:noctx // test
	if err != nil {
		t.Fatalf("with the public roots, the core is not reached: %v", err)
	}
	_ = resp.Body.Close()
	ownOnly := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: CoreRoots(own, false), MinVersion: tls.VersionTLS12}}}
	if resp, err := ownOnly.Get(srv.URL); err == nil { //nolint:noctx // test
		_ = resp.Body.Close()
		t.Fatal("a core on its own CA's trust alone accepted a certificate from another root")
	}
}

func TestTLS010ACoreOnItsOwnCAIsNotPublicAndAnUnknownCertificateIsRefused(t *testing.T) {
	own, ownLeaf := testCA(t)
	t.Cleanup(setSystemRoots(func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }))
	isPublic, err := ProbeServerCertificate(t.Context(), tlsServer(t, ownLeaf).URL, own)
	if err != nil || isPublic {
		t.Fatalf("probe of a core on its own CA = %v %v, want not public", isPublic, err)
	}
	_, stranger := testCA(t)
	if _, err := ProbeServerCertificate(t.Context(), tlsServer(t, stranger).URL, own); err == nil {
		t.Fatal("a certificate from neither root was accepted")
	}
}

func TestTLS010CoreConfigRecordsAPublicServerCertificate(t *testing.T) {
	paths := ClientPaths(t.TempDir())
	if err := WriteCoreConfig(paths, CoreConfig{CoreURL: "https://core.innsegl.test", InstallationID: "x", ServerCertificate: ServerCertificatePublic}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCoreConfig(paths)
	if err != nil || !got.PublicServer() {
		t.Fatalf("core.json = %+v %v, want a public server certificate", got, err)
	}
}

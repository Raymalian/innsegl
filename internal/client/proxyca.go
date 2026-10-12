// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"sync"
	"time"
)

// ProviderAPIHost is the one name the client opens (RM-329, #500): the
// provider's API, where Claude Code's model requests go. Every other host is
// tunnelled unopened.
const ProviderAPIHost = "api.anthropic.com"

const (
	// proxyCAValidity is a year (privilege review N8; it was ten). Claude
	// Code reads NODE_EXTRA_CA_CERTS once, at start, so a CA that changed
	// under a running session ends that session's model traffic: the CA is
	// replaced only by `innsegl connect --update`, which says to restart
	// Claude Code, once less than proxyCARotateBefore is left (or the CA is
	// a ten-year one from before), and by the service itself only once it
	// has expired, when it already serves nothing.
	proxyCAValidity     = 365 * 24 * time.Hour
	proxyCARotateBefore = 30 * 24 * time.Hour
	// proxyLeafValidity and proxyLeafRenewBefore: the leaf is short-lived
	// and minted in memory; it is never written down.
	proxyLeafValidity    = 24 * time.Hour
	proxyLeafRenewBefore = 6 * time.Hour
	proxyClockSkew       = 5 * time.Minute
)

// proxyCA is the client's own certificate authority for opening the
// provider's traffic. It is name-constrained to ProviderAPIHost, so a
// process that trusts it can be fooled about no other site.
type proxyCA struct {
	certPath, keyPath string

	mu     sync.Mutex
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	stamp  fileStamp
	issued *tls.Certificate
}

// fileStamp tells a file changed: its size and modification time.
type fileStamp struct {
	size int64
	mod  time.Time
}

func stampOf(path string) fileStamp {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{size: info.Size(), mod: info.ModTime()}
}

// loadOrCreateProxyCA reads the CA at certPath and keyPath, or creates it
// there (the certificate 0644, for NODE_EXTRA_CA_CERTS; the key 0600) when
// neither exists or the one there has expired by now.
func loadOrCreateProxyCA(certPath, keyPath string, now time.Time) (*proxyCA, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist) {
		return createProxyCA(certPath, keyPath, now, proxyCAValidity)
	}
	ca, err := readProxyCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if !now.Before(ca.cert.NotAfter) {
		return createProxyCA(certPath, keyPath, now, proxyCAValidity)
	}
	return ca, nil
}

// readProxyCA reads the CA at certPath and keyPath.
func readProxyCA(certPath, keyPath string) (*proxyCA, error) {
	stamp := stampOf(certPath)
	certs, err := loadCerts(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading the proxy CA: %w", err)
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading the proxy CA key: %w", err)
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("%s is not the key of %s", keyPath, certPath)
	}
	return &proxyCA{certPath: certPath, keyPath: keyPath, cert: certs[0], key: key, stamp: stamp}, nil
}

// proxyCADue reports whether `connect --update` replaces c at now: less than
// proxyCARotateBefore left, or a life longer than proxyCAValidity (a CA from
// before the one-year life).
func proxyCADue(c *x509.Certificate, now time.Time) bool {
	return c.NotAfter.Sub(now) < proxyCARotateBefore || c.NotAfter.Sub(c.NotBefore) > proxyCAValidity+proxyClockSkew
}

// reloadLocked takes up a CA replaced on disk since it was read (`connect
// --update`), so the running service mints from the CA new sessions trust,
// without a restart. A CA caught half-written is read again at the next
// call; until then the one in memory stays.
func (ca *proxyCA) reloadLocked() {
	if ca.certPath == "" || stampOf(ca.certPath) == ca.stamp {
		return
	}
	next, err := readProxyCA(ca.certPath, ca.keyPath)
	if err != nil {
		return
	}
	ca.cert, ca.key, ca.stamp, ca.issued = next.cert, next.key, next.stamp, nil
}

func createProxyCA(certPath, keyPath string, now time.Time, validity time.Duration) (*proxyCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := proxySerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "innsegl client proxy CA"},
		NotBefore:             now.Add(-proxyClockSkew),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		// RFC 5280 name constraints: this CA vouches for the provider's API
		// name only.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{ProviderAPIHost},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating the proxy CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// The key first: a certificate on disk without its key would be read
	// back as a broken CA.
	if err = writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, fmt.Errorf("writing the proxy CA key: %w", err)
	}
	if err = writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, fmt.Errorf("writing the proxy CA: %w", err)
	}
	return &proxyCA{certPath: certPath, keyPath: keyPath, cert: cert, key: key, stamp: stampOf(certPath)}, nil
}

// leaf answers the current certificate for ProviderAPIHost, minting a new
// one when there is none or it is due, or the CA was replaced on disk.
func (ca *proxyCA) leaf(now time.Time) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.reloadLocked()
	if ca.issued != nil && now.Before(ca.issued.Leaf.NotAfter.Add(-proxyLeafRenewBefore)) {
		return ca.issued, nil
	}
	c, err := ca.issue(ProviderAPIHost, now)
	if err != nil {
		return nil, err
	}
	ca.issued = c
	return c, nil
}

// issue mints a leaf for host. Only ProviderAPIHost verifies; the name
// constraints make any other name fail.
func (ca *proxyCA) issue(host string, now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := proxySerial()
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(proxyLeafValidity)
	if notAfter.After(ca.cert.NotAfter) {
		// No leaf outlives its CA.
		notAfter = ca.cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-proxyClockSkew),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("minting a proxy leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

func proxySerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// EnsureProxyCA creates the proxy CA under paths when it is not there yet,
// replaces one that is due (proxyCADue), and leaves any other alone. rotated
// says it replaced one: Claude Code sessions already running trust the old
// CA until they restart. owned says connect runs as root for uid (sudo):
// the files are then given to uid, so the client service, which runs as
// uid, can read its key.
func EnsureProxyCA(paths Paths, uid int, owned bool) (rotated bool, err error) {
	return ensureProxyCAAt(paths, uid, owned, time.Now())
}

func ensureProxyCAAt(paths Paths, uid int, owned bool, now time.Time) (bool, error) {
	ca, err := loadOrCreateProxyCA(paths.ProxyCA, paths.ProxyCAKey, now)
	if err != nil {
		return false, err
	}
	rotated := false
	if proxyCADue(ca.cert, now) {
		if _, err = createProxyCA(paths.ProxyCA, paths.ProxyCAKey, now, proxyCAValidity); err != nil {
			return false, err
		}
		rotated = true
	}
	if !owned {
		return rotated, nil
	}
	for _, p := range []string{paths.ProxyCA, paths.ProxyCAKey} {
		if err := os.Lchown(p, uid, -1); err != nil {
			return rotated, fmt.Errorf("giving %s to uid %d: %w", p, uid, err)
		}
	}
	return rotated, nil
}

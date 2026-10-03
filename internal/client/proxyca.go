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
	// proxyCAValidity is long on purpose: Claude Code reads
	// NODE_EXTRA_CA_CERTS once, at start, so a CA that changed under a
	// running session would end it.
	proxyCAValidity = 10 * 365 * 24 * time.Hour
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
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu     sync.Mutex
	issued *tls.Certificate
}

// loadOrCreateProxyCA reads the CA at certPath and keyPath, or creates it
// there (the certificate 0644, for NODE_EXTRA_CA_CERTS; the key 0600) when
// neither exists.
func loadOrCreateProxyCA(certPath, keyPath string) (*proxyCA, error) {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist) {
		return createProxyCA(certPath, keyPath)
	}
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
	return &proxyCA{cert: certs[0], key: key}, nil
}

func createProxyCA(certPath, keyPath string) (*proxyCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := proxySerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "innsegl client proxy CA"},
		NotBefore:             now.Add(-proxyClockSkew),
		NotAfter:              now.Add(proxyCAValidity),
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
	return &proxyCA{cert: cert, key: key}, nil
}

// leaf answers the current certificate for ProviderAPIHost, minting a new
// one when there is none or it is due.
func (ca *proxyCA) leaf(now time.Time) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
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
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-proxyClockSkew),
		NotAfter:     now.Add(proxyLeafValidity),
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

// EnsureProxyCA creates the proxy CA under paths when it is not there yet
// and leaves an existing one alone. owned says connect runs as root for
// uid (sudo): the files are then given to uid, so the client service, which
// runs as uid, can read its key.
func EnsureProxyCA(paths Paths, uid int, owned bool) error {
	if _, err := loadOrCreateProxyCA(paths.ProxyCA, paths.ProxyCAKey); err != nil {
		return err
	}
	if !owned {
		return nil
	}
	for _, p := range []string{paths.ProxyCA, paths.ProxyCAKey} {
		if err := os.Lchown(p, uid, -1); err != nil {
			return fmt.Errorf("giving %s to uid %d: %w", p, uid, err)
		}
	}
	return nil
}

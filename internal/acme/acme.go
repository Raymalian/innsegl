// SPDX-License-Identifier: Apache-2.0

// Package acme obtains and renews a publicly trusted server certificate for
// the core's one name (ADR-0066 decision 4, #473) through an ACME DNS-01
// challenge, as an option beside the core's own CA, which stays the default.
//
// It covers the server only. Clients still authenticate with certificates
// from the deployment's own authority (ADR-0063); nothing here touches that.
//
// Two certificates are kept, each with a key of its own: the gateway's, and
// the dashboard's (ADR-0066's 2026-10-02 amendment: a process that reads the
// dashboard's key cannot present the gateway's certificate). Both, and the
// ACME account, are kept in a state directory, so a restart orders nothing.
// Renewal swaps a certificate in place: the gateway reads the current one on
// every handshake, the dashboard's server reads its file on every handshake.
//
// The DNS-01 record is written through the DNS provider named by
// configuration, with the provider's own credential, which is scoped by the
// operator to the one zone every name must be in.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

// DashboardTLSFileName is the file the dashboard's server reads its chain
// and key from; the same name and format the core's own CA writes
// (internal/gateway.DashboardTLSFileName).
const DashboardTLSFileName = "dashboard-tls.pem"

// SourceACME names a certificate this package obtained.
const SourceACME = "acme"

// renewFraction is how much of a certificate's lifetime is left when it is
// renewed by default: a third, so a 90-day certificate is renewed 30 days
// before expiry and a short-lived one in proportion, and a renewal that
// fails has a third of the lifetime to succeed in.
const renewFraction = 3

// The two certificates.
const (
	kindGateway   = "gateway"
	kindDashboard = "dashboard"
)

// Config is what the manager runs on.
type Config struct {
	// Email is the ACME account's contact.
	Email string
	// DirectoryURL is the ACME server's directory; https only.
	DirectoryURL string
	// Names are the DNS names the certificate covers, every one inside Zone.
	Names []string
	// Zone is the one DNS zone the provider's credential is for.
	Zone string
	// StateDir keeps the account and both certificates, 0700.
	StateDir string
	// ProviderName is the DNS provider, by the library's name for it. Its
	// credential is read from the provider's own settings (each accepts a
	// _FILE form). Provider, when set, is used instead (tests).
	ProviderName string
	Provider     challenge.Provider
	// HTTPClient reaches the ACME server; nil is the system's roots.
	HTTPClient *http.Client
	// ChallengeOptions tune the DNS-01 checks (tests).
	ChallengeOptions []dns01.ChallengeOption
	// RenewBefore renews a certificate this long before it expires. Zero
	// renews it with a third of its lifetime left.
	RenewBefore time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Status is what `innsegl status` shows about the server certificate.
type Status struct {
	Source   string    `json:"source"`
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
}

// Manager keeps the two certificates current.
type Manager struct {
	cfg    Config
	client *lego.Client
	mu     sync.RWMutex
	certs  map[string]*tls.Certificate
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// validate refuses an incomplete configuration, naming what is missing.
func (c Config) validate() error {
	switch {
	case c.Email == "":
		return errors.New("acme: no contact email for the account")
	case c.StateDir == "":
		return errors.New("acme: no state directory to keep the account and certificates in")
	case c.Zone == "":
		return errors.New("acme: no DNS zone; the DNS credential is for one zone, and every name must be in it")
	case len(c.Names) == 0:
		return errors.New("acme: no names to certify")
	case c.Provider == nil && c.ProviderName == "":
		return errors.New("acme: no DNS provider")
	}
	u, err := url.Parse(c.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("acme: the directory %q is not an https URL", c.DirectoryURL)
	}
	zone := strings.ToLower(strings.TrimSuffix(c.Zone, "."))
	for _, n := range c.Names {
		name := strings.ToLower(strings.TrimSuffix(n, "."))
		if name != zone && !strings.HasSuffix(name, "."+zone) {
			return fmt.Errorf("acme: %s is not in the zone %s the DNS credential is for", n, c.Zone)
		}
	}
	return nil
}

// New opens the manager: the account and certificates kept in StateDir, or
// a new account and new certificates when there are none (or they no longer
// cover Names). It returns only once both certificates are in hand.
func New(ctx context.Context, cfg Config) (*Manager, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("acme: the state directory: %w", err)
	}
	provider := cfg.Provider
	if provider == nil {
		p, err := dns.NewDNSChallengeProviderByName(cfg.ProviderName)
		if err != nil {
			return nil, fmt.Errorf("acme: the DNS provider %q: %w", cfg.ProviderName, err)
		}
		provider = p
	}
	m := &Manager{cfg: cfg, certs: map[string]*tls.Certificate{}}
	user, err := m.loadAccount()
	if err != nil {
		return nil, err
	}
	lc := lego.NewConfig(user)
	lc.CADirURL = cfg.DirectoryURL
	lc.Certificate.KeyType = certcrypto.EC256
	if cfg.HTTPClient != nil {
		// A copy: the library wraps the client it is given in place.
		c := *cfg.HTTPClient
		lc.HTTPClient = &c
	}
	client, err := lego.NewClient(lc)
	if err != nil {
		return nil, fmt.Errorf("acme: the ACME server at %s: %w", cfg.DirectoryURL, err)
	}
	if err := client.Challenge.SetDNS01Provider(provider, cfg.ChallengeOptions...); err != nil {
		return nil, fmt.Errorf("acme: %w", err)
	}
	m.client = client
	if user.Registration == nil {
		reg, rerr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if rerr != nil {
			return nil, fmt.Errorf("acme: register the account: %w", rerr)
		}
		user.Registration = reg
		if err := m.saveAccount(user); err != nil {
			return nil, err
		}
	}
	for _, kind := range []string{kindGateway, kindDashboard} {
		if cert, ok := m.loadCert(kind); ok {
			m.certs[kind] = cert
			continue
		}
		if err := m.obtain(ctx, kind); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// GetCertificate is tls.Config.GetCertificate: the gateway's current
// certificate, read under the lock a renewal swaps it under.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.certs[kindGateway]
	if c == nil {
		return nil, errors.New("acme: no gateway certificate")
	}
	return c, nil
}

// WriteDashboardCert writes the dashboard's certificate chain and its own key
// to dir/DashboardTLSFileName (0600, by rename) and answers when it expires.
func (m *Manager) WriteDashboardCert(dir string) (time.Time, error) {
	m.mu.RLock()
	c := m.certs[kindDashboard]
	m.mu.RUnlock()
	if c == nil {
		return time.Time{}, errors.New("acme: no dashboard certificate")
	}
	data, err := encodeTLSCert(c)
	if err != nil {
		return time.Time{}, err
	}
	if err := writeExact(dir, DashboardTLSFileName, data); err != nil {
		return time.Time{}, err
	}
	return c.Leaf.NotAfter, nil
}

// RenewAt is when leaf is renewed.
func (m *Manager) RenewAt(leaf *x509.Certificate) time.Time {
	before := m.cfg.RenewBefore
	if before <= 0 {
		before = leaf.NotAfter.Sub(leaf.NotBefore) / renewFraction
	}
	return leaf.NotAfter.Add(-before)
}

// NextRenewal is the earliest time either certificate is due.
func (m *Manager) NextRenewal() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var next time.Time
	for _, c := range m.certs {
		if at := m.RenewAt(c.Leaf); next.IsZero() || at.Before(next) {
			next = at
		}
	}
	return next
}

// RenewDue renews each certificate inside its renewal window and answers how
// many it renewed. One that fails is kept, and the error says which.
func (m *Manager) RenewDue(ctx context.Context) (int, error) {
	renewed := 0
	var errs []error
	for _, kind := range []string{kindGateway, kindDashboard} {
		m.mu.RLock()
		c := m.certs[kind]
		m.mu.RUnlock()
		if c != nil && m.cfg.now().Before(m.RenewAt(c.Leaf)) {
			continue
		}
		if err := m.obtain(ctx, kind); err != nil {
			errs = append(errs, err)
			continue
		}
		renewed++
	}
	return renewed, errors.Join(errs...)
}

// Status is the gateway certificate's source, names and expiry.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{Source: SourceACME, Names: append([]string(nil), m.cfg.Names...)}
	if c := m.certs[kindGateway]; c != nil {
		st.NotAfter = c.Leaf.NotAfter
	}
	return st
}

// obtain orders a certificate for kind with a fresh key, keeps it in the
// state directory, and swaps it in.
func (m *Manager) obtain(ctx context.Context, kind string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	res, err := m.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: m.cfg.Names, PrivateKey: key, Bundle: true,
	})
	if err != nil {
		return fmt.Errorf("acme: obtain the %s certificate for %s: %w", kind, strings.Join(m.cfg.Names, ", "), err)
	}
	cert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return fmt.Errorf("acme: the %s certificate: %w", kind, err)
	}
	data, err := encodeTLSCert(&cert)
	if err != nil {
		return err
	}
	if err := writeExact(m.cfg.StateDir, kind+".pem", data); err != nil {
		return err
	}
	m.mu.Lock()
	m.certs[kind] = &cert
	m.mu.Unlock()
	return nil
}

// loadCert reads kind from the state directory, if it is there, parses, and
// still covers every name.
func (m *Manager) loadCert(kind string) (*tls.Certificate, bool) {
	raw, err := os.ReadFile(filepath.Join(m.cfg.StateDir, kind+".pem"))
	if err != nil {
		return nil, false
	}
	cert, err := tls.X509KeyPair(raw, raw)
	if err != nil || cert.Leaf == nil {
		return nil, false
	}
	for _, n := range m.cfg.Names {
		if cert.Leaf.VerifyHostname(n) != nil {
			return nil, false
		}
	}
	return &cert, true
}

// account is the ACME account: its key and registration, kept as JSON.
type account struct {
	email        string
	key          crypto.PrivateKey
	Registration *registration.Resource
}

func (a *account) GetEmail() string                        { return a.email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

type accountFile struct {
	Email        string                 `json:"email"`
	Key          string                 `json:"key"`
	Registration *registration.Resource `json:"registration"`
}

func (m *Manager) loadAccount() (*account, error) {
	path := filepath.Join(m.cfg.StateDir, "account.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if kerr != nil {
			return nil, kerr
		}
		return &account{email: m.cfg.Email, key: key}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("acme: the account: %w", err)
	}
	var f accountFile
	if uerr := json.Unmarshal(raw, &f); uerr != nil {
		return nil, fmt.Errorf("acme: the account at %s: %w", path, uerr)
	}
	block, _ := pem.Decode([]byte(f.Key))
	if block == nil {
		return nil, fmt.Errorf("acme: the account key at %s is not PEM", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("acme: the account key at %s: %w", path, err)
	}
	return &account{email: f.Email, key: key, Registration: f.Registration}, nil
}

func (m *Manager) saveAccount(a *account) error {
	key, ok := a.key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("acme: the account key is not ECDSA")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(accountFile{
		Email: a.email, Key: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		Registration: a.Registration,
	}, "", "  ")
	if err != nil {
		return err
	}
	return writeExact(m.cfg.StateDir, "account.json", raw)
}

// encodeTLSCert is the chain, leaf first, then the key, as PEM.
func encodeTLSCert(c *tls.Certificate) ([]byte, error) {
	var out []byte
	for _, der := range c.Certificate {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, ok := c.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("acme: the key is %T, not ECDSA", c.PrivateKey)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})...), nil
}

// writeExact writes dir/name 0600 through a rename, so a reader never sees
// half of it.
func writeExact(dir, name string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("acme: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	return nil
}

// txtRecord is the DNS-01 record for domain: its name and value.
func txtRecord(domain, keyAuth string) (string, string) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return info.EffectiveFQDN, info.Value
}

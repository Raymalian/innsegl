// SPDX-License-Identifier: Apache-2.0

// tls.go — RM-246 (#391): the gateway's own listener serves TLS, from a
// certificate authority this deployment owns rather than a certificate from
// anywhere else. The host commands (internal/commitpath.Client, used by
// `innsegl git-hook` and `innsegl sign`) trust ONLY this CA -- never the
// system's public root store, never InsecureSkipVerify -- because nothing
// else answers on this loopback port as this deployment's own core.
//
// # Shape
//
// CA is a self-signed ECDSA P-256 root, created once (LoadOrCreateCA) and
// loaded unchanged on every start after that: ADR-0060 decision 1 keeps the
// gateway a companion of the one `innsegl` process, and a CA that changed on
// every restart would mean every host command's trust file goes stale on
// every restart too. Its private key lives only under CAConfig.KeyDir --
// deploy/compose/innsegl.yml gives that a named Docker volume mounted into
// no other service -- and is never written, logged, or copied anywhere
// else. Its certificate (public, by design: every host command has to be
// able to read it to trust the gateway at all) is written to
// CAConfig.PublicDir too, when set -- a host bind mount in the shipped
// compose file, so `innsegl git-hook` and `innsegl sign`, running on the
// host, can find it.
//
// CA.GetCertificate mints a short-lived leaf certificate for 127.0.0.1 and
// localhost, signed by the CA, and renews it before it expires -- see
// leafValidity and leafRenewBefore below. This is the function
// *tls.Config.GetCertificate wants, so the gateway's own http.Server needs
// nothing more than ca.ServerTLSConfig() to serve TLS 1.2+ from a
// certificate that stays valid for as long as the process runs.
package gateway

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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CACertFileName is the CA's own public certificate's file name, inside
// both CAConfig.KeyDir (the CA's own record of what it minted) and
// CAConfig.PublicDir (the host-reachable copy). Exported so a caller
// (cmd/innsegl/gateway.go, internal/commitpath, this package's own tests)
// never hard-codes it a second time.
const CACertFileName = "gateway-ca.pem"

// caKeyFileName is the CA's private key's file name, inside CAConfig.KeyDir
// ONLY -- never exported, and never written anywhere PublicDir's own copy
// step can reach.
const caKeyFileName = "gateway-ca-key.pem"

const (
	// caKeyDirMode / caKeyFileMode: the private key's own directory and
	// file. GW-TLS's whole security argument is that the key exists in
	// exactly one place, so these are never relaxed.
	caKeyDirMode  = 0o700
	caKeyFileMode = 0o600

	// caPublicDirMode / caCertFileMode: the certificate is PUBLIC by
	// design -- every host command has to be able to read it to trust this
	// deployment's gateway at all -- so these are tidy, not a secrecy
	// boundary.
	caPublicDirMode = 0o755
	caCertFileMode  = 0o644
)

const (
	// caValidity is deliberately long: this is a self-hosted root that
	// never leaves the deployment, minted once and kept for the volume's
	// lifetime. There is no rotation story for the ROOT (renewal is the
	// LEAF's job, below); a short root validity would need one.
	caValidity = 10 * 365 * 24 * time.Hour

	// leafValidity / leafRenewBefore: RM-246's "short-lived, renewed by the
	// core before expiry". A day is short enough that a leaf leaked from a
	// log or a core dump is worthless within hours of the deployment's next
	// restart; six hours of renewal slack is long enough that a stalled
	// process still has room to recover before a client ever sees an
	// expired certificate.
	leafValidity    = 24 * time.Hour
	leafRenewBefore = 6 * time.Hour

	// certClockSkewSlack backdates NotBefore on every certificate this
	// package mints, so a leaf or CA minted a moment before a verifying
	// client's own clock is never rejected as "not yet valid".
	certClockSkewSlack = 5 * time.Minute
)

// CAConfig locates the gateway's own certificate authority.
type CAConfig struct {
	// KeyDir holds the CA's private key and the CA's own copy of its
	// certificate. Created (0700) if it does not exist. Required: this
	// package refuses to guess a default, because a caller that forgets to
	// set it is a caller that has not decided where a private key lives,
	// and guessing that decision is worse than refusing to start.
	KeyDir string

	// PublicDir, if set, receives a copy of the CA's certificate (never the
	// key) on every LoadOrCreateCA -- the host-reachable half of RM-246's
	// contract. Created (0755) if it does not exist. Empty skips the copy,
	// for a caller that only needs the CA's own persistence (a unit test).
	PublicDir string

	// Now stands in for time.Now, so a test can drive certificate issuance
	// and renewal without a real wait. Nil means time.Now.
	Now func() time.Time
}

func (c CAConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// CA is the gateway's own certificate authority: a self-signed ECDSA P-256
// root, created on first start and loaded unchanged on every one after,
// that signs the short-lived leaf certificate the gateway's TLS listener
// presents. See LoadOrCreateCA.
type CA struct {
	cfg     CAConfig
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey

	mu   sync.Mutex
	leaf *tls.Certificate // the current leaf; minted lazily by GetCertificate.
}

// CACertPEM is the CA's own certificate, PEM-encoded -- what
// CAConfig.PublicDir receives and what a trusting client's root pool is
// built from (commitpath.TrustedHTTPClient; this package's own tests build
// one the identical way).
func (ca *CA) CACertPEM() []byte {
	return ca.certPEM
}

// LoadOrCreateCA loads the CA at cfg.KeyDir, or creates one there on first
// start -- RM-246's "created on first start and kept across restarts: the
// CA private key lives only in a named Docker volume the core mounts". A
// second call with the same KeyDir, in the same or a later process (a
// restart), returns the SAME CA: the identical key, the identical
// certificate, byte for byte.
func LoadOrCreateCA(cfg CAConfig) (*CA, error) {
	if cfg.KeyDir == "" {
		return nil, errors.New("gateway: CAConfig.KeyDir is required")
	}
	if err := os.MkdirAll(cfg.KeyDir, caKeyDirMode); err != nil {
		return nil, fmt.Errorf("gateway: create the CA key directory: %w", err)
	}
	// Belt and suspenders: MkdirAll does not tighten a directory that
	// already existed with looser permissions, and the umask applied at
	// creation time is not this package's to assume.
	if err := os.Chmod(cfg.KeyDir, caKeyDirMode); err != nil {
		return nil, fmt.Errorf("gateway: set the CA key directory's mode: %w", err)
	}

	keyPath := filepath.Join(cfg.KeyDir, caKeyFileName)
	certPath := filepath.Join(cfg.KeyDir, CACertFileName)

	// Whether to CREATE a CA turns on ONE question, asked directly: does the
	// key file itself exist. That is deliberately not "did loadCA return an
	// error satisfying errors.Is(_, os.ErrNotExist)" -- a key that exists
	// with a missing or corrupt CERTIFICATE, or a key that fails to parse,
	// must never be read as "no CA yet, safe to create a fresh one": that
	// would silently replace a private key that might still be exactly
	// right (only its certificate copy went missing) or might be evidence
	// of tampering, either way not something to paper over by regenerating.
	// Only "the key file itself is not there" is the ordinary first-start
	// case.
	_, statErr := os.Stat(keyPath)
	switch {
	case statErr == nil:
		ca, err := loadCA(keyPath, certPath)
		if err != nil {
			return nil, err
		}
		return finishLoadOrCreateCA(cfg, ca)
	case errors.Is(statErr, os.ErrNotExist):
		ca, err := createCA(cfg, keyPath, certPath)
		if err != nil {
			return nil, err
		}
		return finishLoadOrCreateCA(cfg, ca)
	default:
		return nil, fmt.Errorf("gateway: stat the CA private key: %w", statErr)
	}
}

// finishLoadOrCreateCA is LoadOrCreateCA's shared tail: stamp cfg onto ca
// and publish its certificate, if cfg.PublicDir asks for that.
func finishLoadOrCreateCA(cfg CAConfig, ca *CA) (*CA, error) {
	ca.cfg = cfg

	if cfg.PublicDir != "" {
		if err := publishCACert(cfg.PublicDir, ca.certPEM); err != nil {
			return nil, err
		}
	}
	return ca, nil
}

// loadCA reads an existing CA key and certificate. Called only once
// LoadOrCreateCA has confirmed the key file itself exists, so every failure
// here -- a key with no matching certificate, or either file unparseable --
// is a hard failure, reported as itself and returned verbatim: never
// silently papered over by minting a replacement that would orphan
// whatever already trusts the certificate on disk, or discard evidence of
// tampering.
func loadCA(keyPath, certPath string) (*CA, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf(
			"gateway: the CA private key exists at %s but its certificate at %s does not (or cannot be read): %w",
			keyPath, certPath, err)
	}
	key, err := parseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse the CA private key at %s: %w", keyPath, err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse the CA certificate at %s: %w", certPath, err)
	}
	return &CA{cert: cert, certPEM: certPEM, key: key}, nil
}

// createCA mints a fresh CA and writes its key (KeyDir only, 0600) and its
// certificate (KeyDir, 0644 -- public by design) to disk.
func createCA(cfg CAConfig, keyPath, certPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate the CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := cfg.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "innsegl gateway CA", Organization: []string{"innsegl"}},
		NotBefore:             now.Add(-certClockSkewSlack),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("gateway: create the CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse the freshly minted CA certificate: %w", err)
	}

	keyPEM, err := encodeECKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := writeFileExact(keyPath, keyPEM, caKeyFileMode); err != nil {
		return nil, fmt.Errorf("gateway: write the CA private key: %w", err)
	}
	certPEM := encodeCertPEM(der)
	if err := writeFileExact(certPath, certPEM, caCertFileMode); err != nil {
		return nil, fmt.Errorf("gateway: write the CA certificate: %w", err)
	}
	return &CA{cert: cert, certPEM: certPEM, key: key}, nil
}

// publishCACert writes certPEM to dir/CACertFileName, atomically: a
// temporary file, then a rename, so a host command reading it concurrently
// (a git hook firing while the core is starting) never observes a
// half-written certificate.
func publishCACert(dir string, certPEM []byte) error {
	if err := os.MkdirAll(dir, caPublicDirMode); err != nil {
		return fmt.Errorf("gateway: create the CA's public directory: %w", err)
	}
	path := filepath.Join(dir, CACertFileName)
	tmp := path + ".tmp"
	if err := writeFileExact(tmp, certPEM, caCertFileMode); err != nil {
		return fmt.Errorf("gateway: write the CA's published certificate: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("gateway: publish the CA certificate: %w", err)
	}
	return nil
}

// writeFileExact writes data to path with EXACTLY perm, regardless of the
// process umask: os.WriteFile alone only ever narrows perm by the umask, so
// a permissive umask could leave a "0600" key file group- or
// world-readable. The explicit Chmod closes that gap.
func writeFileExact(path string, data []byte, perm os.FileMode) error {
	// #nosec G703 -- path is always this package's own CAConfig.KeyDir or
	// CAConfig.PublicDir (the deployment's own configuration, a compose
	// volume mount or bind mount) joined with one of this file's own
	// literal file names (caKeyFileName, CACertFileName); there is no
	// attacker-controlled input reaching this call.
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	return os.Chmod(path, perm)
}

// issueLeaf mints a fresh short-lived leaf certificate for 127.0.0.1 and
// localhost, signed by ca, valid from now (less clock-skew slack) for
// leafValidity.
func (ca *CA) issueLeaf(now time.Time) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate the leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-certClockSkewSlack),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("gateway: mint a leaf certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse the freshly minted leaf certificate: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// GetCertificate implements the signature tls.Config.GetCertificate wants.
// It returns the current leaf, minting or renewing it first when there is
// none yet or the one on hand is within leafRenewBefore of expiring --
// RM-246's "renewed by the core before expiry". Safe for concurrent use;
// hello is unused (this gateway presents one certificate regardless of SNI)
// but kept in the signature so ca.GetCertificate itself is assignable
// straight into tls.Config.GetCertificate.
func (ca *CA) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := ca.cfg.now()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.leaf != nil && now.Before(ca.leaf.Leaf.NotAfter.Add(-leafRenewBefore)) {
		return ca.leaf, nil
	}
	leaf, err := ca.issueLeaf(now)
	if err != nil {
		return nil, err
	}
	ca.leaf = leaf
	return leaf, nil
}

// ServerTLSConfig is the *tls.Config the gateway's own listener serves:
// GetCertificate is ca's own, so the leaf is minted and renewed
// automatically, and MinVersion is TLS 1.2 -- RM-246's "TLS 1.2+ only".
func (ca *CA) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: ca.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func encodeCertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func encodeECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("gateway: marshal the EC private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func parseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not PEM data")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// randomSerial returns a random, positive certificate serial number, per
// RFC 5280's "unique for each certificate issued by a given CA".
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("gateway: generate a certificate serial: %w", err)
	}
	return serial, nil
}

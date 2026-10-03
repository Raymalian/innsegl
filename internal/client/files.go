// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultListen is the client service's loopback address.
const DefaultListen = "127.0.0.1:28195"

// Paths are the files an enrolled machine holds, under ~/.innsegl/client.
// The harness sandbox denies ~/.innsegl to an agent's shell (only
// ~/.innsegl/ca is readable), so the key is not readable from it.
type Paths struct {
	Dir    string
	Key    string // the machine's private key, 0600
	Cert   string // the client certificate chain, leaf first
	Bundle string // the deployment's trust bundle
	CA     string // the core's own CA, the only root the client trusts for the core
	Core   string // core.json
	// Revoked exists once the core has refused a renewal.
	Revoked string
	// Journal holds what the core could not record (ADR-0068), 0700.
	Journal string
	// ProxyCA and ProxyCAKey are the client's own CA for opening the
	// provider's traffic (RM-329): the certificate is what
	// NODE_EXTRA_CA_CERTS names; the key never leaves this folder.
	ProxyCA    string
	ProxyCAKey string
}

// ClientPaths are the paths under home.
func ClientPaths(home string) Paths {
	dir := filepath.Join(home, ".innsegl", "client")
	return Paths{
		Dir:        dir,
		Key:        filepath.Join(dir, "key.pem"),
		Cert:       filepath.Join(dir, "cert.pem"),
		Bundle:     filepath.Join(dir, "bundle.pem"),
		CA:         filepath.Join(dir, "gateway-ca.pem"),
		Core:       filepath.Join(dir, "core.json"),
		Revoked:    filepath.Join(dir, "revoked"),
		Journal:    filepath.Join(dir, "journal"),
		ProxyCA:    filepath.Join(dir, "proxy-ca.pem"),
		ProxyCAKey: filepath.Join(dir, "proxy-ca-key.pem"),
	}
}

// CoreConfig is core.json.
type CoreConfig struct {
	CoreURL        string `json:"core_url"`
	InstallationID string `json:"installation_id"`
	// Listen is the loopback address the managed settings point at, so the
	// service listens where the harness looks.
	Listen string `json:"listen,omitempty"`
	// ProviderURL is where model requests go when the core does not answer
	// (ADR-0068); empty means DefaultProviderURL.
	ProviderURL string `json:"provider_url,omitempty"`
}

// ErrNotEnrolled means there is no core.json: this machine never connected.
var ErrNotEnrolled = errors.New("this machine is not connected to a core; run `innsegl connect` first")

// ReadCoreConfig reads core.json.
func ReadCoreConfig(p Paths) (CoreConfig, error) {
	var cfg CoreConfig
	text, err := os.ReadFile(p.Core)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, ErrNotEnrolled
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(text, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", p.Core, err)
	}
	if cfg.CoreURL == "" || cfg.InstallationID == "" {
		return cfg, fmt.Errorf("%s names no core_url or installation_id", p.Core)
	}
	return cfg, nil
}

// WriteEnrolment writes everything an enrolment produced. The directory is
// created 0700 and the key 0600; nothing is written before the core has
// answered, so a refused enrolment leaves no state.
func WriteEnrolment(p Paths, e *Enrolment, listen string) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(p.Dir, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(e.Key)
	if err != nil {
		return err
	}
	cfg, err := json.MarshalIndent(CoreConfig{CoreURL: e.CoreURL, InstallationID: e.InstallationID, Listen: listen}, "", "  ")
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{p.Key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600},
		{p.Cert, e.ChainPEM, 0o644},
		{p.Bundle, e.BundlePEM, 0o644},
		{p.CA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.CA.Raw}), 0o644},
		{p.Core, append(cfg, '\n'), 0o644},
	}
	for _, f := range files {
		if err := writeFileAtomic(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// writeFileAtomic replaces path with data in one rename, so a reader never
// sees half a certificate.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// loadKey reads the machine's private key.
func loadKey(path string) (*ecdsa.PrivateKey, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(text)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM key", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// loadCerts reads every certificate in a PEM file.
func loadCerts(path string) ([]*x509.Certificate, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := parseCertsPEM(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return certs, nil
}

func parseCertsPEM(text []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, text = pem.Decode(text)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate")
	}
	return certs, nil
}

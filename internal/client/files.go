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
	Dir string
	// Key is the machine's private key as a file, 0600: where the platform
	// has no hardware key store (Linux; a macOS build without cgo), and on
	// a Mac enrolled before RM-357 until its next renewal moves the key.
	Key string
	// EnclaveKey is, on macOS, the Secure Enclave's wrapped handle to the
	// machine key (RM-357), 0600. It is not a private key: only this Mac's
	// Enclave can use it, and nothing can export the key from it.
	EnclaveKey string
	Cert       string // the client certificate chain, leaf first
	Bundle     string // the deployment's trust bundle
	CA         string // the core's own CA, the only root the client trusts for the core
	Core       string // core.json
	// Revoked exists once the core has refused a renewal.
	Revoked string
	// Outbox holds what the core did not take (ADR-0068): journal entries,
	// telemetry exports and session ends, 0700.
	Outbox string
	// ProxyCA and ProxyCAKey are the client's own CA for opening the
	// provider's traffic (RM-329): the certificate is what
	// NODE_EXTRA_CA_CERTS names; the key never leaves this folder.
	ProxyCA    string
	ProxyCAKey string
	// TrustBackups keeps the copies of the core's encrypted trust-key backup
	// (ADR-0074), 0700, each bundle 0600. Beside the client folder, not in
	// it: it is the operator's, not the enrolment's.
	TrustBackups string
	// TrustIdentity is the operator's age identity: a Secure Enclave key
	// that opens the trust-key backup (ADR-0074) and the CA store's unlock
	// material (ADR-0076), asking for Touch ID each time.
	TrustIdentity string
	// Authors is which repositories author agent commits as the operator
	// rather than the unlinked agent address, and the operator identity they
	// use (ENF-010), 0600. Written by `innsegl author`, read by the hook.
	Authors string
}

// ClientPaths are the paths under home.
func ClientPaths(home string) Paths {
	dir := filepath.Join(home, ".innsegl", "client")
	return Paths{
		Dir:        dir,
		Key:        filepath.Join(dir, "key.pem"),
		EnclaveKey: filepath.Join(dir, "key.se"),
		Cert:       filepath.Join(dir, "cert.pem"),
		Bundle:     filepath.Join(dir, "bundle.pem"),
		CA:         filepath.Join(dir, "gateway-ca.pem"),
		Core:       filepath.Join(dir, "core.json"),
		Revoked:    filepath.Join(dir, "revoked"),
		Outbox:     filepath.Join(dir, "outbox"),
		ProxyCA:    filepath.Join(dir, "proxy-ca.pem"),
		ProxyCAKey: filepath.Join(dir, "proxy-ca-key.pem"),
		// ADR-0074.
		TrustBackups: filepath.Join(home, ".innsegl", "trust-backups"),
		// ADR-0074, ADR-0076.
		TrustIdentity: filepath.Join(home, ".innsegl", "trust-backup", "identity.txt"),
		Authors:       filepath.Join(dir, "authors.json"),
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
	// ServerCertificate is ServerCertificatePublic for a core whose server
	// certificate is publicly trusted (#473); empty for the core's own CA.
	ServerCertificate string `json:"server_certificate,omitempty"`
}

// ErrNotEnrolled means there is no core.json: this machine never connected.
var ErrNotEnrolled = errors.New("this machine is not connected to a core; run `innsegl connect` first")

// ReadCoreConfig reads core.json.
func ReadCoreConfig(p Paths) (CoreConfig, error) {
	var cfg CoreConfig
	if err := TightenState(p.Dir); err != nil {
		return cfg, fmt.Errorf("making %s private: %w", filepath.Dir(p.Dir), err)
	}
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
// created 0700 and the key 0600 (a file key as key.pem, an Enclave key's
// handle as key.se); nothing is written before the core has answered, so a
// refused enrolment leaves no state.
func WriteEnrolment(p Paths, e *Enrolment, listen string) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	if err := TightenState(p.Dir); err != nil {
		return err
	}
	keyPath, keyPEM, err := machineKeyFile(p, e.Key, e.keyBlob)
	if err != nil {
		return err
	}
	core := CoreConfig{CoreURL: e.CoreURL, InstallationID: e.InstallationID, Listen: listen}
	if e.PublicServer {
		core.ServerCertificate = ServerCertificatePublic
	}
	cfg, err := json.MarshalIndent(core, "", "  ")
	if err != nil {
		return err
	}
	files := []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{keyPath, keyPEM, 0o600},
		{p.Cert, e.ChainPEM, 0o600},
		{p.Bundle, e.BundlePEM, 0o600},
		{p.CA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.CA.Raw}), 0o600},
		{p.Core, append(cfg, '\n'), 0o600},
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

// TightenState makes the state folder (~/.innsegl and everything under it)
// private to the operator (RM-349): directories 0700, files with no group or
// other access. It only removes access, never adds it: a file already 0400
// stays 0400. Symbolic links are left alone. A missing folder is not an
// error. dir is Paths.Dir; the folder tightened is its parent.
func TightenState(dir string) error {
	root := filepath.Dir(dir)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		perm := info.Mode().Perm()
		want := perm &^ 0o077
		if d.IsDir() {
			want = 0o700
		}
		if want == perm {
			return nil
		}
		return os.Chmod(path, want) //nolint:gosec // want never exceeds 0700, and only removes access
	})
}

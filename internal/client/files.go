// SPDX-License-Identifier: Apache-2.0

package client

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// Refused records that the core did not accept this certificate. Unlike
	// the legacy Revoked marker, it does not claim the installation is revoked.
	Refused string
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
		Cert:       filepath.Join(dir, "cert.pem"),
		Bundle:     filepath.Join(dir, "bundle.pem"),
		CA:         filepath.Join(dir, "gateway-ca.pem"),
		Core:       filepath.Join(dir, "core.json"),
		Revoked:    filepath.Join(dir, "revoked"),
		Refused:    filepath.Join(dir, "credential-refused"),
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

type fileChange struct {
	path   string
	data   []byte
	mode   os.FileMode
	remove bool
}

type stagedFileChange struct {
	fileChange
	staged    string
	backup    string
	backed    bool
	installed bool
}

// ErrNotEnrolled means there is no core.json: this machine never connected.
var ErrNotEnrolled = errors.New("this machine is not connected to a core; run `innsegl connect` first")

// ErrEnrolmentCommitted marks a cleanup error after all new credential files
// were installed. Callers must not roll back dependent state on this error.
var ErrEnrolmentCommitted = errors.New("the new enrolment was committed but cleanup failed")

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
// created 0700 and the key 0600; nothing is written before the core has
// answered, so a refused enrolment leaves no state.
func WriteEnrolment(p Paths, e *Enrolment, listen string) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	if err := TightenState(p.Dir); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(e.Key)
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
	files := []fileChange{
		{path: p.Key, data: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), mode: 0o600},
		{path: p.Cert, data: e.ChainPEM, mode: 0o600},
		{path: p.Bundle, data: e.BundlePEM, mode: 0o600},
		{path: p.CA, data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.CA.Raw}), mode: 0o600},
		{path: p.Core, data: append(cfg, '\n'), mode: 0o600},
		{path: p.Refused, remove: true},
		{path: p.Revoked, remove: true},
	}
	return writeFilesTransaction(files, os.Rename)
}

// writeFilesTransaction stages every new file first, then replaces the set
// with rollback if any rename fails. Refusal markers are part of the same
// transaction, so a failed replacement cannot clear them while retaining an
// old or mixed credential set.
func writeFilesTransaction(files []fileChange, rename func(string, string) error) error {
	changes := make([]stagedFileChange, len(files))
	cleanup := func() {
		for _, c := range changes {
			if c.staged != "" {
				_ = os.Remove(c.staged)
			}
			if c.backup != "" && !c.backed {
				_ = os.Remove(c.backup)
			}
		}
	}
	for i, f := range files {
		changes[i].fileChange = f
		if f.path == "" {
			continue
		}
		if f.remove {
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(f.path), "."+filepath.Base(f.path)+".stage-*")
		if err != nil {
			cleanup()
			return fmt.Errorf("staging %s: %w", f.path, err)
		}
		changes[i].staged = tmp.Name()
		if err := tmp.Chmod(f.mode); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("staging %s: %w", f.path, err)
		}
		if _, err := tmp.Write(f.data); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("staging %s: %w", f.path, err)
		}
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			cleanup()
			return fmt.Errorf("staging %s: %w", f.path, err)
		}
		if err := tmp.Close(); err != nil {
			cleanup()
			return fmt.Errorf("staging %s: %w", f.path, err)
		}
	}
	rollback := func(cause error, committed int) error {
		var rollbackErr error
		for i := committed - 1; i >= 0; i-- {
			c := &changes[i]
			if c.installed {
				if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove replacement %s: %w", c.path, err))
				}
			}
			if c.backed {
				if err := rename(c.backup, c.path); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore %s from %s: %w", c.path, c.backup, err))
				} else {
					c.backup = ""
				}
			}
		}
		cleanup()
		return errors.Join(cause, rollbackErr)
	}
	for i := range changes {
		c := &changes[i]
		if c.path == "" {
			continue
		}
		info, statErr := os.Lstat(c.path)
		if statErr == nil {
			if !info.Mode().IsRegular() {
				return rollback(fmt.Errorf("refusing to replace non-regular state file %s", c.path), i)
			}
			backup, err := os.CreateTemp(filepath.Dir(c.path), "."+filepath.Base(c.path)+".backup-*")
			if err != nil {
				return rollback(fmt.Errorf("preparing backup for %s: %w", c.path, err), i)
			}
			c.backup = backup.Name()
			if err := backup.Close(); err != nil {
				return rollback(fmt.Errorf("preparing backup for %s: %w", c.path, err), i)
			}
			if err := os.Remove(c.backup); err != nil {
				return rollback(fmt.Errorf("preparing backup for %s: %w", c.path, err), i)
			}
			if err := rename(c.path, c.backup); err != nil {
				return rollback(fmt.Errorf("backing up %s: %w", c.path, err), i)
			}
			c.backed = true
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return rollback(fmt.Errorf("checking %s: %w", c.path, statErr), i)
		}
		if !c.remove {
			if err := rename(c.staged, c.path); err != nil {
				return rollback(fmt.Errorf("installing %s: %w", c.path, err), i+1)
			}
			c.staged = ""
			c.installed = true
		}
	}
	var cleanupErr error
	for _, c := range changes {
		if c.backup != "" {
			if err := os.Remove(c.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("removing credential backup %s: %w", c.backup, err))
			} else {
				c.backup = ""
			}
		}
	}
	cleanup()
	if cleanupErr != nil {
		return fmt.Errorf("%w: %w", ErrEnrolmentCommitted, cleanupErr)
	}
	return nil
}

// ArchiveOutboxForReplacement moves the old installation's pending records
// out of the active outbox before its credentials are replaced. Journal
// entries are signed by the old installation key and cannot be replayed as
// records from the new installation.
func ArchiveOutboxForReplacement(p Paths, installationID string) (string, error) {
	if p.Outbox == "" {
		return "", errors.New("the outbox path is empty")
	}
	if _, err := os.Lstat(p.Outbox); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("checking the current outbox: %w", err)
	}
	if !idShape.MatchString(installationID) {
		return "", fmt.Errorf("invalid installation id %q", installationID)
	}
	archive := filepath.Join(p.Dir, "outbox-recovery-"+installationID)
	if _, err := os.Lstat(archive); err == nil {
		return "", fmt.Errorf("recovery archive already exists at %s", archive)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("checking recovery archive %s: %w", archive, err)
	}
	if err := os.Rename(p.Outbox, archive); err != nil {
		return "", fmt.Errorf("preserving the old installation outbox at %s: %w", archive, err)
	}
	return archive, nil
}

// ArchivedOutbox describes pending records from an installation replaced on
// this machine. Archives are retained for explicit export; they are never
// sent under a different installation certificate.
type ArchivedOutbox struct {
	InstallationID string
	Path           string
	Items          int
	Bytes          int64
}

// ListArchivedOutboxes finds recovery archives left by --replace.
func ListArchivedOutboxes(p Paths) ([]ArchivedOutbox, error) {
	entries, err := os.ReadDir(p.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	const prefix = "outbox-recovery-"
	var out []ArchivedOutbox
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		id := strings.TrimPrefix(name, prefix)
		if !idShape.MatchString(id) || !entry.IsDir() {
			continue
		}
		path := filepath.Join(p.Dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("checking outbox archive %s: %w", path, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("outbox archive %s is not a directory", path)
		}
		items, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("reading outbox archive %s: %w", path, err)
		}
		summary := ArchivedOutbox{InstallationID: id, Path: path}
		for _, item := range items {
			if item.Name() == outboxHeadFile {
				continue
			}
			if _, _, ok := parseItemName(item.Name()); !ok {
				continue
			}
			itemInfo, err := os.Lstat(filepath.Join(path, item.Name()))
			if err != nil {
				return nil, fmt.Errorf("checking archived item %s: %w", item.Name(), err)
			}
			if !itemInfo.Mode().IsRegular() {
				return nil, fmt.Errorf("archived outbox item %s is not a regular file", item.Name())
			}
			summary.Items++
			summary.Bytes += itemInfo.Size()
		}
		out = append(out, summary)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstallationID < out[j].InstallationID })
	return out, nil
}

// ExportArchivedOutbox copies an archive to a new private directory. It
// never modifies or deletes the preserved source records.
func ExportArchivedOutbox(p Paths, installationID, destination string) error {
	if !idShape.MatchString(installationID) {
		return fmt.Errorf("invalid installation id %q", installationID)
	}
	source := filepath.Join(p.Dir, "outbox-recovery-"+installationID)
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("checking archived outbox %s: %w", source, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("archived outbox %s is not a directory", source)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return fmt.Errorf("creating export directory %s: %w", destination, err)
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(destination)
		}
	}()
	for _, entry := range entries {
		from := filepath.Join(source, entry.Name())
		itemInfo, err := os.Lstat(from)
		if err != nil {
			return fmt.Errorf("checking archived file %s: %w", from, err)
		}
		if !itemInfo.Mode().IsRegular() {
			return fmt.Errorf("archived file %s is not a regular file", from)
		}
		in, err := os.Open(from)
		if err != nil {
			return fmt.Errorf("opening archived file %s: %w", from, err)
		}
		to := filepath.Join(destination, entry.Name())
		out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = in.Close()
			return fmt.Errorf("creating export file %s: %w", to, err)
		}
		_, copyErr := io.Copy(out, in)
		inErr := in.Close()
		if copyErr == nil {
			copyErr = out.Sync()
		}
		outErr := out.Close()
		if copyErr != nil || inErr != nil || outErr != nil {
			return errors.Join(fmt.Errorf("exporting archived file %s", from), copyErr, inErr, outErr)
		}
	}
	failed = false
	return nil
}

// RestoreOutboxAfterFailedReplacement returns an archived outbox to its
// active location when replacement aborts before writing new credentials.
func RestoreOutboxAfterFailedReplacement(p Paths, archive string) error {
	if archive == "" {
		return nil
	}
	if filepath.Dir(archive) != p.Dir || !strings.HasPrefix(filepath.Base(archive), "outbox-recovery-") {
		return errors.New("the outbox recovery path is outside the client directory")
	}
	if _, err := os.Lstat(p.Outbox); err == nil {
		return fmt.Errorf("cannot restore the old outbox because %s already exists", p.Outbox)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking the active outbox: %w", err)
	}
	if err := os.Rename(archive, p.Outbox); err != nil {
		return fmt.Errorf("restoring the old outbox from %s: %w", archive, err)
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

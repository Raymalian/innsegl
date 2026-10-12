// SPDX-License-Identifier: Apache-2.0

package client

// The machine key (RM-357, privilege review N7): the private key behind the
// client certificate, which signs every TLS handshake to the core and seals
// every journal entry.
//
// On a Mac it is generated in the Secure Enclave (enclave_darwin.go) and
// cannot be exported or copied: on disk is only key.se, the Enclave's handle
// to it. Where there is no hardware store (Linux; a macOS build without
// cgo) it is a P-256 file, key.pem, 0600 in a 0700 folder.
//
// A Mac enrolled before the Enclave was used still has key.pem. Its next
// renewal moves the key: a new key in the Enclave, a certificate request
// from it, the new certificate, then key.pem overwritten and removed
// (Server.MaybeRenew). Nothing for the operator to do.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Where the machine key is held, as GET /_client/status says.
const (
	MachineKeyFile    = "file"
	MachineKeyEnclave = "secure-enclave"
)

// enclaveKeyPEMType is key.se's one PEM block: the Enclave's handle.
const enclaveKeyPEMType = "INNSEGL SECURE ENCLAVE KEY"

// MachineKey is the enrolled machine's private key, wherever it is held.
type MachineKey interface {
	crypto.Signer
	// Hardware is true for a key a hardware store holds and will not
	// export.
	Hardware() bool
}

// keyVault is a hardware key store.
type keyVault interface {
	name() string
	// generate makes a new P-256 key and answers it with the store's
	// handle to it, the bytes load takes back.
	generate() (MachineKey, []byte, error)
	load(handle []byte) (MachineKey, error)
}

// hardwareVault is this machine's hardware key store, nil where there is
// none. Tests replace it.
var hardwareVault = platformVault()

// fileKey is a machine key held in memory, read from key.pem.
type fileKey struct{ *ecdsa.PrivateKey }

func (fileKey) Hardware() bool { return false }

// newMachineKey is a new machine key: in the hardware store when there is
// one that works, otherwise in memory, to be written as key.pem. handle is
// the store's handle, nil for a file key.
func newMachineKey() (key MachineKey, handle []byte, err error) {
	if hardwareVault != nil {
		if key, handle, err = hardwareVault.generate(); err == nil {
			return key, handle, nil
		}
		// A Mac without a Secure Enclave (an Intel Mac without a T2 chip)
		// keeps a file key.
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return fileKey{k}, nil, nil
}

// machineKeyFile is the file that holds key, and its contents: key.se with
// the handle for a hardware key, key.pem with the private key otherwise.
func machineKeyFile(p Paths, key MachineKey, handle []byte) (string, []byte, error) {
	if key.Hardware() {
		if len(handle) == 0 {
			return "", nil, errors.New("a hardware machine key without its handle")
		}
		return p.EnclaveKey, pem.EncodeToMemory(&pem.Block{Type: enclaveKeyPEMType, Bytes: handle}), nil
	}
	fk, ok := key.(fileKey)
	if !ok {
		return "", nil, fmt.Errorf("a file machine key of type %T", key)
	}
	der, err := x509.MarshalECPrivateKey(fk.PrivateKey)
	if err != nil {
		return "", nil, err
	}
	return p.Key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// loadMachineKey is the machine key whose public half is want, the client
// certificate's. key.se is tried first, then key.pem. When both are there,
// a move into the Enclave was cut short: the one the certificate names is
// kept, and the other removed (key.pem shredded).
func loadMachineKey(p Paths, want crypto.PublicKey) (MachineKey, error) {
	hw, hwErr := loadEnclaveKey(p.EnclaveKey)
	file, fileErr := loadFileKey(p.Key)
	matches := func(k MachineKey) bool {
		pub, ok := k.Public().(*ecdsa.PublicKey)
		return ok && pub.Equal(want)
	}
	switch {
	case hwErr == nil && matches(hw):
		if err := shredFile(p.Key); err != nil {
			return nil, fmt.Errorf("removing %s, the key the Secure Enclave replaced: %w", p.Key, err)
		}
		return hw, nil
	case fileErr == nil && matches(file):
		if !errors.Is(hwErr, fs.ErrNotExist) {
			// A handle no certificate names: the move never finished.
			if err := os.Remove(p.EnclaveKey); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		}
		return file, nil
	case hwErr != nil && !errors.Is(hwErr, fs.ErrNotExist):
		return nil, hwErr
	case fileErr != nil && !errors.Is(fileErr, fs.ErrNotExist):
		return nil, fileErr
	case hwErr != nil && fileErr != nil:
		return nil, fmt.Errorf("no machine key: neither %s nor %s is there", p.EnclaveKey, p.Key)
	default:
		return nil, errors.New("the machine key is not the client certificate's")
	}
}

// loadEnclaveKey opens the hardware key key.se names.
func loadEnclaveKey(path string) (MachineKey, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(text)
	if block == nil || block.Type != enclaveKeyPEMType {
		return nil, fmt.Errorf("%s holds no %s block", path, enclaveKeyPEMType)
	}
	if hardwareVault == nil {
		return nil, fmt.Errorf("the machine key is in the Secure Enclave (%s), and this innsegl was built without "+
			"Secure Enclave support (not macOS, or cgo off); build it on this Mac with `make build`", path)
	}
	return hardwareVault.load(block.Bytes)
}

// loadFileKey reads key.pem, refusing one that group or other can read.
func loadFileKey(path string) (MachineKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is %04o: a machine key must be readable by its owner only (0600)", path, perm)
	}
	k, err := loadKey(path)
	if err != nil {
		return nil, err
	}
	return fileKey{k}, nil
}

// LoadClientCertificate is the enrolled machine's client certificate with
// its machine key, wherever the key is held.
func LoadClientCertificate(p Paths) (tls.Certificate, error) {
	chain, err := loadCerts(p.Cert)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := loadMachineKey(p, chain[0].PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ders := make([][]byte, len(chain))
	for i, c := range chain {
		ders[i] = c.Raw
	}
	return tls.Certificate{Certificate: ders, PrivateKey: key, Leaf: chain[0]}, nil
}

// shredHook, when set, sees the file after it is overwritten and before it
// is removed. Tests only.
var shredHook func(*os.File)

// shredFile overwrites path with random bytes, syncs, and removes it. On a
// copy-on-write or flash file system the old blocks may survive the
// overwrite; it still keeps the key out of the file and out of any later
// read of it. A missing file is not an error.
func shredFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if errors.Is(err, fs.ErrPermission) {
		// A key file made read-only (0400): the owner may write it again.
		if cerr := os.Chmod(path, 0o600); cerr != nil {
			return err
		}
		f, err = os.OpenFile(path, os.O_WRONLY, 0)
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	noise := make([]byte, info.Size())
	if _, err = rand.Read(noise); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.WriteAt(noise, 0); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if shredHook != nil {
		shredHook(f)
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

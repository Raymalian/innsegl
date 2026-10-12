// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/clientjournal"
)

// fakeVault stands in for the Secure Enclave on every platform: its "blob"
// is a software key, so the renewal migration is tested where there is no
// Enclave. The real Enclave is CLI-056.
type fakeVault struct{ refuse bool }

type fakeHardwareKey struct{ *ecdsa.PrivateKey }

func (fakeHardwareKey) Hardware() bool { return true }

const fakeBlobPrefix = "fake-enclave:"

func (v fakeVault) name() string { return "test vault" }

func (v fakeVault) generate() (MachineKey, []byte, error) {
	if v.refuse {
		return nil, nil, errors.New("the test vault refuses")
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return fakeHardwareKey{k}, append([]byte(fakeBlobPrefix), der...), nil
}

func (v fakeVault) load(blob []byte) (MachineKey, error) {
	der, ok := bytes.CutPrefix(blob, []byte(fakeBlobPrefix))
	if !ok {
		return nil, errors.New("not a test vault blob")
	}
	k, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return fakeHardwareKey{k}, nil
}

// useVault makes v the machine's hardware key store for one test.
func useVault(t *testing.T, v keyVault) {
	t.Helper()
	old := hardwareVault
	hardwareVault = v
	t.Cleanup(func() { hardwareVault = old })
}

func publicOf(t *testing.T, k crypto.Signer) *ecdsa.PublicKey {
	t.Helper()
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the key's public half is %T, not ECDSA", k.Public())
	}
	return pub
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// CLI-055 (PROPOSED for doc 07's TC-CLI) — where the platform has no
// hardware key store (Linux; a macOS build without cgo), the machine key is
// a P-256 file, 0600 in a 0700 folder; the service refuses a key file that
// group or other can read, and loads it only as the certificate's own key.
// Runs everywhere.
func TestCLI055WithoutHardwareTheMachineKeyIsAPrivateFile(t *testing.T) {
	useVault(t, nil)
	core, paths := enrolled(t)
	if !exists(paths.Key) || exists(paths.EnclaveKey) {
		t.Fatalf("without a hardware store: key.pem present=%v, key.se present=%v; want only key.pem",
			exists(paths.Key), exists(paths.EnclaveKey))
	}
	if m := modeOf(t, paths.Key); m != 0o600 {
		t.Errorf("key.pem is %o, want 0600", m)
	}
	if m := modeOf(t, paths.Dir); m != 0o700 {
		t.Errorf("%s is %o, want 0700", paths.Dir, m)
	}
	srv, _, _ := startClient(t, paths)
	if got := srv.Status(context.Background()).MachineKey; got != MachineKeyFile {
		t.Errorf("status machine_key = %q, want %q", got, MachineKeyFile)
	}
	_ = core

	// A key file someone else can read is refused, not used.
	cert, err := loadCerts(paths.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(paths.Key, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err = loadMachineKey(paths, cert[0].PublicKey); err == nil || !strings.Contains(err.Error(), "0640") {
		t.Fatalf("a 0640 key file loaded (err %v); it must be refused, naming its mode", err)
	}
	if err = os.Chmod(paths.Key, 0o600); err != nil {
		t.Fatal(err)
	}

	// A key that is not the certificate's is refused.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = loadMachineKey(paths, &other.PublicKey); err == nil {
		t.Fatal("the machine key loaded for a certificate of another key")
	}

	// LoadClientCertificate pairs the certificate with the key, whatever holds it.
	pair, err := LoadClientCertificate(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pair.PrivateKey.(crypto.Signer); !ok || pair.Leaf == nil {
		t.Fatalf("LoadClientCertificate: key %T, leaf %v", pair.PrivateKey, pair.Leaf)
	}
}

// enclaveOrSkip is the real Secure Enclave, or a skip saying why there is none.
func enclaveOrSkip(t *testing.T) keyVault {
	t.Helper()
	v := platformVault()
	if v == nil {
		t.Skip("no Secure Enclave in this build: the Enclave is macOS-only and needs cgo " +
			"(this is GOOS=" + runtime.GOOS + "); CLI-055 covers the file key here")
	}
	if _, _, err := v.generate(); err != nil {
		t.Skipf("this Mac has no usable Secure Enclave (%v); CLI-055 covers the file key", err)
	}
	return v
}

// CLI-056 (PROPOSED for doc 07's TC-CLI) — on macOS the machine key is a
// non-exportable P-256 key in the Secure Enclave. On disk is only the
// Enclave's wrapped handle (key.se, 0600), which no software can turn into
// a private key and which no other Mac's Enclave opens. Signing asks for no
// user presence, so the service works unattended. The key reloads from the
// handle, signs the TLS handshake through crypto.Signer, and seals journal
// entries. Runs on a Mac (with cgo); skips elsewhere, saying why.
func TestCLI056OnMacOSTheMachineKeyLivesInTheSecureEnclave(t *testing.T) {
	v := enclaveOrSkip(t)
	useVault(t, v)

	key, blob, err := v.generate()
	if err != nil {
		t.Fatal(err)
	}
	if !key.Hardware() {
		t.Fatal("an Enclave key says it is not hardware")
	}
	// The handle is not a private key in any form software reads.
	if _, perr := x509.ParseECPrivateKey(blob); perr == nil {
		t.Fatal("the Enclave handle parses as an EC private key")
	}
	if _, perr := x509.ParsePKCS8PrivateKey(blob); perr == nil {
		t.Fatal("the Enclave handle parses as a PKCS#8 private key")
	}
	again, err := v.load(blob)
	if err != nil {
		t.Fatalf("reloading the Enclave key from its handle: %v", err)
	}
	if !publicOf(t, again).Equal(publicOf(t, key)) {
		t.Fatal("the reloaded Enclave key is another key")
	}
	sum := sha256.Sum256([]byte("innsegl CLI-056"))
	sig, err := again.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("signing with the Enclave key (no user presence may be asked): %v", err)
	}
	if !ecdsa.VerifyASN1(publicOf(t, key), sum[:], sig) {
		t.Fatal("the Enclave's signature does not verify under its public key")
	}

	// A journal entry sealed by the Enclave key opens under its public key.
	sealed, err := clientjournal.Seal(clientjournal.Entry{Seq: 1, InstallationID: strings.Repeat("a", 32)}, again)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sealed.Open(again.Public()); err != nil {
		t.Fatalf("an Enclave-sealed entry does not open: %v", err)
	}

	// Enrolment on this Mac puts the key in the Enclave: key.se, no key.pem.
	core, paths := enrolled(t)
	if exists(paths.Key) || !exists(paths.EnclaveKey) {
		t.Fatalf("after enrolment on a Mac: key.pem present=%v, key.se present=%v; want only key.se",
			exists(paths.Key), exists(paths.EnclaveKey))
	}
	if m := modeOf(t, paths.EnclaveKey); m != 0o600 {
		t.Errorf("key.se is %o, want 0600", m)
	}
	if typ := pemBlockType(t, paths.EnclaveKey); typ != enclaveKeyPEMType {
		t.Errorf("key.se holds a %q block, want %q", typ, enclaveKeyPEMType)
	}
	// The mutual TLS handshake is signed by the Enclave: the core sees the
	// certificate, and the service says where its key is.
	core.Mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "pong") })
	srv, front, _ := startClient(t, paths)
	resp, err := http.Get(front.URL + "/ping") //nolint:noctx // a one-shot test request
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "pong" {
		t.Fatalf("through the Enclave-signed handshake the core answered %d %q", resp.StatusCode, body)
	}
	if got := srv.Status(context.Background()).MachineKey; got != MachineKeyEnclave {
		t.Errorf("status machine_key = %q, want %q", got, MachineKeyEnclave)
	}
	pair, err := LoadClientCertificate(paths)
	if err != nil {
		t.Fatal(err)
	}
	if mk, ok := pair.PrivateKey.(MachineKey); !ok || !mk.Hardware() {
		t.Fatalf("LoadClientCertificate's key is %T, not the Enclave's", pair.PrivateKey)
	}
	// A plain TLS client with the Enclave key completes a handshake against
	// a server that requires a client certificate.
	handshakeWithClientCert(t, pair)
}

func handshakeWithClientCert(t *testing.T, pair tls.Certificate) {
	t.Helper()
	pool := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(c)
	}
	var seen *x509.Certificate
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.TLS.PeerCertificates[0]
	}))
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()
	c := ts.Client()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.Transport)
	}
	tr.TLSClientConfig.Certificates = []tls.Certificate{pair}
	resp, err := c.Get(ts.URL) //nolint:noctx // a one-shot test request
	if err != nil {
		t.Fatalf("a handshake signed by the machine key failed: %v", err)
	}
	_ = resp.Body.Close()
	if seen == nil || !seen.Equal(pair.Leaf) {
		t.Fatal("the server did not see the machine's certificate")
	}
}

// renewDue renews srv's certificate as if its half-life had passed.
func renewDue(t *testing.T, srv *Server) (bool, error) {
	t.Helper()
	leaf := srv.Leaf()
	srv.Now = func() time.Time { return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore)*2/3 + time.Minute) }
	return srv.MaybeRenew(context.Background())
}

// CLI-057 (PROPOSED for doc 07's TC-CLI) — an enrolled machine whose key is
// still a file moves it into hardware at its next renewal, with nothing for
// the operator to do: a new key in the store, a certificate request from it,
// the new certificate, and the old key file overwritten and removed. A
// renewal that fails leaves the file key in use; journal entries still
// waiting under the file key hold the move back until they are delivered;
// and a move cut short between writing the handle and the certificate is
// finished at the next start. Runs everywhere with a stand-in store.
func TestCLI057RenewalMovesAFileKeyIntoHardware(t *testing.T) {
	migrationCases(t, fakeVault{})
}

// CLI-057, against the real Secure Enclave. Runs on a Mac; skips elsewhere.
func TestCLI057RenewalMovesAFileKeyIntoTheSecureEnclave(t *testing.T) {
	migrationCases(t, enclaveOrSkip(t))
}

func migrationCases(t *testing.T, vault keyVault) {
	t.Run("moves", func(t *testing.T) {
		useVault(t, nil)
		core, paths := enrolled(t)
		core.Mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "pong") })
		srv, front, logs := startClient(t, paths)
		oldPub := publicOf(t, srv.key)
		oldKeyFile := readFile(t, paths.Key)

		useVault(t, vault)
		renewed, err := renewDue(t, srv)
		if err != nil || !renewed {
			t.Fatalf("renewal: renewed=%v err=%v", renewed, err)
		}
		csrPub, ok := core.LastCSR().PublicKey.(*ecdsa.PublicKey)
		if !ok || csrPub.Equal(oldPub) {
			t.Fatal("the renewal's request came from the old file key; it must come from the new hardware key")
		}
		leafPub := publicOf(t, srv.key)
		if certPub, ok := srv.Leaf().PublicKey.(*ecdsa.PublicKey); !ok || !leafPub.Equal(csrPub) || !certPub.Equal(csrPub) {
			t.Fatal("the service does not use the new key and its certificate together")
		}
		if exists(paths.Key) {
			t.Fatal("key.pem is still on disk after the move")
		}
		if !exists(paths.EnclaveKey) || modeOf(t, paths.EnclaveKey) != 0o600 {
			t.Fatal("key.se is missing or not 0600 after the move")
		}
		if bytes.Contains(readFile(t, paths.EnclaveKey), oldKeyFile) {
			t.Fatal("the old key's bytes are in key.se")
		}
		if !strings.Contains(logs.String(), vault.name()) {
			t.Errorf("the log does not say the key moved into the %s: %q", vault.name(), logs.String())
		}
		if got := srv.Status(context.Background()).MachineKey; got != MachineKeyEnclave {
			t.Errorf("status machine_key = %q after the move", got)
		}
		// The next request presents the new certificate.
		resp, err := http.Get(front.URL + "/ping") //nolint:noctx // a one-shot test request
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		serials := core.SeenSerials()
		if len(serials) == 0 || serials[len(serials)-1].Cmp(srv.Leaf().SerialNumber) != 0 {
			t.Fatal("the core did not see the certificate of the new key")
		}
		// A restarted service loads the hardware key.
		again, err := NewServer(paths, io.Discard)
		if err != nil {
			t.Fatalf("restart after the move: %v", err)
		}
		if !publicOf(t, again.key).Equal(csrPub) || !again.key.Hardware() {
			t.Fatal("a restart did not load the hardware key")
		}
		// The next renewal keeps the hardware key.
		renewed, err = renewDue(t, srv)
		if err != nil || !renewed {
			t.Fatalf("second renewal: renewed=%v err=%v", renewed, err)
		}
		if p, ok := core.LastCSR().PublicKey.(*ecdsa.PublicKey); !ok || !p.Equal(csrPub) {
			t.Fatal("a renewal of a hardware key changed the key")
		}
	})

	t.Run("a failed renewal keeps the file key", func(t *testing.T) {
		useVault(t, nil)
		core, paths := enrolled(t)
		srv, _, _ := startClient(t, paths)
		oldPub := publicOf(t, srv.key)
		useVault(t, vault)
		core.SetUnavailable(true)
		if renewed, err := renewDue(t, srv); err == nil || renewed {
			t.Fatalf("renewal against an unavailable core: renewed=%v err=%v", renewed, err)
		}
		if !exists(paths.Key) || exists(paths.EnclaveKey) || !publicOf(t, srv.key).Equal(oldPub) {
			t.Fatal("a failed renewal changed the key on disk or in use")
		}
		core.SetUnavailable(false)
		if renewed, err := renewDue(t, srv); err != nil || !renewed {
			t.Fatalf("the retry: renewed=%v err=%v", renewed, err)
		}
		if exists(paths.Key) || !srv.key.Hardware() {
			t.Fatal("the retry did not move the key")
		}
	})

	t.Run("held journal entries hold the move back", func(t *testing.T) {
		useVault(t, nil)
		core, paths := enrolled(t)
		srv, _, logs := startClient(t, paths)
		oldPub := publicOf(t, srv.key)
		if _, err := srv.outbox.appendExchange(clientjournal.Entry{}); err != nil {
			t.Fatal(err)
		}
		useVault(t, vault)
		renewed, err := renewDue(t, srv)
		if err != nil || !renewed {
			t.Fatalf("renewal with a held entry: renewed=%v err=%v", renewed, err)
		}
		if p, ok := core.LastCSR().PublicKey.(*ecdsa.PublicKey); !ok || !p.Equal(oldPub) {
			t.Fatal("the key moved while an entry sealed by the file key waited; the core would refuse that entry")
		}
		if !exists(paths.Key) || exists(paths.EnclaveKey) {
			t.Fatal("the key files changed while the move was held back")
		}
		if !strings.Contains(logs.String(), "journal") {
			t.Errorf("the log does not say why the key did not move: %q", logs.String())
		}
	})

	t.Run("a move cut short is finished at the next start", func(t *testing.T) {
		useVault(t, nil)
		_, paths := enrolled(t)
		srv, _, _ := startClient(t, paths)
		useVault(t, vault)
		if renewed, err := renewDue(t, srv); err != nil || !renewed {
			t.Fatalf("renewal: renewed=%v err=%v", renewed, err)
		}
		newHandle := readFile(t, paths.EnclaveKey)

		// Cut short before the certificate: the handle is new, the
		// certificate and key.pem are the old ones. The file key is used and
		// the unused handle removed.
		useVault(t, nil)
		_, paths2 := enrolled(t)
		useVault(t, vault)
		oldCert := readFile(t, paths2.Cert)
		if err := writeFileAtomic(paths2.EnclaveKey, newHandle, 0o600); err != nil {
			t.Fatal(err)
		}
		s2, err := NewServer(paths2, io.Discard)
		if err != nil {
			t.Fatalf("start with an unused handle beside the file key: %v", err)
		}
		if s2.key.Hardware() || exists(paths2.EnclaveKey) || !bytes.Equal(oldCert, readFile(t, paths2.Cert)) {
			t.Fatal("an unused handle was not set aside in favour of the certificate's file key")
		}

		// Cut short after the certificate: key.pem is still there beside the
		// handle the certificate names. The handle is used and key.pem shredded.
		if werr := writeFileAtomic(paths.Key, []byte("-----BEGIN EC PRIVATE KEY-----\nold\n-----END EC PRIVATE KEY-----\n"), 0o600); werr != nil {
			t.Fatal(werr)
		}
		s3, err := NewServer(paths, io.Discard)
		if err != nil {
			t.Fatalf("start with a leftover key.pem: %v", err)
		}
		if !s3.key.Hardware() || exists(paths.Key) {
			t.Fatal("a leftover key.pem was not removed once the certificate named the hardware key")
		}
	})
}

// shredFile overwrites before it removes: the old bytes are not left in the
// file's blocks for a plain read of the disk to find.
func TestCLI057ShredOverwritesThenRemoves(t *testing.T) {
	path := shortTempDir(t) + "/key.pem"
	secret := bytes.Repeat([]byte("S"), 300)
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	var overwritten []byte
	shredHook = func(f *os.File) {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Error(err)
		}
		overwritten = b
	}
	t.Cleanup(func() { shredHook = nil })
	if err := shredFile(path); err != nil {
		t.Fatal(err)
	}
	if exists(path) {
		t.Fatal("the shredded file is still there")
	}
	if len(overwritten) != len(secret) || bytes.Contains(overwritten, []byte("SSSS")) {
		t.Fatalf("before removal the file held %d bytes, still the secret's: %q", len(overwritten), overwritten)
	}
	if err := shredFile(path); err != nil {
		t.Fatalf("shredding a file already gone: %v", err)
	}
}

// pemBlockType is the type of the first PEM block in path.
func pemBlockType(t *testing.T, path string) string {
	t.Helper()
	b, _ := pem.Decode(readFile(t, path))
	if b == nil {
		return ""
	}
	return b.Type
}

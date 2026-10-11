// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// OPS-146 (PROPOSED for doc 07's TC-OPS) — `innsegl ca-custodian` refuses to
// start without what it needs, and says which (#533, ADR-0076). A custodian
// with no recipient would seal the unlock material to nobody; one with no
// store address would report a sealed CA forever.
func TestOPS146TheCustodianNamesWhatItIsMissing(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
		code int
	}{
		{"no verb", nil, nil, "init, serve, ready or restore", exitUsage},
		{"unknown verb", []string{"export"}, nil, "init, serve, ready or restore", exitUsage},
		{"no store", []string{"init"}, map[string]string{envCARecipients: id.Recipient().String(),
			envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"}, envCAStoreAddr, exitCACustodyFailed},
		{"no recipient", []string{"init"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"}, envCARecipients, exitCACustodyFailed},
		{"no directory", []string{"serve"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCARecipients: id.Recipient().String(), envCATokenPath: t.TempDir() + "/t"}, envCADir, exitCACustodyFailed},
		{"unreachable store", []string{"init"}, map[string]string{envCAStoreAddr: "http://127.0.0.1:1",
			envCARecipients: id.Recipient().String(), envCADir: t.TempDir(), envCATokenPath: t.TempDir() + "/t"},
			"not answering", exitCACustodyFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			getenv := func(k string) string { return c.env[k] }
			code := runCACustodian(t.Context(), c.args, &out, &errOut, getenv)
			if code != c.code || !strings.Contains(errOut.String(), c.want) {
				t.Fatalf("exit %d (want %d), stderr %q (want it to name %q)", code, c.code, errOut.String(), c.want)
			}
		})
	}
}

// readyStore is a stand-in for the store's answers that `ready` reads. The
// answers themselves are tested against the real store in
// internal/cacustody (OPS-183..OPS-186); this is the command's wiring.
type readyStore struct {
	sealed, initialised, refused bool
	key                          *ecdsa.PrivateKey
}

func newReadyStore(t *testing.T) (*readyStore, *httptest.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rs := &readyStore{sealed: true, initialised: true, key: key}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"initialized":%t,"sealed":%t}`, rs.initialised, rs.sealed)
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		if rs.refused {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"errors":["permission denied"]}`)
			return
		}
		fmt.Fprint(w, `{"data":{"ttl":3600}}`)
	})
	mux.HandleFunc("/v1/transit/keys/innsegl-ca", func(w http.ResponseWriter, _ *http.Request) {
		b, err := json.Marshal(map[string]any{"data": map[string]any{"latest_version": 1,
			"keys": map[string]any{"1": map[string]string{"public_key": pubPEM}}}})
		if err != nil {
			t.Error(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Error(err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return rs, srv
}

func readyEnv(t *testing.T, storeURL string) map[string]string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{envCAStoreAddr: storeURL, envCARecipients: id.Recipient().String(),
		envCADir: t.TempDir(), envCATokenPath: filepath.Join(t.TempDir(), ".vault-token")}
}

func runReady(t *testing.T, env map[string]string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runCACustodian(t.Context(), []string{"ready"}, &out, &errOut, func(k string) string { return env[k] })
	return code, errOut.String()
}

// OPS-146 (PROPOSED) — `ready` is the custodian container's health: the
// store answers, is initialised and unlocked, and the CA can sign. Fulcio's
// bootstrap waits for it, so it must say no to each missing piece.
func TestOPS146ReadyIsTheStoreUnlockedAndATokenWritten(t *testing.T) {
	rs, store := newReadyStore(t)
	env := readyEnv(t, store.URL)
	if code, _ := runReady(t, env); code != exitCACustodyFailed {
		t.Fatalf("a sealed store is ready: exit %d", code)
	}
	rs.sealed = false
	if code, _ := runReady(t, env); code != exitCACustodyFailed {
		t.Fatalf("an unlocked store with no token written is ready: exit %d", code)
	}
	if err := os.WriteFile(env[envCATokenPath], []byte("s.token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, msg := runReady(t, env); code != exitOK {
		t.Fatalf("an unlocked store with a working token is not ready: exit %d: %s", code, msg)
	}
	rs.initialised = false
	if code, _ := runReady(t, env); code != exitCACustodyFailed {
		t.Fatalf("an uninitialised store is ready: exit %d", code)
	}
}

// OPS-185 (PROPOSED) — a token file the store refuses is not ready, and
// `ready` says why. The token file existing is not the CA able to sign.
func TestOPS185ReadyRefusesATokenTheStoreRefuses(t *testing.T) {
	rs, store := newReadyStore(t)
	rs.sealed = false
	env := readyEnv(t, store.URL)
	if err := os.WriteFile(env[envCATokenPath], []byte("s.token"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs.refused = true
	code, msg := runReady(t, env)
	if code == exitOK || !strings.Contains(msg, "token was refused") {
		t.Fatalf("a refused token: exit %d, %q; want non-zero, naming the refusal", code, msg)
	}
}

// OPS-186 (PROPOSED) — with INNSEGL_CA_CHAIN_PATH set, `ready` compares the
// store's key with the chain the CA presents, and names a drift.
func TestOPS186ReadyNamesAChainThatDrifted(t *testing.T) {
	rs, store := newReadyStore(t)
	rs.sealed = false
	env := readyEnv(t, store.URL)
	if err := os.WriteFile(env[envCATokenPath], []byte("s.token"), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &other.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	env[envCAChainPath] = filepath.Join(t.TempDir(), "chain.pem")
	if err = os.WriteFile(env[envCAChainPath], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	code, msg := runReady(t, env)
	if code == exitOK || !strings.Contains(msg, "drifted") {
		t.Fatalf("a drifted chain: exit %d, %q; want non-zero, naming the drift", code, msg)
	}
}

// OPS-155 (PROPOSED) — `restore SNAPSHOT` puts a backup's store into a new
// store, sealed under the original keys, for the operator's machine to
// unlock. It names what it is missing, and refuses a store that holds data.
func TestOPS155RestoreNamesWhatItNeedsAndRefusesAStoreWithData(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	initialised := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"initialized":true,"sealed":true}`)
	}))
	defer initialised.Close()
	snap := filepath.Join(t.TempDir(), "store.snap")
	if err = os.WriteFile(snap, []byte("snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{envCAStoreAddr: initialised.URL, envCARecipients: id.Recipient().String(),
		envCADir: t.TempDir(), envCATokenPath: filepath.Join(t.TempDir(), "t")}
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := runCACustodian(t.Context(), args, &out, &errOut, func(k string) string { return env[k] })
		return code, errOut.String()
	}
	if code, msg := run("restore"); code != exitUsage || !strings.Contains(msg, "snapshot") {
		t.Fatalf("restore with no snapshot: exit %d: %s", code, msg)
	}
	if code, msg := run("restore", filepath.Join(t.TempDir(), "absent")); code != exitCACustodyFailed || !strings.Contains(msg, "absent") {
		t.Fatalf("restore of an absent file: exit %d: %s", code, msg)
	}
	if code, msg := run("restore", snap); code != exitCACustodyFailed || !strings.Contains(msg, "initialised") {
		t.Fatalf("restore over a store with data: exit %d: %s", code, msg)
	}
}

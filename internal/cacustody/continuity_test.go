// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// OPS-183..OPS-186 (PROPOSED for doc 07's TC-OPS) — signing continuity
// (#582). The CA's token outlives any custodian process, and the custodian's
// status says whether the CA can sign by testing it: the store unsealed, the
// token alive, the CA key readable with it, and that key the one in the
// certificate the CA presents.
// ---------------------------------------------------------------------------

// shortPeriod is the role period these tests give the store, so a token
// that is not renewed dies within the test.
const shortPeriod = 9 * time.Second

// newShortCustodian is an initialised custodian whose tokens live for
// shortPeriod without a renewal.
func newShortCustodian(t *testing.T) custodianFixture {
	t.Helper()
	f := newCustodian(t)
	f.c.Store.Period = shortPeriod
	if err := f.c.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return f
}

// restarted is the custodian a container recreate starts: the same store,
// the same token file, no memory of the last one.
func restarted(f custodianFixture) *Custodian {
	return &Custodian{Store: &Store{Addr: f.c.Store.Addr, Period: f.c.Store.Period},
		Dir: f.c.Dir, TokenPath: f.c.TokenPath, Key: f.c.Key, Recipients: f.c.Recipients, Log: f.log}
}

func tokenTTL(t *testing.T, s *Store, tok string) time.Duration {
	t.Helper()
	ttl, err := s.TTL(context.Background(), tok)
	if err != nil {
		t.Fatalf("looking the CA's token up: %v", err)
	}
	return ttl
}

// OPS-183 (PROPOSED) — a new custodian renews the CA's token when it
// starts, not one renewal period later.
func TestOPS183ANewCustodianRenewsAtStart(t *testing.T) {
	f := newShortCustodian(t)
	tok := readToken(t, f.c.TokenPath)
	time.Sleep(4 * time.Second)
	if ttl := tokenTTL(t, f.c.Store, tok); ttl > shortPeriod-3*time.Second {
		t.Fatalf("the token's TTL is %v after 4 s; the store is not counting it down", ttl)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go restarted(f).RunRenewer(ctx, time.Hour)
	deadline := time.Now().Add(3 * time.Second)
	for {
		ttl := tokenTTL(t, f.c.Store, tok)
		if ttl >= shortPeriod-time.Second {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("3 s after a new custodian started the token's TTL is %v; it did not renew at start", ttl)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// OPS-184 (PROPOSED) — the custodian recreated every period/3, for three
// periods, never once living long enough to reach a scheduled renewal: the
// token stays valid and the CA can still sign.
func TestOPS184TheTokenOutlivesAnyNumberOfRestarts(t *testing.T) {
	f := newShortCustodian(t)
	tok := readToken(t, f.c.TokenPath)
	end := time.Now().Add(3 * shortPeriod)
	for time.Now().Before(end) {
		ctx, cancel := context.WithCancel(context.Background())
		go restarted(f).RunRenewer(ctx, time.Hour)
		time.Sleep(shortPeriod / 3)
		cancel()
	}
	if ttl := tokenTTL(t, f.c.Store, tok); ttl <= 0 {
		t.Fatalf("after three periods of restarts the token's TTL is %v", ttl)
	}
	if st := f.c.Status(context.Background()); !st.CanSign {
		t.Fatalf("after three periods of restarts the CA cannot sign: %+v", st)
	}
}

// OPS-185 (PROPOSED) — a token the store refuses is reported at once:
// Status says the CA cannot sign and why, and the renewer logs the refusal
// within one tick.
func TestOPS185ARevokedTokenIsReportedWithinOneTick(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.c.Status(ctx); !st.CanSign || st.Reason != "" {
		t.Fatalf("a freshly initialised CA reports %+v; want it able to sign", st)
	}
	if err := f.c.Store.RevokeSelf(ctx, readToken(t, f.c.TokenPath)); err != nil {
		t.Fatal(err)
	}

	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tick := 300 * time.Millisecond
	go f.c.RunRenewer(rctx, tick)
	time.Sleep(2 * tick)
	cancel()

	st := f.c.Status(ctx)
	if st.CanSign || st.Sealed {
		t.Fatalf("with its token revoked the CA reports %+v; want unsealed and unable to sign", st)
	}
	if !strings.Contains(st.Reason, "token was refused") {
		t.Fatalf("the reason %q does not say the token was refused", st.Reason)
	}
	if !strings.Contains(f.log.String(), "refused") {
		t.Fatalf("the renewer did not log the refusal within one tick:\n%s", f.log.String())
	}
}

// OPS-186 (PROPOSED) — a store key that is not the key in the certificate
// the CA presents is a CA that cannot sign, and the reason names the drift.
// No chain written yet (the bootstrap mints it after the custodian is
// ready) is not drift.
func TestOPS186AStoreKeyThatDriftedFromTheChainCannotSign(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	f.c.ChainPath = filepath.Join(t.TempDir(), "chain.pem")
	if st := f.c.Status(ctx); !st.CanSign {
		t.Fatalf("with no chain written yet the CA reports %+v; want able to sign", st)
	}

	pubPEM, err := f.c.Store.PublicKey(ctx, readToken(t, f.c.TokenPath), f.c.Key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatalf("the store's public key is not PEM: %q", pubPEM)
	}
	storePub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	writeChain(t, f.c.ChainPath, storePub, other)
	if st := f.c.Status(ctx); !st.CanSign {
		t.Fatalf("a chain presenting the store's own key reports %+v; want able to sign", st)
	}

	writeChain(t, f.c.ChainPath, &other.PublicKey, other)
	st := f.c.Status(ctx)
	if st.CanSign {
		t.Fatalf("a chain presenting another key reports %+v; want unable to sign", st)
	}
	if !strings.Contains(st.Reason, "drifted") {
		t.Fatalf("the reason %q does not name the drift", st.Reason)
	}

	if err := os.WriteFile(f.c.ChainPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := f.c.Status(ctx); st.CanSign || !strings.Contains(st.Reason, "chain") {
		t.Fatalf("an unreadable chain reports %+v; want unable to sign, naming the chain", st)
	}
}

// writeChain writes a one-certificate chain whose subject key is pub,
// signed by signer.
func writeChain(t *testing.T, path string, pub any, signer *ecdsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

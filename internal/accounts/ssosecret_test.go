// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/api"
)

// AUTH-012 (PROPOSED for doc 07) — an organisation's sign-in client secret is
// stored encrypted, under a per-host key only the API mounts (#574).
//
// Migration 0019 kept the secret as plain text: anyone who could read the
// auth table, or a database backup, held it. The key is an ADR-0078
// credential (`sso-key`, rendered to innsegl-credential-sso-key); the
// database never holds it.

const testSSOKeyLine = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"

func writeSSOKey(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(body), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

func testSSOKey(t *testing.T) *SSOSecretKey {
	t.Helper()
	k, err := LoadSSOSecretKey(writeSSOKey(t, testSSOKeyLine))
	if err != nil {
		t.Fatalf("LoadSSOSecretKey: %v", err)
	}
	return k
}

func TestAUTH012TheSecretIsSealedAndBoundToItsConnection(t *testing.T) {
	k := testSSOKey(t)
	sealed, err := k.seal("conn-a", "top-secret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, ssoSealedPrefix) || strings.Contains(sealed, "top-secret") {
		t.Fatalf("sealed = %q", sealed)
	}
	again, err := k.seal("conn-a", "top-secret")
	if err != nil || again == sealed {
		t.Fatalf("two seals of one secret are equal (%v): a fresh nonce each time", err)
	}
	if got, oerr := k.open("conn-a", sealed); oerr != nil || got != "top-secret" {
		t.Fatalf("open = %q, %v", got, oerr)
	}
	if _, oerr := k.open("conn-b", sealed); oerr == nil {
		t.Fatal("a ciphertext moved to another connection opened")
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if _, oerr := k.open("conn-a", tampered); oerr == nil {
		t.Fatal("a tampered ciphertext opened")
	}
	other, err := LoadSSOSecretKey(writeSSOKey(t, strings.Repeat("f", 64)+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.open("conn-a", sealed); err == nil {
		t.Fatal("another host's key opened the secret")
	}
	if s, err := k.seal("conn-a", ""); err != nil || s != "" {
		t.Fatalf("an empty secret (a public client) sealed to %q, %v", s, err)
	}
	if _, err := k.open("conn-a", "plain"); err == nil {
		t.Fatal("text that is not a sealed secret opened")
	}
}

func TestAUTH012AKeyFileThatIsNotACredentialIsRefused(t *testing.T) {
	for desc, body := range map[string]string{
		"empty":       "",
		"too short":   "abc\n",
		"two lines":   testSSOKeyLine + testSSOKeyLine,
		"a bad octet": strings.Repeat("a", 32) + " b\n",
	} {
		if _, err := LoadSSOSecretKey(writeSSOKey(t, body)); err == nil {
			t.Errorf("%s: accepted", desc)
		}
	}
	if _, err := LoadSSOSecretKey(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// Against a real Postgres: the row holds ciphertext only, the store answers
// the secret, a store with no key refuses to save one, and a row written
// before this change is sealed by SealSSOSecrets.
func TestAUTH012TheStoredRowHoldsNoSecret(t *testing.T) {
	e, s, a := orgWithPeople(t)
	ctx := tctx(t)
	c, octx := ownerConn(t, e.ownerDSN)

	bare := New(s.pool)
	if _, err := bare.SetSSOConnection(ctx, a.ID, acmeSSO, "u-1"); !errors.Is(err, ErrNoSSOSecretKey) {
		t.Fatalf("a store with no key saved a secret: %v, want ErrNoSSOSecretKey", err)
	}
	public := acmeSSO
	public.ClientSecret = ""
	if _, err := bare.SetSSOConnection(ctx, a.ID, public, "u-1"); err != nil {
		t.Fatalf("a public client needs no key: %v", err)
	}

	conn, err := s.SetSSOConnection(ctx, a.ID, acmeSSO, "u-1")
	if err != nil {
		t.Fatal(err)
	}
	var plain, sealed string
	if err = c.QueryRow(octx, `SELECT client_secret, client_secret_sealed FROM innsegl_auth.sso_connections
		WHERE connection_id = $1`, conn.ID).Scan(&plain, &sealed); err != nil {
		t.Fatal(err)
	}
	if plain != "" || sealed == "" || strings.Contains(sealed, acmeSSO.ClientSecret) {
		t.Fatalf("the row holds client_secret %q, sealed %q", plain, sealed)
	}
	if got, gerr := s.SSOConnectionByName(ctx, "acme"); gerr != nil || got.ClientSecret != acmeSSO.ClientSecret {
		t.Fatalf("read back %q, %v", got.ClientSecret, gerr)
	}
	if _, err = bare.SSOConnection(ctx, a.ID); !errors.Is(err, ErrNoSSOSecretKey) {
		t.Fatalf("a store with no key read a sealed secret: %v", err)
	}
	keep := acmeSSO
	keep.ClientSecret, keep.KeepSecret = "", true
	if got, kerr := s.SetSSOConnection(ctx, a.ID, keep, "u-1"); kerr != nil || got.ClientSecret != acmeSSO.ClientSecret {
		t.Fatalf("keeping the secret: %q, %v", got.ClientSecret, kerr)
	}

	// A row as 0019 left it: plain text, nothing sealed.
	if _, err = c.Exec(octx, `UPDATE innsegl_auth.sso_connections SET client_secret = 'legacy-secret',
		client_secret_sealed = '' WHERE connection_id = $1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	if got, gerr := s.SSOConnection(ctx, a.ID); gerr != nil || got.ClientSecret != "legacy-secret" {
		t.Fatalf("a legacy row reads %q, %v", got.ClientSecret, gerr)
	}
	if _, err = bare.SealSSOSecrets(ctx); !errors.Is(err, ErrNoSSOSecretKey) {
		t.Fatalf("sealing with no key: %v", err)
	}
	n, err := s.SealSSOSecrets(ctx)
	if err != nil || n != 1 {
		t.Fatalf("SealSSOSecrets = %d, %v; want 1", n, err)
	}
	if err = c.QueryRow(octx, `SELECT client_secret, client_secret_sealed FROM innsegl_auth.sso_connections
		WHERE connection_id = $1`, conn.ID).Scan(&plain, &sealed); err != nil {
		t.Fatal(err)
	}
	if plain != "" || sealed == "" {
		t.Fatalf("after sealing: client_secret %q, sealed %q", plain, sealed)
	}
	if got, gerr := s.SSOConnection(ctx, a.ID); gerr != nil || got.ClientSecret != "legacy-secret" {
		t.Fatalf("a sealed legacy row reads %q, %v", got.ClientSecret, gerr)
	}
	if n, err = s.SealSSOSecrets(ctx); err != nil || n != 0 {
		t.Fatalf("sealing again = %d, %v; want 0", n, err)
	}

	// A ciphertext copied onto another organisation's row does not open.
	recordPseudonymous(t, e)
	other, err := s.CreateAccount(ctx, CreateAccountParams{Name: "Other", Owner: "u-admin"})
	if err != nil {
		t.Fatal(err)
	}
	oc, err := s.SetSSOConnection(ctx, other.ID, api.SSOConnectionParams{
		SignInName: "other", Issuer: acmeSSO.Issuer, ClientID: "x", ClientSecret: "theirs"}, "u-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(octx, `UPDATE innsegl_auth.sso_connections SET client_secret_sealed = $1
		WHERE connection_id = $2`, sealed, oc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SSOConnection(ctx, other.ID); err == nil {
		t.Fatal("a secret copied from another connection opened")
	}
}

// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// OPS-136 (PROPOSED for doc 07's TC-OPS) — the CA's token may sign with the
// CA key and read its public half, and nothing else (#533, ADR-0076).
//
// The custodian logs the CA in with an AppRole secret it holds only while
// unlocking. What that login hands out is what a reader of the CA's container
// gets: if it could read the store's configuration, export the key or mint
// itself a wider token, custody would be a key in a different place.
// ---------------------------------------------------------------------------

func provisioned(t *testing.T) (*testStore, *Store, Material, string) {
	t.Helper()
	ts := startStore(t)
	s := &Store{Addr: ts.addr}
	ctx := context.Background()
	unseal, root, err := s.Init(ctx)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if err = s.Unseal(ctx, unseal); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	m, err := s.Provision(ctx, root, "innsegl-ca")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	m.UnsealKey = unseal
	return ts, s, m, root
}

func TestOPS136TheCATokenSignsAndDoesNothingElse(t *testing.T) {
	_, s, m, _ := provisioned(t)
	ctx := context.Background()
	tok, err := s.Login(ctx, m.RoleID, m.SecretID)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if code := s.raw(t, http.MethodPost, "/v1/transit/sign/innsegl-ca", tok,
		`{"input":"aGVsbG8=","hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"}`); code != http.StatusOK {
		t.Fatalf("the CA's token could not sign with the CA key: %d", code)
	}
	if code := s.raw(t, http.MethodGet, "/v1/transit/keys/innsegl-ca", tok, ""); code != http.StatusOK {
		t.Fatalf("the CA's token could not read the key's public half: %d", code)
	}

	refused := []struct{ method, path, body string }{
		{http.MethodGet, "/v1/transit/export/signing-key/innsegl-ca", ""},
		{http.MethodPost, "/v1/transit/keys/another", `{"type":"ecdsa-p256"}`},
		{http.MethodPost, "/v1/transit/keys/innsegl-ca/config", `{"exportable":true}`},
		{http.MethodGet, "/v1/sys/policies/acl/innsegl-ca-signer", ""},
		{http.MethodPost, "/v1/auth/token/create", `{"policies":["innsegl-ca-signer"]}`},
		{http.MethodGet, "/v1/auth/approle/role/innsegl-ca/role-id", ""},
		{http.MethodPost, "/v1/auth/approle/role/innsegl-ca/secret-id", ""},
		{http.MethodPost, "/v1/sys/seal", ""},
	}
	for _, r := range refused {
		if code := s.raw(t, r.method, r.path, tok, r.body); code != http.StatusForbidden {
			t.Errorf("%s %s with the CA's token answered %d, not 403", r.method, r.path, code)
		}
	}
}

// OPS-137 (PROPOSED) — the CA key cannot leave the store. It is created
// non-exportable, so not even the root token can export it as it stands.
// MEASURED: the store lets a ROOT token turn exportable on afterwards (a
// one-way switch). So what keeps the key in is that no root token outlives
// provisioning (OPS-140): once it is revoked, the switch is refused.
func TestOPS137TheCAKeyCannotBeExported(t *testing.T) {
	_, s, _, root := provisioned(t)
	if code := s.raw(t, http.MethodGet, "/v1/transit/export/signing-key/innsegl-ca", root, ""); code == http.StatusOK {
		t.Fatal("the root token exported a key created non-exportable")
	}
	if err := s.RevokeSelf(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if code := s.raw(t, http.MethodPost, "/v1/transit/keys/innsegl-ca/config", root,
		`{"exportable":true}`); code != http.StatusForbidden {
		t.Fatalf("after provisioning, turning export on answered %d, not 403", code)
	}
}

// OPS-138 (PROPOSED) — a restarted store is sealed, refuses the CA until the
// unlock material is given back, and then serves it again with the same key.
func TestOPS138ARestartedStoreRefusesUntilUnlocked(t *testing.T) {
	ts, s, m, _ := provisioned(t)
	ctx := context.Background()
	before, err := s.Login(ctx, m.RoleID, m.SecretID)
	if err != nil {
		t.Fatal(err)
	}

	ts.restart(t)
	st, err := s.SealStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Initialized || !st.Sealed {
		t.Fatalf("a restarted store is %+v; want initialised and sealed", st)
	}
	if _, err = s.Login(ctx, m.RoleID, m.SecretID); !errors.Is(err, ErrSealed) {
		t.Fatalf("login to a sealed store: %v; want ErrSealed", err)
	}

	if err = s.Unseal(ctx, "AAAA"+m.UnsealKey[4:]); err == nil {
		t.Fatal("a wrong unseal key was accepted")
	}
	if err = s.Unseal(ctx, m.UnsealKey); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	after, err := s.Login(ctx, m.RoleID, m.SecretID)
	if err != nil {
		t.Fatalf("login after unseal: %v", err)
	}
	if code := s.raw(t, http.MethodPost, "/v1/transit/sign/innsegl-ca", after,
		`{"input":"aGVsbG8=","hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"}`); code != http.StatusOK {
		t.Fatalf("the CA could not sign after the unlock: %d", code)
	}
	// A token handed out before the restart outlives it: tokens are in the
	// store's storage, not its memory. Its period bounds it, not the restart.
	if err := s.RenewSelf(ctx, before); err != nil {
		t.Fatalf("a token from before the restart could not be renewed: %v", err)
	}
}

// OPS-139 (PROPOSED) — the CA's token is periodic: renewing it keeps it, and
// a revoked one is refused, which is how the custodian retires the previous
// one when it logs in again.
func TestOPS139TheCATokenIsRenewedAndRevokedBySelf(t *testing.T) {
	_, s, m, _ := provisioned(t)
	ctx := context.Background()
	tok, err := s.Login(ctx, m.RoleID, m.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	ttl, err := s.TTL(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 || ttl > TokenPeriod {
		t.Fatalf("the CA's token lives %v; want a periodic token of at most %v", ttl, TokenPeriod)
	}
	if err := s.RenewSelf(ctx, tok); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if err := s.RevokeSelf(ctx, tok); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.RenewSelf(ctx, tok); err == nil {
		t.Fatal("a revoked token was renewed")
	}
}

// OPS-140 (PROPOSED) — the root token from init is revoked once the store is
// provisioned: nothing on the core holds a token that can change the store.
func TestOPS140TheRootTokenIsRevokedAfterProvisioning(t *testing.T) {
	_, s, _, root := provisioned(t)
	if err := s.RevokeSelf(context.Background(), root); err != nil {
		t.Fatalf("revoke the root token: %v", err)
	}
	if code := s.raw(t, http.MethodGet, "/v1/sys/policies/acl", root, ""); code != http.StatusForbidden {
		t.Fatalf("the revoked root token still answered %d", code)
	}
}

// raw sends one request and answers the status, for asserting refusals.
func (s *Store) raw(t *testing.T, method, path, token, body string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, s.Addr+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

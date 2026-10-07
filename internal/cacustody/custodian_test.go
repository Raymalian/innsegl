// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// ---------------------------------------------------------------------------
// OPS-141..OPS-144 (PROPOSED for doc 07's TC-OPS) — the custodian (#533,
// ADR-0076). It initialises the store once, keeps the unlock material only as
// ciphertext to the operator's recipients, hands the CA a token on a file the
// CA reads, and unlocks the store again with material the operator's machine
// sends back.
// ---------------------------------------------------------------------------

type custodianFixture struct {
	store *testStore
	c     *Custodian
	id    *age.X25519Identity
	log   *bytes.Buffer
}

func newCustodian(t *testing.T) custodianFixture {
	t.Helper()
	ts := startStore(t)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	log := &bytes.Buffer{}
	c := &Custodian{
		Store:      &Store{Addr: ts.addr},
		Dir:        t.TempDir(),
		TokenPath:  filepath.Join(t.TempDir(), ".vault-token"),
		Key:        "innsegl-ca",
		Recipients: []age.Recipient{id.Recipient()},
		Log:        log,
	}
	return custodianFixture{store: ts, c: c, id: id, log: log}
}

func (f custodianFixture) material(t *testing.T) Material {
	t.Helper()
	ct, err := f.c.Material()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Open(ct, []age.Identity{f.id})
	if err != nil {
		t.Fatalf("open the unlock material: %v", err)
	}
	return m
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the CA's token file: %v", err)
	}
	return string(b)
}

// OPS-141 (PROPOSED) — init leaves the store unlocked and the CA logged in,
// and leaves behind only ciphertext: the unseal key and the secret id are in
// no file in plaintext, the root token is gone, and a second init refuses.
func TestOPS141InitLeavesOnlyCiphertextBehind(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	m := f.material(t)
	if !m.Valid() {
		t.Fatalf("the sealed material is incomplete: unseal=%t role=%t secret=%t",
			m.UnsealKey != "", m.RoleID != "", m.SecretID != "")
	}

	for _, dir := range []string{f.c.Dir, filepath.Dir(f.c.TokenPath)} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			body, err := os.ReadFile(p) //nolint:gosec // G304: the test's own temp dirs
			if err != nil {
				return err
			}
			for name, secret := range map[string]string{"unseal key": m.UnsealKey, "secret id": m.SecretID,
				"snapshot secret id": m.BackupSecretID} {
				if bytes.Contains(body, []byte(secret)) {
					t.Errorf("%s holds the %s in plaintext", p, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, secret := range map[string]string{"unseal key": m.UnsealKey, "secret id": m.SecretID} {
		if strings.Contains(f.log.String(), secret) {
			t.Errorf("the custodian logged the %s", name)
		}
	}

	st := f.c.Status(ctx)
	if !st.Initialized || st.Sealed || !st.TokenPresent {
		t.Fatalf("after init the custodian reports %+v; want initialised, unsealed, token present", st)
	}
	if err := f.c.Init(ctx); err == nil {
		t.Fatal("a second init was accepted on an initialised store")
	}
}

// OPS-142 (PROPOSED) — the CA's token is on a file the CA reads: mode 0600,
// exactly the token (the CA's KMS client reads the whole file as the token),
// and it signs.
func TestOPS142TheCATokenFileIsExactlyAWorkingToken(t *testing.T) {
	f := newCustodian(t)
	if err := f.c.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.c.TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the token file is %v; want 0600", info.Mode().Perm())
	}
	tok := readToken(t, f.c.TokenPath)
	if strings.TrimSpace(tok) != tok {
		t.Fatalf("the token file holds whitespace around the token, which the CA would send as part of it")
	}
	if code := f.c.Store.raw(t, http.MethodPost, "/v1/transit/sign/innsegl-ca", tok,
		`{"input":"aGVsbG8=","hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"}`); code != http.StatusOK {
		t.Fatalf("the token on the file could not sign: %d", code)
	}
	if err := f.c.Renew(context.Background()); err != nil {
		t.Fatalf("renew: %v", err)
	}
}

// OPS-143 (PROPOSED) — after a restart the store is sealed; the material
// opened on the operator's machine unlocks it, the CA gets a new token, and
// the previous token is revoked. Wrong material changes nothing.
func TestOPS143TheOperatorsMaterialUnlocksARestartedStore(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.material(t)
	before := readToken(t, f.c.TokenPath)

	f.store.restart(t)
	if st := f.c.Status(ctx); !st.Sealed {
		t.Fatalf("a restarted store reports %+v; want sealed", st)
	}

	wrong := m
	wrong.UnsealKey = "AAAA" + m.UnsealKey[4:]
	if err := f.c.Unlock(ctx, wrong); err == nil {
		t.Fatal("wrong material unlocked the store")
	}
	if st := f.c.Status(ctx); !st.Sealed {
		t.Fatal("wrong material left the store unsealed")
	}
	if readToken(t, f.c.TokenPath) != before {
		t.Fatal("wrong material changed the CA's token file")
	}

	if err := f.c.Unlock(ctx, m); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	after := readToken(t, f.c.TokenPath)
	if after == before {
		t.Fatal("the unlock left the CA on the token from before the restart")
	}
	if code := f.c.Store.raw(t, http.MethodPost, "/v1/transit/sign/innsegl-ca", after,
		`{"input":"aGVsbG8=","hash_algorithm":"sha2-256","marshaling_algorithm":"asn1"}`); code != http.StatusOK {
		t.Fatalf("the new token could not sign: %d", code)
	}
	if err := f.c.Store.RenewSelf(ctx, before); err == nil {
		t.Fatal("the token from before the unlock was not revoked")
	}
	for _, secret := range []string{m.UnsealKey, m.SecretID} {
		if strings.Contains(f.log.String(), secret) {
			t.Fatal("the custodian logged unlock material")
		}
	}
}

// OPS-144 (PROPOSED) — the custodian's own surface, which only the core
// reaches: status and material by GET, unlock by POST alone, a bounded body,
// and no error that echoes what was sent.
func TestOPS144TheCustodianSurface(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.material(t)
	srv := httptest.NewServer(f.c.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + PathStatus) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	var st Status
	if err = json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !st.Initialized || st.Sealed {
		t.Fatalf("status: %+v", st)
	}

	resp, err = http.Get(srv.URL + PathMaterial) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("material: %d", resp.StatusCode)
	}
	if _, err = Open(buf.Bytes(), []age.Identity{f.id}); err != nil {
		t.Fatalf("the served material does not open: %v", err)
	}

	resp, err = http.Get(srv.URL + PathUnlock) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET unlock answered %d", resp.StatusCode)
	}

	big := bytes.Repeat([]byte("x"), 1<<20)
	resp, err = http.Post(srv.URL+PathUnlock, "application/json", bytes.NewReader(big)) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an oversized unlock answered %d", resp.StatusCode)
	}

	f.store.restart(t)
	wrong := m
	wrong.SecretID = "not-the-secret-" + m.SecretID[:4]
	body, err := json.Marshal(wrong)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.Post(srv.URL+PathUnlock, "application/json", bytes.NewReader(body)) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("wrong material answered success")
	}
	for _, secret := range []string{m.UnsealKey, wrong.SecretID} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("the refusal echoed what was sent: %s", buf.String())
		}
	}

	if body, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
	resp, err = http.Post(srv.URL+PathUnlock, "application/json", bytes.NewReader(body)) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("the right material answered %d", resp.StatusCode)
	}
	if st := f.c.Status(ctx); st.Sealed || !st.TokenPresent {
		t.Fatalf("after the unlock: %+v", st)
	}
}

// OPS-145 (PROPOSED) — material opens only with the operator's identity.
func TestOPS145TheMaterialOpensOnlyForTheOperator(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	m := Material{UnsealKey: "u", RoleID: "r", SecretID: "s", BackupRoleID: "br", BackupSecretID: "bs"}
	ct, err := Seal(m, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(ct, []age.Identity{other}); err == nil {
		t.Fatal("the material opened for an identity it was not sealed to")
	}
	got, err := Open(ct, []age.Identity{id})
	if err != nil || got != m {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if _, err = Seal(m, nil); err == nil {
		t.Fatal("sealing to no recipient was accepted")
	}
	if _, err = Seal(Material{UnsealKey: "u"}, []age.Recipient{id.Recipient()}); !errors.Is(err, ErrIncomplete) {
		t.Fatalf("sealing incomplete material: %v", err)
	}
}

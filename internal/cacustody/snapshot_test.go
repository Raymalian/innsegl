// SPDX-License-Identifier: Apache-2.0

package cacustody

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// ---------------------------------------------------------------------------
// OPS-153..OPS-155 (PROPOSED for doc 07's TC-OPS) — the store is backed up by
// its own snapshot, taken by a token that can do nothing else, and that
// snapshot restores to a working store holding the same CA key (#533,
// ADR-0076). Under custody the CA key lives only in the store, so a copy of
// its files taken while it writes is not a backup: a snapshot is.
// ---------------------------------------------------------------------------

// OPS-153 (PROPOSED) — the snapshot token takes snapshots and nothing else.
func TestOPS153TheSnapshotTokenCanOnlySnapshot(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	m := f.material(t)
	tok, err := f.c.Store.Login(ctx, m.BackupRoleID, m.BackupSecretID)
	if err != nil {
		t.Fatalf("the snapshot role's login: %v", err)
	}
	if code := f.c.Store.raw(t, http.MethodGet, "/v1/sys/storage/raft/snapshot", tok, ""); code != http.StatusOK {
		t.Fatalf("the snapshot token could not snapshot: %d", code)
	}
	for _, p := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/transit/sign/innsegl-ca", `{"input":"aGVsbG8="}`},
		{http.MethodGet, "/v1/transit/keys/innsegl-ca", ""},
		{http.MethodPost, "/v1/sys/storage/raft/snapshot-force", "x"},
		{http.MethodPost, "/v1/auth/approle/role/innsegl-ca/secret-id", ""},
	} {
		if code := f.c.Store.raw(t, p.method, p.path, tok, p.body); code != http.StatusForbidden {
			t.Errorf("%s %s with the snapshot token answered %d, not 403", p.method, p.path, code)
		}
	}
}

// OPS-154 (PROPOSED) — the custodian keeps a current snapshot beside the
// sealed material: written at init, and again on demand.
func TestOPS154TheCustodianKeepsASnapshot(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(f.c.SnapshotPath())
	if err != nil || first.Size() == 0 || first.Mode().Perm() != 0o600 {
		t.Fatalf("no snapshot after init: %v %v", first, err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err = f.c.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	second, err := os.Stat(f.c.SnapshotPath())
	if err != nil || !second.ModTime().After(first.ModTime()) {
		t.Fatalf("the snapshot was not taken again: %v %v", second, err)
	}
	f.store.restart(t)
	if err = f.c.Snapshot(ctx); err == nil {
		t.Fatal("a sealed store gave a snapshot")
	}
	if after, _ := os.Stat(f.c.SnapshotPath()); after == nil || after.Size() == 0 {
		t.Fatal("a failed snapshot removed the last good one")
	}
}

// OPS-155 (PROPOSED) — a trust-key bundle's store and material restore the
// CA: the bundle's snapshot, restored into a fresh real store, is sealed; the
// material from the same bundle unseals it; and the CA key read back is the
// key the original store held. Nothing from the original store but the
// bundle is used.
func TestOPS155ABundleRestoresTheSameCAKeyIntoAFreshStore(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	if err := f.c.Init(ctx); err != nil {
		t.Fatal(err)
	}
	original := f.material(t)
	tok, err := f.c.Store.Login(ctx, original.RoleID, original.SecretID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := f.c.Store.PublicKey(ctx, tok, f.c.Key)
	if err != nil {
		t.Fatal(err)
	}

	bundles := &trustbackup.Store{Dir: t.TempDir(), Keep: 2}
	if _, _, err = bundles.Create([]age.Recipient{f.id.Recipient()}, []trustbackup.Source{
		trustbackup.PathSource("ca-store", filepath.Dir(f.c.SnapshotPath())),
		trustbackup.PathSource("ca-custody", filepath.Dir(f.c.MaterialPath())),
	}); err != nil {
		t.Fatalf("writing the bundle: %v", err)
	}
	e, err := bundles.Latest()
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := bundles.Open(e.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	out := filepath.Join(t.TempDir(), "restore")
	if err = os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err = trustbackup.ReadBundle(r, []age.Identity{f.id}, out); err != nil {
		t.Fatalf("reading the bundle: %v", err)
	}

	sealed, err := os.ReadFile(filepath.Join(out, "ca-custody", MaterialFile))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Open(sealed, []age.Identity{f.id})
	if err != nil {
		t.Fatalf("the bundle's material: %v", err)
	}
	snap, err := os.ReadFile(filepath.Join(out, "ca-store", SnapshotFile))
	if err != nil {
		t.Fatal(err)
	}

	fresh := &Store{Addr: startStore(t).addr}
	if err = fresh.Restore(ctx, bytes.NewReader(snap)); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if st, serr := fresh.SealStatus(ctx); serr != nil || !st.Sealed || !st.Initialized {
		t.Fatalf("a restored store is %+v %v; want initialised and sealed under the original key", st, serr)
	}
	if err = fresh.Unseal(ctx, m.UnsealKey); err != nil {
		t.Fatalf("the bundle's unseal key: %v", err)
	}
	ftok, err := fresh.Login(ctx, m.RoleID, m.SecretID)
	if err != nil {
		t.Fatalf("the bundle's CA login: %v", err)
	}
	got, err := fresh.PublicKey(ctx, ftok, f.c.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("the restored store's CA key is not the original:\n got %q\nwant %q", got, want)
	}
}

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
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/trustbackup"
)

// ---------------------------------------------------------------------------
// OPS-201..OPS-206 (PROPOSED for doc 07's TC-OPS) — the custody reseal (#609,
// ADR-0082 decision 7). The same unlock material is sealed again to a new
// set of recipients in two steps: a staged copy, then a confirm from the
// opener that opened it. The old copy stays until the confirm. The CA key,
// the store, the unseal key and the secret ids do not change.
// ---------------------------------------------------------------------------

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func recipientOf(id *age.X25519Identity) string { return id.Recipient().String() }

func (f custodianFixture) initialised(t *testing.T) Material {
	t.Helper()
	if err := f.c.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return f.material(t)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func resealRequest(m Material, opener string, set ...string) ResealRequest {
	return ResealRequest{Material: m, Opener: opener, Recipients: set, SetDigest: SetDigest(set)}
}

// confirmWith opens the staged copy with id and confirms it.
func (f custodianFixture) confirmWith(t *testing.T, staged ResealStaged, id age.Identity) error {
	t.Helper()
	m, check, err := OpenStaged(staged.Sealed, []age.Identity{id})
	if err != nil {
		t.Fatalf("the staged copy does not open: %v", err)
	}
	return f.c.ConfirmReseal(context.Background(), ResealConfirm{Material: m, Check: check, SetDigest: staged.SetDigest})
}

func (f custodianFixture) caPublicKey(t *testing.T) string {
	t.Helper()
	pub, err := f.c.Store.PublicKey(context.Background(), readToken(t, f.c.TokenPath), f.c.Key)
	if err != nil {
		t.Fatalf("the CA key: %v", err)
	}
	return pub
}

// OPS-201 (PROPOSED) — init records the set it sealed to; a reseal to a set
// of two stages a copy each identity opens, leaves the old copy in place
// until the confirm, and the confirm swaps it in and writes recipients.txt
// in the format the trust backup reads. The CA key does not change.
func TestOPS201AResealSealsTheSameMaterialToTheNewSet(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	m := f.initialised(t)
	a, b := f.id, newIdentity(t)
	keyBefore := f.caPublicKey(t)

	set, err := f.c.CurrentRecipients()
	if err != nil {
		t.Fatalf("the set init recorded: %v", err)
	}
	if !set.Recorded || len(set.Recipients) != 1 || set.Recipients[0] != recipientOf(a) ||
		set.Digest != SetDigest([]string{recipientOf(a)}) {
		t.Fatalf("init recorded %+v; want the one recipient it sealed to, and its digest", set)
	}

	old := readFile(t, f.c.MaterialPath())
	staged, err := f.c.Reseal(ctx, resealRequest(m, recipientOf(a), recipientOf(a), recipientOf(b)))
	if err != nil {
		t.Fatalf("reseal: %v", err)
	}
	if !bytes.Equal(readFile(t, f.c.MaterialPath()), old) {
		t.Fatal("staging replaced the sealed material before any confirm")
	}
	for name, id := range map[string]age.Identity{"a": a, "b": b} {
		got, _, oerr := OpenStaged(staged.Sealed, []age.Identity{id})
		if oerr != nil || got != m {
			t.Fatalf("identity %s on the staged copy: %v (same material %t)", name, oerr, got == m)
		}
	}

	if err = f.confirmWith(t, staged, a); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	now := readFile(t, f.c.MaterialPath())
	if !bytes.Equal(now, staged.Sealed) {
		t.Fatal("the confirm did not swap in the copy the opener opened")
	}
	for name, id := range map[string]age.Identity{"a": a, "b": b} {
		got, oerr := Open(now, []age.Identity{id})
		if oerr != nil || got != m {
			t.Fatalf("identity %s on the resealed material: %v (same material %t)", name, oerr, got == m)
		}
	}

	rs, err := trustbackup.LoadRecipients("", filepath.Join(filepath.Dir(f.c.MaterialPath()), trustbackup.RecipientsFile))
	if err != nil || len(rs) != 2 {
		t.Fatalf("recipients.txt as the trust backup reads it: %d recipient(s), %v; want 2", len(rs), err)
	}

	srv := httptest.NewServer(f.c.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + PathRecipients) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	var listed RecipientSet
	if err = json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if listed.Digest != staged.SetDigest || len(listed.Recipients) != 2 {
		t.Fatalf("/recipients lists %+v; want the applied set", listed)
	}

	if keyBefore != f.caPublicKey(t) {
		t.Fatal("the reseal changed the CA key")
	}
	if st := f.c.Status(ctx); !st.CanSign {
		t.Fatalf("after the reseal the CA cannot sign: %s", st.Reason)
	}
	for _, line := range []string{"reseal staged", "resealed"} {
		if !strings.Contains(f.log.String(), line) {
			t.Errorf("no audit line %q in:\n%s", line, f.log.String())
		}
	}
	for _, secret := range []string{m.UnsealKey, m.SecretID, m.BackupSecretID} {
		if strings.Contains(f.log.String(), secret) {
			t.Fatal("the custodian logged unlock material")
		}
	}
}

// OPS-202 (PROPOSED) — a reseal is refused for an empty set, a set without
// the opener, a digest other than the set's, and a confirm for a set other
// than the staged one or without the staged copy's check. None of them
// touches the sealed material. The HTTP surface answers each as a client
// error and repeats nothing that was sent.
func TestOPS202AResealIsRefusedForAWrongSet(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	m := f.initialised(t)
	a, b := recipientOf(f.id), recipientOf(newIdentity(t))
	old := readFile(t, f.c.MaterialPath())

	cases := []struct {
		name string
		req  ResealRequest
		want error
	}{
		{"empty set", resealRequest(m, a), ErrEmptySet},
		{"opener not in the set", resealRequest(m, a, b), ErrOpenerNotInSet},
		{"digest of another set", ResealRequest{Material: m, Opener: a, Recipients: []string{a, b}, SetDigest: SetDigest([]string{a})}, ErrSetMismatch},
	}
	for _, tc := range cases {
		if _, err := f.c.Reseal(ctx, tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v; want %v", tc.name, err, tc.want)
		}
	}
	if _, err := f.c.Reseal(ctx, resealRequest(m, a, a, "not-a-recipient")); err == nil {
		t.Error("a set with a line that is no recipient was accepted")
	}

	staged, err := f.c.Reseal(ctx, resealRequest(m, a, a, b))
	if err != nil {
		t.Fatal(err)
	}
	opened, check, err := OpenStaged(staged.Sealed, []age.Identity{f.id})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.c.ConfirmReseal(ctx, ResealConfirm{Material: opened, Check: check, SetDigest: SetDigest([]string{a})}); !errors.Is(err, ErrSetMismatch) {
		t.Errorf("confirm for another set: %v; want %v", err, ErrSetMismatch)
	}
	if err = f.c.ConfirmReseal(ctx, ResealConfirm{Material: opened, Check: "00" + check[2:], SetDigest: staged.SetDigest}); !errors.Is(err, ErrNotOpened) {
		t.Errorf("confirm without the staged copy's check: %v; want %v", err, ErrNotOpened)
	}
	if !bytes.Equal(readFile(t, f.c.MaterialPath()), old) {
		t.Fatal("a refused reseal changed the sealed material")
	}

	srv := httptest.NewServer(f.c.Handler())
	defer srv.Close()
	for _, path := range []string{PathReseal, PathResealConfirm} {
		resp, gerr := http.Get(srv.URL + path) //nolint:noctx // a test
		if gerr != nil {
			t.Fatal(gerr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s answered %d", path, resp.StatusCode)
		}
	}
	body, err := json.Marshal(resealRequest(m, a, b))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(srv.URL+PathReseal, "application/json", bytes.NewReader(body)) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a set without the opener answered %d", resp.StatusCode)
	}
	for _, secret := range []string{m.UnsealKey, m.SecretID} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("the refusal echoed what was sent: %s", buf.String())
		}
	}
	if !bytes.Equal(readFile(t, f.c.MaterialPath()), old) {
		t.Fatal("a refused reseal changed the sealed material")
	}
}

// OPS-203 (PROPOSED) — nothing is sealed that the store did not accept.
// Unsealed: material whose unseal key is not the committed one, or whose
// secret id the store refuses; a store with no commitment yet. Sealed: an
// unseal key the store refuses. A sealed-store unlock writes the commitment.
func TestOPS203AResealNeedsMaterialTheStoreAccepts(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	m := f.initialised(t)
	a := recipientOf(f.id)
	old := readFile(t, f.c.MaterialPath())

	wrongUnseal := m
	wrongUnseal.UnsealKey = "AAAA" + m.UnsealKey[4:]
	wrongSecret := m
	wrongSecret.SecretID = "not-the-secret-" + m.SecretID[:4]
	for name, bad := range map[string]Material{"unseal key": wrongUnseal, "secret id": wrongSecret} {
		if _, err := f.c.Reseal(ctx, resealRequest(bad, a, a)); !errors.Is(err, errNotAccepted) {
			t.Errorf("unsealed store, wrong %s: %v; want %v", name, err, errNotAccepted)
		}
	}

	if err := os.Remove(f.c.materialDigestPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.Reseal(ctx, resealRequest(m, a, a)); !errors.Is(err, ErrNoMaterialCommitment) {
		t.Errorf("unsealed store with no commitment: %v; want %v", err, ErrNoMaterialCommitment)
	}

	f.store.restart(t)
	if _, err := f.c.Reseal(ctx, resealRequest(wrongUnseal, a, a)); err == nil {
		t.Error("sealed store, wrong unseal key: the reseal was accepted")
	}
	if st := f.c.Status(ctx); !st.Sealed {
		t.Fatal("a refused reseal unsealed the store")
	}
	if !bytes.Equal(readFile(t, f.c.MaterialPath()), old) {
		t.Fatal("a refused reseal changed the sealed material")
	}

	if err := f.c.Unlock(ctx, m); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := os.Stat(f.c.materialDigestPath()); err != nil {
		t.Fatalf("a sealed-store unlock wrote no commitment: %v", err)
	}
	if _, err := f.c.Reseal(ctx, resealRequest(m, a, a)); err != nil {
		t.Fatalf("after the unlock the reseal is still refused: %v", err)
	}
	if body := readFile(t, f.c.materialDigestPath()); bytes.Contains(body, []byte(m.UnsealKey)) {
		t.Fatal("the commitment holds the unseal key")
	}
}

// OPS-204 (PROPOSED) — a staged copy with no confirm inside the window is
// dropped: the confirm is refused, the old copy is still the material, and
// an identity only the staged set held does not open it.
func TestOPS204AnUnconfirmedResealExpires(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	m := f.initialised(t)
	b := newIdentity(t)
	old := readFile(t, f.c.MaterialPath())

	clock := time.Now()
	f.c.now = func() time.Time { return clock }
	staged, err := f.c.Reseal(ctx, resealRequest(m, recipientOf(f.id), recipientOf(f.id), recipientOf(b)))
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(ResealWindow + time.Second)
	if err := f.confirmWith(t, staged, f.id); !errors.Is(err, ErrNothingStaged) {
		t.Fatalf("a confirm after the window: %v; want %v", err, ErrNothingStaged)
	}
	if !bytes.Equal(readFile(t, f.c.MaterialPath()), old) {
		t.Fatal("an expired reseal changed the sealed material")
	}
	if _, err := Open(old, []age.Identity{b}); err == nil {
		t.Fatal("an identity of the expired set opens the material")
	}
	if got := f.material(t); got != m {
		t.Fatal("the original identity no longer opens the same material")
	}
	if !strings.Contains(f.log.String(), "expired") {
		t.Errorf("no audit line for the expired reseal:\n%s", f.log.String())
	}
}

// OPS-205 (PROPOSED) — a reseal on a real store, then a store restart: the
// NEW recipient alone unlocks it and the CA signs again.
func TestOPS205TheNewRecipientAloneUnlocksARestartedStore(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	m := f.initialised(t)
	b := newIdentity(t)
	staged, err := f.c.Reseal(ctx, resealRequest(m, recipientOf(f.id), recipientOf(f.id), recipientOf(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.confirmWith(t, staged, f.id); err != nil {
		t.Fatal(err)
	}

	f.store.restart(t)
	ct, err := f.c.Material()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(ct, []age.Identity{b})
	if err != nil {
		t.Fatalf("the new recipient cannot open the material: %v", err)
	}
	if err = f.c.Unlock(ctx, opened); err != nil {
		t.Fatalf("unlock with the new recipient's copy: %v", err)
	}
	if st := f.c.Status(ctx); st.Sealed || !st.CanSign {
		t.Fatalf("after the unlock: %+v", st)
	}
}

// OPS-206 (PROPOSED) — a reseal that leaves a recipient out: the left-out
// identity no longer opens the current material. The new opener authorises
// it from a copy it holds.
func TestOPS206AResealLeavesARecipientOut(t *testing.T) {
	f := newCustodian(t)
	ctx := context.Background()
	m := f.initialised(t)
	a, b := f.id, newIdentity(t)
	staged, err := f.c.Reseal(ctx, resealRequest(m, recipientOf(a), recipientOf(a), recipientOf(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.confirmWith(t, staged, a); err != nil {
		t.Fatal(err)
	}

	byB, err := Open(readFile(t, f.c.MaterialPath()), []age.Identity{b})
	if err != nil {
		t.Fatal(err)
	}
	staged, err = f.c.Reseal(ctx, resealRequest(byB, recipientOf(b), recipientOf(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.confirmWith(t, staged, b); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(readFile(t, f.c.MaterialPath()), []age.Identity{a}); err == nil {
		t.Fatal("the left-out identity still opens the current material")
	}
	set, err := f.c.CurrentRecipients()
	if err != nil || len(set.Recipients) != 1 || set.Recipients[0] != recipientOf(b) {
		t.Fatalf("the recorded set: %+v, %v; want b alone", set, err)
	}
}

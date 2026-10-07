// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/client/clienttest"
)

// ---------------------------------------------------------------------------
// BAK-026..BAK-028 (PROPOSED for doc 07's TC-BAK) — the operator's machine
// unlocks the CA key store (#533, ADR-0076). It asks the core whether the
// store is sealed; only then does it fetch the sealed material, open it with
// the operator's identity (Touch ID, for a Secure Enclave key), and send it
// back over its own certificate.
// ---------------------------------------------------------------------------

type coreCustody struct {
	mu        sync.Mutex
	status    cacustody.CoreStatus
	material  []byte
	unlocked  []byte
	unlockErr int
	fetches   atomic.Int32
}

func (c *coreCustody) mount(t *testing.T, core *clienttest.Core) {
	core.Mux.HandleFunc(cacustody.CorePath, func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := json.NewEncoder(w).Encode(c.status); err != nil {
			t.Error(err)
		}
	})
	core.Mux.HandleFunc(cacustody.CoreMaterialPath, func(w http.ResponseWriter, _ *http.Request) {
		c.fetches.Add(1)
		if _, err := w.Write(c.material); err != nil {
			t.Error(err)
		}
	})
	core.Mux.HandleFunc(cacustody.CoreUnlockPath, func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if c.unlockErr != 0 {
			w.WriteHeader(c.unlockErr)
			write(t, w, `{"error":"ca custody: the unlock material was not accepted"}`)
			return
		}
		c.unlocked = b
		c.status.Sealed = false
		w.WriteHeader(http.StatusNoContent)
	})
}

func sealedCustody(t *testing.T) (*coreCustody, *age.X25519Identity, cacustody.Material) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	m := cacustody.Material{UnsealKey: "unseal", RoleID: "role", SecretID: "secret"}
	ct, err := cacustody.Seal(m, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	return &coreCustody{status: cacustody.CoreStatus{Enabled: true, Initialized: true, Sealed: true},
		material: ct}, id, m
}

func identitiesOf(ids ...age.Identity) func() ([]age.Identity, error) {
	return func() ([]age.Identity, error) { return ids, nil }
}

// BAK-026 (PROPOSED) — a sealed store is unlocked with exactly the material
// the core holds, opened by the operator's identity.
func TestBAK026TheOperatorsMachineUnlocksASealedStore(t *testing.T) {
	core, paths := enrolled(t)
	cc, id, m := sealedCustody(t)
	cc.mount(t, core)

	unlocked, err := UnlockCA(t.Context(), paths, identitiesOf(id))
	if err != nil || !unlocked {
		t.Fatalf("UnlockCA = %v, %v", unlocked, err)
	}
	var sent cacustody.Material
	if err := json.Unmarshal(cc.unlocked, &sent); err != nil || sent != m {
		t.Fatalf("the core was sent %q, want the opened material", cc.unlocked)
	}
}

// BAK-027 (PROPOSED) — nothing is fetched, and Touch ID is not asked for,
// when there is nothing to unlock: custody off, or the store already open.
func TestBAK027NoTouchIDWhenThereIsNothingToUnlock(t *testing.T) {
	for name, st := range map[string]cacustody.CoreStatus{
		"custody off": {},
		"unsealed":    {Enabled: true, Initialized: true},
	} {
		t.Run(name, func(t *testing.T) {
			core, paths := enrolled(t)
			cc, _, _ := sealedCustody(t)
			cc.status = st
			cc.mount(t, core)
			asked := false
			ids := func() ([]age.Identity, error) { asked = true; return nil, nil }
			unlocked, err := UnlockCA(t.Context(), paths, ids)
			if err != nil || unlocked || asked || cc.fetches.Load() != 0 {
				t.Fatalf("unlocked=%v err=%v asked=%v fetches=%d", unlocked, err, asked, cc.fetches.Load())
			}
		})
	}
}

// BAK-028 (PROPOSED) — a declined Touch ID, or the wrong identity, sends
// nothing; a refusal by the core is an error that says so; and the service
// does not ask again until its back-off has passed.
func TestBAK028AFailedUnlockSendsNothingAndDoesNotNag(t *testing.T) {
	core, paths := enrolled(t)
	cc, _, _ := sealedCustody(t)
	cc.mount(t, core)

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = UnlockCA(t.Context(), paths, identitiesOf(other)); err == nil || cc.unlocked != nil {
		t.Fatalf("the wrong identity: err=%v, sent %q", err, cc.unlocked)
	}
	declined := errors.New("touch id was declined")
	if _, err = UnlockCA(t.Context(), paths, func() ([]age.Identity, error) { return nil, declined }); !errors.Is(err, declined) {
		t.Fatalf("a declined prompt: %v", err)
	}

	cc2, id2, _ := sealedCustody(t)
	core2, paths2 := enrolled(t)
	cc2.unlockErr = http.StatusForbidden
	cc2.mount(t, core2)
	if _, err = UnlockCA(t.Context(), paths2, identitiesOf(id2)); err == nil ||
		!strings.Contains(err.Error(), "not accepted") {
		t.Fatalf("a refused unlock: %v", err)
	}

	s, err := NewServer(paths, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	ids := func() ([]age.Identity, error) { asked.Add(1); return nil, declined }
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	s.RunCAUnlock(ctx, ids, 10*time.Millisecond, time.Hour)
	if n := asked.Load(); n != 1 {
		t.Fatalf("the operator was asked %d times in 300ms after declining; want once", n)
	}
}

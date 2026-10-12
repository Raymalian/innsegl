// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// CLI-054 (PROPOSED for doc 07's TC-CLI) — the reseal end to end on a real
// store (#614, ADR-0082 decision 7): a custodian on a real OpenBao, the
// core's custody routes, the client service and `innsegl ca-custody`, with
// two generated age identities. The operator adds the second recipient;
// the store restarts sealed; the second identity alone unlocks it and the
// CA can sign. Then the first is removed with the second, and no longer
// opens the material. Integration: run with -p 1, never with a stack up.
// ---------------------------------------------------------------------------

func TestCLI054ResealOnARealStoreThenUnlockWithTheSecondRecipient(t *testing.T) {
	addr, storeName := startIncidentStore(t)
	ctx := t.Context()
	first, second := newIdentity(t), newIdentity(t)
	r1, r2 := first.Recipient().String(), second.Recipient().String()

	serving := &cacustody.Custodian{Store: &cacustody.Store{Addr: addr}, Dir: t.TempDir(),
		TokenPath: t.TempDir() + "/.vault-token", Key: "innsegl-ca",
		Recipients: []age.Recipient{first.Recipient()}, Log: io.Discard}
	if err := serving.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	routes := httptest.NewServer(serving.Handler())
	t.Cleanup(routes.Close)

	// The core's real limit, on a clock the test moves: an operator's
	// reseal, unlock and second reseal, minutes apart.
	var mu sync.Mutex
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	later := func() { mu.Lock(); defer mu.Unlock(); now = now.Add(5 * time.Minute) }
	f := resealFixtureLimited(t, routes.URL, newCustodyLimiter(clock))
	firstFile, secondFile := identityFile(t, first), identityFile(t, second)

	code, out := runReseal(t, f, "y\n", "reseal", "--add", r2, "--identity", firstFile)
	if code != exitOK || !strings.Contains(out, "resealed") {
		t.Fatalf("reseal --add: exit %d\n%s", code, out)
	}
	set, err := serving.CurrentRecipients()
	if err != nil || !set.Recorded || set.Digest != cacustody.SetDigest([]string{r1, r2}) {
		t.Fatalf("the custodian's set after the reseal: %+v, %v", set, err)
	}
	later()
	if code, out = runReseal(t, f, "", "recipients"); code != exitOK || !strings.Contains(out, r1) || !strings.Contains(out, r2) {
		t.Fatalf("recipients: exit %d\n%s", code, out)
	}

	// The store restarts sealed; the second identity alone unlocks it.
	restartStore(t, addr, storeName)
	if st := serving.Status(ctx); !st.Sealed {
		t.Fatalf("after a restart the store is not sealed: %+v", st)
	}
	later()
	if code, out = runReseal(t, f, "", "unlock", "--identity", secondFile); code != exitOK ||
		!strings.Contains(out, "unlocked; the CA can sign") {
		t.Fatalf("unlock with the second recipient: exit %d\n%s", code, out)
	}
	if st := serving.Status(ctx); st.Sealed || !st.CanSign {
		t.Fatalf("after the second recipient's unlock: %+v", st)
	}

	// The second removes the first; the first no longer opens the material.
	later()
	if code, out = runReseal(t, f, "y\n", "reseal", "--remove", r1, "--identity", secondFile); code != exitOK {
		t.Fatalf("reseal --remove: exit %d\n%s", code, out)
	}
	sealed, err := serving.Material()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cacustody.Open(sealed, []age.Identity{first}); err == nil {
		t.Fatal("the removed recipient still opens the current material")
	}
	if _, err = cacustody.Open(sealed, []age.Identity{second}); err != nil {
		t.Fatalf("the remaining recipient cannot open the material: %v", err)
	}
}

func restartStore(t *testing.T, addr, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := dockertest.Docker(ctx, "restart", name); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		resp, err := http.Get(addr + "/v1/sys/seal-status") //nolint:noctx // a probe loop
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
	t.Fatalf("the store at %s never answered after its restart", addr)
}

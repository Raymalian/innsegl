// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/dockertest"
)

// ---------------------------------------------------------------------------
// AUTH-018 — an unlock key applied by a reseal unlocks a real store after a
// restart (#613, ADR-0082 decisions 4, 7 and 8). A custodian on a real
// OpenBao, the API in front of it, two security keys and the host's own
// identity (the operator's machine). Integration: run with -p 1, never with
// a stack up.
// ---------------------------------------------------------------------------

// custodyStoreImage is the store the key-custody overlay runs, pinned as
// internal/cacustody's own tests pin it.
const custodyStoreImage = "openbao/openbao:2.4.1@sha256:597f62847dd382382056a1d6704d50465908c2040038c4611832a23269a67112"

const custodyStoreConfig = `ui = false
storage "raft" {
  path    = "/openbao/file"
  node_id = "innsegl-ca-store"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
`

// startCustodyStore starts a sealed, uninitialised store, or skips with no
// Docker and fails when Docker is there and the store is not (#101).
func startCustodyStore(t *testing.T) (addr, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("skipping: docker is not on PATH (%v); AUTH-018 needs a real store", err)
	}
	if _, err := dockertest.Docker(ctx, "version", "--format", "{{.Server.Version}}"); err != nil {
		t.Skipf("skipping: no reachable docker daemon (%v); AUTH-018 needs a real store", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "store.hcl"), []byte(custodyStoreConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	port, err := dockertest.FreeHostPort(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name = fmt.Sprintf("innsegl-apiunlock-test-%d", time.Now().UnixNano())
	if _, err := dockertest.Docker(ctx, "run", "--detach", "--name", name, "--label", "dev.innsegl.test=1",
		"--publish", "127.0.0.1:"+port+":8200", "--volume", dir+":/openbao/config:ro",
		custodyStoreImage, "server", "-config=/openbao/config/store.hcl"); err != nil {
		t.Fatalf("the store did not start, and Docker is present and working: %v\n\n"+
			"This is a FAILURE and not a skip (#101).", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := dockertest.Docker(ctx, "rm", "--force", "--volumes", name); err != nil {
			t.Logf("removing the test store: %v", err)
		}
	})
	addr = "http://127.0.0.1:" + port
	waitCustodyStore(t, addr, name)
	return addr, name
}

func waitCustodyStore(t *testing.T, addr, name string) {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		resp, err := http.Get(addr + "/v1/sys/seal-status") //nolint:noctx // a probe loop
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
	logs, err := dockertest.Docker(context.Background(), "logs", name)
	if err != nil {
		logs = err.Error()
	}
	t.Fatalf("the store at %s never answered:\n%s", addr, logs)
}

// resealAsTheHost is the operator's machine applying a set with its own
// identity, as `innsegl ca-custody reseal` does through the core.
func resealAsTheHost(t *testing.T, c *cacustody.Custodian, host *age.X25519Identity, set []string) {
	t.Helper()
	ctx := t.Context()
	sealed, err := c.Material()
	if err != nil {
		t.Fatal(err)
	}
	m, err := cacustody.Open(sealed, []age.Identity{host})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := c.Reseal(ctx, cacustody.ResealRequest{Material: m, Opener: host.Recipient().String(),
		Recipients: set, SetDigest: cacustody.SetDigest(set)})
	if err != nil {
		t.Fatalf("the host's reseal: %v", err)
	}
	opened, check, err := cacustody.OpenStaged(staged.Sealed, []age.Identity{host})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ConfirmReseal(ctx, cacustody.ResealConfirm{Material: opened, Check: check, SetDigest: staged.SetDigest}); err != nil {
		t.Fatalf("the host's confirm: %v", err)
	}
}

// resealFromTheDashboard is the owner's Apply: an active key opens the
// material, the API stages the proposed set, the same key opens the staged
// copy, the API confirms it.
func (h orgHarness) resealFromTheDashboard(t *testing.T, key *prfKey) (ResealChallenge, answer) {
	t.Helper()
	begin := h.post(t, "/api/v1/account/ca-custody/reseal/begin", struct{}{})
	if begin.status != http.StatusOK {
		return ResealChallenge{}, begin
	}
	var ch ResealChallenge
	decodeBody(t, begin, &ch)
	m, id := openWith(t, ch.CustodyChallenge, key)
	finish := h.custodyFinish(t, "/api/v1/account/ca-custody/reseal/finish", ch.CustodyChallenge, key, m)
	if finish.status != http.StatusOK {
		return ch, finish
	}
	var staged ResealStagedAnswer
	decodeBody(t, finish, &staged)
	if staged.Staged.SetDigest != ch.SetDigest {
		t.Fatalf("staged %s, proposed %s", staged.Staged.SetDigest, ch.SetDigest)
	}
	opened, check, err := cacustody.OpenStaged(staged.Staged.Sealed, []age.Identity{id})
	if err != nil {
		t.Fatalf("the browser cannot open the staged copy: %v", err)
	}
	raw := mustJSON(t, opened)
	return ch, h.post(t, "/api/v1/account/ca-custody/reseal/confirm",
		ResealConfirmRequest{ConfirmID: staged.ConfirmID, Material: []byte(raw), Check: check})
}

func recipientsOf(rs []ResealRecipient) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Recipient)
	}
	slices.Sort(out)
	return out
}

func TestAUTH018AKeyAppliedByAResealUnlocksARealStoreAfterARestart(t *testing.T) {
	addr, storeName := startCustodyStore(t)
	ctx := t.Context()
	host := newHostIdentity(t)
	custodian := &cacustody.Custodian{Store: &cacustody.Store{Addr: addr}, Dir: t.TempDir(),
		TokenPath: filepath.Join(t.TempDir(), ".vault-token"), Key: "innsegl-ca",
		Recipients: []age.Recipient{host.Recipient()}, Log: io.Discard}
	if err := custodian.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	routes := httptest.NewServer(custodian.Handler())
	t.Cleanup(routes.Close)
	h := newUnlockHarness(t, roleOwner, routes.URL)
	hostR := host.Recipient().String()

	// A new key is pending until a reseal applies it, and a person with no
	// active key cannot apply anything from the dashboard.
	first := newPRFKey(t)
	k1 := h.mustEnrol(t, first, "first key")
	if got, _ := keyByID(h.unlockKeys(t), k1.ID); got.State != "pending" {
		t.Fatalf("a new key is %q", got.State)
	}
	if _, a := h.resealFromTheDashboard(t, first); a.status != http.StatusConflict {
		t.Fatalf("a reseal with no active key: %d %s", a.status, a.body)
	}

	// The operator's machine applies the first key.
	resealAsTheHost(t, custodian, host, []string{hostR, k1.CustodyRecipient})
	if got, _ := keyByID(h.unlockKeys(t), k1.ID); got.State != "active" {
		t.Fatalf("after the host's reseal the key is %q", got.State)
	}

	// The first key applies a second from the dashboard.
	second := newPRFKey(t)
	k2 := h.mustEnrol(t, second, "second key")
	ch, a := h.resealFromTheDashboard(t, first)
	if a.status != http.StatusOK {
		t.Fatalf("reseal from the dashboard: %d %s", a.status, a.body)
	}
	if got := recipientsOf(ch.Added); !slices.Equal(got, []string{k2.CustodyRecipient}) {
		t.Errorf("added %v, want the second key", got)
	}
	want := []string{hostR, k1.CustodyRecipient, k2.CustodyRecipient}
	slices.Sort(want)
	if got := recipientsOf(ch.Recipients); !slices.Equal(got, want) || len(ch.Removed) != 0 {
		t.Errorf("proposed %v removing %v, want %v", got, recipientsOf(ch.Removed), want)
	}
	for _, r := range ch.Recipients {
		if r.Fingerprint == "" || r.Label == "" {
			t.Errorf("a proposed recipient without a label or fingerprint: %+v", r)
		}
	}
	set, err := custodian.CurrentRecipients()
	if err != nil || set.Digest != cacustody.SetDigest(want) {
		t.Fatalf("the custodian's set after the dashboard reseal: %+v, %v", set, err)
	}
	if got, _ := keyByID(h.unlockKeys(t), k2.ID); got.State != "active" {
		t.Errorf("the second key after the reseal is %q", got.State)
	}

	// Revoked, the second key leaves the set at the next reseal and no
	// longer opens the material.
	if r := h.confirmRevoke(t, k2.ID, h.auth); r.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", r.status, r.body)
	}
	ch, a = h.resealFromTheDashboard(t, first)
	if a.status != http.StatusOK {
		t.Fatalf("the reseal after the revoke: %d %s", a.status, a.body)
	}
	if got := recipientsOf(ch.Removed); !slices.Equal(got, []string{k2.CustodyRecipient}) {
		t.Errorf("removed %v, want the revoked key", got)
	}
	sealed, err := custodian.Material()
	if err != nil {
		t.Fatal(err)
	}
	salt := func(k *prfKey) []byte {
		c, cctx := ownerConnAPI(t, h.ownerDSN)
		var s []byte
		if err := c.QueryRow(cctx, `SELECT custody_salt FROM innsegl_auth.unlock_keys WHERE credential_id = $1`,
			credentialIDString(k.CredentialID())).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if _, err := cacustody.Open(sealed, []age.Identity{second.identity(t, salt(second), "custody")}); err == nil {
		t.Error("the revoked key still opens the current material")
	}

	// The store restarts sealed; the first key unlocks it from the dashboard.
	if _, err := dockertest.Docker(ctx, "restart", storeName); err != nil {
		t.Fatal(err)
	}
	waitCustodyStore(t, addr, storeName)
	if st := custodian.Status(ctx); !st.Sealed {
		t.Fatalf("after a restart the store is not sealed: %+v", st)
	}
	a = h.unlockWith(t, first)
	if a.status != http.StatusOK {
		t.Fatalf("unlock from the dashboard: %d %s", a.status, a.body)
	}
	var done CustodyUnlocked
	decodeBody(t, a, &done)
	if done.Status.Sealed || !done.Status.CanSign {
		t.Errorf("after the dashboard's unlock: %+v", done.Status)
	}
	if st := custodian.Status(ctx); st.Sealed || !st.CanSign {
		t.Errorf("the custodian after the dashboard's unlock: %+v", st)
	}
}
